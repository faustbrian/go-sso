package postgres

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
)

// ProviderServiceConfig selects the existing native session, organization,
// policy, counter, command and envelope owners. No provider HTTP client or
// credentials are accepted. Install ProviderMigrationSource,
// ProviderUpdateMigrationSource and the selected owners' request-key/preparation,
// audit, outbox and authority migrations first.
// The caller retains the pool and keys for the entire service/recovery lifetime.
type ProviderServiceConfig struct {
	Clock           clock.Clock
	MaximumDuration time.Duration
	Sessions        *session.SessionService
	Session         sessionpg.Config
	Profile         sessionpg.IdentifierAdmissionConfig
	LookupKeys      map[uint32]session.DigestKey
	Organizations   *organizationpg.Repository
	Authorization   authorization.Service
	PolicyID        string
	PolicyVersion   uint64
	Counters        *riskpg.Repository
	RequestKeys     kernel.RequestKeyConfig
	Coordinator     kernel.CoordinatorConfig
	Envelope        *envelope.Service
	KeyReference    string
}

// ProviderService authenticates each invocation and exposes disabled metadata
// registration, non-secret update, opt-in enablement and scoped safe reads.
// The service is concurrency-safe;
// each mutation gets a separate native contributor and immutable admission.
// Authentication and network are trusted transport inputs, not request fields.
type ProviderService struct {
	pool                 *database.Pool
	config               ProviderServiceConfig
	authentication       organization.Authentication
	network              string
	directory            *kernel.Repository
	directoryBrowser     *directoryBrowserSession
	updateOrganization   string
	updateAuthorization  ProviderUpdateAuthorization
	enableAuthorization  ProviderEnableAuthorization
	disableAuthorization ProviderDisableAuthorization
	oauthRegistration    bool
	samlOrigin           string
	samlValidator        sso.SAMLRegistrationValidator
	samlSigningValidator sso.SAMLSigningCredentialValidator
}

func (ProviderService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("sso.postgres.ProviderService(redacted)"))
}
func (ProviderServiceConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("sso.postgres.ProviderServiceConfig(redacted)"))
}
func (ProviderService) MarshalJSON() ([]byte, error)       { return nil, sso.ErrSensitiveSerialization }
func (ProviderService) MarshalText() ([]byte, error)       { return nil, sso.ErrSensitiveSerialization }
func (ProviderServiceConfig) MarshalJSON() ([]byte, error) { return nil, sso.ErrSensitiveSerialization }
func (ProviderServiceConfig) MarshalText() ([]byte, error) { return nil, sso.ErrSensitiveSerialization }

// NewProviderService performs bounded local configuration validation without
// I/O. Only ordinary password-authenticated bearer human-member sessions are
// selected; cookie and selected-organization session profiles fail closed.
func NewProviderService(pool *database.Pool, c ProviderServiceConfig, a organization.Authentication, network string) (*ProviderService, error) {
	if pool == nil || pool.Raw() == nil || c.Clock == nil || c.MaximumDuration <= 0 || c.MaximumDuration > 5*time.Second || !c.Sessions.Configured() || c.Session.MaximumDuration <= 0 || c.Session.MaximumDuration > time.Minute || c.Profile.Validate() != nil || c.Profile.AuthenticationMethod != "password" || c.Profile.CredentialKind != identity.CredentialPassword || c.Profile.CredentialOwner != "identity/password" || c.Organizations == nil || c.Authorization == nil || !providerID(c.PolicyID) || c.PolicyVersion == 0 || c.Counters == nil || c.Envelope == nil || !providerID(c.KeyReference) || len(c.LookupKeys) == 0 || len(c.LookupKeys) > 4 || !providerID(string(a.TenantID)) || c.Coordinator.QueryPolicy == nil || c.Coordinator.AdmissionPolicy == nil || c.Coordinator.QueryPolicy.PolicyVersion != c.PolicyVersion || c.Coordinator.AdmissionPolicy.PolicyVersion != c.PolicyVersion || c.RequestKeys.Policy.PolicyVersion != c.PolicyVersion {
		return nil, sso.ErrInvalidInput
	}
	ip, err := netip.ParseAddr(network)
	if err != nil || ip.String() != network {
		return nil, sso.ErrInvalidInput
	}
	if _, err := session.ParseToken(a.Bearer.Token()); err != nil {
		return nil, sso.ErrInvalidInput
	}
	keys := make(map[uint32]session.DigestKey, len(c.LookupKeys))
	probe, _ := session.ParseToken(a.Bearer.Token())
	for version, key := range c.LookupKeys {
		digest, err := probe.Digest(key, string(a.TenantID))
		if err != nil || version == 0 || digest.KeyVersion != version {
			return nil, sso.ErrInvalidInput
		}
		keys[version] = key
	}
	c.LookupKeys = keys
	fingerprints := make(map[uint32][32]byte, len(c.Coordinator.RetainedFingerprintKeys))
	for version, key := range c.Coordinator.RetainedFingerprintKeys {
		fingerprints[version] = key
	}
	c.Coordinator.RetainedFingerprintKeys = fingerprints
	queryPolicy, admissionPolicy := *c.Coordinator.QueryPolicy, *c.Coordinator.AdmissionPolicy
	c.Coordinator.QueryPolicy = &queryPolicy
	c.Coordinator.AdmissionPolicy = &admissionPolicy
	directory, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: c.MaximumDuration})
	if err != nil {
		return nil, sso.ErrInvalidInput
	}
	return &ProviderService{pool: pool, config: c, authentication: a, network: network, directory: directory}, nil
}

func providerID(v string) bool {
	if len(v) == 0 || len(v) > 128 || !utf8.ValidString(v) {
		return false
	}
	for _, r := range v {
		if r < '!' || r > '~' {
			return false
		}
	}
	return true
}

type providerAdmission struct {
	session                  session.GetResult
	organization             organization.CredentialAuthorityObservation
	status                   identity.UserStatusRecord
	started, verified, until time.Time
}

func (s *ProviderService) decision(actor identity.UserID, organizationID, action string) authorization.DecisionContext {
	return authorization.DecisionContext{PolicyRevision: authorization.Revision(s.config.PolicyVersion), Request: authorization.Request{Tenant: authorization.TenantID(s.authentication.TenantID), Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(actor)}, Action: authorization.Action(action), Resource: authorization.Resource{Type: "organization", ID: authorization.ResourceID(organizationID)}}}
}

func (s *ProviderService) admit(ctx context.Context, organizationID, action string) (providerAdmission, error) {
	var a providerAdmission
	a.started = s.config.Clock.Now().UTC().Truncate(time.Microsecond)
	token, err := session.ParseToken(s.authentication.Bearer.Token())
	if err != nil {
		return a, sso.ErrForbidden
	}
	transport := session.CredentialBearer
	if s.directoryBrowser != nil {
		transport = session.CredentialCookie
	}
	credential, err := session.NewCredential(transport, token)
	if err != nil {
		return a, sso.ErrForbidden
	}
	a.session, err = s.config.Sessions.Get(ctx, session.GetRequest{TenantID: s.authentication.TenantID, Credential: credential})
	if err != nil {
		return providerAdmission{}, providerError(ctx, err)
	}
	bound, err := a.session.Session.Bindings()
	if err != nil || a.session.ValidateAt(s.config.Clock.Now()) != nil || bound.TenantID != s.authentication.TenantID || bound.Authentication.Kind != session.AuthenticationVerified || bound.Authentication.Proof.Method != "password" || bound.Authentication.Proof.Assurance != authentication.AssuranceSingleFactor {
		return providerAdmission{}, sso.ErrForbidden
	}
	if !s.directoryBrowser.valid(a.session.Session, action != "org:sso-read") {
		return providerAdmission{}, sso.ErrForbidden
	}
	original := identity.CommandBinding{TenantID: bound.TenantID, UserID: bound.UserID, ActorID: identity.ActorID(bound.UserID), ActorKind: authorization.SubjectUser}
	if _, _, _, err = sessionpg.OriginalSessionAdmission(s.config.Profile, a.session.Session, original); err != nil {
		return providerAdmission{}, sso.ErrForbidden
	}
	query := organization.CredentialAuthorityQuery{TenantID: bound.TenantID, OrganizationID: organization.ID(organizationID), ActorID: bound.UserID}
	a.organization, err = s.config.Organizations.ObserveCredentialAuthority(ctx, query)
	if err != nil {
		return providerAdmission{}, providerError(ctx, err)
	}
	if a.organization.Validate(query, s.config.Clock.Now()) != nil || a.organization.Actor.Role != organization.RoleOwner && a.organization.Actor.Role != organization.RoleAdministrator {
		return providerAdmission{}, sso.ErrForbidden
	}
	dc := s.decision(bound.UserID, organizationID, action)
	decision, err := s.config.Authorization.Decide(ctx, dc)
	if err != nil {
		return providerAdmission{}, providerError(ctx, err)
	}
	if decision.Outcome != authorization.Allow || decision.Revision != dc.PolicyRevision {
		return providerAdmission{}, sso.ErrForbidden
	}
	a.status, err = s.directory.GetStatus(ctx, identity.UserStatusQuery{TenantID: bound.TenantID, UserID: bound.UserID})
	if err != nil {
		return providerAdmission{}, providerError(ctx, err)
	}
	if a.status.User.Status != identity.StatusActive {
		return providerAdmission{}, sso.ErrForbidden
	}
	if err = s.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&a.verified); err != nil {
		return providerAdmission{}, providerError(ctx, err)
	}
	a.verified = a.verified.UTC().Truncate(time.Microsecond)
	a.until = a.started.Add(20 * time.Second)
	for _, until := range []time.Time{a.session.ValidUntil(), a.organization.ValidUntil} {
		if until.Before(a.until) {
			a.until = until
		}
	}
	if a.session.ValidateAt(a.verified) != nil || !a.verified.Before(a.until) {
		return providerAdmission{}, sso.ErrForbidden
	}
	return a, nil
}

func (s *ProviderService) providerMetadataSelect() string {
	const columns = `SELECT provider_id,COALESCE(metadata_mapping_version,mapping_version)::text,metadata_version::text,enabled`
	if s.oauthRegistration || s.samlOrigin != "" {
		return columns + ",protocol"
	}
	return columns
}

func (s *ProviderService) scanProviderMetadata(row interface{ Scan(...any) error }, organizationID string) (sso.Provider, error) {
	p := sso.Provider{OrganizationID: organizationID, Protocol: providerProtocolOIDC, VerifiedDomains: []string{}}
	var mappingVersion, providerVersion string
	var err error
	if s.oauthRegistration || s.samlOrigin != "" {
		err = row.Scan(&p.ID, &mappingVersion, &providerVersion, &p.Enabled, &p.Protocol)
	} else {
		err = row.Scan(&p.ID, &mappingVersion, &providerVersion, &p.Enabled)
	}
	if err != nil {
		return sso.Provider{}, err
	}
	switch p.Protocol {
	case providerProtocolOIDC, providerProtocolOAuth2, providerProtocolSAML:
	default:
		return sso.Provider{}, sso.ErrUnavailable
	}
	if p.MappingVersion, err = strconv.ParseUint(mappingVersion, 10, 64); err != nil || p.MappingVersion == 0 {
		return sso.Provider{}, sso.ErrUnavailable
	}
	if p.Version, err = strconv.ParseUint(providerVersion, 10, 64); err != nil || p.Version == 0 {
		return sso.Provider{}, sso.ErrUnavailable
	}
	return p, nil
}

func (s *ProviderService) read(ctx context.Context, organizationID string, cursor sso.ProviderID, limit uint32) ([]sso.Provider, error) {
	rows, err := s.pool.Raw().Query(ctx, s.providerMetadataSelect()+` FROM sso_providers.providers WHERE tenant_id=$1 AND organization_id=$2 AND provider_id>$3 ORDER BY provider_id LIMIT $4`, string(s.authentication.TenantID), organizationID, string(cursor), int32(limit))
	if err != nil {
		return nil, providerError(ctx, err)
	}
	defer rows.Close()
	providers := make([]sso.Provider, 0, limit)
	for rows.Next() {
		p, err := s.scanProviderMetadata(rows, organizationID)
		if err != nil {
			return nil, providerError(ctx, err)
		}
		providers = append(providers, p)
	}
	if err = rows.Err(); err != nil {
		return nil, providerError(ctx, err)
	}
	return providers, nil
}

// ProviderGet authenticates current organization read authority; missing and
// foreign providers have the same redacted denial. Enabled describes persisted
// configuration, not current domain or login authority. No envelope is opened.
func (s *ProviderService) ProviderGet(ctx context.Context, r sso.ProviderGetRequest) (sso.ProviderGetResult, error) {
	if s == nil || ctx == nil || !providerID(r.OrganizationID) || !providerID(string(r.ProviderID)) {
		return sso.ProviderGetResult{}, sso.ErrInvalidInput
	}
	ctx, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	if _, err := s.admit(ctx, r.OrganizationID, "org:sso-read"); err != nil {
		return sso.ProviderGetResult{}, err
	}
	row := s.pool.Raw().QueryRow(ctx, s.providerMetadataSelect()+` FROM sso_providers.providers WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`, string(s.authentication.TenantID), r.OrganizationID, string(r.ProviderID))
	p, err := s.scanProviderMetadata(row, r.OrganizationID)
	if err != nil {
		return sso.ProviderGetResult{}, providerError(ctx, err)
	}
	if _, err = s.admit(ctx, r.OrganizationID, "org:sso-read"); err != nil {
		return sso.ProviderGetResult{}, err
	}
	return sso.ProviderGetResult{Provider: p}, nil
}

// ProviderList returns at most 100 providers in stable opaque-ID order. Cursors
// are scoped anew on each call and never confer authority to another owner.
func (s *ProviderService) ProviderList(ctx context.Context, r sso.ProviderListRequest) (sso.ProviderListResult, error) {
	if s == nil || ctx == nil || !providerID(r.OrganizationID) || r.Limit == 0 || r.Limit > 100 || r.Cursor != "" && !providerID(string(r.Cursor)) {
		return sso.ProviderListResult{}, sso.ErrInvalidInput
	}
	ctx, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	if _, err := s.admit(ctx, r.OrganizationID, "org:sso-read"); err != nil {
		return sso.ProviderListResult{}, err
	}
	providers, err := s.read(ctx, r.OrganizationID, r.Cursor, r.Limit+1)
	if err != nil {
		return sso.ProviderListResult{}, err
	}
	if _, err = s.admit(ctx, r.OrganizationID, "org:sso-read"); err != nil {
		return sso.ProviderListResult{}, err
	}
	out := sso.ProviderListResult{Providers: providers}
	if len(providers) > int(r.Limit) {
		out.Providers = providers[:r.Limit]
		out.NextCursor = sso.ProviderID(out.Providers[len(out.Providers)-1].ID)
	}
	return out, nil
}

func validateProviderRequest(r sso.ProviderRegisterOidcRequest) error {
	metadata, err := r.StaticMetadata.Spec()
	_, commandErr := identity.ParseCommandID(string(r.CommandID))
	if err != nil || !providerID(r.OrganizationID) || commandErr != nil || r.Issuer != metadata.Issuer || r.DiscoveryURL.String() != "" || len(r.Domains) < 1 || len(r.Domains) > 128 {
		return sso.ErrInvalidInput
	}
	if _, err = r.Mapping.Spec(); err != nil {
		return sso.ErrInvalidInput
	}
	seen := make(map[string]bool, len(r.Domains))
	for _, domain := range r.Domains {
		canonical, err := organization.CanonicalDomain(domain)
		if err != nil || canonical != domain || seen[domain] {
			return sso.ErrInvalidInput
		}
		seen[domain] = true
	}
	if strings.TrimSpace(r.Issuer) != r.Issuer {
		return sso.ErrInvalidInput
	}
	return nil
}
