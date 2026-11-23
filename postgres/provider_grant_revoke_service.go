package postgres

import (
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	auditpg "github.com/faustbrian/go-audit/postgres"
	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	organization "github.com/faustbrian/go-organization"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	"github.com/faustbrian/go-sso"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// ProviderGrantRevocationEndpoint opts one installed enterprise provider into
// revocation at an explicitly configured same-origin HTTPS endpoint.
type ProviderGrantRevocationEndpoint struct {
	OrganizationID organization.ID
	ProviderID     sso.ProviderID
	URL            string
}

// ProviderGrantRevocationConfig selects uncached native cookie validation and
// a bounded set of trusted provider endpoints. No HTTP routes are installed.
type ProviderGrantRevocationConfig struct {
	Session   session.ServiceConfig
	Endpoints []ProviderGrantRevocationEndpoint
}

// ProviderGrantRevocationBrowser carries the current enterprise cookie and
// its session-bound CSRF token. Origin is the trusted receiving origin.
type ProviderGrantRevocationBrowser struct {
	Origin  string
	Session authentication.BearerCredential
	CSRF    session.CSRFToken
}

func (ProviderGrantRevocationBrowser) Format(w fmt.State, _ rune) {
	_, _ = fmt.Fprint(w, "postgres.ProviderGrantRevocationBrowser(redacted)")
}

func (ProviderGrantRevocationBrowser) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}

func (ProviderGrantRevocationBrowser) MarshalText() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}

// ProviderGrantRevocationResult keeps local commit, provider disposition and
// local removal separate. A committed unknown provider disposition does not
// authorize replay or indicate provider success. No result contains tokens.
type ProviderGrantRevocationResult struct {
	Completion      kernel.CommandRecord
	ProviderOutcome ProviderGrantRevocationOutcome
	LocalErased     bool
}

type ProviderGrantRevocationService struct {
	completion *ProviderOAuth2LoginCompletionService
	sessions   *session.SessionService
	endpoints  map[providerLoginProfileKey]string
	outcomes   providerLoginPayloadConfig
}

// NewProviderGrantRevocationService selects native revocation for existing
// linked enterprise cookie sessions. Apply the optional grant fence and
// revocation receipt migrations on the same primary before serving calls.
// Construction opens no connection and borrows the installed profile owners.
func NewProviderGrantRevocationService(login *ProviderOAuth2LoginCompletionService, cfg ProviderGrantRevocationConfig) (*ProviderGrantRevocationService, error) {
	if login == nil || login.start == nil || len(cfg.Endpoints) == 0 || len(cfg.Endpoints) > 128 || cfg.Session.Audience != login.policy.Audience {
		return nil, sso.ErrInvalidInput
	}
	start := login.start
	cfg.Session.Clock = start.router.config.Clock
	endpoints := make(map[providerLoginProfileKey]string, len(cfg.Endpoints))
	for _, endpoint := range cfg.Endpoints {
		key := providerLoginProfileKey{endpoint.OrganizationID, endpoint.ProviderID}
		profile, ok := login.profiles[key]
		if !ok || endpoints[key] != "" {
			return nil, sso.ErrInvalidInput
		}
		validator, err := newProviderOAuth2Transport(profile, cfg.Session.Clock, []byte("trusted-config-validation"), nil)
		if err != nil {
			return nil, sso.ErrInvalidInput
		}
		_, err = oauth.NewSharedOAuth2RefreshRevocationProvider(validator, endpoint.URL)
		validator.Close()
		if err != nil {
			return nil, sso.ErrInvalidInput
		}
		endpoints[key] = endpoint.URL
	}
	reader, err := sessionpg.NewSelectedSessionServiceWithSSOOAuth2(start.router.pool,
		sessionpg.SelectedSessionServiceConfig{Repository: start.config.Session, Validation: cfg.Session},
		sessionpg.SSOOAuth2SessionAdmission{Profile: login.policy, Authority: start.router.organizations})
	if err != nil {
		return nil, sso.ErrInvalidInput
	}
	outcomes, err := localProviderGrantRevocationOutcomes(start.payload.StateKeys, start.payload.CurrentStateKey)
	if err != nil {
		return nil, err
	}
	return &ProviderGrantRevocationService{completion: login, sessions: reader, endpoints: endpoints, outcomes: outcomes}, nil
}

// Restore and final Work must not call a remote key provider. Derive a
// distinct local wrapping key from each already-retained state key, whose
// retention also covers the revocation preparation's shorter lifetime.
func localProviderGrantRevocationOutcomes(stateKeys map[uint32][32]byte, current uint32) (providerLoginPayloadConfig, error) {
	keys := make(map[string][]byte, len(stateKeys))
	defer func() {
		for _, key := range keys {
			clear(key)
		}
	}()
	for version, stateKey := range stateKeys {
		ref := strconv.FormatUint(uint64(version), 10)
		key, err := hkdf.Key(sha256.New, stateKey[:], nil, "sso-provider-grant-revoke-outcome-key-v1/"+ref, envelope.DataKeySize)
		clear(stateKey[:])
		if err != nil {
			return providerLoginPayloadConfig{}, sso.ErrInvalidInput
		}
		keys[ref] = key
	}
	ring, err := keyring.New(keys)
	if err != nil {
		return providerLoginPayloadConfig{}, sso.ErrInvalidInput
	}
	service, err := envelope.NewService(ring)
	if err != nil {
		return providerLoginPayloadConfig{}, sso.ErrInvalidInput
	}
	return providerLoginPayloadConfig{Envelope: service, KeyReference: strconv.FormatUint(uint64(current), 10)}, nil
}

// Revoke authorizes the current member before looking up original history.
// Reuse the exact request key. A competing key cannot resend a fenced grant;
// an ambiguous call does not represent provider success or local removal.
func (s *ProviderGrantRevocationService) Revoke(ctx context.Context, request sso.RevokeEnterpriseToken, browser ProviderGrantRevocationBrowser) (ProviderGrantRevocationResult, error) {
	if ctx == nil || s == nil || s.completion == nil || s.sessions == nil {
		return ProviderGrantRevocationResult{}, sso.ErrInvalidInput
	}
	grant, key, err := request.Bindings()
	if err != nil {
		return ProviderGrantRevocationResult{}, err
	}
	ref, err := grant.Spec()
	if err != nil {
		return ProviderGrantRevocationResult{}, err
	}
	start := s.completion.start
	ctx, cancel := context.WithTimeout(ctx, start.config.Coordinator.MaximumDuration)
	defer cancel()
	p, err := s.admit(ctx, ref, browser)
	if err != nil {
		return ProviderGrantRevocationResult{}, err
	}
	coord, registry, err := p.coordinator()
	if err != nil {
		return ProviderGrantRevocationResult{}, err
	}
	intent, err := identity.NewRequestIntent([]identity.FeatureField{revokeBytes("sso.vault.intent", p.intent[:])})
	if err != nil {
		return ProviderGrantRevocationResult{}, err
	}
	k, wire, err := coord.ResolvePreparedRequestKey(ctx, p.scope(), key, intent, p.caller("identity.request-admission", providerGrantRevokeOperation), p.registration(), p)
	defer clear(wire)
	if err != nil {
		return ProviderGrantRevocationResult{}, err
	}
	if err := p.restoreInput(ctx, k, wire); err != nil {
		return ProviderGrantRevocationResult{}, err
	}
	record, err := p.queryCommand(ctx, coord)
	if err == nil && record.Outcome == identity.CommitOutcomeCommitted {
		return p.result(ctx, record)
	}
	var hidden identity.ForbiddenError
	if err != nil && !errors.As(err, &hidden) {
		return ProviderGrantRevocationResult{}, err
	}
	if (record.Binding.CommandID != "" && record.Outcome != identity.CommitOutcomeInProgress) || p.checkOriginal(ctx) != nil {
		return ProviderGrantRevocationResult{}, identity.UnknownCommitError{CommandID: p.binding().CommandID}
	}
	p.plan, err = p.declare(registry)
	if err != nil {
		return ProviderGrantRevocationResult{}, err
	}
	p.plan, err = coord.PrepareFeaturePreparationPlan(p.command, p.plan)
	if err != nil {
		return ProviderGrantRevocationResult{}, err
	}
	out, err := coord.ExecutePreparedFeature(ctx, p.command, p.plan)
	if err != nil || out.Outcome != identity.CommitOutcomeCommitted {
		if err != nil && out.Outcome == 0 {
			return ProviderGrantRevocationResult{}, err
		}
		return ProviderGrantRevocationResult{}, identity.UnknownCommitError{CommandID: p.binding().CommandID}
	}
	record, err = p.queryCommand(ctx, coord)
	if err != nil {
		return ProviderGrantRevocationResult{}, err
	}
	return p.result(ctx, record)
}

func (s *ProviderGrantRevocationService) admit(ctx context.Context, ref sso.TokenVersionSpec, browser ProviderGrantRevocationBrowser) (*providerGrantRevokePhase, error) {
	start := s.completion.start
	endpoint := s.endpoints[providerLoginProfileKey{ref.OrganizationID, ref.ProviderID}]
	if ref.TenantID != start.config.TenantID || endpoint == "" || browser.Origin != start.config.Origin {
		return nil, sso.ErrForbidden
	}
	token, err := session.ParseToken(browser.Session.Token())
	if err != nil {
		return nil, sso.ErrForbidden
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		return nil, sso.ErrForbidden
	}
	observed, err := s.sessions.Get(ctx, session.GetRequest{TenantID: ref.TenantID, Credential: credential})
	now := start.router.config.Clock.Now().UTC()
	if err != nil || observed.ValidateAt(now) != nil {
		return nil, sso.ErrForbidden
	}
	spec, err := observed.Session.Bindings()
	if err != nil || spec.TenantID != ref.TenantID || spec.Authentication.Proof.Method != "sso-oauth2" {
		return nil, sso.ErrForbidden
	}
	vector, err := spec.Authority.Bindings()
	if err != nil || !vector.Organization.Present || vector.ActiveOrganizationID != string(ref.OrganizationID) {
		return nil, sso.ErrForbidden
	}
	csrf := session.CSRFBinding{TenantID: spec.TenantID, SessionID: spec.SessionID, SessionVersion: spec.Version}
	if observed.Session.CSRFState().Check(csrf, browser.CSRF, s.completion.csrfKey) != nil {
		return nil, sso.ErrForbidden
	}
	wire, err := json.Marshal(struct {
		Grant    providerGrantTokenVersionWire
		Endpoint string
		Config   string
	}{providerGrantTokenVersionWire(ref), endpoint, start.config.ConfigurationID})
	defer clear(wire)
	if err != nil {
		return nil, sso.ErrUnavailable
	}
	return &providerGrantRevokePhase{service: s, observed: observed, record: spec, ref: ref, endpoint: endpoint,
		browser: browser, started: now, intent: sha256.Sum256(wire)}, nil
}

// TokenVersionSpec's public serialization intentionally denies this projection.
type providerGrantTokenVersionWire sso.TokenVersionSpec

func (p *providerGrantRevokePhase) scope() kernel.RequestKeyScope {
	return kernel.RequestKeyScope{TenantID: p.record.TenantID, ActorID: identity.ActorID(p.record.UserID),
		ActorKind: authorization.SubjectUser, Method: "POST", RouteID: providerGrantRevokeOperation}
}

func (p *providerGrantRevokePhase) caller(resource authorization.ResourceType, id string) authorization.DecisionContext {
	return authorization.DecisionContext{PolicyRevision: authorization.Revision(p.service.completion.start.policyVersion), Request: authorization.Request{
		Tenant: authorization.TenantID(p.record.TenantID), Action: providerGrantRevokeOperation,
		Subject:     authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(p.record.UserID)},
		Resource:    authorization.Resource{Type: resource, ID: authorization.ResourceID(id)},
		Environment: authorization.Environment{Time: p.started},
	}}
}

func (p *providerGrantRevokePhase) coordinator() (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
	start := p.service.completion.start
	auditing, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, nil, err
	}
	lifecycle, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, nil, err
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{start.directory, auditing, lifecycle, p})
	if err != nil {
		return nil, nil, err
	}
	coord, err := kernel.NewCoordinatorWithRequestKeys(start.router.pool, registry, start.config.Coordinator, start.config.RequestKeys)
	return coord, registry, err
}

func (p *providerGrantRevokePhase) queryCommand(ctx context.Context, c *kernel.Coordinator) (kernel.CommandRecord, error) {
	b := p.binding()
	record, err := c.QueryCommand(ctx, identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID,
		ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}, p.caller("identity.user", string(b.UserID)))
	if record.Binding.CommandID != "" && (record.Binding != b || record.Feature == nil || *record.Feature != p.registration().Operation) {
		return kernel.CommandRecord{}, identity.ForbiddenError{}
	}
	return record, err
}

func (p *providerGrantRevokePhase) result(ctx context.Context, record kernel.CommandRecord) (ProviderGrantRevocationResult, error) {
	if record.Outcome != identity.CommitOutcomeCommitted || record.Binding != p.binding() {
		return ProviderGrantRevocationResult{}, identity.UnknownCommitError{CommandID: p.binding().CommandID}
	}
	b := p.binding()
	id, _ := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	row := p.service.completion.start.router.pool.Raw().QueryRow(ctx, readProviderGrantRevocationReceiptSQL, string(b.TenantID), string(b.UserID), id)
	r, err := scanProviderGrantRevocationReceipt(row)
	if err != nil || !p.matchesReceipt(r) {
		return ProviderGrantRevocationResult{}, identity.UnavailableError{}
	}
	return ProviderGrantRevocationResult{Completion: record, ProviderOutcome: r.Outcome, LocalErased: r.LocalErased}, nil
}
