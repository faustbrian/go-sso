package postgres

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"strconv"
	"sync/atomic"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// ProviderSAMLIDPArrivalConfig explicitly selects the native linked-user
// pending writer. Install the pending, issued capability, audit and outbox
// histories before use. The envelope belongs to the admission router's primary
// composition; keep the referenced envelope and commitment keys while pending.
type ProviderSAMLIDPArrivalConfig struct {
	ActorID                                    identity.ActorID
	PolicyID, GlobalAuthorityID, KeyReference  string
	PolicyVersion, AuditRetentionPolicyVersion uint64
	Coordinator                                kernel.CoordinatorConfig
	Capability                                 capabilitypg.IssuerConfig
	CurrentConfirmationKey                     uint32
	ConfirmationKeys                           map[uint32][32]byte
}

// Format redacts settings and borrowed keys.
func (ProviderSAMLIDPArrivalConfig) Format(s fmt.State, _ rune) {
	_, _ = fmt.Fprint(s, "sso.postgres.ProviderSAMLIDPArrivalConfig(redacted)")
}

func (ProviderSAMLIDPArrivalConfig) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}
func (ProviderSAMLIDPArrivalConfig) MarshalText() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}

// ProviderSAMLIDPArrivalService admits the installed assertion and saves a
// pending confirmation. It never publishes the issued grant, reserves SAML
// replay, creates sessions, performs SP initiation or exposes an HTTP route.
type ProviderSAMLIDPArrivalService struct {
	admission  *ProviderSAMLIDPAdmissionService
	issuer     *capabilitypg.Issuer
	issuerName string
	audience   string
	config     ProviderSAMLIDPArrivalConfig
	payload    providerLoginPayloadConfig
}

// NewProviderSAMLIDPArrivalService borrows a linked admission service on the
// same primary. Construction snapshots settings and performs no I/O.
func NewProviderSAMLIDPArrivalService(admission *ProviderSAMLIDPAdmissionService, config ProviderSAMLIDPArrivalConfig) (*ProviderSAMLIDPArrivalService, error) {
	if admission == nil || admission.router == nil || admission.linked == nil ||
		!providerID(string(config.ActorID)) || !providerID(config.PolicyID) || !providerID(config.GlobalAuthorityID) || !providerID(config.KeyReference) ||
		config.PolicyVersion == 0 || config.AuditRetentionPolicyVersion == 0 || config.CurrentConfirmationKey == 0 ||
		len(config.ConfirmationKeys) == 0 || len(config.ConfirmationKeys) > 32 || config.ConfirmationKeys[config.CurrentConfirmationKey] == ([32]byte{}) {
		return nil, sso.ErrInvalidInput
	}
	seen := make(map[[32]byte]bool, len(config.ConfirmationKeys))
	for version, key := range config.ConfirmationKeys {
		if version == 0 || key == ([32]byte{}) || seen[key] {
			return nil, sso.ErrInvalidInput
		}
		seen[key] = true
	}
	issuer, err := capabilitypg.NewIssuer(config.Capability)
	if err != nil {
		return nil, sso.ErrInvalidInput
	}
	issuerName, audience := config.Capability.Crypto.Issuer, config.Capability.Audience
	config.Capability = capabilitypg.IssuerConfig{}
	config.ConfirmationKeys = maps.Clone(config.ConfirmationKeys)
	config.Coordinator.RetainedFingerprintKeys = maps.Clone(config.Coordinator.RetainedFingerprintKeys)
	// Receipt lookup is separately selected and cannot authorize execution or
	// request a new browser disclosure from an existing command.
	if config.Coordinator.QueryPolicy != nil {
		queryPolicy := *config.Coordinator.QueryPolicy
		config.Coordinator.QueryPolicy = &queryPolicy
	}
	config.Coordinator.AdmissionPolicy = nil
	config.Coordinator.FinalAuthentication = nil
	s := &ProviderSAMLIDPArrivalService{admission: admission, issuer: issuer, issuerName: issuerName, audience: audience, config: config,
		payload: providerLoginPayloadConfig{Envelope: admission.router.config.Envelope, KeyReference: config.KeyReference}}
	if _, _, err := s.coordinator(&samlIDPArrivalPhase{service: s}); err != nil {
		return nil, providerError(context.Background(), err)
	}
	return s, nil
}

// Format redacts the borrowed issuer and configuration.
func (*ProviderSAMLIDPArrivalService) Format(s fmt.State, _ rune) {
	_, _ = fmt.Fprint(s, "sso.postgres.ProviderSAMLIDPArrivalService(redacted)")
}

func (*ProviderSAMLIDPArrivalService) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}
func (*ProviderSAMLIDPArrivalService) MarshalText() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}

// SAMLIDPArrivalResult reports the original command outcome, not a session.
// Only a new acknowledged commit carries a one-shot browser disclosure.
type SAMLIDPArrivalResult struct {
	CommandID identity.CommandID
	Outcome   identity.CommitOutcome
	pair      *samlIDPArrivalPair
}

type samlIDPArrivalPair struct {
	taken         atomic.Bool
	browser, form auth.BearerCredential
	expires       time.Time
}

// Format redacts all browser custody.
func (SAMLIDPArrivalResult) Format(s fmt.State, _ rune) {
	_, _ = fmt.Fprint(s, "sso.postgres.SAMLIDPArrivalResult(redacted)")
}

func (SAMLIDPArrivalResult) MarshalJSON() ([]byte, error) { return nil, sso.ErrSensitiveSerialization }
func (SAMLIDPArrivalResult) MarshalText() ([]byte, error) { return nil, sso.ErrSensitiveSerialization }

// TakeConfirmation lends the original independent cookie and form values once.
// Result copies share that attempt. Failed, old or unknown arrivals never carry
// these values. The returned original deadline must still be enforced by the
// trusted transport and the native confirmation owner.
func (r SAMLIDPArrivalResult) TakeConfirmation() (browser, form auth.BearerCredential, expires time.Time, ok bool) {
	if r.pair == nil || !r.pair.taken.CompareAndSwap(false, true) {
		return browser, form, expires, false
	}
	browser, form = r.pair.browser, r.pair.form
	r.pair.browser, r.pair.form = auth.BearerCredential{}, auth.BearerCredential{}
	return browser, form, r.pair.expires, true
}

// Prepare verifies the assertion against installed authority, then atomically
// commits bounded encrypted pending custody and the one-use confirmation grant.
// It does no retries or session work. A known failed or uncertain commit does
// not disclose browser credentials. Call only from trusted native composition.
func (s *ProviderSAMLIDPArrivalService) Prepare(ctx context.Context, request SAMLIDPAdmissionRequest) (out SAMLIDPArrivalResult, err error) {
	if ctx == nil || s == nil || s.admission == nil || s.issuer == nil {
		return out, sso.ErrInvalidInput
	}
	ctx, cancel := context.WithTimeout(ctx, s.admission.router.config.MaximumDuration)
	defer cancel()
	admitted, err := s.admission.VerifyLinkedRecipient(ctx, request)
	if err != nil {
		return out, err
	}
	p, pair, err := s.prepareArrival(ctx, admitted)
	if err != nil {
		return out, providerError(ctx, err)
	}
	defer clear(p.pending.Envelope)
	coordinator, registry, err := s.coordinator(p)
	if err != nil {
		return out, providerError(ctx, err)
	}
	result, fresh, err := p.execute(ctx, coordinator, registry)
	out = SAMLIDPArrivalResult{CommandID: p.pending.Binding.CommandID, Outcome: result.Outcome}
	if result.Outcome == identity.CommitOutcomeUnknown {
		return out, identity.UnknownCommitError{CommandID: out.CommandID}
	}
	if err != nil {
		var unknown identity.UnknownCommitError
		if errors.As(err, &unknown) {
			out.Outcome = identity.CommitOutcomeUnknown
			return out, unknown
		}
		return out, providerError(ctx, err)
	}
	if fresh && result.Binding == p.pending.Binding && result.Outcome == identity.CommitOutcomeCommitted &&
		result.Feature != nil && *result.Feature == samlIDPArrivalReceipt() && s.admission.router.config.Clock.Now().Before(pair.expires) {
		out.pair = pair
	}
	return out, nil
}

// RecoverArrival looks up or reconciles an exact original arrival through the
// existing coordinator and a configured current query policy. It never
// returns the original browser values, reads fresh authentication authority,
// or attempts another arrival. An ambiguous result remains ambiguous.
func (s *ProviderSAMLIDPArrivalService) RecoverArrival(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (out SAMLIDPArrivalResult, err error) {
	if ctx == nil || s == nil || s.admission == nil || s.config.Coordinator.QueryPolicy == nil || q.OperationID != samlIDPPendingArrivalOperation().OperationID ||
		q.TenantID != s.admission.tenant || q.ActorID != s.config.ActorID || q.ActorKind != authorization.SubjectServiceAccount ||
		q.RecordID != string(q.CommandID) || q.AnonymousFlowID != "" || q.UserID == "" || q.LinkMode != 0 {
		return out, sso.ErrInvalidInput
	}
	p := &samlIDPArrivalPhase{service: s}
	c, _, err := s.coordinator(p)
	if err != nil {
		return out, providerError(ctx, err)
	}
	result, err := c.RecoverFeatureCommand(ctx, q, caller)
	if result.Binding.CommandID == q.CommandID && result.Feature != nil && result.Feature.Operation == samlIDPPendingArrivalOperation() {
		out.CommandID, out.Outcome = result.Binding.CommandID, result.Outcome
	}
	if err != nil {
		var unknown identity.UnknownCommitError
		if errors.As(err, &unknown) {
			return out, unknown
		}
		// An authorized pending receipt paired with an unavailable reconciliation
		// does not prove a live lease or rollback. Keep its original identity.
		if out.Outcome == identity.CommitOutcomeInProgress && errors.Is(err, identity.UnavailableError{}) {
			out.Outcome = identity.CommitOutcomeUnknown
			return out, identity.UnknownCommitError{CommandID: out.CommandID}
		}
		return out, providerError(ctx, err)
	}
	if out.CommandID == "" {
		return out, sso.ErrForbidden
	}
	return out, nil
}

func (s *ProviderSAMLIDPArrivalService) coordinator(p *samlIDPArrivalPhase) (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
	audits, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, nil, err
	}
	lifecycle, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, nil, err
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{s.admission.linked.directory, audits, lifecycle, p, s.issuer})
	if err != nil {
		return nil, nil, err
	}
	c, err := kernel.NewCoordinator(s.admission.router.pool, registry, s.config.Coordinator)
	return c, registry, err
}

// Only this sealed payload, not the browser cookie nor form value, contains
// the original authority and the signed proof. None of it is public output.
type samlIDPArrivalOrigin struct {
	Version                      uint8
	Binding                      identity.CommandBinding
	Route                        samlIDPArrivalRoute
	Issuer                       string
	MappingVersion               uint64
	Evidence                     samlIDPArrivalEvidence
	Account                      samlIDPArrivalAccount
	Member                       organization.CredentialAuthorityObservation
	GlobalAuthorityID            string
	GlobalVersion, TenantVersion uint64
	FactorVersion                uint64
	PolicyVersion                uint64
	Grant                        providerLoginStoredGrant
	Proof                        []byte
}

// Public diagnostic encoders deliberately reject these observations. The
// bounded private representation is written only inside the pending envelope.
type samlIDPArrivalEvidence SAMLVerifiedResponse

type samlIDPArrivalRoute struct {
	ProviderID                                           sso.ProviderID
	ProviderVersion, CredentialGeneration, PolicyVersion uint64
	ProofKey                                             organization.DomainProofKey
	ProofVersion                                         uint64
	ObservedAt, ValidUntil                               time.Time
}

type samlIDPArrivalAccount struct {
	Account                                                                 identity.Account
	Credential                                                              identity.CredentialRef
	LinkVersion, UserVersion, IdentifierVersion, CredentialAuthorityVersion uint64
}

func (s *ProviderSAMLIDPArrivalService) prepareArrival(ctx context.Context, a ProviderSAMLIDPLinkedAdmission) (*samlIDPArrivalPhase, *samlIDPArrivalPair, error) {
	route := a.admission.route
	selected, ok := s.admission.profiles[route.ProviderID]
	started := a.admission.verifiedAt.UTC().Truncate(time.Microsecond)
	deadline := a.admission.validUntil.UTC().Truncate(time.Microsecond)
	issued, grantExpiry := started.Truncate(time.Second), deadline.Truncate(time.Second)
	if !ok || a.LinkedUser() == "" || !started.Before(deadline) || !s.admission.router.config.Clock.Now().Before(grantExpiry) {
		return nil, nil, identity.ForbiddenError{}
	}
	op := samlIDPPendingArrivalOperation()
	id, err := identity.NewCommandID()
	if err != nil {
		return nil, nil, identity.UnavailableError{}
	}
	binding := identity.CommandBinding{CommandID: id, TenantID: s.admission.tenant, UserID: a.LinkedUser(), ActorID: s.config.ActorID, ActorKind: authorization.SubjectServiceAccount,
		OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, RecordID: string(id), CorrelationID: string(id), PolicyID: s.config.PolicyID, PolicyVersion: s.config.PolicyVersion}
	if binding.ValidateFor(op) != nil || route.Proof.Key.TenantID != binding.TenantID {
		return nil, nil, identity.ForbiddenError{}
	}
	query := kernel.DirectoryAuthorityQuery{GlobalAuthorityID: s.config.GlobalAuthorityID, TenantID: binding.TenantID}
	directory, err := s.admission.linked.directory.GetDirectoryAuthority(ctx, query)
	if err != nil {
		return nil, nil, err
	}
	if !directory.Enabled {
		return nil, nil, identity.ForbiddenError{}
	}
	directoryFence := kernel.DirectoryAuthorityAdmission{Query: directory.Query, GlobalVersion: directory.GlobalVersion, TenantVersion: directory.TenantVersion}
	keyVersion := s.config.CurrentConfirmationKey
	key := s.config.ConfirmationKeys[keyVersion]
	var browserRaw, formRaw [32]byte
	defer clear(browserRaw[:])
	defer clear(formRaw[:])
	if _, err := rand.Read(browserRaw[:]); err != nil {
		return nil, nil, identity.UnavailableError{}
	}
	if _, err := rand.Read(formRaw[:]); err != nil || browserRaw == formRaw {
		return nil, nil, identity.UnavailableError{}
	}
	browserDigest, formDigest := samlIDPBrowserCommitments(key, keyVersion, binding, route.ProviderID, browserRaw[:], formRaw[:])
	pending := samlIDPPendingArrival{Binding: binding, Organization: route.Proof.Key.OrganizationID, Provider: route.ProviderID, KeyVersion: keyVersion,
		BrowserDigest: browserDigest, FormDigest: formDigest, IssuedAt: started, ExpiresAt: deadline}
	grant, err := s.issuer.Prepare(ctx, binding, []capability.Payload{{Version: 1, Issuer: s.issuerName, Audiences: []string{s.audience}, Subject: string(binding.UserID),
		Tenant: string(binding.TenantID), Resource: binding.RecordID, Operation: kernel.SSOSAMLIDPConfirmationOperation().OperationID, CorrelationID: binding.CorrelationID,
		IssuedAt: issued, NotBefore: issued, ExpiresAt: grantExpiry, MaxUses: 1}})
	if err != nil {
		return nil, nil, err
	}
	declaration, err := grant.Plan()
	if err != nil || len(declaration.Grants) != 1 {
		return nil, nil, identity.UnavailableError{}
	}
	aad, err := samlIDPArrivalAAD(pending)
	if err != nil {
		return nil, nil, err
	}
	account, credential := a.recipient.account, a.recipient.account.Credential
	origin := samlIDPArrivalOrigin{Version: 1, Binding: binding, Issuer: a.admission.issuer, MappingVersion: selected.profile.Provider.MappingVersion,
		Route: samlIDPArrivalRoute{ProviderID: route.ProviderID, ProviderVersion: route.ProviderVersion, CredentialGeneration: route.CredentialGeneration,
			PolicyVersion: route.PolicyVersion, ProofKey: route.Proof.Key, ProofVersion: route.Proof.ProofVersion, ObservedAt: route.ObservedAt, ValidUntil: route.ValidUntil},
		Evidence: samlIDPArrivalEvidence(a.admission.wire), Member: a.recipient.member,
		Account: samlIDPArrivalAccount{Account: account.Account, Credential: credential.Credential, LinkVersion: account.SocialLinkVersion,
			UserVersion: credential.UserAuthorityVersion, IdentifierVersion: credential.IdentifierAuthorityVersion, CredentialAuthorityVersion: credential.CredentialAuthorityVersion},
		GlobalAuthorityID: query.GlobalAuthorityID, GlobalVersion: directory.GlobalVersion, TenantVersion: directory.TenantVersion,
		FactorVersion: a.recipient.factorVersion, PolicyVersion: a.recipient.policyVersion, Grant: providerLoginStoredGrant(declaration.Grants[0])}
	err = grant.TransferForDelivery(ctx, 0, func(ctx context.Context, proof []byte) error {
		origin.Proof = proof
		plain, err := providerLoginPayloadEncode(origin)
		defer clear(plain)
		if err != nil || len(plain) > 32768 {
			return identity.UnavailableError{}
		}
		pending.Envelope, err = s.payload.seal(ctx, aad, plain, 65536)
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	envelopeDigest := sha256.Sum256(pending.Envelope)
	command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Operation: op, Binding: binding, Fields: []identity.FeatureField{
		{Name: "saml.arrival.envelope-digest", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: envelopeDigest[:]}},
	}})
	if err != nil {
		clear(pending.Envelope)
		return nil, nil, err
	}
	p := &samlIDPArrivalPhase{service: s, pending: pending, admitted: a, mappingVersion: origin.MappingVersion,
		directory: directoryFence, command: command, issuance: declaration, grant: grant}
	return p, &samlIDPArrivalPair{browser: auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(browserRaw[:])),
		form: auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(formRaw[:])), expires: grantExpiry}, nil
}

func samlIDPBrowserCommitments(key [32]byte, version uint32, b identity.CommandBinding, provider sso.ProviderID, browser, form []byte) ([32]byte, [32]byte) {
	return providerLoginPayloadMAC(key, version, "identity.sso.saml-idp.browser.v1", []byte(b.TenantID), []byte(provider), []byte(b.CommandID), browser),
		providerLoginPayloadMAC(key, version, "identity.sso.saml-idp.form.v1", []byte(b.TenantID), []byte(provider), []byte(b.CommandID), form)
}

func samlIDPArrivalAAD(a samlIDPPendingArrival) (envelope.Context, error) {
	return envelope.NewContext(map[string]string{"profile": "identity-sso-saml-idp-pending-v1", "tenant": string(a.Binding.TenantID),
		"organization": string(a.Organization), "provider": string(a.Provider), "user": string(a.Binding.UserID), "arrival": string(a.Binding.CommandID),
		"issued": a.IssuedAt.Format(time.RFC3339Nano), "expires": a.ExpiresAt.Format(time.RFC3339Nano),
		"key_version": strconv.FormatUint(uint64(a.KeyVersion), 10), "browser": hex.EncodeToString(a.BrowserDigest[:]), "form": hex.EncodeToString(a.FormDigest[:])})
}
