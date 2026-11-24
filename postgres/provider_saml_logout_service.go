package postgres

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	organization "github.com/faustbrian/go-organization"
	"github.com/faustbrian/go-sso"
	"github.com/faustbrian/go-sso/saml"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// ProviderSAMLLogoutConfig explicitly selects the same native session profile,
// CSRF keys and exact application targets used by the installed SAML sessions.
// Install SSOSAMLLogoutStartMigrationSource before enabling the service.
type ProviderSAMLLogoutConfig struct {
	Session                session.ServiceConfig
	Admission              sessionpg.SSOSAMLSessionAdmission
	CSRFKeys               []session.CSRFKey
	FinalRedirectAllowlist []string
}

func (ProviderSAMLLogoutConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("sso.postgres.ProviderSAMLLogoutConfig(redacted)"))
}

func (ProviderSAMLLogoutConfig) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}
func (ProviderSAMLLogoutConfig) MarshalText() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}

// ProviderSAMLLogoutStartResult separates the original local session outcome
// from any front-channel outcome. A zero projection means selection failed.
type ProviderSAMLLogoutStartResult struct {
	LocalRevocation saml.LocalRevocation
	LocalOnly       bool
	Completion      identity.CommandResult
}

// ProviderSAMLLogoutService owns the protected local part of SAML logout. It
// uses the actual SAML cookie and the original linked account. It does not
// discover provider capabilities, contact the provider or install HTTP routes.
type ProviderSAMLLogoutService struct {
	login         *ProviderLoginService
	sessions      *session.SessionService
	retained      *sessionpg.Repository
	effect        *sessionpg.SSOSAMLLogoutStartEffect
	lookupKeys    []session.DigestKey
	csrfKeys      []session.CSRFKey
	finalRedirect map[string]struct{}
}

// NewProviderSAMLLogoutService snapshots the selected session authority,
// CSRF keys and allowlist. It performs no I/O and starts no background work.
// It retains the login-service input's request-key namespace for existing
// callers that already select dedicated logout custody.
func NewProviderSAMLLogoutService(login *ProviderLoginService, cfg ProviderSAMLLogoutConfig) (*ProviderSAMLLogoutService, error) {
	return newProviderSAMLLogoutService(login, cfg, nil)
}

// NewProviderSAMLLogoutServiceWithRequestKeys selects a stable logout
// namespace distinct from canonical SAML sign-in. Keep the original keys
// and namespace while any original logout request can still be retried.
func NewProviderSAMLLogoutServiceWithRequestKeys(login *ProviderLoginService, cfg ProviderSAMLLogoutConfig, keys kernel.RequestKeyConfig) (*ProviderSAMLLogoutService, error) {
	return newProviderSAMLLogoutService(login, cfg, &keys)
}

func newProviderSAMLLogoutService(login *ProviderLoginService, cfg ProviderSAMLLogoutConfig, keys *kernel.RequestKeyConfig) (*ProviderSAMLLogoutService, error) {
	if login == nil || login.router == nil || login.config.RequestKeys.Namespace == "" ||
		login.config.Coordinator.AdmissionPolicy == nil || login.config.Coordinator.QueryPolicy == nil ||
		cfg.Admission.Profile.GlobalAuthorityID != login.config.GlobalAuthorityID ||
		len(cfg.CSRFKeys) == 0 || len(cfg.CSRFKeys) > 32 ||
		len(cfg.FinalRedirectAllowlist) == 0 || len(cfg.FinalRedirectAllowlist) > 64 {
		return nil, sso.ErrInvalidInput
	}
	login, err := withSAMLLogoutRequestKeys(login, keys)
	if err != nil {
		return nil, err
	}
	seenKeys := make(map[uint32]struct{}, len(cfg.CSRFKeys))
	for _, key := range cfg.CSRFKeys {
		if _, duplicate := seenKeys[key.Version()]; key.Version() == 0 || duplicate {
			return nil, sso.ErrInvalidInput
		}
		seenKeys[key.Version()] = struct{}{}
	}
	allowed := make(map[string]struct{}, len(cfg.FinalRedirectAllowlist))
	for _, target := range cfg.FinalRedirectAllowlist {
		if _, duplicate := allowed[target]; !validProviderLoginCallback(target) || duplicate {
			return nil, sso.ErrInvalidInput
		}
		allowed[target] = struct{}{}
	}
	store := login.config.Session
	reader, err := sessionpg.NewSelectedSessionServiceWithSSOSAML(login.router.pool,
		sessionpg.SelectedSessionServiceConfig{Repository: store, Validation: cfg.Session}, cfg.Admission, nil)
	if err != nil {
		return nil, sso.ErrInvalidInput
	}
	retained, err := sessionpg.NewRepository(login.router.pool, store)
	if err != nil {
		return nil, sso.ErrInvalidInput
	}
	effect, err := sessionpg.NewSSOSAMLLogoutStartEffect(store, cfg.Admission)
	if err != nil {
		return nil, sso.ErrInvalidInput
	}
	return &ProviderSAMLLogoutService{login: login, sessions: reader, retained: retained, effect: effect,
		lookupKeys: slices.Clone(cfg.Session.LookupKeys), csrfKeys: slices.Clone(cfg.CSRFKeys), finalRedirect: allowed}, nil
}

func withSAMLLogoutRequestKeys(login *ProviderLoginService, keys *kernel.RequestKeyConfig) (*ProviderLoginService, error) {
	if keys == nil {
		return login, nil
	}
	selected := *keys
	if selected.Namespace == login.config.RequestKeys.Namespace || selected.Policy.PolicyVersion != login.policyVersion {
		return nil, sso.ErrInvalidInput
	}
	// Validate the opaque configuration through its owner, without starting a
	// transaction or copying the caller's policy and key into the sign-in path.
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{login.directory})
	if err != nil {
		return nil, sso.ErrInvalidInput
	}
	if _, err := kernel.NewCoordinatorWithRequestKeys(login.router.pool, registry, login.config.Coordinator, selected); err != nil {
		return nil, sso.ErrInvalidInput
	}
	view := *login
	view.config.RequestKeys = selected
	return &view, nil
}

// Start revokes the selected original cookie session without a provider
// round trip. An individually revoked cookie can recover only the retained
// result of its exact request; it cannot start another command.
func (s *ProviderSAMLLogoutService) Start(ctx context.Context, request ProviderLogoutStartRequest, browser ProviderLogoutBrowser) (ProviderSAMLLogoutStartResult, error) {
	return s.start(ctx, request, browser, nil)
}

func (s *ProviderSAMLLogoutService) start(ctx context.Context, request ProviderLogoutStartRequest, browser ProviderLogoutBrowser,
	afterCommit func(context.Context, *providerSAMLLogoutStartPhase, ProviderSAMLLogoutStartResult) error) (out ProviderSAMLLogoutStartResult, err error) {
	if s == nil || s.login == nil || ctx == nil || !providerID(request.ProviderID) || request.IdempotencyKey == (identity.IdempotencyKey{}) {
		return out, sso.ErrInvalidInput
	}
	if _, allowed := s.finalRedirect[request.FinalRedirect]; browser.Origin != s.login.config.Origin || !allowed {
		return out, sso.ErrForbidden
	}
	ctx, cancel := context.WithTimeout(ctx, s.login.config.Coordinator.MaximumDuration)
	defer cancel()
	p := &providerSAMLLogoutStartPhase{service: s, request: request, browser: browser}
	if err := p.admitBrowser(ctx); err != nil {
		return out, providerError(ctx, err)
	}
	policy := s.login.config.Coordinator.AdmissionPolicy
	decision, err := policy.Authorization.Decide(ctx, p.caller("identity.user", string(p.record.UserID)))
	if err != nil {
		return out, providerError(ctx, err)
	}
	if decision.Outcome != authorization.Allow || decision.Revision != authorization.Revision(s.login.policyVersion) {
		return out, sso.ErrForbidden
	}
	if !p.historical {
		out.LocalRevocation = p.localRevocation()
	}
	intent, err := p.requestIntent()
	if err != nil {
		return out, providerError(ctx, err)
	}
	coordinator, registry, err := s.coordinator(p)
	if err != nil {
		return out, providerError(ctx, err)
	}
	admission := p.caller("identity.request-admission", p.operation().OperationID)
	var key kernel.RequestKeyPreparationBinding
	var wire []byte
	if p.historical {
		var found bool
		key, wire, found, err = coordinator.ReadPreparedRequestKey(ctx, p.scope(), request.IdempotencyKey, intent, admission, p.registration(), p)
		if err == nil && !found {
			return out, sso.ErrForbidden
		}
	} else {
		key, wire, err = coordinator.ResolvePreparedRequestKey(ctx, p.scope(), request.IdempotencyKey, intent, admission, p.registration(), p)
	}
	defer clear(wire)
	if err != nil {
		return out, providerError(ctx, err)
	}
	binding, err := p.RestoreRequestKey(ctx, key, wire)
	if err != nil {
		return out, providerError(ctx, err)
	}
	out.LocalRevocation = p.localRevocation()

	if p.historical {
		out.Completion, err = coordinator.RecoverPreparedFeatureCommand(ctx, providerRecovery(binding),
			p.caller("identity.user", string(binding.UserID)), p.registration(), p)
	} else {
		out.Completion, err = p.execute(ctx, coordinator, registry)
	}
	out, err = p.finish(ctx, out, err)
	if err != nil || !out.LocalRevocation.Committed || afterCommit == nil {
		return out, err
	}
	return out, afterCommit(ctx, p, out)
}

func (p *providerSAMLLogoutStartPhase) localRevocation() saml.LocalRevocation {
	return saml.LocalRevocation{SessionID: p.record.SessionID, Version: p.record.Version + 1}
}

func (p *providerSAMLLogoutStartPhase) finish(ctx context.Context, out ProviderSAMLLogoutStartResult, err error) (ProviderSAMLLogoutStartResult, error) {
	receipt := out.Completion
	exact := receipt.Binding == p.input.binding() && receipt.Validate() == nil && receipt.Feature != nil &&
		receipt.Feature.Operation == p.operation()
	if exact {
		switch receipt.Outcome {
		case identity.CommitOutcomeCommitted:
			if receipt.Feature.BeforeVersion == p.record.Version && receipt.Feature.AfterVersion == out.LocalRevocation.Version {
				out.LocalRevocation.Committed = true
				out.LocalOnly = true
				return out, providerError(ctx, err)
			}
		case identity.CommitOutcomeNotCommitted:
			if err == nil {
				err = sso.ErrUnavailable
			}
			return out, providerError(ctx, err)
		}
	}
	// An unavailable or ambiguous command is not proof of rollback. Preserve
	// the original selected session and never synthesize a committed receipt.
	out.LocalRevocation.ReconciliationRequired = true
	if !exact {
		out.Completion = identity.CommandResult{}
	}
	return out, identity.UnknownCommitError{CommandID: p.input.binding().CommandID}
}

func (s *ProviderSAMLLogoutService) coordinator(p *providerSAMLLogoutStartPhase) (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
	auditing, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, nil, err
	}
	lifecycle, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, nil, err
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{s.login.directory, auditing, lifecycle, p})
	if err != nil {
		return nil, nil, err
	}
	c, err := kernel.NewCoordinatorWithRequestKeys(s.login.router.pool, registry, s.login.config.Coordinator, s.login.config.RequestKeys)
	return c, registry, err
}

func (p *providerSAMLLogoutStartPhase) admitBrowser(ctx context.Context) error {
	s := p.service
	tenant := s.login.config.TenantID
	token, err := session.ParseToken(p.browser.Session.Token())
	if err != nil {
		return sso.ErrForbidden
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		return sso.ErrForbidden
	}
	observed, err := s.sessions.Get(ctx, session.GetRequest{TenantID: tenant, Credential: credential})
	if err != nil {
		return err
	}
	if observed.Authenticated {
		if observed.ValidateAt(s.login.router.config.Clock.Now()) != nil {
			return sso.ErrForbidden
		}
		p.original, p.deadline = observed.Session, observed.ValidUntil().UTC().Truncate(time.Microsecond)
	} else if err := p.findRevokedSession(ctx, tenant, token); err != nil {
		return err
	}
	spec, err := p.original.Bindings()
	if err != nil || spec.TenantID != tenant || spec.Authentication.Proof.Method != "sso-saml" || spec.Version == ^uint64(0) {
		return sso.ErrForbidden
	}
	csrfScope := session.CSRFBinding{TenantID: tenant, SessionID: spec.SessionID, SessionVersion: spec.Version}
	for _, key := range s.csrfKeys {
		if p.original.CSRFState().Check(csrfScope, p.browser.CSRF, key) == nil {
			p.record, p.csrfKey = spec, key
			break
		}
	}
	if p.csrfKey.Version() == 0 {
		return sso.ErrForbidden
	}
	scopes, err := spec.Authority.Bindings()
	if err != nil || !scopes.Organization.Present {
		return sso.ErrForbidden
	}
	p.accountProvider, err = SSOSAMLAccountProviderNamespace(organization.ID(scopes.ActiveOrganizationID), sso.ProviderID(p.request.ProviderID))
	if err != nil || spec.Authentication.CredentialID == "" {
		return sso.ErrForbidden
	}
	if p.historical {
		return nil // The original exact key and receipt, not current provider availability, own recovery.
	}
	rows, err := s.login.router.pool.Raw().Query(ctx, samlLogoutLinkedProviderSQL, p.linkedProviderArgs()...)
	if err != nil {
		return err
	}
	return readSAMLLogoutLinkedProvider(rows)
}

func (p *providerSAMLLogoutStartPhase) findRevokedSession(ctx context.Context, tenant identity.TenantID, token session.Token) error {
	for _, key := range p.service.lookupKeys {
		digest, err := token.Digest(key, string(tenant))
		if err != nil {
			return sso.ErrForbidden
		}
		retained, err := p.service.retained.Lookup(ctx, tenant, digest)
		if errors.Is(err, sessionpg.ErrRecordAbsent) {
			continue
		}
		if err != nil {
			return err
		}
		if p.historical || !retained.Revoked {
			return sso.ErrForbidden
		}
		p.original, p.historical = retained.Session, true
	}
	if !p.historical {
		return sso.ErrForbidden
	}
	return nil
}
