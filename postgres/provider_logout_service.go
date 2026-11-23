package postgres

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

	auditpg "github.com/faustbrian/go-audit/postgres"
	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	organization "github.com/faustbrian/go-organization"
	"github.com/faustbrian/go-sso"
	"github.com/faustbrian/go-sso/oidc"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// ProviderLogoutProfile explicitly selects provider-side logout for one
// installed enterprise OIDC provider. Protocol.CallbackURI must be registered
// at that provider and use this tenant's exact native callback route.
type ProviderLogoutProfile struct {
	OrganizationID organization.ID
	ProviderID     sso.ProviderID
	Protocol       oidc.RPLogoutProfileConfig
}

// ProviderLogoutConfig selects native cookie logout. Profiles may be empty:
// an eligible installed OIDC provider then supports local-only logout. The
// final application redirect is independently selected from an exact allowlist.
// Install the provider logout and session revocation migrations first.
type ProviderLogoutConfig struct {
	Session                session.ServiceConfig
	Admission              sessionpg.SSOOIDCSessionAdmission
	CSRFKeys               []session.CSRFKey
	Profiles               []ProviderLogoutProfile
	FinalRedirectAllowlist []string
}

// ProviderLogoutStartRequest carries explicit provider selection and one
// caller-owned retry key. FinalRedirect is not the provider callback URI.
type ProviderLogoutStartRequest struct {
	ProviderID     string
	IdempotencyKey identity.IdempotencyKey
	FinalRedirect  string
}

// ProviderLogoutBrowser carries the actual original cookie and session CSRF.
// The transport supplies the exact trusted origin, not a body/header fallback.
type ProviderLogoutBrowser struct {
	Session authentication.BearerCredential
	CSRF    session.CSRFToken
	Origin  string
}

func (ProviderLogoutBrowser) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("sso.postgres.ProviderLogoutBrowser(redacted)"))
}
func (ProviderLogoutBrowser) MarshalJSON() ([]byte, error) { return nil, sso.ErrSensitiveSerialization }
func (ProviderLogoutBrowser) MarshalText() ([]byte, error) { return nil, sso.ErrSensitiveSerialization }
func (ProviderLogoutConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("sso.postgres.ProviderLogoutConfig(redacted)"))
}
func (ProviderLogoutConfig) MarshalJSON() ([]byte, error) { return nil, sso.ErrSensitiveSerialization }
func (ProviderLogoutConfig) MarshalText() ([]byte, error) { return nil, sso.ErrSensitiveSerialization }

// ProviderLogoutService owns native SSO logout persistence and the original
// local-session effect. It does not issue a session or expose an HTTP route.
// The login configuration, native primary and cryptographic owners are borrowed.
type ProviderLogoutService struct {
	login         *ProviderLoginService
	sessions      *session.SessionService
	retained      *sessionpg.Repository
	effect        *sessionpg.SSOOIDCLogoutEffect
	lookupKeys    []session.DigestKey
	csrfKeys      []session.CSRFKey
	profiles      map[providerLoginProfileKey]oidc.RPLogoutProfile
	finalRedirect map[string]struct{}
}

// NewProviderLogoutService snapshots explicit lookup/CSRF and logout profile
// selection. The session reader and effect use the same primary, schema and
// original enterprise session admission. It performs no I/O or network work.
func NewProviderLogoutService(login *ProviderLoginService, cfg ProviderLogoutConfig) (*ProviderLogoutService, error) {
	if login == nil || login.router == nil || len(login.profiles) == 0 || len(cfg.CSRFKeys) == 0 || len(cfg.CSRFKeys) > 32 ||
		cfg.Admission.Profile.GlobalAuthorityID != login.config.GlobalAuthorityID || len(cfg.Profiles) > 128 || len(cfg.FinalRedirectAllowlist) == 0 || len(cfg.FinalRedirectAllowlist) > 64 {
		return nil, sso.ErrInvalidInput
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
	profiles := make(map[providerLoginProfileKey]oidc.RPLogoutProfile, len(cfg.Profiles))
	for _, selection := range cfg.Profiles {
		key := providerLoginProfileKey{selection.OrganizationID, selection.ProviderID}
		original, known := login.profiles[key]
		path := providerLogoutCallbackPath(string(selection.ProviderID))
		if _, duplicate := profiles[key]; !known || duplicate || path == "" || original.ClientID != selection.Protocol.ClientID ||
			selection.Protocol.CallbackURI != strings.TrimSuffix(login.config.Origin, "/")+path {
			return nil, sso.ErrInvalidInput
		}
		profile, err := oidc.NewRPLogoutProfile(selection.Protocol)
		if err != nil {
			return nil, sso.ErrInvalidInput
		}
		profiles[key] = profile
	}
	store, validation := login.config.Session, cfg.Session
	reader, err := sessionpg.NewSelectedSessionService(login.router.pool, sessionpg.SelectedSessionServiceConfig{
		Repository: store, Validation: validation, Admission: sessionpg.SelectedSessionAdmissionConfig{SSOOIDC: &cfg.Admission},
	})
	if err != nil {
		return nil, sso.ErrInvalidInput
	}
	retained, err := sessionpg.NewRepository(login.router.pool, store)
	if err != nil {
		return nil, sso.ErrInvalidInput
	}
	effect, err := sessionpg.NewSSOOIDCLogoutEffect(store, cfg.Admission)
	if err != nil {
		return nil, sso.ErrInvalidInput
	}
	return &ProviderLogoutService{
		login: login, sessions: reader, retained: retained, effect: effect, profiles: profiles, finalRedirect: allowed,
		lookupKeys: slices.Clone(validation.LookupKeys), csrfKeys: slices.Clone(cfg.CSRFKeys),
	}, nil
}

// Start revokes the exact original enterprise cookie and returns the provider
// redirect only when the existing coordinator acknowledges the same local
// revocation and one-use state. A revoked cookie can prove possession only for
// read/recovery of its original keyed request, not initiate another operation.
// Unknown outcomes never disclose a redirect. This method performs no provider
// request or cookie writes; trusted transport owns rate limits and delivery.
func (s *ProviderLogoutService) Start(ctx context.Context, request ProviderLogoutStartRequest, browser ProviderLogoutBrowser) (out oidc.LogoutStartResult, err error) {
	if s == nil || s.login == nil || ctx == nil || providerLogoutCallbackPath(request.ProviderID) == "" || request.IdempotencyKey == (identity.IdempotencyKey{}) {
		return out, sso.ErrInvalidInput
	}
	if _, allowed := s.finalRedirect[request.FinalRedirect]; browser.Origin != s.login.config.Origin || !allowed {
		return out, sso.ErrForbidden
	}
	ctx, cancel := context.WithTimeout(ctx, s.login.config.Coordinator.MaximumDuration)
	defer cancel()
	defer func() {
		if recover() != nil {
			out, err = oidc.LogoutStartResult{}, sso.ErrUnavailable
		}
	}()
	p := &providerLogoutStartPhase{service: s, request: request, browser: browser}
	defer func() {
		if p.input != nil && p.input.Remote != nil {
			clear(p.input.Remote.Raw[:])
			clear(p.input.Remote.Wire)
		}
	}()
	if err := p.admitBrowser(ctx); err != nil {
		return out, providerError(ctx, err)
	}
	intent, err := p.requestIntent()
	if err != nil {
		return out, providerError(ctx, err)
	}
	coordinator, registry, err := s.coordinator(p)
	if err != nil {
		return out, providerError(ctx, err)
	}
	scope, caller := p.scope(), p.caller("identity.request-admission", p.DescriptorOperation().OperationID)
	var key kernel.RequestKeyPreparationBinding
	var wire []byte
	if p.historical {
		var found bool
		key, wire, found, err = coordinator.ReadPreparedRequestKey(ctx, scope, request.IdempotencyKey, intent, caller, p.registration(), p)
		if err == nil && !found {
			return out, sso.ErrForbidden
		}
	} else {
		key, wire, err = coordinator.ResolvePreparedRequestKey(ctx, scope, request.IdempotencyKey, intent, caller, p.registration(), p)
	}
	defer clear(wire)
	if err != nil {
		var unavailable identity.UnavailableError
		if p.deniedPreparation && errors.As(err, &unavailable) && ctx.Err() == nil {
			return out, sso.ErrForbidden
		}
		return out, providerError(ctx, err)
	}
	if _, err := p.RestoreRequestKey(ctx, key, wire); err != nil {
		return out, providerError(ctx, err)
	}
	var result identity.CommandResult
	if p.historical {
		b := p.input.binding()
		result, err = coordinator.RecoverPreparedFeatureCommand(ctx, providerRecovery(b), p.caller("identity.user", string(b.UserID)), p.registration(), p)
	} else {
		policy := s.login.config.Coordinator.AdmissionPolicy
		decision, policyErr := policy.Authorization.Decide(ctx, p.caller("identity.user", string(p.session.UserID)))
		if policyErr != nil {
			return out, providerError(ctx, policyErr)
		}
		if decision.Outcome != authorization.Allow || decision.Revision != authorization.Revision(s.login.policyVersion) {
			return out, sso.ErrForbidden
		}
		result, err = p.execute(ctx, coordinator, registry)
	}
	if result.Outcome == identity.CommitOutcomeUnknown || result.Outcome == identity.CommitOutcomeInProgress {
		return oidc.NewLogoutStartResult(oidc.OIDCLogoutUnknownReconciliation, url.URL{}, result)
	}
	if err != nil {
		return out, providerError(ctx, err)
	}
	if result.Outcome != identity.CommitOutcomeCommitted || result.Binding != p.input.binding() {
		return out, sso.ErrForbidden
	}
	return p.disclose(ctx, result)
}

func (s *ProviderLogoutService) coordinator(p kernel.FeatureExecutionContributor) (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
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
	coordinator, err := kernel.NewCoordinatorWithRequestKeys(s.login.router.pool, registry, s.login.config.Coordinator, s.login.config.RequestKeys)
	return coordinator, registry, err
}

func (p *providerLogoutStartPhase) admitBrowser(ctx context.Context) error {
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
		p.observed, p.original = observed, observed.Session
	} else {
		// Storage lookup alone cannot authenticate. Only a retained individually
		// revoked record can enter the read-only keyed recovery path below.
		for _, key := range s.lookupKeys {
			digest, err := token.Digest(key, string(tenant))
			if err != nil {
				return sso.ErrForbidden
			}
			retained, err := s.retained.Lookup(ctx, tenant, digest)
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
	}
	spec, err := p.original.Bindings()
	if err != nil || spec.TenantID != tenant || spec.Authentication.Proof.Method != "sso-oidc" {
		return sso.ErrForbidden
	}
	csrfScope := session.CSRFBinding{TenantID: tenant, SessionID: spec.SessionID, SessionVersion: spec.Version}
	for _, key := range s.csrfKeys {
		if p.original.CSRFState().Check(csrfScope, p.browser.CSRF, key) == nil {
			p.session, p.csrfKey = spec, key
			return nil
		}
	}
	return sso.ErrForbidden
}

func (p *providerLogoutStartPhase) scope() kernel.RequestKeyScope {
	return kernel.RequestKeyScope{TenantID: p.session.TenantID, ActorID: identity.ActorID(p.session.UserID), ActorKind: authorization.SubjectUser, Method: "POST", RouteID: p.DescriptorOperation().OperationID}
}

func (p *providerLogoutStartPhase) caller(resource, id string) authorization.DecisionContext {
	return authorization.DecisionContext{PolicyRevision: authorization.Revision(p.service.login.policyVersion), Request: authorization.Request{
		Tenant: authorization.TenantID(p.session.TenantID), Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(p.session.UserID)},
		Action: authorization.Action(p.DescriptorOperation().OperationID), Resource: authorization.Resource{Type: authorization.ResourceType(resource), ID: authorization.ResourceID(id)},
	}}
}
