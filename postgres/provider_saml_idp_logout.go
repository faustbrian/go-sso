package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	"github.com/faustbrian/go-sso"
	"github.com/faustbrian/go-sso/saml"
)

// ProviderSAMLIDPLogoutProfile pins one installed provider and the exact trusted
// HTTPS IdP endpoint for LogoutResponse POST, independently of Redirect support.
type ProviderSAMLIDPLogoutProfile struct {
	Provider                 StaticSAMLLoginProfile
	IdentityProviderEntityID string
	ResponseEndpoint         string
}

// ProviderSAMLIDPLogoutConfig selects retained SAML sign-in subject custody
// and the provider profiles enabled for inbound LogoutRequest.
type ProviderSAMLIDPLogoutConfig struct {
	Custody   *SAMLLogoutSubjectCustody
	Providers []ProviderSAMLIDPLogoutProfile
}

// ProviderSAMLIDPLogoutRequest is the request branch of the trusted POST form.
// Pass all values so duplicates deny. The caller must not mutate the slice
// during the call. RelayState is not selected by this native profile.
type ProviderSAMLIDPLogoutRequest struct {
	ProviderID  sso.ProviderID
	SAMLRequest []string
}

func (ProviderSAMLIDPLogoutRequest) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprint(f, "sso.postgres.ProviderSAMLIDPLogoutRequest(redacted)")
}

func (ProviderSAMLIDPLogoutRequest) LogValue() slog.Value {
	return slog.StringValue("sso.postgres.ProviderSAMLIDPLogoutRequest(redacted)")
}

func (ProviderSAMLIDPLogoutRequest) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}

func (ProviderSAMLIDPLogoutRequest) MarshalText() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}

// ProviderSAMLIDPLogoutResult carries the safe local result independently of
// response signing. After selection, every target has its retained predecessor
// plus one as the revocation version. An unknown commit sets reconciliation
// required and never marks local state committed or exposes response wire.
type ProviderSAMLIDPLogoutResult struct {
	LocalRevocations []saml.LocalRevocation
	Completion       identity.CommandResult
	response         saml.SignedLogoutPOSTResponse
}

// Response returns signed POST fields only after a newly acknowledged local
// commit. Failure and exact replay never produce another response.
func (r ProviderSAMLIDPLogoutResult) Response() (saml.LogoutPOSTResponseFields, bool) {
	if r.Completion.Outcome != identity.CommitOutcomeCommitted {
		return saml.LogoutPOSTResponseFields{}, false
	}
	fields, err := r.response.Fields()
	return fields, err == nil
}

type samlIDPLogoutProvider struct {
	config ProviderSAMLIDPLogoutProfile
	wire   saml.LogoutPOSTResponseProfile
}

// ProviderSAMLIDPLogoutService uses installed SAML trust and the native
// coordinator. It has no browser credential path, outbound network request,
// private transaction, or HTTP route registration.
type ProviderSAMLIDPLogoutService struct {
	login    *ProviderLoginService
	custody  *SAMLLogoutSubjectCustody
	profiles map[sso.ProviderID]samlIDPLogoutProvider
	sessions *sessionpg.Repository
	effect   *sessionpg.SSOSAMLIDPLogoutEffect
}

// NewProviderSAMLIDPLogoutService selects this opt-in POST flow without I/O.
// Install retained SAML subject custody, prepared request-key and session IdP
// logout histories before enabling it. The native login actor and request-key
// namespace must remain unchanged while original requests can be recovered.
func NewProviderSAMLIDPLogoutService(login *ProviderLoginService, cfg ProviderSAMLIDPLogoutConfig) (*ProviderSAMLIDPLogoutService, error) {
	return newProviderSAMLIDPLogoutService(login, cfg, nil)
}

// NewProviderSAMLIDPLogoutServiceWithRequestKeys selects a stable namespace
// distinct from canonical SAML sign-in. Keep the original keys and namespace
// while original signed logout requests can still be retried.
func NewProviderSAMLIDPLogoutServiceWithRequestKeys(login *ProviderLoginService, cfg ProviderSAMLIDPLogoutConfig, keys kernel.RequestKeyConfig) (*ProviderSAMLIDPLogoutService, error) {
	return newProviderSAMLIDPLogoutService(login, cfg, &keys)
}

func newProviderSAMLIDPLogoutService(login *ProviderLoginService, cfg ProviderSAMLIDPLogoutConfig, keys *kernel.RequestKeyConfig) (*ProviderSAMLIDPLogoutService, error) {
	if login == nil || login.router == nil || !login.router.protocolRegistry || login.router.samlRouteValidate == nil ||
		login.config.RequestKeys.Namespace == "" || login.config.Coordinator.AdmissionPolicy == nil || login.config.Coordinator.QueryPolicy == nil ||
		cfg.Custody == nil || cfg.Custody.config.CurrentMatchKey == 0 || len(cfg.Providers) == 0 || len(cfg.Providers) > 128 {
		return nil, sso.ErrInvalidInput
	}
	login, err := withSAMLLogoutRequestKeys(login, keys)
	if err != nil {
		return nil, err
	}
	service := &ProviderSAMLIDPLogoutService{login: login, custody: cfg.Custody, profiles: make(map[sso.ProviderID]samlIDPLogoutProvider, len(cfg.Providers))}
	for _, profile := range cfg.Providers {
		p, err := normalizeStaticSAMLLoginProfile(profile.Provider)
		if err != nil || p.TrustedOrigin != login.config.Origin {
			return nil, sso.ErrInvalidInput
		}
		if _, duplicate := service.profiles[p.ProviderID]; duplicate {
			return nil, sso.ErrInvalidInput
		}
		// The two wire profiles deliberately have distinct destinations: the
		// inbound SP endpoint and the configured provider's response endpoint.
		entityID := p.TrustedOrigin + "/saml2/" + string(p.ProviderID) + "/metadata"
		if len(profile.IdentityProviderEntityID) == 0 || len(profile.IdentityProviderEntityID) > 1024 {
			return nil, sso.ErrInvalidInput
		}
		wire, err := saml.NewLogoutPOSTResponseProfile(saml.LogoutPOSTResponseConfig{SPEntityID: entityID, IdentityProviderURL: profile.ResponseEndpoint})
		if err != nil {
			return nil, sso.ErrInvalidInput
		}
		service.profiles[p.ProviderID] = samlIDPLogoutProvider{config: profile, wire: wire}
	}
	service.sessions, err = sessionpg.NewRepository(login.router.pool, login.config.Session)
	if err != nil {
		return nil, sso.ErrInvalidInput
	}
	service.effect, err = sessionpg.NewSSOSAMLIDPLogoutEffect(login.config.Session)
	if err != nil {
		return nil, sso.ErrInvalidInput
	}
	return service, nil
}

const samlIDPLogoutClockSkew = 30 * time.Second

func samlIDPLogoutDestination(p StaticSAMLLoginProfile) string {
	return p.TrustedOrigin + "/saml2/" + string(p.ProviderID) + "/slo"
}

// HandleRequest verifies the exact installed-provider signature before
// selecting local sessions. One coordinator request key retains the immutable
// signed-message intent and target snapshot; exact retries cannot repeat the
// mutation, and changed bytes under its signed ID do not open that snapshot.
func (s *ProviderSAMLIDPLogoutService) HandleRequest(ctx context.Context, input ProviderSAMLIDPLogoutRequest) (out ProviderSAMLIDPLogoutResult, err error) {
	if s == nil || s.login == nil || ctx == nil || len(input.SAMLRequest) != 1 || input.SAMLRequest[0] == "" {
		return out, sso.ErrInvalidInput
	}
	profile, selected := s.profiles[input.ProviderID]
	if !selected {
		return out, sso.ErrInvalidInput
	}
	ctx, cancel := context.WithTimeout(ctx, s.login.config.Coordinator.MaximumDuration)
	defer cancel()
	p, err := s.admitRequest(ctx, profile, input.SAMLRequest[0])
	if err != nil {
		return out, providerError(ctx, err)
	}
	coordinator, registry, err := p.coordinator()
	if err != nil {
		return out, providerError(ctx, err)
	}
	if err = p.resolve(ctx, coordinator); err != nil {
		return out, providerError(ctx, err)
	}
	if err = p.authorizeUser(ctx, p.prepared.binding().UserID); err != nil {
		return out, providerError(ctx, err)
	}
	result, fresh, err := p.execute(ctx, coordinator, registry)
	out, err = p.project(result, err)
	if err != nil || !fresh || out.Completion.Outcome != identity.CommitOutcomeCommitted {
		return out, err
	}
	out.response, err = p.signResponse(ctx)
	return out, providerError(ctx, err)
}

func (s *ProviderSAMLIDPLogoutService) admitRequest(ctx context.Context, profile samlIDPLogoutProvider, raw string) (*samlIDPLogoutPhase, error) {
	configured := profile.config.Provider
	router, tenant := s.login.router, s.login.config.TenantID
	request, err := sso.NewDomainRouteRequest(tenant, configured.Domain, configured.ProviderID)
	if err != nil {
		return nil, sso.ErrInvalidInput
	}
	route, err := router.RouteSAML(ctx, request)
	if err != nil {
		return nil, err
	}
	installed, err := router.readProviderSAMLLoginProfile(ctx, route, configured)
	if err != nil {
		return nil, err
	}
	if installed.configuration.EntityID != profile.config.IdentityProviderEntityID {
		return nil, sso.ErrForbidden
	}
	verifier, err := saml.NewLogoutPOSTProfile(saml.LogoutPOSTConfig{SPEntityID: installed.spEntityID, IdentityProviderEntityID: installed.configuration.EntityID,
		SingleLogoutURL: samlIDPLogoutDestination(configured), SigningCertificates: installed.configuration.SigningCertificates,
		MaximumAge: samlLogoutRequestLife, ClockSkew: samlIDPLogoutClockSkew})
	if err != nil {
		return nil, sso.ErrUnavailable
	}
	now := router.config.Clock.Now()
	verified, err := verifier.Validate(ctx, saml.LogoutPOSTInput{SAMLRequest: []string{raw}, Now: now})
	if err != nil {
		return nil, sso.ErrInvalidInput
	}
	evidence, err := verified.Request()
	if err != nil {
		return nil, sso.ErrInvalidInput
	}
	authority, err := router.observeProviderLoginAuthority(ctx, route)
	if err != nil {
		return nil, err
	}
	selected, err := route.Bindings()
	if err != nil {
		return nil, err
	}
	scope := samlLogoutIssuerScope{string(configured.OrganizationID), string(configured.ProviderID), installed.configuration.EntityID}
	probe, err := s.custody.prepareIDPLogoutProbe(tenant, scope, evidence)
	if err != nil {
		return nil, err
	}
	return &samlIDPLogoutPhase{service: s, profile: profile, selected: selected, organization: authority.organization,
		probe: probe, replayID: samlIDPLogoutReplayID(scope, evidence.ID), messageDigest: sha256.Sum256([]byte(raw)),
		requestID: evidence.ID, requestUntil: evidence.ValidUntil}, nil
}

func (p *samlIDPLogoutPhase) signResponse(ctx context.Context) (response saml.SignedLogoutPOSTResponse, err error) {
	router := p.service.login.router
	now := router.config.Clock.Now()
	deadline := p.prepared.Intent.ValidUntil
	if !now.Before(deadline) {
		return response, sso.ErrUnavailable
	}
	request := saml.LogoutResponse{ID: "_" + string(p.prepared.binding().CommandID), InResponseTo: p.requestID,
		IssuedAt: now, Status: saml.LogoutPOSTStatus{Code: saml.LogoutStatusSuccess}}
	err = router.withRouteCredential(ctx, p.selected, providerProtocolSAML, func(ctx context.Context, bundle []byte) error {
		signed, cutoff, err := p.profile.wire.SignWithSPSigningCredential(ctx, request, bundle, now)
		if err != nil {
			return sso.ErrUnavailable
		}
		deadline = minSAMLLogoutTime(deadline, cutoff)
		response = signed
		return nil
	})
	if err == nil {
		err = router.requireSAMLLogoutRoute(ctx, p.selected)
	}
	if err != nil || !router.config.Clock.Now().Before(deadline) {
		if err == nil {
			err = sso.ErrUnavailable
		}
		return saml.SignedLogoutPOSTResponse{}, err
	}
	return response, nil
}

func (p *samlIDPLogoutPhase) project(result identity.CommandResult, outcomeErr error) (ProviderSAMLIDPLogoutResult, error) {
	var out ProviderSAMLIDPLogoutResult
	binding := p.prepared.binding()
	operation := kernel.SSOSAMLIDPLogoutOperation()
	transition := kernel.SSOSAMLIDPLogoutLifecycle()
	exact := result.Binding == binding && result.Feature != nil && result.Feature.Operation == operation
	committed := exact && result.Outcome == identity.CommitOutcomeCommitted &&
		result.Feature.BeforeVersion == transition.BeforeVersion && result.Feature.AfterVersion == transition.AfterVersion
	if exact && (result.Outcome != identity.CommitOutcomeCommitted || committed) {
		out.Completion = result
	}
	reconciliation := !committed && out.Completion.Outcome != identity.CommitOutcomeNotCommitted
	for _, target := range p.prepared.Intent.Targets {
		out.LocalRevocations = append(out.LocalRevocations, saml.LocalRevocation{
			SessionID: target.SessionID, Version: target.Version + 1, Committed: committed, ReconciliationRequired: reconciliation,
		})
	}
	if reconciliation {
		return out, identity.UnknownCommitError{CommandID: binding.CommandID}
	}
	if !committed && outcomeErr == nil {
		outcomeErr = sso.ErrUnavailable
	}
	return out, providerError(nil, outcomeErr)
}

func samlIDPLogoutRequestKey(id [32]byte) (identity.IdempotencyKey, error) {
	return identity.NewIdempotencyKey([]byte(base64.RawURLEncoding.EncodeToString(id[:])))
}

func samlIDPLogoutReplayID(scope samlLogoutIssuerScope, requestID string) [32]byte {
	// The coordinator provides the tenant and immutable configured actor
	// scope. The same verified SAML ID must open the same request-key mapping,
	// even when the message bytes differ and have to fail the intent check.
	frame, _ := json.Marshal([5]string{"sso-saml-idp-logout-v1", scope.organization, scope.provider, scope.issuer, requestID})
	return sha256.Sum256(frame)
}
