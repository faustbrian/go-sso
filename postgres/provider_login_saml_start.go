package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-sso"
)

// SAMLSigninStartRequest contains the selected provider and application
// callbacks. The original browser flow owns correlation; a supplied
// IdempotencyKey may only alias it. The caller cannot choose a command ID.
type SAMLSigninStartRequest struct {
	ProviderID                     sso.ProviderID
	SuccessCallback, ErrorCallback url.URL
	LoginIntent                    sso.LoginIntent
	IdempotencyKey                 identity.IdempotencyKey
}

// SAMLAuthnRedirectInput is projected from the installed provider configuration
// and original start command, not from browser-supplied endpoint or signing data.
// RelayState is opaque and must not be logged.
type SAMLAuthnRedirectInput struct {
	SPEntityID, AssertionConsumerURL, IdentityProviderURL string
	RequestID, RelayState                                 string
	IssuedAt                                              time.Time
}

func (SAMLAuthnRedirectInput) Format(s fmt.State, _ rune) {
	_, _ = fmt.Fprint(s, "sso.postgres.SAMLAuthnRedirectInput(redacted)")
}
func (SAMLAuthnRedirectInput) LogValue() slog.Value {
	return slog.StringValue("sso.postgres.SAMLAuthnRedirectInput(redacted)")
}
func (SAMLAuthnRedirectInput) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}
func (SAMLAuthnRedirectInput) MarshalText() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}

// SAMLAuthnRedirectSigner signs with the borrowed installed signer bundle and
// returns its original exclusive certificate cutoff. The callback runs outside
// transactions under the caller's deadline. It must not retain the bundle,
// log RelayState, or perform network I/O. Use the selected SAML wire adapter.
type SAMLAuthnRedirectSigner func(context.Context, SAMLAuthnRedirectInput, []byte, time.Time) (url.URL, time.Time, error)

type providerSAMLStart struct {
	profiles map[sso.ProviderID]StaticSAMLLoginProfile
	digest   [32]byte
	sign     SAMLAuthnRedirectSigner
}

// NewProviderLoginServiceWithSAML opts into native SP-initiated SAML starts.
// Use a dedicated canonical SAML request namespace and install the kernel
// canonical start and SSO SAML login-transaction migrations. An OIDC/OAuth
// service, if needed, is composed independently with its own request scope.
// The constructor neither signs nor starts background work.
func NewProviderLoginServiceWithSAML(router *ProviderRouter, config ProviderLoginConfig, profiles []StaticSAMLLoginProfile, sign SAMLAuthnRedirectSigner) (*ProviderLoginService, error) {
	if router == nil || !router.protocolRegistry || router.samlRouteValidate == nil || len(config.Profiles) != 0 || sign == nil ||
		len(profiles) == 0 || len(profiles) > 128 || config.StateLifetime > 5*time.Minute {
		return nil, sso.ErrInvalidInput
	}
	selected := &providerSAMLStart{profiles: make(map[sso.ProviderID]StaticSAMLLoginProfile, len(profiles)), sign: sign}
	for _, profile := range profiles {
		canonical, err := normalizeStaticSAMLLoginProfile(profile)
		if err != nil || canonical.TrustedOrigin != config.Origin {
			return nil, sso.ErrInvalidInput
		}
		if _, duplicate := selected.profiles[canonical.ProviderID]; duplicate {
			return nil, sso.ErrInvalidInput
		}
		selected.profiles[canonical.ProviderID] = canonical
	}
	frame, err := json.Marshal(selected.profiles)
	if err != nil {
		return nil, sso.ErrInvalidInput
	}
	defer clear(frame)
	selected.digest = sha256.Sum256(frame)
	return newProviderLoginService(router, config, nil, selected)
}

// SigninStartSAML starts or recovers one signed SAML redirect for the original
// pre-authenticated browser. It returns no redirect before acknowledged native
// Work and fresh disclosure admission, and never signs again for a replay.
func (s *ProviderLoginService) SigninStartSAML(ctx context.Context, request SAMLSigninStartRequest, browser ProviderLoginBrowser) (sso.SigninStartResult, error) {
	if s == nil || s.saml == nil {
		return sso.SigninStartResult{}, sso.ErrInvalidInput
	}
	configured, ok := s.saml.profiles[request.ProviderID]
	if !ok {
		return sso.SigninStartResult{}, sso.ErrForbidden
	}
	start := sso.SigninStartRequest{
		ProviderID: string(request.ProviderID), Domain: configured.Domain, LoginIntent: request.LoginIntent,
		SuccessCallback: request.SuccessCallback, ErrorCallback: request.ErrorCallback, IdempotencyKey: request.IdempotencyKey,
	}
	return s.startProviderTransactionForProtocol(ctx, start, browser, nil, providerProtocolSAML)
}

func (p *providerLoginPhase) resolveStartRequest(ctx context.Context, coordinator *kernel.Coordinator, intent identity.RequestIntent) (kernel.RequestKeyPreparationBinding, []byte, error) {
	if p.protocol != providerProtocolSAML {
		return coordinator.ResolvePreparedRequestKey(ctx, p.startScope(), p.request.IdempotencyKey, intent, p.startCaller(), p.registration(), p)
	}
	// Intent separately includes both callbacks, remember policy and retained
	// browser evidence. Changing those never selects another command.
	flow, err := identity.ParsePreAuthTransactionID(string(p.browser.FlowID))
	if err != nil {
		return kernel.RequestKeyPreparationBinding{}, nil, identity.ForbiddenError{}
	}
	selector, err := kernel.NewCanonicalRequestKey([]byte("sso-saml-start-v1\x00" + string(flow) + "\x00" + p.request.ProviderID))
	if err != nil {
		return kernel.RequestKeyPreparationBinding{}, nil, err
	}
	var optional *identity.IdempotencyKey
	if p.request.IdempotencyKey != (identity.IdempotencyKey{}) {
		optional = &p.request.IdempotencyKey
	}
	return coordinator.ResolvePreparedCanonicalRequest(ctx, p.startScope(), selector, optional, intent, p.startCaller(), p.registration(), p)
}

func (p *providerLoginPhase) selectSAMLRoute(ctx context.Context, lookup sso.DomainRouteRequest) (sso.DomainRoute, providerLoginProfile, error) {
	s := p.service
	if s.saml == nil {
		return sso.DomainRoute{}, providerLoginProfile{}, sso.ErrForbidden
	}
	configured, ok := s.saml.profiles[sso.ProviderID(p.request.ProviderID)]
	if !ok || configured.Domain != p.request.Domain {
		return sso.DomainRoute{}, providerLoginProfile{}, sso.ErrForbidden
	}
	route, err := s.router.RouteSAML(ctx, lookup)
	if err != nil {
		return sso.DomainRoute{}, providerLoginProfile{}, err
	}
	profile, err := s.router.readProviderSAMLLoginProfile(ctx, route, configured)
	if err != nil {
		return sso.DomainRoute{}, providerLoginProfile{}, err
	}
	return route, providerLoginProfile{saml: &profile, protocol: providerProtocolSAML,
		issuer: profile.configuration.EntityID, authorizationEndpoint: profile.configuration.RedirectEndpoint}, nil
}

func (p *providerLoginPhase) signSAMLRedirect(ctx context.Context, requestID string, issuedAt time.Time, relayState string) (url.URL, error) {
	input := p.input
	if input == nil || p.service.saml == nil {
		return url.URL{}, identity.ForbiddenError{}
	}
	route, profile, err := p.selectRoute(ctx)
	if err != nil {
		return url.URL{}, err
	}
	selected, err := route.Bindings()
	if err != nil || !input.matchesSelectedRoute(selected, profile) || profile.saml == nil {
		return url.URL{}, identity.ForbiddenError{}
	}
	redirectInput := SAMLAuthnRedirectInput{SPEntityID: profile.saml.spEntityID, AssertionConsumerURL: profile.saml.acsURL,
		IdentityProviderURL: profile.authorizationEndpoint, RequestID: requestID, IssuedAt: issuedAt, RelayState: relayState}
	router := p.service.router
	var redirect url.URL
	deadline := earlierLoginTime(selected.ValidUntil, input.Expires)
	err = router.withRouteCredential(ctx, selected, providerProtocolSAML, func(ctx context.Context, bundle []byte) error {
		now := router.config.Clock.Now().UTC()
		if !now.Before(deadline) {
			return sso.ErrForbidden
		}
		var cutoff time.Time
		var err error
		redirect, cutoff, err = p.service.saml.sign(ctx, redirectInput, bundle, now)
		if err != nil {
			return sso.ErrUnavailable
		}
		deadline = earlierLoginTime(deadline, cutoff)
		return nil
	})
	if err != nil {
		return url.URL{}, err
	}
	if !router.config.Clock.Now().Before(deadline) || !matchesSAMLRedirectEndpoint(redirect, profile.authorizationEndpoint) {
		return url.URL{}, identity.ForbiddenError{}
	}
	return redirect, nil
}

func matchesSAMLRedirectEndpoint(redirect url.URL, endpoint string) bool {
	base, err := url.Parse(endpoint)
	if err != nil || base.RawQuery != "" && !strings.HasPrefix(redirect.RawQuery, base.RawQuery+"&") {
		return false
	}
	redirect.RawQuery, redirect.ForceQuery = base.RawQuery, base.ForceQuery
	return redirect == *base
}
