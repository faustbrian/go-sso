package postgres

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	organization "github.com/faustbrian/go-organization"
	"github.com/faustbrian/go-sso"
)

// StaticOAuth2CompletionProfile pins the OAuth2-only transport and identity
// resource for one installed provider. Configuration and installed endpoints,
// stable subject policy, and the original start must agree. HTTPClient is a
// trusted borrowed transport, not a callback-supplied destination.
type StaticOAuth2CompletionProfile struct {
	OrganizationID organization.ID
	ProviderID     sso.ProviderID
	Profile        oauth.OAuth2UserInfoProfile
	HTTPClient     *http.Client
}

// ProviderOAuth2LoginCallbackRequest carries the raw query without a leading
// question mark and the original browser. Supply ReceivedRedirectURI from a
// trusted local route, never Host, forwarded headers, or provider fields.
type ProviderOAuth2LoginCallbackRequest struct {
	RawQuery            string
	Browser             ProviderLoginBrowser
	ReceivedRedirectURI string
}

// Format redacts callback code, state and browser credentials.
func (ProviderOAuth2LoginCallbackRequest) Format(w fmt.State, _ rune) {
	_, _ = w.Write([]byte("postgres.ProviderOAuth2LoginCallbackRequest(redacted)"))
}

// MarshalJSON refuses serialization of callback and browser credentials.
func (ProviderOAuth2LoginCallbackRequest) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}

// MarshalText refuses serialization of callback and browser credentials.
func (ProviderOAuth2LoginCallbackRequest) MarshalText() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}

// ProviderOAuth2LoginCompletionService completes only existing linked member
// sign-ins against its configured active provider. It owns no pool, HTTP
// route, lifecycle worker, JIT admission or provider-token reveal surface.
type ProviderOAuth2LoginCompletionService struct {
	start    *ProviderLoginService
	profiles map[providerLoginProfileKey]StaticOAuth2CompletionProfile
	policy   sessionpg.IdentifierAdmissionConfig
	effect   *sessionpg.SSOOAuth2SigninEffect
	issuer   session.IssuerConfig
	csrfKey  session.CSRFKey
}

// NewProviderOAuth2LoginCompletionService selects static enterprise OAuth2
// sign-in without I/O. Install the OAuth callback, vault, session and original
// preparation migrations before use. OIDC configuration remains separate.
func NewProviderOAuth2LoginCompletionService(start *ProviderLoginService, config ProviderLoginCompletionConfig, profiles []StaticOAuth2CompletionProfile) (*ProviderOAuth2LoginCompletionService, error) {
	if start == nil || start.router == nil || start.router.organizations == nil || len(config.Profiles) != 0 ||
		len(profiles) == 0 || len(profiles) > len(start.oauthProfiles) || config.Issuer.MaximumDuration > start.config.Coordinator.MaximumDuration {
		return nil, sso.ErrInvalidInput
	}
	policy := sessionpg.IdentifierAdmissionConfig{GlobalAuthorityID: start.config.GlobalAuthorityID, PolicyNamespace: config.PolicyNamespace,
		Audience: config.Audience, AuthenticationMethod: "sso-oauth2", CredentialKind: identity.CredentialProvider, CredentialOwner: "sso"}
	effect, err := sessionpg.NewSSOOAuth2SigninEffect(start.config.Session, policy, start.router.organizations)
	if err != nil {
		return nil, sso.ErrInvalidInput
	}
	config.Issuer.Clock = start.router.config.Clock
	if _, err := session.NewSSOOAuth2SessionIssuerWithCSRF(&providerLoginCallbackPhase{}, config.Issuer, config.CSRFKey); err != nil {
		return nil, sso.ErrInvalidInput
	}
	selected := make(map[providerLoginProfileKey]StaticOAuth2CompletionProfile, len(profiles))
	for _, p := range profiles {
		key := providerLoginProfileKey{organization: p.OrganizationID, provider: p.ProviderID}
		original, ok := start.oauthProfiles[key]
		id, idErr := ssoOAuth2TransportProviderID(p.OrganizationID, p.ProviderID)
		base := p.Profile.Profile
		if _, duplicate := selected[key]; duplicate || !ok || idErr != nil || base.ID != id || base.ClientID != original.ClientID ||
			base.Version != original.ProviderVersion || base.RedirectURI != original.ProtocolRedirectURI || !slices.Equal(base.Scopes, original.Scopes) ||
			base.NonceRequired || base.NonceBytes != 0 || len(base.Algorithms) != 0 || base.GoogleAccounts || (base.ClockSkew != 0 && base.ClockSkew != time.Minute) ||
			(base.ResponseMode != "" && base.ResponseMode != "query") || (base.PKCEMethod != "" && base.PKCEMethod != "S256") ||
			(base.StateBytes != 0 && base.StateBytes != 32) || base.MaxCodeBytes > 4096 {
			return nil, sso.ErrInvalidInput
		}
		if p.Profile.Details.ProofLifetime == 0 {
			p.Profile.Details.ProofLifetime = 20 * time.Second
		}
		validator, err := newProviderOAuth2Transport(p, config.Issuer.Clock, []byte("trusted-config-validation"), nil)
		if err != nil {
			return nil, sso.ErrInvalidInput
		}
		p.Profile.Profile = validator.Profile()
		validator.Close()
		if p.Profile.Profile.MaxCodeBytes > 4096 {
			return nil, sso.ErrInvalidInput
		}
		selected[key] = p
	}
	return &ProviderOAuth2LoginCompletionService{start: start, profiles: selected, policy: policy, effect: effect, issuer: config.Issuer, csrfKey: config.CSRFKey}, nil
}

func ssoOAuth2TransportProviderID(organizationID organization.ID, provider sso.ProviderID) (string, error) {
	namespace, err := SSOOAuth2AccountProviderNamespace(organizationID, provider)
	return strings.ReplaceAll(namespace, ".", "-"), err
}

// Extract only a bounded lookup hint. The authenticated row chooses the
// trusted profile; the Golib parser alone grants typed callback custody.
func providerOAuth2CallbackState(raw string) (string, error) {
	if len(raw) == 0 || len(raw) > 3*4096+(16<<10) || raw[0] == '?' || strings.Contains(raw, "#") || strings.Count(raw, "&") >= 32 {
		return "", sso.ErrForbidden
	}
	// Inspect only state, so a malformed issuer can still receive a terminal
	// denial after the exact original browser authenticates. A duplicate or
	// malformed state itself cannot select any transaction.
	var state string
	for field := range strings.SplitSeq(raw, "&") {
		name, value, present := strings.Cut(field, "=")
		name, err := url.QueryUnescape(name)
		if err != nil || name != "state" {
			continue
		}
		if !present || state != "" || len(value) > 3*43 {
			return "", sso.ErrForbidden
		}
		state, err = url.QueryUnescape(value)
		if err != nil || len(state) != 43 {
			return "", sso.ErrForbidden
		}
	}
	if state == "" {
		return "", sso.ErrForbidden
	}
	return state, nil
}

// SigninCallbackOAuth2 verifies the exact original browser and issuer, then
// completes a single prepared provider exchange and callback transaction.
// Only an acknowledged new commit can return the cookie and CSRF secret.
func (s *ProviderOAuth2LoginCompletionService) SigninCallbackOAuth2(ctx context.Context, request ProviderOAuth2LoginCallbackRequest) (out ProviderLoginCallbackResult, err error) {
	if s == nil || s.start == nil || s.effect == nil || ctx == nil || request.ReceivedRedirectURI == "" {
		return out, sso.ErrInvalidInput
	}
	ctx, cancel := context.WithTimeout(ctx, s.start.config.Coordinator.MaximumDuration)
	defer cancel()
	var entered identity.CommandID
	defer func() {
		if recover() != nil {
			out = ProviderLoginCallbackResult{}
			err = sso.ErrUnavailable
			if entered != "" {
				err = identity.UnknownCommitError{CommandID: entered}
			}
		}
	}()
	state, err := providerOAuth2CallbackState(request.RawQuery)
	if err != nil {
		return out, err
	}
	found, err := s.start.lookupProviderOAuth2LoginCallback(ctx, state)
	if err != nil {
		return out, err
	}
	defer clear(found.Binding.Proof)
	transport, ok := s.profiles[providerLoginProfileKey{organization: organization.ID(found.Row.OrganizationID), provider: sso.ProviderID(found.Row.ProviderID)}]
	if !ok || found.CompletedAt != nil || transport.Profile.Profile.Issuer != found.Binding.Metadata.Input.Issuer ||
		request.ReceivedRedirectURI != found.Binding.Metadata.Input.RedirectURI {
		return out, sso.ErrForbidden
	}
	callback, parseErr := oauth.ParseSharedOAuth2QueryCallback(ctx, request.RawQuery, request.ReceivedRedirectURI, transport.Profile.Profile)
	if parseErr != nil {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		var failure *oauth.Error
		if !errors.As(parseErr, &failure) || failure.Kind() != oauth.InvalidInput {
			return out, sso.ErrUnavailable
		}
	}
	defer callback.Destroy()
	flow, err := s.start.authenticateProviderLoginCallbackBrowser(ctx, found, request.Browser)
	if err != nil {
		return out, err
	}
	command, err := s.start.prepareProviderOAuth2CallbackCommand(ctx, found, request, callback, parseErr != nil)
	if err != nil {
		return out, err
	}
	original, err := s.start.readProviderLoginCallbackOrigin(ctx, found, flow)
	if err != nil {
		return out, err
	}
	authority, err := s.start.observeProviderLoginCallbackAuthority(ctx, found, original)
	if err != nil {
		return out, err
	}
	grant, err := s.start.prepareProviderLoginCallbackGrant(ctx, found)
	if err != nil {
		return out, err
	}
	phase := &providerLoginCallbackPhase{
		providerLoginCallbackInvocation: providerLoginCallbackInvocation{service: s.start, found: found, original: original, authority: authority, flow: flow, browser: request.Browser, command: command},
		grant:                           grant, oauth2: &transport, oauthCallback: callback, oauthInputRefused: parseErr != nil, oauthEffect: s.effect, policy: s.policy,
	}
	defer func() {
		if phase.refusal != nil {
			clear(phase.refusal.Terminal)
		}
		if phase.execution != nil {
			clear(phase.execution.terminal)
			clear(phase.execution.tokens.Ciphertext)
		}
	}()
	phase.issuer, err = session.NewSSOOAuth2SessionIssuerWithCSRF(phase, s.issuer, s.csrfKey)
	if err != nil {
		return out, sso.ErrUnavailable
	}
	coordinator, err := providerLoginCallbackCoordinator(s.start, phase)
	if err != nil {
		return out, sso.ErrUnavailable
	}
	plan, err := phase.plan()
	if err != nil {
		return out, providerError(ctx, err)
	}
	plan, err = coordinator.PrepareFeaturePreparationPlan(command, plan)
	if err != nil {
		return out, providerError(ctx, err)
	}
	entered = found.Binding.Metadata.CallbackCommand
	result, err := coordinator.ExecutePreparedFeature(ctx, command, plan)
	out.Completion = result
	if err != nil {
		return out, providerError(ctx, err)
	}
	if result.Validate() != nil || result.Binding.CommandID != entered || result.Outcome != identity.CommitOutcomeCommitted {
		return out, sso.ErrUnavailable
	}
	if phase.execution == nil || phase.prepared == (session.PreparedIssuance{}) {
		return out, nil
	}
	bound, err := phase.issuer.BindSSOOAuth2(phase.prepared, phase.execution.command)
	if err != nil {
		return out, providerError(ctx, err)
	}
	phase.acknowledged, phase.canDisclose = result, true
	issued, err := phase.issuer.Issue(ctx, bound)
	if err != nil {
		return out, providerError(ctx, err)
	}
	csrf, err := bound.CSRFToken()
	if err != nil || issued.Replayed || issued.Token == (session.Token{}) {
		return out, sso.ErrUnavailable
	}
	out.Issuance, out.CSRF, out.RedirectURI = issued, csrf, original.SuccessCallback
	return out, nil
}
