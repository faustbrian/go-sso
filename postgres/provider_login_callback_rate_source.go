package postgres

import (
	"context"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	organization "github.com/faustbrian/go-organization"
	"github.com/faustbrian/go-sso"
)

// ProviderLoginCallbackRateContext identifies the authenticated original callback
// for transport-owned quota admission. TransactionID is its callback command,
// not the start command or raw provider state. Lifetime is the immutable stored
// expiry minus issuance, never a renewed or remaining lifetime. This observation
// grants no permission to consume state, exchange a code or issue a session.
type ProviderLoginCallbackRateContext struct {
	ProviderID    sso.ProviderID
	FlowID        identity.PreAuthTransactionID
	TransactionID string
	Lifetime      time.Duration
}

// ProviderSharedCallbackRateContext identifies the authenticated original mode
// for a transport with one shared callback route. MemberLink is true only for
// stored explicit-member custody, in which case FlowID is empty. Neither mode
// nor quota correlation grants permission to complete the callback.
type ProviderSharedCallbackRateContext struct {
	ProviderLoginCallbackRateContext
	MemberLink bool
}

// SharedCallbackRateSource authenticates one pending transaction and the cookie
// required by its stored mode, never choosing a mode from cookie presence. A
// member link requires the exact original fresh local password session; anonymous
// sign-in requires the original flow cookie. The other cookie grants no fallback.
// Trusted tenant, browser context, configured profile and redirect must match.
// Input remains borrowed and caller-owned. No state is reserved or consumed,
// provider request made, session issued, or original lifetime renewed. Missing
// composition is invalid input; unmatched custody is forbidden. Cancellation and
// primary failures propagate, and every failure returns zero correlation.
// LinkCallback or SigninCallback must repeat all protected checks after quotas.
func (s *ProviderLoginCompletionService) SharedCallbackRateSource(ctx context.Context, tenant identity.TenantID, request ProviderLoginCallbackRequest, memberSession authentication.BearerCredential) (out ProviderSharedCallbackRateContext, err error) {
	if s == nil || s.start == nil || s.effect == nil || ctx == nil || request.ReceivedRedirectURI == "" {
		return out, sso.ErrInvalidInput
	}
	if tenant != s.start.config.TenantID {
		return out, sso.ErrForbidden
	}
	ctx, cancel := context.WithTimeout(ctx, s.start.config.Coordinator.MaximumDuration)
	defer cancel()
	defer func() {
		if recover() != nil {
			out, err = ProviderSharedCallbackRateContext{}, sso.ErrUnavailable
		}
	}()
	var state string
	if err := request.Input.Use(ctx, func(_ context.Context, _, value []byte) error {
		state = string(value)
		return nil
	}); err != nil {
		return out, providerError(ctx, err)
	}
	found, err := s.start.lookupProviderLoginCallback(ctx, state)
	if err != nil {
		return out, err
	}
	defer clear(found.Binding.Proof)
	input := found.Binding.Metadata.Input
	if found.CompletedAt != nil || request.ReceivedRedirectURI != input.RedirectURI {
		return out, sso.ErrForbidden
	}
	key := providerLoginProfileKey{organization: organization.ID(found.Row.OrganizationID), provider: sso.ProviderID(found.Row.ProviderID)}
	transport, available := s.profiles[key]
	profile, selected := s.start.profiles[key]
	if !available || !selected || transport.metadata.Issuer != input.Issuer || profile.ClientID != input.ClientID ||
		profile.ProtocolRedirectURI != input.RedirectURI || profile.ProviderVersion != input.ProviderVersion ||
		profile.CredentialGeneration != input.CredentialGeneration || profile.MappingVersion != input.MappingVersion {
		return out, sso.ErrForbidden
	}
	if input.Link == nil {
		anonymous, err := s.signinCallbackRateContext(ctx, found, request, key.provider)
		if err != nil {
			return out, err
		}
		return ProviderSharedCallbackRateContext{ProviderLoginCallbackRateContext: anonymous}, nil
	}

	phase := &providerLoginPhase{service: s.start, member: &providerLoginMemberAdmission{user: input.Command.UserID}}
	if input.Command != phase.commandBinding(found.Row.StartCommandID) || input.Command.ValidateFor(phase.operation()) != nil {
		return out, sso.ErrForbidden
	}
	_, original, err := s.start.authenticateProviderLoginMemberCallbackCookie(ctx, found, ProviderLinkCallbackRequest{
		Session: memberSession, ReceivedRedirectURI: request.ReceivedRedirectURI,
		Origin: request.Browser.Origin, Network: request.Browser.Network, Device: request.Browser.Device,
	})
	if err != nil {
		return out, err
	}
	if _, _, _, err := sessionpg.OriginalSessionAdmission(s.start.link.Profile, original, input.Command); err != nil {
		return out, sso.ErrForbidden
	}
	if !s.start.router.config.Clock.Now().UTC().Before(found.Row.ExpiresAt) {
		return out, sso.ErrForbidden
	}
	return ProviderSharedCallbackRateContext{ProviderLoginCallbackRateContext: ProviderLoginCallbackRateContext{
		ProviderID: key.provider, TransactionID: string(found.Binding.Metadata.CallbackCommand),
		Lifetime: found.Row.ExpiresAt.Sub(found.Row.IssuedAt)}, MemberLink: true}, nil
}

// SigninCallbackRateSource authenticates a pending callback's original state and
// browser cookie for quota correlation, without reservation or provider I/O.
// The trusted tenant and configured redirect must match the original route.
// Browser.FlowID may be empty for a provider GET; a supplied value must match
// the authenticated original flow. Input remains borrowed and caller-owned.
// Missing composition is invalid input; unmatched custody is forbidden.
// Cancellation and primary failures propagate without granting authority.
// SigninCallback must still perform all protected checks after quota admission.
func (s *ProviderLoginCompletionService) SigninCallbackRateSource(ctx context.Context, tenant identity.TenantID, request ProviderLoginCallbackRequest) (out ProviderLoginCallbackRateContext, err error) {
	if s == nil || s.start == nil || s.effect == nil || ctx == nil || request.ReceivedRedirectURI == "" {
		return out, sso.ErrInvalidInput
	}
	if tenant != s.start.config.TenantID {
		return out, sso.ErrForbidden
	}
	ctx, cancel := context.WithTimeout(ctx, s.start.config.Coordinator.MaximumDuration)
	defer cancel()
	defer func() {
		if recover() != nil {
			out, err = ProviderLoginCallbackRateContext{}, sso.ErrUnavailable
		}
	}()
	var state string
	if err := request.Input.Use(ctx, func(_ context.Context, _, value []byte) error {
		state = string(value)
		return nil
	}); err != nil {
		return out, providerError(ctx, err)
	}
	found, err := s.start.lookupProviderLoginCallback(ctx, state)
	if err != nil {
		return out, err
	}
	defer clear(found.Binding.Proof)
	if found.CompletedAt != nil || found.Binding.Metadata.Input.Link != nil || request.ReceivedRedirectURI != found.Binding.Metadata.Input.RedirectURI {
		return out, sso.ErrForbidden
	}
	key := providerLoginProfileKey{organization: organization.ID(found.Row.OrganizationID), provider: sso.ProviderID(found.Row.ProviderID)}
	transport, available := s.profiles[key]
	if !available || transport.metadata.Issuer != found.Binding.Metadata.Input.Issuer {
		return out, sso.ErrForbidden
	}
	return s.signinCallbackRateContext(ctx, found, request, key.provider)
}

func (s *ProviderLoginCompletionService) signinCallbackRateContext(ctx context.Context, found providerLoginCallbackLookup, request ProviderLoginCallbackRequest, provider sso.ProviderID) (ProviderLoginCallbackRateContext, error) {
	flowID, err := identity.ParsePreAuthTransactionID(found.Binding.Metadata.Input.Command.AnonymousFlowID)
	if err != nil || (request.Browser.FlowID != "" && request.Browser.FlowID != flowID) {
		return ProviderLoginCallbackRateContext{}, sso.ErrForbidden
	}
	browser := request.Browser
	browser.FlowID = flowID
	if _, err := s.start.authenticateProviderLoginCallbackBrowser(ctx, found, browser); err != nil {
		return ProviderLoginCallbackRateContext{}, err
	}
	return ProviderLoginCallbackRateContext{
		ProviderID: provider, FlowID: flowID, TransactionID: string(found.Binding.Metadata.CallbackCommand),
		Lifetime: found.Row.ExpiresAt.Sub(found.Row.IssuedAt),
	}, nil
}
