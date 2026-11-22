package postgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	"github.com/faustbrian/go-sso"
)

// SigninCallbackRateSource authenticates one pending native OAuth2 callback's
// original state and browser for transport-owned quota admission. The trusted
// tenant, installed profile and local redirect must match its stored custody.
// An omitted Browser.FlowID is recovered from that custody; a supplied flow must
// match. RawQuery remains borrowed and is bounded by the native state locator.
// Issuer input is not parsed here, so the original browser's definitive issuer
// refusal can receive quota admission before native completion settles it.
// The result identifies the original callback command and immutable initial
// lifetime, never raw state, the start command or renewed authority. No state is
// reserved or consumed, provider I/O performed, or grant or session issued.
// Missing composition is invalid input; unmatched custody is forbidden. Context
// cancellation and primary failures propagate; all failures return zero context.
// SigninCallbackOAuth2 must repeat every protected check after quota admission.
func (s *ProviderOAuth2LoginCompletionService) SigninCallbackRateSource(ctx context.Context, tenant identity.TenantID, request ProviderOAuth2LoginCallbackRequest) (out ProviderLoginCallbackRateContext, err error) {
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
	state, err := providerOAuth2CallbackState(request.RawQuery)
	if err != nil {
		return out, err
	}
	found, err := s.start.lookupProviderOAuth2LoginCallback(ctx, state)
	if err != nil {
		return out, err
	}
	defer clear(found.Binding.Proof)
	input := found.Binding.Metadata.Input
	if found.CompletedAt != nil || input.Link != nil || request.ReceivedRedirectURI != input.RedirectURI {
		return out, sso.ErrForbidden
	}
	key := providerLoginProfileKey{organization: organization.ID(found.Row.OrganizationID), provider: sso.ProviderID(found.Row.ProviderID)}
	transport, available := s.profiles[key]
	profile, selected := s.start.oauthProfiles[key]
	if !available || !selected || transport.Profile.Profile.Issuer != input.Issuer ||
		profile.ClientID != input.ClientID || profile.ProtocolRedirectURI != input.RedirectURI ||
		profile.ProviderVersion != input.ProviderVersion || profile.CredentialGeneration != input.CredentialGeneration ||
		profile.MappingVersion != input.MappingVersion {
		return out, sso.ErrForbidden
	}
	flowID, err := identity.ParsePreAuthTransactionID(input.Command.AnonymousFlowID)
	if err != nil || (request.Browser.FlowID != "" && request.Browser.FlowID != flowID) {
		return out, sso.ErrForbidden
	}
	browser := request.Browser
	browser.FlowID = flowID
	if _, err := s.start.authenticateProviderLoginCallbackBrowser(ctx, found, browser); err != nil {
		return out, err
	}
	return ProviderLoginCallbackRateContext{
		ProviderID: key.provider, FlowID: flowID, TransactionID: string(found.Binding.Metadata.CallbackCommand),
		Lifetime: found.Row.ExpiresAt.Sub(found.Row.IssuedAt),
	}, nil
}
