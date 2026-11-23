package postgres

import (
	"context"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-sso"
)

// SigninCallbackRateSource authenticates a pending SP-initiated SAML callback's
// original RelayState and frontchannel browser for transport-owned quotas. The
// trusted tenant, selected provider and exact local ACS must match stored custody.
// An omitted Browser.FlowID is recovered only from that custody; a supplied flow
// must match. Request inputs remain borrowed. SAMLResponse is neither inspected
// nor verified, so malformed responses can receive quota admission before native
// completion rejects them. No grant is queried or reserved, state consumed,
// provider contacted or session issued. The result contains only the original
// provider, flow, callback command and immutable initial lifetime. Missing
// composition is invalid input; unmatched custody is forbidden. Cancellation and
// primary failures propagate, and every failure returns zero correlation.
// SigninCallback must repeat every protected check after quota admission.
func (s *ProviderSAMLLoginCompletionService) SigninCallbackRateSource(ctx context.Context, tenant identity.TenantID, request SAMLSigninCallbackRequest) (out ProviderLoginCallbackRateContext, err error) {
	if s == nil || s.start == nil || s.effect == nil || s.start.saml == nil || ctx == nil || request.ReceivedAssertionConsumerURL == "" {
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
	found, err := s.start.lookupProviderSAMLLoginCallback(ctx, request.RelayState)
	if err != nil {
		return out, err
	}
	defer clear(found.Binding.Proof)
	input := found.Binding.Metadata.Input
	if found.CompletedAt != nil || input.Link != nil || found.Row.ProviderID != string(request.ProviderID) {
		return out, sso.ErrForbidden
	}
	configured, selected := s.start.saml.profiles[request.ProviderID]
	acs, validACS := samlProviderCallbackURL(configured.TrustedOrigin, string(request.ProviderID))
	if !selected || !validACS || configured.TrustedOrigin != s.start.config.Origin ||
		request.ReceivedAssertionConsumerURL != acs || input.RedirectURI != acs ||
		string(configured.OrganizationID) != found.Row.OrganizationID || configured.ProviderVersion != found.Row.ProviderVersion ||
		configured.CredentialGeneration != found.Row.CredentialGeneration || configured.MappingVersion != found.Row.MappingVersion {
		return out, sso.ErrForbidden
	}
	flowID, err := identity.ParsePreAuthTransactionID(input.Command.AnonymousFlowID)
	if err != nil || (request.Browser.FlowID != "" && request.Browser.FlowID != flowID) {
		return out, sso.ErrForbidden
	}
	browser := request.Browser
	browser.FlowID = flowID
	flow, err := s.start.authenticateSAMLCallbackBrowser(ctx, found, browser, acs)
	if err != nil {
		return out, err
	}
	original, err := s.start.readProviderLoginCallbackOrigin(ctx, found, flow)
	if err != nil {
		return out, err
	}
	// Restoring the protected original is read-only and cannot renew the
	// callback lookup's bounded observation or the original transaction expiry.
	now := s.start.router.config.Clock.Now().UTC()
	if now.Before(found.ObservedAt) || !now.Before(found.ObservedAt.Add(20*time.Second)) || !now.Before(original.Expires) {
		return out, sso.ErrForbidden
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	return ProviderLoginCallbackRateContext{
		ProviderID: request.ProviderID, FlowID: flowID, TransactionID: string(found.Binding.Metadata.CallbackCommand),
		Lifetime: found.Row.ExpiresAt.Sub(found.Row.IssuedAt),
	}, nil
}
