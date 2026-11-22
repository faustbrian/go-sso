package postgres

import (
	"context"
	"time"

	identity "github.com/faustbrian/go-identity"
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
	if found.CompletedAt != nil || request.ReceivedRedirectURI != found.Binding.Metadata.Input.RedirectURI {
		return out, sso.ErrForbidden
	}
	key := providerLoginProfileKey{organization: organization.ID(found.Row.OrganizationID), provider: sso.ProviderID(found.Row.ProviderID)}
	transport, available := s.profiles[key]
	if !available || transport.metadata.Issuer != found.Binding.Metadata.Input.Issuer {
		return out, sso.ErrForbidden
	}
	flowID, err := identity.ParsePreAuthTransactionID(found.Binding.Metadata.Input.Command.AnonymousFlowID)
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
