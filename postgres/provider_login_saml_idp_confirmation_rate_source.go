package postgres

import (
	"context"

	"github.com/faustbrian/go-sso"
)

// ConfirmationRateSource authenticates the original pending IdP-initiated
// arrival and both browser values for transport-owned quota admission. The
// trusted tenant, provider and exact same-origin request must match current
// bounded pending custody. Inputs remain borrowed; neither browser value nor
// protected material is returned. TransactionID is the canonical original
// PendingID, FlowID is empty, and Lifetime is the persisted original expiry
// minus issuance, never a renewed or remaining lifetime.
//
// This observation does not verify SAML, reserve or spend proof, mutate pending
// custody, issue a session or perform external work. Missing composition is
// invalid input; unmatched or terminal custody is forbidden. Cancellation
// propagates, other failures are redacted, and every failure returns zero
// correlation. Confirm must repeat the protected checks after quota admission.
func (s *ProviderSAMLIDPConfirmationService) ConfirmationRateSource(ctx context.Context, request SAMLIDPConfirmationRequest) (out ProviderLoginCallbackRateContext, err error) {
	if ctx == nil || s == nil || s.arrival == nil || s.effect == nil {
		return out, sso.ErrInvalidInput
	}
	ctx, cancel := context.WithTimeout(ctx, s.arrival.config.Coordinator.MaximumDuration)
	defer cancel()
	defer func() {
		if recover() != nil {
			out, err = ProviderLoginCallbackRateContext{}, sso.ErrUnavailable
		}
	}()
	pending, original, err := s.arrival.readPendingConfirmation(ctx, request)
	if err != nil {
		return out, providerError(ctx, err)
	}
	defer clear(pending.Envelope)
	defer clear(original.Proof)
	if err := ctx.Err(); err != nil {
		return out, err
	}
	return ProviderLoginCallbackRateContext{
		ProviderID: pending.Provider, TransactionID: string(pending.Binding.CommandID),
		Lifetime: pending.ExpiresAt.Sub(pending.IssuedAt),
	}, nil
}
