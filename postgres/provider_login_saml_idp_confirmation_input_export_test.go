//go:build integration

package postgres

import "context"

// CheckSAMLIDPConfirmationInputForTest exercises the native primary lookup
// without returning browser, sealed, proof or other private custody.
func CheckSAMLIDPConfirmationInputForTest(ctx context.Context, s *ProviderSAMLIDPArrivalService, req SAMLIDPConfirmationRequest) error {
	pending, original, err := s.readPendingConfirmation(ctx, req)
	clear(pending.Envelope)
	clear(original.Proof)
	return err
}
