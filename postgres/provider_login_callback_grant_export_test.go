//go:build integration

package postgres

import "context"

func VerifyProviderLoginCallbackGrantForTest(ctx context.Context, s *ProviderLoginService, state string, altered string) error {
	found, err := s.lookupProviderLoginCallback(ctx, state)
	if err != nil {
		return err
	}
	defer clear(found.Binding.Proof)
	switch altered {
	case "nonce":
		// Parseable, but not what the original start signed.
		found.Binding.Metadata.Public.Nonce = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	case "fingerprint":
		found.Binding.Plan.Grant.ProofFingerprint[0] ^= 1
	}
	_, err = s.prepareProviderLoginCallbackGrant(ctx, found)
	return err
}
