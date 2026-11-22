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

func VerifyProviderOAuth2CallbackGrantForTest(ctx context.Context, s *ProviderLoginService, state string, altered string) error {
	found, err := s.lookupProviderOAuth2LoginCallback(ctx, state)
	if err != nil {
		return err
	}
	defer clear(found.Binding.Proof)
	switch altered {
	case "issuer":
		found.Binding.Metadata.Input.Issuer = "https://unrelated.example"
	case "fingerprint":
		found.Binding.Plan.Grant.ProofFingerprint[0] ^= 1
	case "OIDC-domain":
		found.Row.Protocol = ""
	}
	_, err = s.prepareProviderLoginCallbackGrant(ctx, found)
	return err
}

func AuthenticateOriginalOAuth2CallbackForTest(ctx context.Context, s *ProviderLoginService, state string, browser ProviderLoginBrowser) error {
	found, err := s.lookupProviderOAuth2LoginCallback(ctx, state)
	if err != nil {
		return err
	}
	defer clear(found.Binding.Proof)
	flow, err := s.authenticateProviderLoginCallbackBrowser(ctx, found, browser)
	if err != nil {
		return err
	}
	_, err = s.readProviderLoginCallbackOrigin(ctx, found, flow)
	return err
}
