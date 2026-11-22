//go:build integration

package postgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
)

func PrepareProviderLoginCallbackCommandForTest(ctx context.Context, s *ProviderLoginService, state, redirect string, browser ProviderLoginBrowser, input identity.OAuthCallbackInput) (identity.Command, error) {
	found, err := s.lookupProviderLoginCallback(ctx, state)
	if err != nil {
		return identity.Command{}, err
	}
	defer clear(found.Binding.Proof)
	return s.prepareProviderLoginCallbackCommand(ctx, found, redirect, browser, input)
}
