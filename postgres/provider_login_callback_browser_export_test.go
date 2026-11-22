//go:build integration

package postgres

import (
	"context"

	"github.com/faustbrian/go-identity/session"
)

func AuthenticateProviderLoginCallbackBrowserForTest(ctx context.Context, s *ProviderLoginService, state string, browser ProviderLoginBrowser) (session.PreAuthTransactionSpec, error) {
	found, err := s.lookupProviderLoginCallback(ctx, state)
	if err != nil {
		return session.PreAuthTransactionSpec{}, err
	}
	defer clear(found.Binding.Proof)
	flow, err := s.authenticateProviderLoginCallbackBrowser(ctx, found, browser)
	if err != nil {
		return session.PreAuthTransactionSpec{}, err
	}
	return flow.Bindings()
}
