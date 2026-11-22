package postgres

import (
	"errors"
	"testing"

	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-sso"
)

func TestOIDCCallbackAdapterRejectsUnconfiguredSelection(t *testing.T) {
	var missing *ProviderLoginCompletionService
	for _, service := range []*ProviderLoginCompletionService{missing, {}} {
		if selected, err := service.WithOIDCCallbackAdapter(nil); selected != nil || !errors.Is(err, sso.ErrInvalidInput) {
			t.Fatal("missing factory or native owner must not enable selected callbacks")
		}
		if _, err := service.SigninParsedCallback(t.Context(), ProviderLoginBrowser{}, "", oauth.QueryCallback{}); !errors.Is(err, sso.ErrInvalidInput) {
			t.Fatal("unconfigured parsed sign-in must deny")
		}
		if _, err := service.LinkParsedCallback(t.Context(), ProviderLinkCallbackRequest{}, oauth.QueryCallback{}); !errors.Is(err, sso.ErrInvalidInput) {
			t.Fatal("unconfigured parsed member link must deny")
		}
	}
}
