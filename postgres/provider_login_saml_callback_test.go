package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/faustbrian/go-sso"
)

func TestSAMLCompletionRequiresAnExplicitNativeSAMLStart(t *testing.T) {
	for _, start := range []*ProviderLoginService{nil, {}} {
		owner, err := NewProviderSAMLLoginCompletionService(start, ProviderSAMLLoginCompletionConfig{})
		if owner != nil || !errors.Is(err, sso.ErrInvalidInput) {
			t.Fatal("unselected start enabled SAML completion")
		}
	}
	var owner *ProviderSAMLLoginCompletionService
	out, err := owner.SigninCallback(context.Background(), SAMLSigninCallbackRequest{})
	if out.Completion.Binding.CommandID != "" || out.RedirectURI != "" || !errors.Is(err, sso.ErrInvalidInput) {
		t.Fatal("uncomposed callback returned authentication evidence")
	}
}
