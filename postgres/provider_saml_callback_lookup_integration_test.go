//go:build integration

package postgres_test

import (
	"errors"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestNativeSAMLCallbackFindsOnlyOriginalPendingRelayState(t *testing.T) {
	x := newSAMLStartFixture(t)
	ctx := x.start.enable.f.ctx
	started, err := x.start.service.SigninStartSAML(ctx, x.request, x.start.browser)
	if err != nil || started.Completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("commit original browser start", err)
	}
	state := started.RedirectURI.Query().Get("RelayState")
	before := nativeProviderLoginCounts(t, x.start)

	original, err := ssopg.LookupProviderSAMLLoginCallbackForTest(ctx, x.start.service, state)
	if err != nil || original.StartCommandID != started.TransactionID || original.ProviderID != string(x.request.ProviderID) ||
		original.CallbackCommandID == started.TransactionID || original.CompletedAt != nil || !original.HasPlan || !original.HasProof ||
		!original.ObservedAt.Before(original.ExpiresAt) {
		t.Fatal("SAML callback did not find the exact original pending binding without PKCE", err)
	}
	for _, variant := range []struct {
		name string
		load func() error
	}{
		{"noncanonical RelayState", func() error {
			_, err := ssopg.LookupProviderSAMLLoginCallbackForTest(ctx, x.start.service, state+"=")
			return err
		}},
		{"foreign OIDC", func() error {
			_, err := ssopg.LookupProviderLoginCallbackForTest(ctx, x.start.service, state)
			return err
		}},
		{"foreign OAuth2", func() error {
			_, err := ssopg.LookupProviderOAuth2LoginCallbackForTest(ctx, x.start.service, state)
			return err
		}},
	} {
		t.Run(variant.name, func(t *testing.T) {
			if err := variant.load(); !errors.Is(err, sso.ErrForbidden) {
				t.Fatal("non-original callback obtained pending custody", err)
			}
		})
	}
	if after := nativeProviderLoginCounts(t, x.start); after != before {
		t.Fatal("lookup consumed RelayState or created an effect")
	}
	if err := ssopg.RecordProviderSAMLCallbackTerminalForTest(ctx, x.start.service, state); err != nil {
		t.Fatal("install historical correlation fixture", err)
	}
	terminal, err := ssopg.LookupProviderSAMLLoginCallbackForTest(ctx, x.start.service, state)
	if err != nil || terminal.CompletedAt == nil || terminal.HasProof || terminal.HasPlan ||
		terminal.StartCommandID != original.StartCommandID || terminal.CallbackCommandID != original.CallbackCommandID ||
		!terminal.ExpiresAt.Equal(original.ExpiresAt) {
		t.Fatal("terminal lookup lost original correlation or retained executable authorization", err)
	}
}
