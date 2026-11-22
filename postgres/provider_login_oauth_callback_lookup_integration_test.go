//go:build integration

package postgres_test

import (
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestNativeProviderOAuth2CallbackFindsOnlyOriginalStoredProtocolState(t *testing.T) {
	t.Run("oauth-state", testNativeOriginalOAuth2CallbackState)
	t.Run("reject-oidc-state", testNativeOAuth2RejectsOriginalOIDCCallbackState)
}

func testNativeOriginalOAuth2CallbackState(t *testing.T) {
	t.Helper()
	x := newProviderOAuthLoginStartFixture(t)
	ctx := x.enable.f.ctx
	started, err := x.service.SigninStartOAuth2(ctx, x.request, x.browser)
	if err != nil {
		t.Fatal("commit the real original OAuth start", err)
	}
	state := started.RedirectURI.Query().Get("state")
	found, err := ssopg.LookupProviderOAuth2LoginCallbackForTest(ctx, x.service, state)
	expectedExpiry := found.IssuedAt.Add(x.config.StateLifetime)
	if x.originalFlow.ExpiresAt.Before(expectedExpiry) {
		expectedExpiry = x.originalFlow.ExpiresAt.UTC().Truncate(time.Second)
	}
	if err != nil || found.TenantID != string(x.config.TenantID) || found.ProviderID != started.ProviderID ||
		found.StartCommandID != started.TransactionID || found.CallbackCommandID == started.TransactionID ||
		found.ProviderVersion != x.profile.ProviderVersion || found.CredentialGeneration != x.profile.CredentialGeneration || found.MappingVersion != x.profile.MappingVersion ||
		found.Origin != x.browser.Origin || found.Success != x.request.SuccessCallback.String() || found.Failure != x.request.ErrorCallback.String() ||
		!found.ExpiresAt.Equal(expectedExpiry) || found.ObservedAt.Before(found.IssuedAt) || !found.ObservedAt.Before(found.ExpiresAt) ||
		found.CompletedAt != nil || !found.HasProof || !found.HasPlan {
		t.Fatal("OAuth lookup lost the original row, protocol, browser intent or expiry", err)
	}
	if _, err := ssopg.LookupProviderLoginCallbackForTest(ctx, x.service, state); !errors.Is(err, sso.ErrForbidden) {
		t.Fatal("OIDC lookup accepted original OAuth custody", err)
	}
}

func testNativeOAuth2RejectsOriginalOIDCCallbackState(t *testing.T) {
	t.Helper()
	oidc := newProviderLoginStartFixture(t)
	legacy, err := oidc.service.SigninStart(oidc.enable.f.ctx, oidc.request, oidc.browser)
	if err != nil {
		t.Fatal("commit the real original OIDC start", err)
	}
	if _, err := ssopg.LookupProviderOAuth2LoginCallbackForTest(oidc.enable.f.ctx, oidc.service, legacy.RedirectURI.Query().Get("state")); !errors.Is(err, sso.ErrForbidden) {
		t.Fatal("OAuth lookup accepted original OIDC custody", err)
	}
}
