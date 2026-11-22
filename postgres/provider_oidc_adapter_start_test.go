package postgres

import (
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/session"
	"github.com/faustbrian/go-sso"
)

func TestOIDCStartAdapterRejectsNilSelection(t *testing.T) {
	var missing *ProviderLoginCompletionService
	for _, service := range []*ProviderLoginCompletionService{missing, {}} {
		start, complete, err := service.WithOIDCStartAdapter(nil)
		if start != nil || complete != nil || !errors.Is(err, sso.ErrInvalidInput) {
			t.Fatal("missing native owner must not select an OIDC adapter")
		}
	}
}

func TestOIDCStartAdapterRejectsChangedCommittedRedirect(t *testing.T) {
	now := time.Date(2026, 11, 22, 23, 25, 0, 0, time.UTC)
	remember, err := session.NewRememberPolicy(session.RememberPolicySpec{
		Choice: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 20 * time.Minute,
		RefreshAfter: time.Minute, FreshFor: 15 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := sso.NewLoginTransaction(sso.LoginTransaction{
		TenantID: "tenant", ID: "AQEBAQEBAQEBAQEBAQEBAQ", ProviderID: "provider", OrganizationID: "org", Protocol: "oidc",
		Callback: url.URL{Scheme: "https", Host: "app.example.com", Path: "/sso/oidc/callback"}, ExpiresAt: now.Add(time.Minute),
		ProviderVersion: 9, MappingVersion: 4, RememberPolicy: remember, CommandID: "AgICAgICAgICAgICAgICAg",
	}, 3)
	if err != nil {
		t.Fatal(err)
	}
	profile := providerLoginProfile{
		configured: StaticOIDCLoginProfile{Domain: "enterprise.example", OrganizationID: "org", ProviderID: "provider",
			ClientID: "installed-client", ProtocolRedirectURI: tx.Callback.String(), ProviderVersion: 9, MappingVersion: 4,
			CredentialGeneration: 3, Scopes: []string{"openid", "email"}},
		authorizationEndpoint: "https://provider.example.com/authorize",
	}
	state := providerLoginPublicState{State: strings.Repeat("A", 43), Nonce: strings.Repeat("E", 43), Challenge: strings.Repeat("I", 43)}
	expected, err := profile.authorizationRedirect(state)
	if err != nil {
		t.Fatal(err)
	}
	valid := sso.ProtocolStartResult{Redirect: expected, ExpiresAt: tx.ExpiresAt}
	if err := validateOIDCAdapterStartRedirect(valid, expected, tx, now); err != nil {
		t.Fatal(err)
	}
	changed := valid
	changed.ExpiresAt = tx.ExpiresAt.Add(-time.Second)
	if err := validateOIDCAdapterStartRedirect(changed, expected, tx, now); !errors.Is(err, sso.ErrForbidden) {
		t.Fatal("adapter shortened original transaction lifetime", err)
	}
	for _, key := range []string{"state", "nonce", "code_challenge", "redirect_uri", "scope"} {
		query := expected.Query()
		query.Set(key, "foreign-value")
		changed := valid
		changed.Redirect.RawQuery = query.Encode()
		if err := validateOIDCAdapterStartRedirect(changed, expected, tx, now); !errors.Is(err, sso.ErrForbidden) {
			t.Fatalf("changed %s disclosed: %v", key, err)
		}
	}
}
