package postgres

import (
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/session"
	"github.com/faustbrian/go-sso"
)

func TestOAuth2AdapterStartRedirectPreservesExactCommittedValues(t *testing.T) {
	now := time.Date(2026, 11, 22, 23, 0, 0, 0, time.UTC)
	remember, err := session.NewRememberPolicy(session.RememberPolicySpec{
		Choice: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 20 * time.Minute,
		RefreshAfter: time.Minute, FreshFor: 15 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := sso.NewLoginTransaction(sso.LoginTransaction{
		TenantID: "tenant", ID: "AQEBAQEBAQEBAQEBAQEBAQ", ProviderID: "provider", OrganizationID: "org", Protocol: "oauth2",
		Callback: url.URL{Scheme: "https", Host: "app.example.com", Path: "/oauth/callback"}, ExpiresAt: now.Add(time.Minute),
		ProviderVersion: 9, MappingVersion: 4, RememberPolicy: remember, CommandID: "AgICAgICAgICAgICAgICAg",
	}, 3)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := "https://provider.example.com/authorize"
	state, challenge := strings.Repeat("A", 43), strings.Repeat("E", 43)
	config := OAuth2ProtocolAdapterConfig{
		Transaction: tx, CredentialGeneration: 3,
		Profile:       oauth.OAuth2UserInfoProfile{Profile: oauth.ProviderProfile{AuthorizationEndpoint: endpoint, ClientID: "client", RedirectURI: tx.Callback.String(), Scopes: []string{"email", "profile"}}},
		Authorization: oauth.AuthorizationParameters{State: state, PKCEChallenge: challenge}, CapabilityExpiresAt: now.Add(45 * time.Second),
	}
	redirect := url.URL{Scheme: "https", Host: "provider.example.com", Path: "/authorize", RawQuery: url.Values{
		"client_id": {"client"}, "redirect_uri": {tx.Callback.String()}, "response_type": {"code"}, "response_mode": {"query"},
		"scope": {"email profile"}, "state": {state}, "code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}.Encode()}
	original := sso.ProtocolStartResult{Redirect: redirect, ExpiresAt: config.CapabilityExpiresAt}
	if err := validateOAuth2AdapterStartRedirect(original, config, now); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*sso.ProtocolStartResult)
	}{
		{"foreign host", func(r *sso.ProtocolStartResult) { r.Redirect.Host = "other.example.com" }},
		{"foreign path", func(r *sso.ProtocolStartResult) { r.Redirect.Path = "/other" }},
		{"foreign state", func(r *sso.ProtocolStartResult) {
			r.Redirect.RawQuery = strings.Replace(r.Redirect.RawQuery, state, strings.Repeat("B", 43), 1)
		}},
		{"wrong S256 challenge", func(r *sso.ProtocolStartResult) {
			r.Redirect.RawQuery = strings.Replace(r.Redirect.RawQuery, challenge, strings.Repeat("B", 43), 1)
		}},
		{"foreign callback", func(r *sso.ProtocolStartResult) {
			r.Redirect.RawQuery = strings.Replace(r.Redirect.RawQuery, "app.example.com", "other.example.com", 1)
		}},
		{"scope substitution", func(r *sso.ProtocolStartResult) {
			r.Redirect.RawQuery = strings.Replace(r.Redirect.RawQuery, "email+profile", "email+admin", 1)
		}},
		{"duplicate selected field", func(r *sso.ProtocolStartResult) { r.Redirect.RawQuery += "&state=" + state }},
		{"unexpected OAuth parameter", func(r *sso.ProtocolStartResult) { r.Redirect.RawQuery += "&nonce=unselected" }},
		{"extended expiry", func(r *sso.ProtocolStartResult) { r.ExpiresAt = config.CapabilityExpiresAt.Add(time.Second) }},
		{"different shorter expiry", func(r *sso.ProtocolStartResult) { r.ExpiresAt = config.CapabilityExpiresAt.Add(-time.Second) }},
		{"expired", func(r *sso.ProtocolStartResult) { r.ExpiresAt = now }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := original
			tc.change(&changed)
			if err := validateOAuth2AdapterStartRedirect(changed, config, now); !errors.Is(err, sso.ErrForbidden) {
				t.Fatal("changed result was eligible for disclosure", err)
			}
		})
	}
}
