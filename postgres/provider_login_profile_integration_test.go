//go:build integration

package postgres

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"

	organization "github.com/faustbrian/go-organization"
	"github.com/faustbrian/go-sso"
)

const ProviderLoginProfileSQLForTest = providerLoginProfileSQL

func FuzzNativeLoginAuthorizationEndpoint(f *testing.F) {
	for _, seed := range []string{
		"https://idp.example.com/authorize?deployment=example",
		"https://idp.example.com/authorize?%73tate=foreign",
		"https://idp.example.com/authorize?deployment=a&deployment=b",
		"https://idp.example.com/authorize?deployment=%ZZ",
		"https://user@idp.example.com/authorize",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, endpoint string) {
		p := providerLoginProfile{configured: profileTestConfiguration(), authorizationEndpoint: endpoint}
		state := providerLoginPublicState{State: strings.Repeat("A", 43), Nonce: strings.Repeat("E", 43), Challenge: strings.Repeat("I", 43)}
		redirect, err := p.authorizationRedirect(state)
		if err != nil {
			return
		}
		q := redirect.Query()
		for name, want := range map[string]string{
			"response_type": "code", "response_mode": "query", "code_challenge_method": "S256", "state": state.State,
			"nonce": state.Nonce, "code_challenge": state.Challenge, "client_id": p.configured.ClientID,
			"redirect_uri": p.configured.ProtocolRedirectURI, "scope": "openid email",
		} {
			if values := q[name]; len(values) != 1 || values[0] != want {
				t.Fatal("authorization endpoint changed a required field", name)
			}
		}
		if redirect.Scheme != "https" || redirect.Hostname() == "" || redirect.User != nil || len(redirect.String()) > 8192 {
			t.Fatal("authorization endpoint produced an invalid redirect")
		}
	})
}

func profileTestConfiguration() StaticOIDCLoginProfile {
	return StaticOIDCLoginProfile{ProviderID: "provider-test", OrganizationID: organization.ID("01ARZ3NDEKTSV4RRFFQ69G5FAV"), Domain: "example.com", ClientID: "enterprise-client", ProtocolRedirectURI: "https://app.example.com/sso/callback", ProviderVersion: 3, CredentialGeneration: 1, MappingVersion: 1, Scopes: []string{"openid", "email"}}
}

func TestNativeLoginProfileSnapshotsScopesAndRejectsUnboundedOrAmbiguousConfiguration(t *testing.T) {
	input := profileTestConfiguration()
	got, err := normalizeStaticOIDCLoginProfile(input)
	if err != nil {
		t.Fatal("normalize selected deployment", err)
	}
	input.Scopes[0] = "write:organization"
	if got.Scopes[0] != "openid" {
		t.Fatal("deployment scopes alias caller storage")
	}
	for name, change := range map[string]func(*StaticOIDCLoginProfile){
		"empty provider":      func(p *StaticOIDCLoginProfile) { p.ProviderID = "" },
		"empty organization":  func(p *StaticOIDCLoginProfile) { p.OrganizationID = "" },
		"noncanonical domain": func(p *StaticOIDCLoginProfile) { p.Domain = "EXAMPLE.com" },
		"zero version":        func(p *StaticOIDCLoginProfile) { p.ProviderVersion = 0 },
		"zero credential":     func(p *StaticOIDCLoginProfile) { p.CredentialGeneration = 0 },
		"zero mapping":        func(p *StaticOIDCLoginProfile) { p.MappingVersion = 0 },
		"blank client":        func(p *StaticOIDCLoginProfile) { p.ClientID = "" },
		"unbounded client":    func(p *StaticOIDCLoginProfile) { p.ClientID = strings.Repeat("a", 1025) },
		"insecure callback":   func(p *StaticOIDCLoginProfile) { p.ProtocolRedirectURI = "http://app.example.com/callback" },
		"callback fragment":   func(p *StaticOIDCLoginProfile) { p.ProtocolRedirectURI += "#fragment" },
		"callback query":      func(p *StaticOIDCLoginProfile) { p.ProtocolRedirectURI += "?state=other" },
		"missing openid":      func(p *StaticOIDCLoginProfile) { p.Scopes = []string{"email"} },
		"duplicate scope":     func(p *StaticOIDCLoginProfile) { p.Scopes = []string{"openid", "openid"} },
		"scope injection":     func(p *StaticOIDCLoginProfile) { p.Scopes = []string{"openid email"} },
		"unbounded scope":     func(p *StaticOIDCLoginProfile) { p.Scopes = []string{"openid", strings.Repeat("s", 129)} },
	} {
		t.Run(name, func(t *testing.T) {
			p := profileTestConfiguration()
			change(&p)
			if _, err := normalizeStaticOIDCLoginProfile(p); !errors.Is(err, sso.ErrInvalidInput) {
				t.Fatal("invalid selected deployment accepted", err)
			}
		})
	}
}

func TestNativeLoginAuthorizationRedirectBindsFixedProtocolAndPreservesEndpointQuery(t *testing.T) {
	p := providerLoginProfile{configured: profileTestConfiguration(), issuer: "https://issuer.example.com", authorizationEndpoint: "https://issuer.example.com/authorize?deployment=company&path=a%2Fb"}
	state := providerLoginPublicState{State: strings.Repeat("s", 43), Nonce: strings.Repeat("n", 42) + "o", Challenge: strings.Repeat("c", 43)}
	got, err := p.authorizationRedirect(state)
	if err != nil {
		t.Fatal("project selected authorization redirect", err)
	}
	q := got.Query()
	want := url.Values{"deployment": {"company"}, "path": {"a/b"}, "response_type": {"code"}, "response_mode": {"query"}, "client_id": {p.configured.ClientID}, "redirect_uri": {p.configured.ProtocolRedirectURI}, "scope": {"openid email"}, "state": {state.State}, "nonce": {state.Nonce}, "code_challenge": {state.Challenge}, "code_challenge_method": {"S256"}}
	if q.Encode() != want.Encode() || got.Host != "issuer.example.com" || got.Path != "/authorize" || len(got.String()) > 8192 {
		t.Fatal("authorization redirect changed selected runtime or deployment binding")
	}
}

func TestNativeLoginAuthorizationRedirectRejectsProtocolCollisionAndMalformedQuery(t *testing.T) {
	state := providerLoginPublicState{State: strings.Repeat("s", 43), Nonce: strings.Repeat("n", 42) + "o", Challenge: strings.Repeat("c", 43)}
	for _, query := range []string{"state=substituted", "%73cope=admin", "response_mode=form_post", "client_id=other", "nonce=other", "code_challenge=other", "request_uri=https%3A%2F%2Fother.example", "deployment=one&deployment=two", "broken=%ZZ", "deployment=one;state=other"} {
		t.Run(query, func(t *testing.T) {
			p := providerLoginProfile{configured: profileTestConfiguration(), issuer: "https://issuer.example.com", authorizationEndpoint: "https://issuer.example.com/authorize?" + query}
			if got, err := p.authorizationRedirect(state); err == nil || got.String() != "" {
				t.Fatal("ambiguous or substituting endpoint query produced redirect")
			}
		})
	}
	p := providerLoginProfile{configured: profileTestConfiguration(), issuer: "https://issuer.example.com", authorizationEndpoint: "https://issuer.example.com/authorize"}
	for _, invalid := range []providerLoginPublicState{{}, {State: "state", Nonce: "nonce", Challenge: "challenge"}, {State: strings.Repeat("s", 8193), Nonce: state.Nonce, Challenge: state.Challenge}} {
		if got, err := p.authorizationRedirect(invalid); err == nil || got.String() != "" {
			t.Fatal("invalid or unbounded runtime state produced redirect")
		}
	}
	for _, change := range []func(*providerLoginPublicState){
		func(s *providerLoginPublicState) { s.State = strings.Repeat("s", 42) + "t" },
		func(s *providerLoginPublicState) { s.Nonce = strings.Repeat("/", 43) },
		func(s *providerLoginPublicState) { s.Challenge += "=" },
	} {
		invalid := state
		change(&invalid)
		if got, err := p.authorizationRedirect(invalid); err == nil || got.String() != "" {
			t.Fatal("noncanonical protocol binding produced redirect")
		}
	}
	oversize := profileTestConfiguration()
	oversize.ProtocolRedirectURI = "https://app.example.com/" + strings.Repeat("a", 2000)
	oversize.ClientID = strings.Repeat("?", 1024)
	p.configured = oversize
	p.authorizationEndpoint += "?deployment=" + strings.Repeat("a", 3500)
	if got, err := p.authorizationRedirect(state); err == nil || got.String() != "" {
		t.Fatal("authorization redirect exceeded final transport bound")
	}
}

// ReadProviderLoginProfileRedirectForTest exercises the native selection boundary
// with the external package's fully migrated PostgreSQL provider fixture.
func ReadProviderLoginProfileRedirectForTest(ctx context.Context, r *ProviderRouter, route sso.DomainRoute, configured StaticOIDCLoginProfile) (url.URL, error) {
	p, err := r.readProviderLoginProfile(ctx, route, configured)
	if err != nil {
		return url.URL{}, err
	}
	return p.authorizationRedirect(providerLoginPublicState{State: strings.Repeat("s", 43), Nonce: strings.Repeat("n", 42) + "o", Challenge: strings.Repeat("c", 43)})
}
