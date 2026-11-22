package postgres

import (
	"context"
	"errors"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-clock"
	organization "github.com/faustbrian/go-organization"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
)

func TestNativeOAuth2LoginProfileRejectsOIDCRouteBeforeRegistryRead(t *testing.T) {
	configured := oauthLoginProfileConfiguration()
	now := time.Now().UTC().Truncate(time.Microsecond)
	proof := organization.DomainProofKey{TenantID: "tenant-profile", OrganizationID: configured.OrganizationID,
		ClaimID: "claim-profile", Domain: configured.Domain, ClaimVersion: 1, ProofVersion: 1,
		Method: organization.DomainDNS, ObservedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}
	binding := sso.DomainRouteBinding{ProviderID: configured.ProviderID, ProviderVersion: configured.ProviderVersion,
		CredentialGeneration: configured.CredentialGeneration, PolicyVersion: 1,
		Proof: sso.DomainProofCheckpoint{Key: proof, ProofVersion: 1}, ObservedAt: now, ValidUntil: now.Add(20 * time.Second)}
	route, err := sso.NewDomainRoute(binding)
	if err != nil {
		t.Fatal("construct foreign-protocol evidence", err)
	}
	// No live pool: rejecting impossible protocol evidence must precede any I/O.
	router := &ProviderRouter{pool: &database.Pool{}, protocolRegistry: true,
		config: ProviderRouterConfig{Clock: clock.System{}, Envelope: &envelope.Service{}}}
	if got, err := router.readProviderOAuth2LoginProfile(context.Background(), route, configured); !errors.Is(err, sso.ErrForbidden) || got.authorizationEndpoint != "" {
		t.Fatal("OIDC evidence reached OAuth configuration", err)
	}
	oauthRoute, err := sso.NewOAuth2DomainRoute(binding)
	if err != nil {
		t.Fatal("construct OAuth evidence", err)
	}
	router.protocolRegistry = false
	if got, err := router.readProviderOAuth2LoginProfile(context.Background(), oauthRoute, configured); !errors.Is(err, sso.ErrForbidden) || got.authorizationEndpoint != "" {
		t.Fatal("unselected protocol registry reached OAuth configuration", err)
	}
	router.protocolRegistry = true
	for name, change := range map[string]func(*sso.DomainRouteBinding){
		"provider":           func(b *sso.DomainRouteBinding) { b.ProviderID = "other-provider" },
		"organization":       func(b *sso.DomainRouteBinding) { b.Proof.Key.OrganizationID = "other-organization" },
		"domain":             func(b *sso.DomainRouteBinding) { b.Proof.Key.Domain = "other.example.com" },
		"version":            func(b *sso.DomainRouteBinding) { b.ProviderVersion++ },
		"generation":         func(b *sso.DomainRouteBinding) { b.CredentialGeneration++ },
		"future observation": func(b *sso.DomainRouteBinding) { b.ObservedAt = now.Add(10 * time.Second) },
		"original expiry": func(b *sso.DomainRouteBinding) {
			b.ObservedAt, b.ValidUntil = now.Add(-20*time.Second), now.Add(-time.Microsecond)
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := binding
			change(&changed)
			retained, err := sso.NewOAuth2DomainRoute(changed)
			if err != nil {
				t.Fatal("construct mismatched OAuth evidence", err)
			}
			if got, err := router.readProviderOAuth2LoginProfile(context.Background(), retained, configured); !errors.Is(err, sso.ErrForbidden) || got.authorizationEndpoint != "" {
				t.Fatal("mismatched or expired OAuth evidence reached configuration", err)
			}
		})
	}
}

func oauthLoginProfileConfiguration() StaticOAuth2LoginProfile {
	return StaticOAuth2LoginProfile{
		ProviderID: "provider-oauth-test", OrganizationID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Domain: "example.com",
		ClientID: "enterprise-client", ProtocolRedirectURI: "https://app.example.com/sso/callback",
		ProviderVersion: 3, CredentialGeneration: 1, MappingVersion: 2,
		Scopes: []string{"read:identity", "email"},
	}
}

func oauthLoginProfileState() providerLoginPublicState {
	return providerLoginPublicState{State: strings.Repeat("s", 43), Challenge: strings.Repeat("c", 43)}
}

func TestNativeOAuth2LoginProfileSnapshotsExactScopes(t *testing.T) {
	input := oauthLoginProfileConfiguration()
	got, err := normalizeStaticOAuth2LoginProfile(input)
	if err != nil || !reflect.DeepEqual(got, input) {
		t.Fatal("selected OAuth profile was not preserved", err)
	}
	input.Scopes[0] = "write:organization"
	if got.Scopes[0] != "read:identity" {
		t.Fatal("selected scopes alias caller storage")
	}
	caseSensitive := oauthLoginProfileConfiguration()
	caseSensitive.Scopes = []string{"OpenID", "read:identity"}
	if got, err := normalizeStaticOAuth2LoginProfile(caseSensitive); err != nil || !reflect.DeepEqual(got.Scopes, caseSensitive.Scopes) {
		t.Fatal("case-sensitive OAuth scopes were rewritten", err)
	}
	maximum := oauthLoginProfileConfiguration()
	maximum.Scopes = make([]string, 32)
	for i := range maximum.Scopes {
		maximum.Scopes[i] = strings.Repeat("x", 126) + string(rune('a'+i/26)) + string(rune('a'+i%26))
	}
	if got, err := normalizeStaticOAuth2LoginProfile(maximum); err != nil || !reflect.DeepEqual(got.Scopes, maximum.Scopes) {
		t.Fatal("bounded maximum selected scopes were rejected or rewritten", err)
	}
}

func TestNativeOAuth2LoginProfileRejectsInvalidAuthenticatedConfiguration(t *testing.T) {
	baseline := providerOAuthConfiguration{
		AuthorizationEndpoint: "https://issuer.example.com/authorize", TokenEndpoint: "https://issuer.example.com/token",
		IdentityEndpoint: "https://issuer.example.com/identity", RevocationEndpoint: "https://issuer.example.com/revoke",
		Proof:   sso.IdentityProofPolicySpec{Version: 1, Issuer: "https://issuer.example.com/Enterprise", SubjectKind: sso.OAuthSubjectString, EmailVerification: sso.OAuthEmailUnverified},
		Mapping: sso.AttributeMappingSpec{Version: 2, SubjectClaim: "stable_id"}, Domains: []string{"example.com"},
	}
	if err := validateProviderOAuth2LoginConfiguration(baseline); err != nil {
		t.Fatal("valid authenticated OAuth configuration rejected", err)
	}
	for name, change := range map[string]func(*providerOAuthConfiguration){
		"mapping":                  func(p *providerOAuthConfiguration) { p.Mapping.SubjectClaim = "" },
		"issuer":                   func(p *providerOAuthConfiguration) { p.Proof.Issuer = "http://issuer.example.com" },
		"subject policy":           func(p *providerOAuthConfiguration) { p.Proof.SubjectKind = 0 },
		"missing verified mail":    func(p *providerOAuthConfiguration) { p.Proof.EmailVerification = sso.OAuthEmailBooleanClaim },
		"unverified mail upgrades": func(p *providerOAuthConfiguration) { p.Mapping.VerifiedEmailClaim = "verified" },
		"verified subject alias": func(p *providerOAuthConfiguration) {
			p.Proof.EmailVerification = sso.OAuthEmailBooleanClaim
			p.Mapping.EmailClaim, p.Mapping.VerifiedEmailClaim = "email", p.Mapping.SubjectClaim
		},
		"authorization scheme":                 func(p *providerOAuthConfiguration) { p.AuthorizationEndpoint = "http://issuer.example.com/authorize" },
		"authorization query":                  func(p *providerOAuthConfiguration) { p.AuthorizationEndpoint += "?deployment=one" },
		"authorization empty query":            func(p *providerOAuthConfiguration) { p.AuthorizationEndpoint += "?" },
		"missing token":                        func(p *providerOAuthConfiguration) { p.TokenEndpoint = "" },
		"token fragment":                       func(p *providerOAuthConfiguration) { p.TokenEndpoint += "#fragment" },
		"token bound":                          func(p *providerOAuthConfiguration) { p.TokenEndpoint += strings.Repeat("x", 2048) },
		"missing identity":                     func(p *providerOAuthConfiguration) { p.IdentityEndpoint = "" },
		"identity userinfo":                    func(p *providerOAuthConfiguration) { p.IdentityEndpoint = "https://user@issuer.example.com/identity" },
		"identity token alias":                 func(p *providerOAuthConfiguration) { p.IdentityEndpoint = "https://ISSUER.example.com:443/token" },
		"identity authorization escaped alias": func(p *providerOAuthConfiguration) { p.IdentityEndpoint = "https://issuer.example.com/%61uthorize" },
		"revocation query":                     func(p *providerOAuthConfiguration) { p.RevocationEndpoint += "?secret=other" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := baseline
			change(&changed)
			if err := validateProviderOAuth2LoginConfiguration(changed); !errors.Is(err, sso.ErrUnavailable) {
				t.Fatal("invalid authenticated OAuth configuration accepted", err)
			}
		})
	}
	baseline.RevocationEndpoint = ""
	if err := validateProviderOAuth2LoginConfiguration(baseline); err != nil {
		t.Fatal("optional revocation endpoint was made mandatory", err)
	}
}

func TestNativeOAuth2LoginProfileRejectsInvalidConfiguration(t *testing.T) {
	for name, change := range map[string]func(*StaticOAuth2LoginProfile){
		"provider":          func(p *StaticOAuth2LoginProfile) { p.ProviderID = "" },
		"organization":      func(p *StaticOAuth2LoginProfile) { p.OrganizationID = "" },
		"domain":            func(p *StaticOAuth2LoginProfile) { p.Domain = "EXAMPLE.com" },
		"version":           func(p *StaticOAuth2LoginProfile) { p.ProviderVersion = 0 },
		"generation":        func(p *StaticOAuth2LoginProfile) { p.CredentialGeneration = 0 },
		"mapping":           func(p *StaticOAuth2LoginProfile) { p.MappingVersion = 0 },
		"client":            func(p *StaticOAuth2LoginProfile) { p.ClientID = "" },
		"client bound":      func(p *StaticOAuth2LoginProfile) { p.ClientID = strings.Repeat("x", 1025) },
		"callback scheme":   func(p *StaticOAuth2LoginProfile) { p.ProtocolRedirectURI = "http://app.example.com/callback" },
		"callback query":    func(p *StaticOAuth2LoginProfile) { p.ProtocolRedirectURI += "?state=other" },
		"callback fragment": func(p *StaticOAuth2LoginProfile) { p.ProtocolRedirectURI += "#fragment" },
		"empty scopes":      func(p *StaticOAuth2LoginProfile) { p.Scopes = nil },
		"oidc selection":    func(p *StaticOAuth2LoginProfile) { p.Scopes = []string{"read:identity", "openid"} },
		"duplicate scope":   func(p *StaticOAuth2LoginProfile) { p.Scopes = []string{"email", "email"} },
		"scope injection":   func(p *StaticOAuth2LoginProfile) { p.Scopes = []string{"read:identity email"} },
		"scope quote":       func(p *StaticOAuth2LoginProfile) { p.Scopes = []string{"read\"identity"} },
		"scope backslash":   func(p *StaticOAuth2LoginProfile) { p.Scopes = []string{"read\\identity"} },
		"scope bound":       func(p *StaticOAuth2LoginProfile) { p.Scopes = []string{strings.Repeat("x", 129)} },
		"scope count":       func(p *StaticOAuth2LoginProfile) { p.Scopes = make([]string, 33) },
	} {
		t.Run(name, func(t *testing.T) {
			input := oauthLoginProfileConfiguration()
			change(&input)
			if _, err := normalizeStaticOAuth2LoginProfile(input); !errors.Is(err, sso.ErrInvalidInput) {
				t.Fatal("invalid OAuth profile accepted", err)
			}
		})
	}
}

func TestNativeOAuth2LoginProfileAuthorizationRedirectBindsCodeQueryS256WithoutNonce(t *testing.T) {
	profile := providerOAuth2LoginProfile{configured: oauthLoginProfileConfiguration(), issuer: "https://issuer.example.com", authorizationEndpoint: "https://issuer.example.com/authorize?deployment=company&path=a%2Fb"}
	state := oauthLoginProfileState()
	got, err := profile.authorizationRedirect(state)
	if err != nil {
		t.Fatal("project selected OAuth authorization redirect", err)
	}
	want := url.Values{
		"deployment": {"company"}, "path": {"a/b"}, "response_type": {"code"}, "response_mode": {"query"},
		"client_id": {profile.configured.ClientID}, "redirect_uri": {profile.configured.ProtocolRedirectURI},
		"scope": {"read:identity email"}, "state": {state.State}, "code_challenge": {state.Challenge}, "code_challenge_method": {"S256"},
	}
	if got.Query().Encode() != want.Encode() || got.Host != "issuer.example.com" || got.Path != "/authorize" {
		t.Fatal("OAuth redirect changed exact selected scopes, state, redirect or PKCE, or emitted a nonce")
	}
}

func TestNativeOAuth2LoginProfileAuthorizationRedirectRejectsNonceAndProtocolSubstitution(t *testing.T) {
	profile := providerOAuth2LoginProfile{configured: oauthLoginProfileConfiguration(), authorizationEndpoint: "https://issuer.example.com/authorize"}
	state := oauthLoginProfileState()
	for name, change := range map[string]func(*providerLoginPublicState){
		"nonce":                func(s *providerLoginPublicState) { s.Nonce = strings.Repeat("n", 42) + "o" },
		"empty state":          func(s *providerLoginPublicState) { s.State = "" },
		"state alphabet":       func(s *providerLoginPublicState) { s.State = strings.Repeat("/", 43) },
		"state canonical bits": func(s *providerLoginPublicState) { s.State = strings.Repeat("s", 42) + "t" },
		"challenge padding":    func(s *providerLoginPublicState) { s.Challenge += "=" },
		"empty challenge":      func(s *providerLoginPublicState) { s.Challenge = "" },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := state
			change(&invalid)
			if got, err := profile.authorizationRedirect(invalid); !errors.Is(err, sso.ErrInvalidInput) || got.String() != "" {
				t.Fatal("malformed state or OIDC nonce produced OAuth redirect", err)
			}
		})
	}
	for _, query := range []string{"nonce=other", "%73tate=other", "response_mode=form_post", "client_secret=secret", "scope=openid", "request_uri=https%3A%2F%2Fother.example", "deployment=a&deployment=b", "broken=%ZZ"} {
		t.Run(query, func(t *testing.T) {
			changed := profile
			changed.authorizationEndpoint += "?" + query
			if got, err := changed.authorizationRedirect(state); !errors.Is(err, sso.ErrInvalidInput) || got.String() != "" {
				t.Fatal("substituting endpoint produced OAuth redirect", err)
			}
		})
	}
	profile.configured.ClientID = strings.Repeat("?", 1024)
	profile.configured.ProtocolRedirectURI = "https://app.example.com/" + strings.Repeat("a", 2000)
	profile.authorizationEndpoint += "?deployment=" + strings.Repeat("a", 3500)
	if got, err := profile.authorizationRedirect(state); !errors.Is(err, sso.ErrInvalidInput) || got.String() != "" {
		t.Fatal("oversized OAuth redirect escaped transport bound", err)
	}
}
