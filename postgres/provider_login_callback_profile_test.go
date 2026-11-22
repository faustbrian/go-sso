package postgres

import (
	"bytes"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/faustbrian/go-clock"
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	"github.com/faustbrian/go-sso"
)

func TestProviderLoginCompletionProtocolProfileReturnsExactDetachedMetadata(t *testing.T) {
	start, config := providerLoginCompletionProfileFixture(t)
	service, err := NewProviderLoginCompletionService(start, config)
	if err != nil {
		t.Fatal(err)
	}
	selected := config.Profiles[0]
	namespace, err := SSOOIDCAccountProviderNamespace(selected.OrganizationID, selected.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	want := oauth.ProviderProfile{
		ID: strings.ReplaceAll(namespace, ".", "-"), Version: 7,
		Issuer: "https://enterprise.example", ClientID: "native-client",
		AuthorizationEndpoint: "https://enterprise.example/authorize", TokenEndpoint: "https://enterprise.example/token",
		RedirectURI: "https://app.example/sso/callback", ClientAuthentication: oauth.ClientSecretBasic,
		Scopes: []string{"openid", "email"}, Algorithms: []string{"ES256", "RS256"},
		ResponseMode: "query", PKCEMethod: "S256", NonceRequired: true, StateBytes: 32, NonceBytes: 32,
		Timeout: 10 * time.Second, ClockSkew: time.Minute, MaxResponseBytes: 64 << 10, MaxTokenBytes: 16 << 10, MaxCodeBytes: 4096,
	}
	profile, err := service.SigninProtocolProfile(selected.OrganizationID, selected.ProviderID)
	if err != nil || !reflect.DeepEqual(profile, want) {
		t.Fatalf("projection did not preserve the validated protocol profile: %v", err)
	}
	if profile.ID == string(selected.ProviderID) || profile.ID != strings.ToLower(profile.ID) {
		t.Fatal("native case-sensitive ID was not projected into its scoped lowercase protocol alias")
	}

	// Deployment and returned slices must not mutate the retained projection.
	config.Profiles[0].Algorithms[0] = "changed-config"
	for _, configured := range start.profiles {
		configured.Scopes[0] = "changed-start"
	}
	profile.Scopes[0], profile.Algorithms[0] = "changed-return", "changed-return"
	again, err := service.SigninProtocolProfile(selected.OrganizationID, selected.ProviderID)
	if err != nil || !reflect.DeepEqual(again, want) {
		t.Fatalf("caller mutation reached the retained protocol profile: %v", err)
	}
}

func TestProviderLoginCompletionProtocolProfileRejectsUnselectedScope(t *testing.T) {
	start, config := providerLoginCompletionProfileFixture(t)
	service, err := NewProviderLoginCompletionService(start, config)
	if err != nil {
		t.Fatal(err)
	}
	selected := config.Profiles[0]
	for _, tc := range []struct {
		name         string
		service      *ProviderLoginCompletionService
		organization organization.ID
		provider     sso.ProviderID
	}{
		{"nil-service", nil, selected.OrganizationID, selected.ProviderID},
		{"zero-service", &ProviderLoginCompletionService{}, selected.OrganizationID, selected.ProviderID},
		{"empty-organization", service, "", selected.ProviderID},
		{"empty-provider", service, selected.OrganizationID, ""},
		{"unknown-organization", service, "other-organization", selected.ProviderID},
		{"unknown-provider", service, selected.OrganizationID, "other-provider"},
		{"organization-case-mismatch", service, organization.ID(strings.ToLower(string(selected.OrganizationID))), selected.ProviderID},
		{"provider-case-mismatch", service, selected.OrganizationID, sso.ProviderID(strings.ToLower(string(selected.ProviderID)))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			profile, err := tc.service.SigninProtocolProfile(tc.organization, tc.provider)
			if !errors.Is(err, sso.ErrInvalidInput) || !reflect.DeepEqual(profile, oauth.ProviderProfile{}) {
				t.Fatal("unselected scope disclosed a protocol profile or lost its invalid-input error")
			}
		})
	}
}

func providerLoginCompletionProfileFixture(t *testing.T) (*ProviderLoginService, ProviderLoginCompletionConfig) {
	t.Helper()
	lookup, err := session.NewDigestKey(1, bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := session.NewCSRFKey(1, bytes.Repeat([]byte{0x32}, 32))
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_session", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	selected := StaticOIDCLoginProfile{
		OrganizationID: "Organization_A7", ProviderID: "Enterprise_A7", Domain: "enterprise.example",
		ClientID: "native-client", ProtocolRedirectURI: "https://app.example/sso/callback",
		ProviderVersion: 7, CredentialGeneration: 2, MappingVersion: 3, Scopes: []string{"openid", "email"},
	}
	// This constructor only borrows owner identities; no primary or credential
	// is needed to exercise its existing configuration-only validation.
	start := &ProviderLoginService{
		router: &ProviderRouter{organizations: &organizationpg.Repository{}, config: ProviderRouterConfig{Clock: clock.System{}}},
		profiles: map[providerLoginProfileKey]StaticOIDCLoginProfile{
			{organization: selected.OrganizationID, provider: selected.ProviderID}: selected,
		},
		config: ProviderLoginConfig{GlobalAuthorityID: "global", Session: sessionpg.Config{Schema: "identity_session", MaximumDuration: time.Second}},
	}
	start.config.Coordinator.MaximumDuration = time.Second
	config := ProviderLoginCompletionConfig{
		Audience: "native-app", PolicyNamespace: "users", CSRFKey: csrf,
		Issuer: session.IssuerConfig{MaximumDuration: time.Second, LookupKey: lookup, TokenSize: 32, Cookie: cookie},
		Profiles: []StaticOIDCCompletionProfile{{
			OrganizationID: selected.OrganizationID, ProviderID: selected.ProviderID,
			Metadata: sso.OIDCStaticMetadataSpec{Issuer: "https://enterprise.example", AuthorizationEndpoint: "https://enterprise.example/authorize",
				TokenEndpoint: "https://enterprise.example/token", JWKSURI: "https://enterprise.example/keys"},
			ClientAuthentication: oauth.ClientSecretBasic, Algorithms: []string{"ES256", "RS256"},
			Keys: &coreoidc.StaticKeySet{},
		}},
	}
	return start, config
}
