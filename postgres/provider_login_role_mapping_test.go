package postgres

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	organization "github.com/faustbrian/go-organization"
	"github.com/faustbrian/go-sso"
)

func roleMappingConfig() StaticOIDCRoleMapping {
	return StaticOIDCRoleMapping{OrganizationID: "organization-a", ProviderID: "Provider_A", MappingVersion: 7,
		Rules: []StaticOIDCRoleRule{{ClaimName: "role_z", RoleID: "custom-z"}, {ClaimName: "role_a", RoleID: "custom-a"}}}
}

func TestProviderLoginRoleMappingRejectsInvalidConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*StaticOIDCRoleMapping, *[]string)
	}{
		{"zero-organization", func(c *StaticOIDCRoleMapping, _ *[]string) { c.OrganizationID = "" }},
		{"zero-provider", func(c *StaticOIDCRoleMapping, _ *[]string) { c.ProviderID = "" }},
		{"zero-version", func(c *StaticOIDCRoleMapping, _ *[]string) { c.MappingVersion = 0 }},
		{"organization-over-bound", func(c *StaticOIDCRoleMapping, _ *[]string) {
			c.OrganizationID = organization.ID(strings.Repeat("a", 129))
		}},
		{"provider-over-bound", func(c *StaticOIDCRoleMapping, _ *[]string) { c.ProviderID = sso.ProviderID(strings.Repeat("a", 129)) }},
		{"invalid-organization", func(c *StaticOIDCRoleMapping, _ *[]string) { c.OrganizationID = "with space" }},
		{"invalid-provider", func(c *StaticOIDCRoleMapping, _ *[]string) { c.ProviderID = "with\nnewline" }},
		{"no-rules", func(c *StaticOIDCRoleMapping, _ *[]string) { c.Rules = nil }},
		{"too-many-rules", func(c *StaticOIDCRoleMapping, _ *[]string) { c.Rules = make([]StaticOIDCRoleRule, 101) }},
		{"duplicate-rule", func(c *StaticOIDCRoleMapping, _ *[]string) { c.Rules[1] = c.Rules[0] }},
		{"duplicate-claim", func(c *StaticOIDCRoleMapping, _ *[]string) { c.Rules[1].ClaimName = c.Rules[0].ClaimName }},
		{"duplicate-role", func(c *StaticOIDCRoleMapping, _ *[]string) { c.Rules[1].RoleID = c.Rules[0].RoleID }},
		{"empty-role", func(c *StaticOIDCRoleMapping, _ *[]string) { c.Rules[0].RoleID = "" }},
		{"invalid-role", func(c *StaticOIDCRoleMapping, _ *[]string) { c.Rules[0].RoleID = "custom role" }},
		{"invalid-role-utf8", func(c *StaticOIDCRoleMapping, _ *[]string) { c.Rules[0].RoleID = organization.ID([]byte{0xff}) }},
		{"invalid-role-control", func(c *StaticOIDCRoleMapping, _ *[]string) { c.Rules[0].RoleID = "custom\x7frole" }},
		{"role-over-bound", func(c *StaticOIDCRoleMapping, _ *[]string) {
			c.Rules[0].RoleID = organization.ID(strings.Repeat("a", 129))
		}},
		{"unprojected-claim", func(c *StaticOIDCRoleMapping, _ *[]string) { c.Rules[0].ClaimName = "other" }},
		{"case-sensitive-claim", func(c *StaticOIDCRoleMapping, _ *[]string) { c.Rules[0].ClaimName = "Role_z" }},
		{"no-projection", func(_ *StaticOIDCRoleMapping, p *[]string) { *p = nil }},
		{"projection-over-bound", func(_ *StaticOIDCRoleMapping, p *[]string) { *p = make([]string, 129) }},
		{"duplicate-projection", func(_ *StaticOIDCRoleMapping, p *[]string) { *p = append(*p, "role_a") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config, projected := roleMappingConfig(), []string{"role_z", "role_a"}
			tc.change(&config, &projected)
			mapping, err := newProviderLoginRoleMapping(config, projected)
			if !errors.Is(err, sso.ErrInvalidInput) || mapping.digest != ([32]byte{}) {
				t.Fatalf("invalid configuration returned a usable mapping: %v", err)
			}
		})
	}
	for _, name := range []string{"", "nonce", "at_hash", "c_hash", "access_token", "refresh_token", "id_token", "with space", "a/b", "a:b", "é", "1name", strings.Repeat("a", 129)} {
		t.Run("claim-"+name, func(t *testing.T) {
			config := roleMappingConfig()
			config.Rules[0].ClaimName = name
			if _, err := newProviderLoginRoleMapping(config, []string{name, "role_a"}); !errors.Is(err, sso.ErrInvalidInput) {
				t.Fatal("invalid claim name accepted")
			}
		})
	}
	for _, role := range []organization.Role{organization.RoleOwner, organization.RoleAdministrator, organization.RoleMember} {
		t.Run("static-role-"+string(role), func(t *testing.T) {
			config := roleMappingConfig()
			config.Rules[0].RoleID = organization.ID(role)
			if _, err := newProviderLoginRoleMapping(config, []string{"role_z", "role_a"}); !errors.Is(err, sso.ErrInvalidInput) {
				t.Fatal("static organization role accepted")
			}
		})
	}
}

func TestProviderLoginRoleMappingAcceptsExactBounds(t *testing.T) {
	config := roleMappingConfig()
	config.OrganizationID, config.ProviderID = organization.ID(strings.Repeat("o", 128)), sso.ProviderID(strings.Repeat("p", 128))
	config.MappingVersion = ^uint64(0)
	config.Rules = make([]StaticOIDCRoleRule, 100)
	projected := make([]string, 128)
	values := make(map[string]any, len(config.Rules))
	for i := range projected {
		projected[i] = fmt.Sprintf("Claim_%d.ext-name", i)
		if i < len(config.Rules) {
			config.Rules[i] = StaticOIDCRoleRule{ClaimName: projected[i], RoleID: organization.ID(fmt.Sprintf("custom-%03d", i))}
		}
	}
	config.Rules[0].ClaimName, projected[0] = strings.Repeat("a", 128), strings.Repeat("a", 128)
	config.Rules[0].RoleID = organization.ID(strings.Repeat("r", 128))
	config.Rules[1].RoleID = "custom-é"
	mapping, err := newProviderLoginRoleMapping(config, projected)
	if err != nil {
		t.Fatalf("valid exact bounds refused: %v", err)
	}
	for _, rule := range config.Rules {
		values[rule.ClaimName] = true
	}
	claims := verifiedRoleMappingClaims(t, values, projected)
	got, err := mapping.desiredRoles(claims)
	if err != nil || len(got) != 100 || !slices.IsSorted(got) || !slices.Contains(got, config.Rules[0].RoleID) || !slices.Contains(got, organization.ID("custom-é")) {
		t.Fatalf("valid exact bounds lost custom grants: %v", err)
	}
}

func TestProviderLoginRoleMappingSnapshotsAndBindsExactPolicy(t *testing.T) {
	config, projected := roleMappingConfig(), []string{"role_z", "role_a", "unmapped"}
	mapping, err := newProviderLoginRoleMapping(config, projected)
	if err != nil {
		t.Fatal(err)
	}
	config.Rules[0] = StaticOIDCRoleRule{ClaimName: "substituted", RoleID: "foreign"}
	projected[0] = "substituted"
	claims := verifiedRoleMappingClaims(t, map[string]any{"role_a": true, "role_z": true, "unmapped": nil}, []string{"role_z", "role_a", "unmapped"})
	got, err := mapping.desiredRoles(claims)
	if err != nil || !slices.Equal(got, []organization.ID{"custom-a", "custom-z"}) {
		t.Fatalf("startup mutation changed selected grants: %v", err)
	}
	got[0] = "foreign"
	fresh, err := mapping.desiredRoles(claims)
	if err != nil || !slices.Equal(fresh, []organization.ID{"custom-a", "custom-z"}) {
		t.Fatal("returned roles were not detached")
	}
	canonical := roleMappingConfig()
	slices.Reverse(canonical.Rules)
	same, err := newProviderLoginRoleMapping(canonical, []string{"unmapped", "role_a", "role_z"})
	if err != nil || same.digest != mapping.digest || mapping.digest == ([32]byte{}) {
		t.Fatal("equivalent order changed policy binding")
	}
	for _, change := range []func(*StaticOIDCRoleMapping){
		func(c *StaticOIDCRoleMapping) { c.OrganizationID = "organization-b" },
		func(c *StaticOIDCRoleMapping) { c.ProviderID = "Provider_B" },
		func(c *StaticOIDCRoleMapping) { c.MappingVersion++ },
		func(c *StaticOIDCRoleMapping) { c.Rules[0].RoleID = "custom-other" },
		func(c *StaticOIDCRoleMapping) { c.Rules[0].ClaimName = "unmapped" },
	} {
		candidate := roleMappingConfig()
		change(&candidate)
		changed, err := newProviderLoginRoleMapping(candidate, []string{"role_a", "role_z", "unmapped"})
		if err != nil || changed.digest == mapping.digest {
			t.Fatal("different scoped mapping reused policy binding")
		}
	}
	changed, err := newProviderLoginRoleMapping(roleMappingConfig(), []string{"role_a", "role_z"})
	if err != nil || changed.digest == mapping.digest {
		t.Fatal("changed projection reused policy binding")
	}
}

func TestProviderLoginRoleMappingUsesOnlyExplicitVerifiedBooleans(t *testing.T) {
	mapping, err := newProviderLoginRoleMapping(roleMappingConfig(), []string{"role_a", "role_z"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		values map[string]any
		want   []organization.ID
	}{
		{"both-true", map[string]any{"role_a": true, "role_z": true}, []organization.ID{"custom-a", "custom-z"}},
		{"false-withdraws-only-its-role", map[string]any{"role_a": false, "role_z": true}, []organization.ID{"custom-z"}},
		{"other-false", map[string]any{"role_a": true, "role_z": false}, []organization.ID{"custom-a"}},
		{"all-false-is-explicit-empty", map[string]any{"role_a": false, "role_z": false}, []organization.ID{}},
		{"absent", map[string]any{"role_a": true}, nil},
		{"null", map[string]any{"role_a": true, "role_z": nil}, nil},
		{"string-true", map[string]any{"role_a": true, "role_z": "true"}, nil},
		{"arbitrary-role-value", map[string]any{"role_a": true, "role_z": "owner"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := verifiedRoleMappingClaims(t, tc.values, []string{"role_z", "role_a"})
			got, err := mapping.desiredRoles(claims)
			if tc.want == nil {
				if !errors.Is(err, sso.ErrForbidden) || got != nil {
					t.Fatal("ambiguous observation returned a grant mutation")
				}
				return
			}
			if err != nil || got == nil || !slices.Equal(got, tc.want) {
				t.Fatalf("wrong explicit desired roles: %v", err)
			}
		})
	}
}

func TestProviderLoginRoleMappingRejectsIncompleteDuplicateAndForeignObservations(t *testing.T) {
	mapping, err := newProviderLoginRoleMapping(roleMappingConfig(), []string{"role_a", "role_z", "unmapped"})
	if err != nil {
		t.Fatal(err)
	}
	claims := verifiedRoleMappingClaims(t, map[string]any{"role_a": true, "role_z": true, "unmapped": false}, []string{"role_a", "role_z", "unmapped"})
	foreign := verifiedRoleMappingClaims(t, map[string]any{"foreign": true}, []string{"foreign"})
	for _, candidate := range [][]oauth.VerifiedOIDCClaim{
		nil, {}, {{}}, claims[:1], append(slices.Clone(claims), claims[0]), append(slices.Clone(claims), claims[2]),
		append(slices.Clone(claims), foreign[0]), make([]oauth.VerifiedOIDCClaim, 129),
	} {
		if got, err := mapping.desiredRoles(candidate); !errors.Is(err, sso.ErrForbidden) || got != nil {
			t.Fatal("invalid observations returned a grant mutation")
		}
	}
	if got, err := (providerLoginRoleMapping{}).desiredRoles(claims); !errors.Is(err, sso.ErrForbidden) || got != nil {
		t.Fatal("zero policy returned desired roles")
	}
}

// Use the same signed ES256/static-key/local-TLS exchange boundary as the
// callback transport tests: opaque claims are never manufactured by this package.
func verifiedRoleMappingClaims(t *testing.T, selected map[string]any, names []string) []oauth.VerifiedOIDCClaim {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	nonce := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	claims := map[string]any{"iss": "https://issuer.example", "sub": "linked-subject", "aud": "mapping-client", "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "nonce": nonce}
	for name, value := range selected {
		claims[name] = value
	}
	wire, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	message := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT"}`)) + "." + base64.RawURLEncoding.EncodeToString(wire)
	digest := sha256.Sum256([]byte(message))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	var signature [64]byte
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	token := message + "." + base64.RawURLEncoding.EncodeToString(signature[:])
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/token" {
			t.Error("claim fixture did not use the token exchange")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "local-fixture-access", "id_token": token, "token_type": "Bearer", "expires_in": 60})
	}))
	t.Cleanup(server.Close)
	request := providerLoginOIDCExchangeInput{profile: StaticOIDCLoginProfile{OrganizationID: "organization-a", ProviderID: "Provider_A", ProviderVersion: 1,
		ClientID: "mapping-client", ProtocolRedirectURI: "https://application.example/callback", Scopes: []string{"openid"}},
		metadata:             sso.OIDCStaticMetadataSpec{Issuer: "https://issuer.example", AuthorizationEndpoint: "https://issuer.example/authorize", TokenEndpoint: server.URL + "/token"},
		clientAuthentication: oauth.ClientSecretBasic, algorithms: []string{"ES256"}, claimNames: names,
		keys: &coreoidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}}, client: server.Client(), clock: providerLoginVaultClock{now}}
	provider, err := request.newOIDCProvider([]byte("local-fixture-secret"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(provider.Close)
	callback, err := identity.NewOAuthCallbackInput([]byte("local-fixture-code"), nonce, identity.OAuthCallbackLimits{MaxCodeBytes: 4096, StateBytes: 32})
	if err != nil {
		t.Fatal(err)
	}
	defer callback.Destroy()
	verifier, err := oauth.NewPKCEVerifier([]byte(strings.Repeat("v", 64)))
	if err != nil {
		t.Fatal(err)
	}
	defer verifier.Destroy()
	result, err := provider.Exchange(t.Context(), callback, verifier, nonce)
	defer result.Tokens.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	return result.VerifiedOIDCClaims()
}
