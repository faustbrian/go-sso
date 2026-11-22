package postgres

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
)

type providerLoginVaultClock struct{ now time.Time }

func (c providerLoginVaultClock) Now() time.Time { return c.now }

// Actual validated TokenSet custody comes from the existing protocol owner;
// neither unsafe reflection nor a fabricated private token owner is used.
func providerLoginVaultFixture(t *testing.T, reported bool, omitRefresh ...bool) (*ProviderLoginService, providerLoginCallbackLookup, identity.Command, oauth.TokenSet) {
	t.Helper()
	payload, input, now, _ := providerLoginPayloadFixture(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
	claims, err := json.Marshal(map[string]any{"iss": input.Issuer, "sub": "stable-subject", "aud": input.ClientID, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "nonce": nonce})
	if err != nil {
		t.Fatal(err)
	}
	message := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT"}`)) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(message))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	idToken := message + "." + base64.RawURLEncoding.EncodeToString(signature)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := map[string]any{"access_token": "synthetic-enterprise-access", "refresh_token": "synthetic-enterprise-refresh", "id_token": idToken, "token_type": "Bearer", "expires_in": 3600}
		if len(omitRefresh) > 0 && omitRefresh[0] {
			delete(response, "refresh_token")
		}
		if reported {
			response["scope"] = "openid"
		}
		if json.NewEncoder(w).Encode(response) != nil {
			t.Error("fixture response failed")
		}
	}))
	t.Cleanup(server.Close)
	provider, err := oauth.NewOIDCProvider(oauth.OIDCConfig{ID: input.ProviderID, Version: input.ProviderVersion, Issuer: input.Issuer, AuthorizationEndpoint: input.Issuer + "/authorize", TokenEndpoint: server.URL + "/token", RedirectURI: input.RedirectURI, ClientID: input.ClientID, ClientAuthentication: oauth.PublicClient, Scopes: []string{"openid", "profile"}, Algorithms: []string{"ES256"}, KeySet: &coreoidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}}, HTTPClient: server.Client(), Clock: providerLoginVaultClock{now.Add(time.Second + 123456789)}, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(provider.Close)
	callbackInput, err := identity.NewOAuthCallbackInput([]byte("synthetic-enterprise-code"), nonce, identity.OAuthCallbackLimits{MaxCodeBytes: 4096, StateBytes: 32})
	if err != nil {
		t.Fatal(err)
	}
	defer callbackInput.Destroy()
	pkce, err := oauth.NewPKCEVerifier(bytes.Repeat([]byte{'v'}, 43))
	if err != nil {
		t.Fatal(err)
	}
	defer pkce.Destroy()
	exchanged, err := provider.Exchange(context.Background(), callbackInput, pkce, nonce)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(exchanged.Tokens.Destroy)
	callback, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	found := providerLoginCallbackLookup{Row: input.rowIdentity(), ObservedAt: *now, BindingWireDigest: [32]byte{10}, Binding: providerLoginStoredBinding{Metadata: providerLoginBindingMetadata{Schema: 1, Input: input, CallbackCommand: callback, StateKey: 1, PKCEKey: 1, StateDigest: [32]byte{8}, PKCECommitment: [32]byte{9}}}}
	account := kernel.ProviderAccountAdmission{Account: identity.Account{ID: "existing-account", TenantID: input.Command.TenantID, UserID: "selected-user", Provider: "sso-organization-provider", Issuer: input.Issuer, Subject: "stable-subject", Version: 5}, SocialLinkVersion: 7, Credential: kernel.CredentialAdmission{Credential: identity.CredentialRef{ID: "provider-reference", TenantID: input.Command.TenantID, UserID: "selected-user", Kind: identity.CredentialProvider, Owner: "sso", Version: 11}, UserAuthorityVersion: 13, IdentifierAuthorityVersion: 17, CredentialAuthorityVersion: 19}}
	fields, err := kernel.SSOOIDCSigninAccountFields(account)
	if err != nil {
		t.Fatal(err)
	}
	binding := input.Command
	binding.CommandID, binding.CorrelationID = callback, string(callback)
	operation := providerOIDCCallbackOperation()
	binding.OperationID, binding.SchemaID, binding.SchemaVersion = operation.OperationID, operation.SchemaID, operation.SchemaVersion
	command, err := identity.NewFeaturePreAuthCommand(identity.FeatureCommandSpec{Operation: operation, Binding: binding, Fields: fields}, auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32))))
	if err != nil {
		t.Fatal(err)
	}
	profile := StaticOIDCLoginProfile{ProviderID: sso.ProviderID(input.ProviderID), OrganizationID: organization.ID(input.OrganizationID), Domain: "enterprise.example", ClientID: input.ClientID, ProtocolRedirectURI: input.RedirectURI, ProviderVersion: input.ProviderVersion, CredentialGeneration: input.CredentialGeneration, MappingVersion: input.MappingVersion, Scopes: []string{"openid", "profile"}}
	service := &ProviderLoginService{config: ProviderLoginConfig{TenantID: input.Command.TenantID}, payload: payload, profiles: map[providerLoginProfileKey]StaticOIDCLoginProfile{{organization: profile.OrganizationID, provider: profile.ProviderID}: profile}}
	return service, found, command, exchanged.Tokens
}

func TestProviderLoginTokenVaultEncryptsActualTokensAndDestroysAliases(t *testing.T) {
	for _, reported := range []bool{false, true} {
		t.Run(fmt.Sprint(reported), func(t *testing.T) {
			service, found, command, tokens := providerLoginVaultFixture(t, reported)
			alias := tokens
			requested, granted := tokens.RequestedScopes(), tokens.GrantedScopes()
			received, expires := tokens.ReceivedAt(), tokens.ExpiresAt()
			var hashes [2][32]byte
			var idHash [32]byte
			if err := tokens.Use(context.Background(), func(_ context.Context, b oauth.TokenBytes) error {
				hashes = [2][32]byte{sha256.Sum256(b.AccessToken), sha256.Sum256(b.RefreshToken)}
				idHash = sha256.Sum256(b.IDToken)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			prepared, err := service.prepareProviderLoginTokens(context.Background(), found, command, 3, tokens)
			if err != nil {
				t.Fatal(err)
			}
			if alias.Use(context.Background(), func(context.Context, oauth.TokenBytes) error { return nil }) == nil {
				t.Fatal("shared token alias survived custody transfer")
			}
			if !reflect.DeepEqual(prepared.RequestedScopes, requested) || !reflect.DeepEqual(prepared.GrantedScopes, granted) || prepared.ScopeReported != reported || prepared.ReceivedAt != received || prepared.AccessExpiresAt != expires || prepared.CallbackGeneration != 3 || prepared.Version != 1 || prepared.BindingWireDigest != found.BindingWireDigest {
				t.Fatal("actual token metadata changed")
			}
			if _, err := envelope.ParseEnvelope(prepared.Ciphertext); err != nil {
				t.Fatal("vault did not retain the actual secret-envelope wire format", err)
			}
			if err := service.validateProviderLoginTokens(context.Background(), prepared); err != nil {
				t.Fatal(err)
			}
			aad, err := providerLoginTokenAAD(prepared)
			if err != nil {
				t.Fatal(err)
			}
			plain, err := service.payload.open(context.Background(), aad, prepared.Ciphertext, 65536, 32790)
			defer clear(plain)
			if err != nil || !bytes.HasPrefix(plain, []byte(providerLoginTokenHeader)) {
				t.Fatal("actual secret-envelope did not restore bounded frame", err)
			}
			remaining := plain[len(providerLoginTokenHeader):]
			for _, expected := range hashes {
				if len(remaining) < 4 {
					t.Fatal("truncated token length")
				}
				n := int(binary.BigEndian.Uint32(remaining))
				remaining = remaining[4:]
				if n > len(remaining) || sha256.Sum256(remaining[:n]) != expected || sha256.Sum256(remaining[:n]) == idHash {
					t.Fatal("vault changed tokens or retained ID token")
				}
				remaining = remaining[n:]
			}
			if len(remaining) != 0 {
				t.Fatal("vault retained raw ID token or unowned material")
			}
			wire, err := json.Marshal(prepared)
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{"synthetic-enterprise-access", "synthetic-enterprise-refresh", "stable-subject"} {
				if strings.Contains(fmt.Sprintf("%#v", prepared), secret) {
					t.Fatal("correlated token custody entered diagnostics")
				}
			}
			if bytes.Contains(wire, []byte("synthetic-enterprise-access")) || bytes.Contains(wire, []byte("synthetic-enterprise-refresh")) {
				t.Fatal("raw tokens entered metadata")
			}
			var restored providerLoginPreparedTokens
			if json.Unmarshal(wire, &restored) != nil || service.validateProviderLoginTokens(context.Background(), restored) != nil {
				t.Fatal("encrypted native preparation failed exact restoration")
			}
		})
	}
}

func TestProviderLoginTokenVaultRejectsWrongContext(t *testing.T) {
	service, found, command, tokens := providerLoginVaultFixture(t, true)
	prepared, err := service.prepareProviderLoginTokens(context.Background(), found, command, 3, tokens)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*providerLoginPreparedTokens)
	}{
		{"tenant", func(p *providerLoginPreparedTokens) { p.Input.Command.TenantID = "foreign" }},
		{"organization", func(p *providerLoginPreparedTokens) { p.Input.OrganizationID = "foreign" }},
		{"provider", func(p *providerLoginPreparedTokens) { p.Input.ProviderID = "foreign" }},
		{"subject", func(p *providerLoginPreparedTokens) { p.Account.Subject = "other-subject" }},
		{"account", func(p *providerLoginPreparedTokens) { p.Account.ID = "other-account" }},
		{"callback", func(p *providerLoginPreparedTokens) { p.Callback.CommandID = p.Input.Command.CommandID }},
		{"generation", func(p *providerLoginPreparedTokens) { p.CallbackGeneration++ }},
		{"binding wire", func(p *providerLoginPreparedTokens) { p.BindingWireDigest[0] ^= 1 }},
		{"zero binding wire", func(p *providerLoginPreparedTokens) { p.BindingWireDigest = [32]byte{} }},
		{"credential generation", func(p *providerLoginPreparedTokens) { p.Input.CredentialGeneration++ }},
		{"mapping", func(p *providerLoginPreparedTokens) { p.Input.MappingVersion++ }},
		{"version", func(p *providerLoginPreparedTokens) { p.Version++ }},
		{"scope", func(p *providerLoginPreparedTokens) { p.GrantedScopes = []string{"openid", "profile"} }},
		{"received", func(p *providerLoginPreparedTokens) { p.ReceivedAt = p.ReceivedAt.Add(time.Nanosecond) }},
		{"expiry", func(p *providerLoginPreparedTokens) { p.AccessExpiresAt = p.AccessExpiresAt.Add(time.Nanosecond) }},
		{"ciphertext", func(p *providerLoginPreparedTokens) { p.Ciphertext = bytes.Repeat([]byte{1}, len(p.Ciphertext)) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := prepared
			tc.change(&changed)
			if service.validateProviderLoginTokens(context.Background(), changed) == nil {
				t.Fatal("wrong-context custody authenticated")
			}
		})
	}
}

func TestProviderLoginTokenVaultDestroysAliasesOnRejection(t *testing.T) {
	for _, mode := range []string{"nil context", "cancelled", "wrong original", "terminal", "zero generation", "zero service", "scope drift", "zero binding wire"} {
		t.Run(mode, func(t *testing.T) {
			service, found, command, tokens := providerLoginVaultFixture(t, false)
			alias := tokens
			ctx := context.Background()
			generation := uint64(3)
			switch mode {
			case "nil context":
				ctx = nil
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			case "wrong original":
				found.Row.StartCommandID = found.Binding.Metadata.CallbackCommand
			case "terminal":
				found.CompletedAt = &found.ObservedAt
			case "zero generation":
				generation = 0
			case "zero binding wire":
				found.BindingWireDigest = [32]byte{}
			case "zero service":
				service = nil
			case "scope drift":
				for key, profile := range service.profiles {
					profile.Scopes = []string{"openid"}
					service.profiles[key] = profile
				}
			}
			if _, err := service.prepareProviderLoginTokens(ctx, found, command, generation, tokens); err == nil {
				t.Fatal("invalid preparation admitted")
			}
			if alias.Use(context.Background(), func(context.Context, oauth.TokenBytes) error { return nil }) == nil {
				t.Fatal("rejected token aliases survived")
			}
		})
	}
}

func TestProviderLoginTokenVaultRejectsUnownedWork(t *testing.T) {
	service, found, command, tokens := providerLoginVaultFixture(t, false)
	prepared, err := service.prepareProviderLoginTokens(context.Background(), found, command, 3, tokens)
	if err != nil {
		t.Fatal(err)
	}
	if service.persistProviderLoginTokens(context.Background(), kernel.Work{}, nil, command, prepared, [32]byte{11}) == nil {
		t.Fatal("token custody accepted an unowned transaction handle")
	}
}

func TestProviderLoginTokenVaultPreservesAbsentRefreshWithoutInventingOne(t *testing.T) {
	service, found, command, tokens := providerLoginVaultFixture(t, false, true)
	prepared, err := service.prepareProviderLoginTokens(context.Background(), found, command, 3, tokens)
	if err != nil || service.validateProviderLoginTokens(context.Background(), prepared) != nil {
		t.Fatal("valid access-only custody was rejected", err)
	}
	aad, err := providerLoginTokenAAD(prepared)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := service.payload.open(context.Background(), aad, prepared.Ciphertext, 65536, providerLoginTokenMaximumFrame)
	defer clear(plain)
	if err != nil {
		t.Fatal(err)
	}
	remaining := plain[len(providerLoginTokenHeader):]
	n := int(binary.BigEndian.Uint32(remaining))
	remaining = remaining[4+n:]
	if len(remaining) != 4 || binary.BigEndian.Uint32(remaining) != 0 {
		t.Fatal("vault invented absent refresh material")
	}
}

func TestProviderLoginTokenVaultRejectsAuthenticatedMalformedFrames(t *testing.T) {
	service, found, command, tokens := providerLoginVaultFixture(t, false)
	prepared, err := service.prepareProviderLoginTokens(context.Background(), found, command, 3, tokens)
	if err != nil {
		t.Fatal(err)
	}
	aad, err := providerLoginTokenAAD(prepared)
	if err != nil {
		t.Fatal(err)
	}
	frame := func(access, refresh []byte) []byte {
		out := append([]byte(nil), providerLoginTokenHeader...)
		for _, token := range [][]byte{access, refresh} {
			out = binary.BigEndian.AppendUint32(out, uint32(len(token)))
			out = append(out, token...)
		}
		return out
	}
	for name, plain := range map[string][]byte{
		"wrong purpose frame": []byte("other-owner-access-frame"),
		"empty access":        frame(nil, []byte("synthetic-refresh")),
		"oversized access":    frame(bytes.Repeat([]byte{'x'}, providerLoginTokenMaximumBytes+1), nil),
		"oversized refresh":   frame([]byte("synthetic-access"), bytes.Repeat([]byte{'x'}, providerLoginTokenMaximumBytes+1)),
		"truncated refresh":   append(frame([]byte("synthetic-access"), nil), byte(1)),
		"trailing ID token":   append(frame([]byte("synthetic-access"), []byte("synthetic-refresh")), []byte("synthetic-id-token")...),
	} {
		t.Run(name, func(t *testing.T) {
			defer clear(plain)
			changed := prepared
			changed.Ciphertext, err = service.payload.seal(context.Background(), aad, plain, 65536)
			if err != nil {
				t.Fatal(err)
			}
			if service.validateProviderLoginTokens(context.Background(), changed) == nil {
				t.Fatal("authenticated malformed token frame admitted")
			}
		})
	}
}

func TestProviderLoginTokenVaultConservesOriginalOutputGenerationOnTakeover(t *testing.T) {
	for _, tc := range []struct {
		name                        string
		prepared, original, current uint64
		want                        bool
	}{
		{"original invocation", 3, 3, 3, true},
		{"retained output takeover", 3, 3, 4, true},
		{"zero prepared", 0, 3, 4, false},
		{"zero original", 3, 0, 4, false},
		{"zero current", 3, 3, 0, false},
		{"substituted current provenance", 4, 3, 4, false},
		{"future original output", 4, 4, 3, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := providerLoginTokenGenerationMatches(tc.prepared, tc.original, tc.current); got != tc.want {
				t.Fatal("original encrypted-output provenance was renewed or discarded", got)
			}
		})
	}
}

func TestProviderLoginTokenVaultRequiresExactAuthenticatedOutputDigest(t *testing.T) {
	original := sha256.Sum256([]byte("synthetic-original-encrypted-output"))
	foreign := sha256.Sum256([]byte("synthetic-foreign-encrypted-output"))
	for _, tc := range []struct {
		name                        string
		prepared, retained, current uint64
		expected, actual            [32]byte
		want                        bool
	}{
		{"original output", 3, 3, 3, original, original, true},
		{"retained takeover", 3, 3, 4, original, original, true},
		{"substituted output", 3, 3, 4, original, foreign, false},
		{"zero restore digest", 3, 3, 4, [32]byte{}, original, false},
		{"zero retained digest", 3, 3, 4, original, [32]byte{}, false},
		{"both digests absent", 3, 3, 4, [32]byte{}, [32]byte{}, false},
		{"renewed provenance", 4, 3, 4, original, original, false},
		{"future output", 4, 4, 3, original, original, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := providerLoginTokenOutputMatches(tc.prepared, tc.retained, tc.current, tc.expected, tc.actual); got != tc.want {
				t.Fatal("callback accepted substituted or renewed encrypted output", got)
			}
		})
	}
}

func TestProviderLoginTokenVaultMetadataValidationNeedsNoEnvelopeProvider(t *testing.T) {
	service, found, command, tokens := providerLoginVaultFixture(t, false)
	prepared, err := service.prepareProviderLoginTokens(context.Background(), found, command, 3, tokens)
	if err != nil {
		t.Fatal(err)
	}
	service.payload.Envelope = nil
	if err := service.validateProviderLoginTokenMetadata(prepared); err != nil {
		t.Fatal("local typed metadata validation required an envelope provider", err)
	}
}
