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
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/risk"
	organization "github.com/faustbrian/go-organization"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
)

func TestProviderLoginCallbackTransportUsesExactOriginalExchange(t *testing.T) {
	payload, input, now, _ := providerLoginPayloadFixture(t)
	input.ProviderVersion = 7
	input.ProviderID = "Enterprise_A7"
	encoded, err := payload.generate(t.Context(), input, 1, risk.PreparedAuthenticationAdmission{})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	prepared, err := payload.restore(t.Context(), input, 1, encoded)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := prepared.State.binding.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(binding)
	retained, err := payload.openBinding(t.Context(), input, binding)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(retained.Proof)
	verifier, err := prepared.State.verifier.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(verifier)

	const syntheticSecret = "local-fixture-client-credential"
	credential := sso.CredentialReferenceContext{TenantID: string(input.Command.TenantID), OrganizationID: input.OrganizationID,
		ProviderID: input.ProviderID, Protocol: "oidc", Purpose: "client-secret", Audience: "identity.sso.provider.credentials-rotate",
		Generation: input.CredentialGeneration, ProviderVersion: 5, EnvelopeKeyID: payload.KeyReference,
		IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-59 * time.Minute)}
	aad, err := credential.EncryptionContext()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := payload.Envelope.Encrypt(t.Context(), envelope.EncryptRequest{Plaintext: []byte(syntheticSecret), KeyReference: payload.KeyReference, Context: aad})
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := sealed.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(ciphertext)
	credentialContext, err := json.Marshal(credential)
	if err != nil {
		t.Fatal(err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public := retained.Metadata.Public
	claims, err := json.Marshal(map[string]any{"iss": input.Issuer, "sub": "linked-subject", "aud": input.ClientID,
		"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "nonce": public.Nonce, "department": "operations"})
	if err != nil {
		t.Fatal(err)
	}
	message := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT"}`)) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(message))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	var signature [64]byte
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	idToken := message + "." + base64.RawURLEncoding.EncodeToString(signature[:])
	var posts atomic.Int32
	var refusal atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		posts.Add(1)
		client, secret, authenticated := req.BasicAuth()
		if req.ParseForm() != nil || req.Method != http.MethodPost || req.URL.Path != "/token" || !authenticated || client != input.ClientID || secret != syntheticSecret ||
			req.PostForm.Get("grant_type") != "authorization_code" || req.PostForm.Get("code") != "original-callback-code" || req.PostForm.Get("redirect_uri") != input.RedirectURI {
			t.Error("request did not use the exact selected callback and installed credential")
		}
		challenge := sha256.Sum256([]byte(req.PostForm.Get("code_verifier")))
		if base64.RawURLEncoding.EncodeToString(challenge[:]) != public.Challenge {
			t.Error("exchanged verifier did not match original authorization challenge")
		}
		w.Header().Set("Content-Type", "application/json")
		if refusal.Load() {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "local-fixture-access", "id_token": idToken, "token_type": "Bearer", "expires_in": 3600})
	}))
	t.Cleanup(server.Close)

	makeInput := func(state string) identity.OAuthCallbackInput {
		t.Helper()
		callback, err := identity.NewOAuthCallbackInput([]byte("original-callback-code"), state, identity.OAuthCallbackLimits{MaxCodeBytes: 4096, StateBytes: 32})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(callback.Destroy)
		return callback
	}
	metadata := sso.OIDCStaticMetadataSpec{Issuer: input.Issuer, AuthorizationEndpoint: input.Issuer + "/authorize", TokenEndpoint: server.URL + "/token", JWKSURI: input.Issuer + "/keys"}
	request := providerLoginOIDCExchangeInput{
		original: retained.Metadata, observedAt: *now, deadline: now.Add(20 * time.Second),
		profile: StaticOIDCLoginProfile{ProviderID: sso.ProviderID(input.ProviderID), OrganizationID: organization.ID(input.OrganizationID), Domain: "enterprise.example",
			ClientID: input.ClientID, ProtocolRedirectURI: input.RedirectURI, ProviderVersion: input.ProviderVersion,
			CredentialGeneration: input.CredentialGeneration, MappingVersion: input.MappingVersion, Scopes: []string{"openid"}},
		metadata: metadata, pinnedMetadata: metadata, credential: ciphertext, credentialContext: credentialContext, credentialVersion: 6, verifier: verifier,
		callback: makeInput(public.State), clientAuthentication: oauth.ClientSecretBasic, algorithms: []string{"ES256"}, claimNames: []string{"department"},
		keys: &coreoidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}}, client: server.Client(), clock: providerLoginVaultClock{now.Add(time.Second)},
		beforePost: func(context.Context, time.Time) error { return nil },
	}
	otherState := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	for _, tc := range []struct {
		name   string
		change func(*providerLoginOIDCExchangeInput)
	}{
		{"changed-token-endpoint", func(p *providerLoginOIDCExchangeInput) { p.metadata.TokenEndpoint = server.URL + "/untrusted" }},
		{"foreign-state", func(p *providerLoginOIDCExchangeInput) { p.callback = makeInput(otherState) }},
		{"changed-generation", func(p *providerLoginOIDCExchangeInput) { p.profile.CredentialGeneration++ }},
		{"expired-authority", func(p *providerLoginOIDCExchangeInput) { p.deadline = now.Add(time.Second) }},
		{"unavailable-original-verifier", func(p *providerLoginOIDCExchangeInput) { p.verifier = nil }},
		{"expired-risk-at-send", func(p *providerLoginOIDCExchangeInput) {
			p.beforePost = func(context.Context, time.Time) error { return identity.ForbiddenError{} }
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := request
			tc.change(&candidate)
			result, err := payload.exchangeProviderLoginOIDC(t.Context(), candidate)
			defer result.Tokens.Destroy()
			if err == nil || posts.Load() != 0 {
				t.Fatal("invalid original custody reached the provider")
			}
		})
	}
	result, err := payload.exchangeProviderLoginOIDC(t.Context(), request)
	defer result.Tokens.Destroy()
	if err != nil || posts.Load() != 1 || result.Identity.Subject() != "linked-subject" {
		t.Fatalf("exact callback did not yield one verified provider exchange: %v", err)
	}
	verified := result.VerifiedOIDCClaims()
	if len(verified) != 1 || verified[0].Name() != "department" {
		t.Fatal("selected verified claims did not survive the exchange")
	}
	refusal.Store(true)
	denied, err := payload.exchangeProviderLoginOIDC(t.Context(), request)
	defer denied.Tokens.Destroy()
	var providerErr *oauth.Error
	if !errors.As(err, &providerErr) || providerErr.Kind() != oauth.Refused || posts.Load() != 2 || denied.Identity.Subject() != "" {
		t.Fatalf("provider refusal lost its definitive disposition: %v", err)
	}
}
