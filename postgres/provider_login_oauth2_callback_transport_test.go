package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	organization "github.com/faustbrian/go-organization"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
)

func TestProviderOAuth2CallbackTransportBindsOriginalCustodyBeforeTLSExchange(t *testing.T) {
	payload, input, now, _ := providerLoginPayloadFixture(t)
	input.Protocol = providerProtocolOAuth2
	input.Command.SchemaID = "identity.sso.signin-start.oauth2-v1"
	var public providerLoginPublicState
	var posts, identities atomic.Int32
	var refuse atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/token":
			posts.Add(1)
			if r.TLS == nil || r.Method != http.MethodPost || r.ParseForm() != nil || r.PostForm.Get("code") != "original-code" || r.PostForm.Get("client_secret") != "synthetic-credential" || r.PostForm.Get("client_id") != input.ClientID || r.PostForm.Get("redirect_uri") != input.RedirectURI {
				t.Error("token request lost original code, client or TLS binding")
			}
			challenge := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
			if base64.RawURLEncoding.EncodeToString(challenge[:]) != public.Challenge {
				t.Error("token request did not use original retained S256 verifier")
			}
			if refuse.Load() {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
				return
			}
			_, _ = w.Write([]byte(`{"access_token":"synthetic-access","token_type":"Bearer","expires_in":60}`))
		case "/identity":
			identities.Add(1)
			if r.TLS == nil || r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer synthetic-access" {
				t.Error("identity endpoint was not authenticated with returned bearer")
			}
			_, _ = w.Write([]byte(`{"stable_id":"linked-subject","email":null,"name":"","mail_verified":false}`))
		default:
			t.Error("unconfigured provider endpoint called")
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	input.Issuer = server.URL
	encoded, err := payload.generate(t.Context(), input, 1, risk.PreparedAuthenticationAdmission{})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	prepared, err := payload.restore(t.Context(), input, 1, encoded)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := prepared.State.binding.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(bound)
	retained, err := payload.openCommittedBinding(t.Context(), input.rowIdentity(), bound)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(retained.Proof)
	public = retained.Metadata.Public
	verifier, err := prepared.State.verifier.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(verifier)
	credential := sso.CredentialReferenceContext{TenantID: string(input.Command.TenantID), OrganizationID: input.OrganizationID, ProviderID: input.ProviderID,
		Protocol: providerProtocolOAuth2, Purpose: "client-secret", Audience: "identity.sso.provider.credentials-rotate", Generation: input.CredentialGeneration,
		ProviderVersion: input.ProviderVersion - 1, EnvelopeKeyID: payload.KeyReference, IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-59 * time.Minute)}
	aad, err := credential.EncryptionContext()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := payload.Envelope.Encrypt(t.Context(), envelope.EncryptRequest{Plaintext: []byte("synthetic-credential"), KeyReference: payload.KeyReference, Context: aad})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := sealed.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(wire)
	credentialContext, err := json.Marshal(credential)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(credentialContext)
	original := providerLoginStartInput{Command: providerLoginStoredCommand(input.Command), Protocol: input.Protocol, ProviderID: sso.ProviderID(input.ProviderID), ProviderVersion: input.ProviderVersion,
		Generation: input.CredentialGeneration, MappingVersion: input.MappingVersion, Issuer: input.Issuer, AuthorizationEndpoint: server.URL + "/authorize", ClientID: input.ClientID,
		ProtocolRedirectURI: input.RedirectURI, Proof: organization.DomainProofKey{OrganizationID: organization.ID(input.OrganizationID), Domain: "enterprise.example"},
		Remember: input.Remember, Issued: input.IssuedAt, Expires: input.ExpiresAt}
	selected := StaticOAuth2LoginProfile{ProviderID: original.ProviderID, OrganizationID: original.Proof.OrganizationID, Domain: original.Proof.Domain,
		ClientID: input.ClientID, ProtocolRedirectURI: input.RedirectURI, ProviderVersion: input.ProviderVersion, CredentialGeneration: input.CredentialGeneration, MappingVersion: input.MappingVersion, Scopes: []string{"identity", "email"}}
	namespace, err := SSOOAuth2AccountProviderNamespace(selected.OrganizationID, selected.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	config := oauth.OAuth2UserInfoConfig{ID: strings.ReplaceAll(namespace, ".", "-"), Version: input.ProviderVersion, Issuer: server.URL, AuthorizationEndpoint: server.URL + "/authorize", TokenEndpoint: server.URL + "/token",
		UserInfoEndpoint: server.URL + "/identity", RedirectURI: input.RedirectURI, ClientID: input.ClientID, ClientAuthentication: oauth.ClientSecretPost, ClientSecret: []byte("synthetic-credential"), Scopes: selected.Scopes,
		SubjectClaim: "stable_id", SubjectEncoding: oauth.OAuth2StringSubject, ProofLifetime: 10 * time.Second, Timeout: time.Second, HTTPClient: server.Client()}
	provider, err := oauth.NewSharedOAuth2UserInfoProvider(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	profile := provider.Profile()
	provider.Close()
	transport := StaticOAuth2CompletionProfile{OrganizationID: selected.OrganizationID, ProviderID: selected.ProviderID, Profile: oauth.OAuth2UserInfoProfile{Profile: profile, Details: oauth.OAuth2UserInfoDetails{UserInfoEndpoint: config.UserInfoEndpoint, SubjectClaim: config.SubjectClaim, SubjectEncoding: config.SubjectEncoding, ProofLifetime: config.ProofLifetime}}, HTTPClient: server.Client()}
	stored := providerOAuthConfiguration{AuthorizationEndpoint: original.AuthorizationEndpoint, TokenEndpoint: config.TokenEndpoint, IdentityEndpoint: config.UserInfoEndpoint,
		Proof:   sso.IdentityProofPolicySpec{Version: 1, Issuer: input.Issuer, SubjectKind: sso.OAuthSubjectString, EmailVerification: sso.OAuthEmailBooleanClaim},
		Mapping: sso.AttributeMappingSpec{Version: input.MappingVersion, SubjectClaim: "stable_id", EmailClaim: "email", DisplayNameClaim: "name", VerifiedEmailClaim: "mail_verified"}, Domains: []string{original.Proof.Domain}}
	callback := func(state string) oauth.QueryCallback {
		t.Helper()
		raw := url.Values{"code": {"original-code"}, "state": {state}, "iss": {input.Issuer}}
		value, err := oauth.ParseSharedOAuth2QueryCallback(t.Context(), raw.Encode(), input.RedirectURI, profile)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(value.Destroy)
		return value
	}
	request := providerLoginOAuth2ExchangeInput{original: original, binding: retained.Metadata, observedAt: *now, deadline: now.Add(20 * time.Second), selected: selected, transport: transport,
		material: providerOAuth2CallbackMaterial{configuration: stored, credential: wire, credentialContext: credentialContext, credentialVersion: input.ProviderVersion, verifier: verifier},
		callback: callback(public.State), clock: providerLoginVaultClock{now.Add(time.Second)}, beforePost: func(context.Context, time.Time) error { return nil }}
	for name, change := range map[string]func(*providerLoginOAuth2ExchangeInput){
		"token endpoint": func(p *providerLoginOAuth2ExchangeInput) { p.transport.Profile.Profile.TokenEndpoint += "/substituted" },
		"identity endpoint": func(p *providerLoginOAuth2ExchangeInput) {
			p.transport.Profile.Details.UserInfoEndpoint += "/substituted"
		},
		"issuer":        func(p *providerLoginOAuth2ExchangeInput) { p.transport.Profile.Profile.Issuer += "/substituted" },
		"subject claim": func(p *providerLoginOAuth2ExchangeInput) { p.transport.Profile.Details.SubjectClaim = "email" },
		"subject kind": func(p *providerLoginOAuth2ExchangeInput) {
			p.transport.Profile.Details.SubjectEncoding = oauth.OAuth2PositiveIntegerSubject
		},
		"provider version":      func(p *providerLoginOAuth2ExchangeInput) { p.transport.Profile.Profile.Version++ },
		"credential generation": func(p *providerLoginOAuth2ExchangeInput) { p.selected.CredentialGeneration++ },
		"mapping version":       func(p *providerLoginOAuth2ExchangeInput) { p.selected.MappingVersion++ },
		"original command substitution": func(p *providerLoginOAuth2ExchangeInput) {
			p.original.Command.CommandID = "AwMDAwMDAwMDAwMDAwMDAw"
		},
		"original remember substitution": func(p *providerLoginOAuth2ExchangeInput) {
			p.original.Remember.Choice = session.PersistentSession
		},
		"original expiry substitution": func(p *providerLoginOAuth2ExchangeInput) {
			p.original.Expires = p.original.Expires.Add(time.Second)
		},
		"scope order": func(p *providerLoginOAuth2ExchangeInput) {
			p.transport.Profile.Profile.Scopes = []string{"email", "identity"}
		},
		"foreign state": func(p *providerLoginOAuth2ExchangeInput) {
			p.callback = callback(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
		},
		"expired authority": func(p *providerLoginOAuth2ExchangeInput) { p.deadline = now.Add(time.Second) },
		"renewed authority": func(p *providerLoginOAuth2ExchangeInput) { p.deadline = now.Add(21 * time.Second) },
		"missing verifier":  func(p *providerLoginOAuth2ExchangeInput) { p.material.verifier = nil },
		"risk denial at send": func(p *providerLoginOAuth2ExchangeInput) {
			p.beforePost = func(context.Context, time.Time) error { return sso.ErrForbidden }
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := request
			change(&candidate)
			result, err := payload.exchangeProviderLoginOAuth2(t.Context(), candidate)
			defer result.Tokens.Destroy()
			if err == nil || posts.Load() != 0 || identities.Load() != 0 {
				t.Fatal("substituted or inadmissible original reached provider")
			}
		})
	}
	result, err := payload.exchangeProviderLoginOAuth2(t.Context(), request)
	defer result.Tokens.Destroy()
	if err != nil || posts.Load() != 1 || identities.Load() != 1 || result.Identity.Subject() != "linked-subject" || result.Identity.Issuer() != input.Issuer || result.Identity.EvidenceExpiresAt() != now.Add(11*time.Second) {
		t.Fatalf("original OAuth TLS exchange failed: %v", err)
	}
	if at, present := result.Identity.AuthenticationTime(); present || !at.IsZero() || !result.Identity.IDTokenIssuedAt().IsZero() || !result.Identity.IDTokenExpiresAt().IsZero() || len(result.VerifiedOIDCClaims()) != 0 {
		t.Fatal("OAuth exchange manufactured OIDC authentication evidence")
	}
	claims := result.ObservedOAuth2Claims()
	if len(claims) != 3 || claims[0].Kind() != oauth.OAuth2ClaimNull || claims[1].Kind() != oauth.OAuth2ClaimString || claims[2].Kind() != oauth.OAuth2ClaimBool {
		t.Fatal("endpoint attribute presence or scalar evidence was lost")
	}
	refuse.Store(true)
	denied, err := payload.exchangeProviderLoginOAuth2(t.Context(), request)
	defer denied.Tokens.Destroy()
	var providerErr *oauth.Error
	if !errors.As(err, &providerErr) || providerErr.Kind() != oauth.Refused || posts.Load() != 2 || identities.Load() != 1 || denied.Identity.Subject() != "" {
		t.Fatalf("definitive provider refusal was lost: %v", err)
	}
}
