package oidc_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/session"
	"github.com/faustbrian/go-sso"
	"github.com/faustbrian/go-sso/oidc"
)

const (
	signinState     = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	signinNonce     = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"
	signinVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	signinChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

var signinNow = time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)

type signinClock struct{ now time.Time }

func (c signinClock) Now() time.Time { return c.now }

type signinBody struct {
	io.Reader
	closes int
}

func (b *signinBody) Close() error { b.closes++; return nil }

type signinFixture struct {
	config                   oidc.Config
	requests, borrows, hooks atomic.Int32
	idToken                  string
	tokens                   oauth.TokenSet
	evidence                 oidc.CallbackEvidence
	borrowedBytes            [][]byte
}

func signinClaims() map[string]any {
	return map[string]any{
		"iss": "https://issuer.example", "sub": "signed-subject-9", "aud": "installed-client",
		"iat": signinNow.Add(-30 * time.Second).Unix(), "exp": signinNow.Add(time.Minute).Unix(),
		"auth_time": signinNow.Add(-5 * time.Minute).Unix(), "nonce": signinNonce,
		"email": "person@example.com", "email_verified": true, "name": nil,
	}
}

func signSigninToken(t *testing.T, key *ecdsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT"}`))
	message := header + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(message))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return message + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func newSigninFixture(t *testing.T, claims map[string]any) *signinFixture {
	t.Helper()
	f := new(signinFixture)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.idToken = signSigninToken(t, key, claims)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		f.requests.Add(1)
		if req.Method != http.MethodPost || req.URL.RequestURI() != "/token" {
			t.Error("exchange reached an endpoint other than the configured token endpoint")
			http.NotFound(w, req)
			return
		}
		if err := req.ParseForm(); err != nil {
			t.Error("exchange did not supply a valid token form")
			return
		}
		if len(req.PostForm) != 6 || req.PostForm.Get("grant_type") != "authorization_code" || req.PostForm.Get("code") != " original +/=: code " || req.PostForm.Get("code_verifier") != signinVerifier || req.PostForm.Get("client_secret") != "installed-client-secret" || req.PostForm.Get("client_id") != "installed-client" || req.PostForm.Get("redirect_uri") != "https://identity.example.com/sso/callback" {
			t.Error("exchange did not preserve the original code, PKCE and installed client")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "borrowed-access", "refresh_token": "borrowed-refresh", "id_token": f.idToken,
			"token_type": "Bearer", "expires_in": 3600,
		})
	}))
	t.Cleanup(server.Close)
	keys := &coreoidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}}
	provider, err := oauth.NewOIDCProvider(oauth.OIDCConfig{
		ID: "provider-transport", Version: 9, Issuer: "https://issuer.example", ClientID: "installed-client",
		AuthorizationEndpoint: "https://issuer.example/authorize", TokenEndpoint: server.URL + "/token",
		RedirectURI: "https://identity.example.com/sso/callback", ClientAuthentication: oauth.ClientSecretPost,
		ClientSecret: []byte("installed-client-secret"), Scopes: []string{"openid", "email", "profile"},
		Algorithms: []string{"ES256"}, KeySet: keys, HTTPClient: server.Client(), Clock: signinClock{signinNow},
	})
	if err != nil {
		t.Fatal(err)
	}
	profile := provider.Profile()
	provider.Close()
	remember, err := session.NewRememberPolicy(session.RememberPolicySpec{
		Choice: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute,
		RefreshAfter: time.Minute, FreshFor: 15 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := sso.NewLoginTransaction(sso.LoginTransaction{
		TenantID: "tenant", ID: "AQEBAQEBAQEBAQEBAQEBAQ", ProviderID: "provider", OrganizationID: "org", Protocol: "oidc",
		Callback:  url.URL{Scheme: "https", Host: "identity.example.com", Path: "/sso/callback"},
		ExpiresAt: signinNow.Add(time.Minute), ProviderVersion: 9, MappingVersion: 4,
		RememberPolicy: remember, CommandID: "AgICAgICAgICAgICAgICAg",
	}, 3)
	if err != nil {
		t.Fatal(err)
	}
	mapping, err := sso.NewAttributeMapping(sso.AttributeMappingSpec{
		Version: 4, SubjectClaim: "sub", EmailClaim: "email", VerifiedEmailClaim: "email_verified", DisplayNameClaim: "name",
	})
	if err != nil {
		t.Fatal(err)
	}
	f.config = oidc.Config{
		Transaction: tx, CredentialGeneration: 3, Profile: profile, Mapping: mapping,
		Authorization:       oauth.AuthorizationParameters{State: signinState, Nonce: signinNonce, PKCEChallenge: signinChallenge},
		CapabilityExpiresAt: signinNow.Add(40 * time.Second), Clock: signinClock{signinNow}, HTTPClient: server.Client(), KeySet: keys,
		Callback: &oidc.CallbackCustody{
			ObservedAt: signinNow.Add(-time.Second), ValidUntil: signinNow.Add(12 * time.Second),
			UseSecrets: func(_ context.Context, use func([]byte, []byte) error) error {
				f.borrows.Add(1)
				return use([]byte("installed-client-secret"), []byte(signinVerifier))
			},
			AcceptTokens: func(ctx context.Context, evidence oidc.CallbackEvidence, tokens oauth.TokenSet) (sso.TokenVersion, error) {
				f.hooks.Add(1)
				f.tokens, f.evidence = tokens, evidence
				return sso.TokenVersion{}, tokens.Use(ctx, func(_ context.Context, material oauth.TokenBytes) error {
					if string(material.AccessToken) != "borrowed-access" || string(material.RefreshToken) != "borrowed-refresh" || string(material.IDToken) != f.idToken {
						t.Error("handoff lost the original exchanged token material")
					}
					f.borrowedBytes = [][]byte{material.AccessToken, material.RefreshToken, material.IDToken}
					return nil
				})
			},
		},
	}
	return f
}

func (f *signinFixture) body(state, issuer string) *signinBody {
	values := url.Values{"state": {state}, "iss": {issuer}, "code": {" original +/=: code "}}
	return &signinBody{Reader: strings.NewReader(values.Encode())}
}

func TestSigninAdapterUsesOriginalAuthorityAndSignedIdentity(t *testing.T) {
	for _, tc := range []struct {
		name             string
		omitNameAndAuth  bool
		verifiedEmail    bool
		idTokenLifetime  time.Duration
		expectedLifetime time.Duration
	}{
		{"explicit null and authentication time", false, true, time.Minute, 12 * time.Second},
		{"absent name and authentication time with false verification", true, false, 7 * time.Second, 7 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := signinClaims()
			claims["email_verified"] = tc.verifiedEmail
			claims["exp"] = signinNow.Add(tc.idTokenLifetime).Unix()
			if tc.omitNameAndAuth {
				delete(claims, "name")
				delete(claims, "auth_time")
			}
			f := newSigninFixture(t, claims)
			svc, err := oidc.New(f.config)
			if err != nil {
				t.Fatal(err)
			}
			var adapter sso.ProtocolAdapter = svc
			tx := f.config.Transaction
			start, err := adapter.Start(t.Context(), sso.ProtocolStartCommand{Transaction: tx, Provider: sso.Provider{
				ID: "provider", OrganizationID: "org", Protocol: "oidc", Version: 9, MappingVersion: 4, Enabled: true,
			}})
			if err != nil {
				t.Fatal(err)
			}
			query := start.Redirect.Query()
			if start.Redirect.Scheme != "https" || start.Redirect.Host != "issuer.example" || start.Redirect.Path != "/authorize" || len(query) != 9 || query.Get("state") != signinState || query.Get("nonce") != signinNonce || query.Get("code_challenge") != signinChallenge || query.Get("code_challenge_method") != "S256" || query.Get("response_type") != "code" || query.Get("response_mode") != "query" || query.Get("client_id") != "installed-client" || query.Get("redirect_uri") != "https://identity.example.com/sso/callback" || query.Get("scope") != "openid email profile" || !start.ExpiresAt.Equal(signinNow.Add(40*time.Second)) || f.borrows.Load() != 0 || f.requests.Load() != 0 || f.hooks.Load() != 0 {
				t.Fatal("start changed original authority or performed protected work")
			}
			body := f.body(signinState, "https://issuer.example")
			assertion, err := adapter.Complete(t.Context(), sso.ProtocolCallback{Transaction: tx, Payload: body, MaximumBytes: 4096})
			if err != nil {
				t.Fatal(err)
			}
			if assertion.ProviderSubject != "signed-subject-9" || assertion.ProviderID != "provider" || assertion.OrganizationID != "org" || assertion.ProviderProfileVersion != 9 || assertion.MappingVersion != 4 || body.closes != 1 || f.requests.Load() != 1 || f.borrows.Load() != 1 || f.hooks.Load() != 1 {
				t.Fatal("completion lost the signed subject, SSO scope or one-exchange boundary")
			}
			if f.evidence.Transaction != tx || !reflect.DeepEqual(f.evidence.Assertion, assertion) || !f.evidence.ExpiresAt.Equal(signinNow.Add(tc.expectedLifetime)) || !f.evidence.IDTokenIssuedAt.Equal(signinNow.Add(-30*time.Second)) || !f.evidence.IDTokenExpiresAt.Equal(signinNow.Add(tc.idTokenLifetime)) || f.evidence.HasAuthenticationTime == tc.omitNameAndAuth {
				t.Fatal("handoff changed original expiry or signed identity evidence")
			}
			wantAuth := signinNow.Add(-5 * time.Minute)
			if tc.omitNameAndAuth {
				wantAuth = time.Time{}
			}
			if !f.evidence.AuthenticatedAt.Equal(wantAuth) {
				t.Fatal("authentication time was replaced by observation or issuance time")
			}
			attributes := make(map[string]sso.VerifiedAttributeSpec)
			for _, attribute := range assertion.Attributes {
				spec, err := attribute.Spec()
				if err != nil {
					t.Fatal(err)
				}
				if spec.Provenance != (sso.AttributeProvenance{ProviderID: "provider", ProviderProfileVersion: 9, Issuer: "https://issuer.example", Source: sso.AttributeSourceOIDCIDToken}) {
					t.Fatal("selected attribute lost its signed ID-token provenance")
				}
				attributes[spec.Name] = spec
			}
			mail, verification, name := attributes["email"], attributes["email_verified"], attributes["name"]
			wantName := sso.AttributeNull
			if tc.omitNameAndAuth {
				wantName = sso.AttributeAbsent
			}
			if len(attributes) != 3 || mail.Presence != sso.AttributeValue || mail.StringValue == nil || *mail.StringValue != "person@example.com" || mail.Verified != tc.verifiedEmail || mail.Authoritative != tc.verifiedEmail || verification.Presence != sso.AttributeValue || verification.BooleanValue == nil || *verification.BooleanValue != tc.verifiedEmail || verification.StringValue != nil || name.Presence != wantName || name.StringValue != nil || name.BooleanValue != nil {
				t.Fatal("signed claims lost null, absence, boolean or email-verification semantics")
			}
			for _, material := range f.borrowedBytes {
				for _, b := range material {
					if b != 0 {
						t.Fatal("token handoff retained borrowed token bytes")
					}
				}
			}
			if err := f.tokens.Use(t.Context(), func(context.Context, oauth.TokenBytes) error {
				t.Error("completed handoff retained usable tokens")
				return nil
			}); err == nil {
				t.Fatal("completed token custody was reusable")
			}
			repeat := f.body(signinState, "https://issuer.example")
			if _, err := adapter.Complete(t.Context(), sso.ProtocolCallback{Transaction: tx, Payload: repeat, MaximumBytes: 4096}); !errors.Is(err, sso.ErrConflict) || repeat.closes != 1 || f.requests.Load() != 1 || f.borrows.Load() != 1 || f.hooks.Load() != 1 {
				t.Fatal("a second callback resubmitted the original authorization code or leaked its body")
			}
		})
	}
}

func TestSigninAdapterRejectsForeignCallbackBeforeBorrowingSecrets(t *testing.T) {
	for _, tc := range []struct{ name, state, issuer string }{
		{"wrong issuer", signinState, "https://foreign.example"},
		{"wrong state", signinNonce, "https://issuer.example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSigninFixture(t, signinClaims())
			svc, err := oidc.New(f.config)
			if err != nil {
				t.Fatal(err)
			}
			body := f.body(tc.state, tc.issuer)
			assertion, err := svc.Complete(t.Context(), sso.ProtocolCallback{Transaction: f.config.Transaction, Payload: body, MaximumBytes: 4096})
			if err == nil || assertion.ProviderSubject != "" || body.closes != 1 || f.borrows.Load() != 0 || f.requests.Load() != 0 || f.hooks.Load() != 0 {
				t.Fatal("foreign callback opened credentials or produced identity evidence")
			}
		})
	}
}

func TestSigninAdapterRejectsUntrustedSignedIdentityWithoutHandoffOrRetry(t *testing.T) {
	for _, field := range []string{"nonce", "aud", "signature"} {
		t.Run(field, func(t *testing.T) {
			claims := signinClaims()
			if field == "nonce" || field == "aud" {
				claims[field] = "foreign-value"
			}
			f := newSigninFixture(t, claims)
			if field == "signature" {
				parts := strings.Split(f.idToken, ".")
				signature, err := base64.RawURLEncoding.DecodeString(parts[2])
				if err != nil {
					t.Fatal(err)
				}
				signature[0] ^= 0x80
				f.idToken = parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(signature)
			}
			svc, err := oidc.New(f.config)
			if err != nil {
				t.Fatal(err)
			}
			body := f.body(signinState, "https://issuer.example")
			assertion, err := svc.Complete(t.Context(), sso.ProtocolCallback{Transaction: f.config.Transaction, Payload: body, MaximumBytes: 4096})
			if err == nil || assertion.ProviderSubject != "" || body.closes != 1 || f.borrows.Load() != 1 || f.requests.Load() != 1 || f.hooks.Load() != 0 {
				t.Fatal("untrusted ID token produced evidence or reached token handoff")
			}
			repeat := f.body(signinState, "https://issuer.example")
			if _, err := svc.Complete(t.Context(), sso.ProtocolCallback{Transaction: f.config.Transaction, Payload: repeat, MaximumBytes: 4096}); !errors.Is(err, sso.ErrConflict) || repeat.closes != 1 || f.requests.Load() != 1 || f.borrows.Load() != 1 || f.hooks.Load() != 0 {
				t.Fatal("rejected identity permitted another code exchange or leaked its payload")
			}
		})
	}
}
