//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/oauth"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

const nativeOAuth2JourneyIssuer = "https://provider.example.com/Enterprise"
const nativeOAuth2JourneySubject = "native-oauth2-stable-linked-subject"
const nativeOAuth2JourneyCode = "native-oauth2-original-code"
const nativeOAuth2RotatedRefresh = "fixture-enterprise-rotated-refresh"
const nativeOAuth2TwiceRotatedRefresh = "fixture-enterprise-twice-rotated-refresh"
const nativeOAuth2RefreshRaceMode = "restorable-vault-refresh-competing-revoke"
const nativeOAuth2NarrowRotatedMode = "restorable-vault-refresh-narrow-rotated"
const nativeOAuth2NarrowRetainedMode = "restorable-vault-refresh-narrow-retained"

type nativeOAuth2JourneyPolicy struct{}

func (nativeOAuth2JourneyPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	if c.PolicyRevision == 1 && c.Request.Tenant == authorization.TenantID(discoveryFixtureTenant) &&
		c.Request.Subject.Kind == authorization.SubjectServiceAccount && c.Request.Subject.ID == "native-sso-login" &&
		c.Request.Action == "identity.sso.oauth-callback" {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
	}
	if c.PolicyRevision == 1 && c.Request.Tenant == authorization.TenantID(discoveryFixtureTenant) &&
		c.Request.Subject.Kind == authorization.SubjectUser && c.Request.Subject.ID == "owner" &&
		(c.Request.Action == "identity.sso.provider-token.revoke" || c.Request.Action == "identity.sso.provider-token.refresh") &&
		(c.Request.Resource.Type == "identity.request-admission" && c.Request.Resource.ID == authorization.ResourceID(c.Request.Action) ||
			c.Request.Resource.Type == "identity.user" && c.Request.Resource.ID == "owner") {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
	}
	return (providerLoginPolicy{}).Decide(ctx, c)
}

type nativeOAuth2JourneyFixture struct {
	start            providerOAuthLoginStartFixture
	completion       *ssopg.ProviderOAuth2LoginCompletionService
	completionConfig ssopg.ProviderLoginCompletionConfig
	request          ssopg.ProviderOAuth2LoginCallbackRequest
	startedID        string
	posts            *atomic.Int32
	identities       *atomic.Int32
	revokes          *atomic.Int32
	refreshes        *atomic.Int32
	refreshEntered   chan struct{}
	refreshRelease   chan struct{}
	transport        ssopg.StaticOAuth2CompletionProfile
	lookup           session.DigestKey
	csrf             session.CSRFKey
}

func newNativeOAuth2JourneyFixture(t *testing.T, mode string, traces ...*providerTrace) nativeOAuth2JourneyFixture {
	t.Helper()
	return newNativeOAuth2JourneyFixtureWithAdapter(t, mode, nil, traces...)
}

func newNativeOAuth2JourneyFixtureWithAdapter(t *testing.T, mode string, factory ssopg.OAuth2ProtocolAdapterFactory, traces ...*providerTrace) nativeOAuth2JourneyFixture {
	t.Helper()
	var revocation url.URL
	if strings.HasPrefix(mode, "restorable-vault-revoke") || strings.HasPrefix(mode, "restorable-vault-refresh") {
		revocation = url.URL{Scheme: "https", Host: "provider.example.com", Path: "/revoke"}
	}
	x := newProviderOAuthLoginStartFixtureWithRevocation(t, revocation)
	x.config.RestorableOAuth2Vault = strings.HasPrefix(mode, "restorable-vault")
	if mode == "restorable-vault-revoke-local-outcome" {
		k, err := keyring.New(map[string][]byte{x.config.KeyReference: bytes.Repeat([]byte{0x94}, 32)})
		if err != nil {
			t.Fatal(err)
		}
		x.config.Envelope, err = envelope.NewService(nativeRevocationManagedKeyFixture{k})
		if err != nil {
			t.Fatal(err)
		}
	}
	installNativeOAuth2JourneyMigrations(t, x.enable.f)
	policy := kernel.CommandQueryPolicy{Authorization: nativeOAuth2JourneyPolicy{}, Clock: clock.System{}, PolicyVersion: 1}
	x.config.Coordinator.AdmissionPolicy, x.config.Coordinator.QueryPolicy = &policy, &policy
	x.config.RequestKeys.Policy = policy
	var err error
	x.service, err = ssopg.NewProviderLoginServiceWithOAuth2(x.router, x.config, []ssopg.StaticOAuth2LoginProfile{x.profile})
	if err != nil {
		t.Fatal("compose authorized native OAuth2 start", err)
	}
	namespace, err := ssopg.SSOOAuth2AccountProviderNamespace(x.profile.OrganizationID, x.profile.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	nativeCallbackJourneyExec(t, x.providerLoginStartFixture, `INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES($1,'owner','enterprise-provider-credential',3,'sso',1,true)`, string(x.config.TenantID))
	nativeCallbackJourneyExec(t, x.providerLoginStartFixture, `WITH a AS (SELECT $2::text AS provider,$3::text AS issuer,$4::text AS subject)
INSERT INTO identity.accounts(tenant_id,user_id,account_id,provider,issuer,subject,subject_key,version,social_link_version,linked)
SELECT $1,'owner','enterprise-linked-account',provider,issuer,subject,
sha256(convert_to(octet_length(provider)::text||':'||provider||octet_length(issuer)::text||':'||issuer||octet_length(subject)::text||':'||subject,'UTF8')),1,1,true FROM a`, string(x.config.TenantID), namespace, nativeOAuth2JourneyIssuer, nativeOAuth2JourneySubject)
	nativeCallbackJourneyExec(t, x.providerLoginStartFixture, `INSERT INTO identity.account_credentials(tenant_id,user_id,credential_id,account_id) VALUES($1,'owner','enterprise-provider-credential','enterprise-linked-account')`, string(x.config.TenantID))
	seedNativeCallbackJourneyFactors(t, x.providerLoginStartFixture, "owner")
	started, err := x.service.SigninStartOAuth2(x.enable.f.ctx, x.request, x.browser)
	if err != nil || started.Completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("commit original OAuth2 browser authorization", err)
	}
	if len(traces) > 1 {
		t.Fatal("native OAuth2 fixture accepts one callback trace")
	}
	if len(traces) == 1 {
		x.router = nativeOAuth2CallbackTracedRouter(t, x, traces[0])
		x.service, err = ssopg.NewProviderLoginServiceWithOAuth2(x.router, x.config, []ssopg.StaticOAuth2LoginProfile{x.profile})
		if err != nil {
			t.Fatal("compose traced native OAuth2 callback", err)
		}
	}
	challenge := started.RedirectURI.Query().Get("code_challenge")
	posts, identities, revokes, refreshes := &atomic.Int32{}, &atomic.Int32{}, &atomic.Int32{}, &atomic.Int32{}
	refreshEntered, refreshRelease := make(chan struct{}, 1), make(chan struct{})
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/token":
			if r.Method != http.MethodPost || r.Host != "provider.example.com" || r.ParseForm() != nil {
				t.Error("provider did not receive the installed HTTPS token endpoint")
				http.Error(w, "invalid request", http.StatusBadRequest)
				return
			}
			if r.PostForm.Get("grant_type") == "refresh_token" && strings.HasPrefix(mode, "restorable-vault-refresh") {
				send := refreshes.Add(1)
				expected := nativeCallbackJourneyRefreshToken
				if mode == nativeOAuth2NarrowRotatedMode && send == 2 {
					expected = nativeOAuth2RotatedRefresh
				}
				if r.PostForm.Get("refresh_token") != expected || r.PostForm.Get("client_id") != x.profile.ClientID ||
					r.PostForm.Get("client_secret") != strings.Repeat("9", 32) || r.PostForm.Has("code") {
					t.Error("refresh did not use the exact stored grant and installed client")
					http.Error(w, "invalid request", http.StatusBadRequest)
					return
				}
				if send == 2 && (mode == nativeOAuth2NarrowRotatedMode || mode == nativeOAuth2NarrowRetainedMode) {
					if values := r.PostForm["scope"]; len(values) != 1 || values[0] != "read:identity" {
						t.Error("second generation did not request the persisted narrower scope explicitly")
						http.Error(w, "scope fixture failed", http.StatusBadRequest)
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "fixture-narrowed-access-generation-three", "refresh_token": nativeOAuth2TwiceRotatedRefresh, "token_type": "Bearer", "expires_in": 3600})
					return
				}
				if values := r.PostForm["scope"]; len(values) != 1 || values[0] != "read:identity email" {
					t.Error("initial refresh did not request the persisted grant scope explicitly")
					http.Error(w, "scope fixture failed", http.StatusBadRequest)
					return
				}
				switch mode {
				case "restorable-vault-refresh-refused", "restorable-vault-refresh-rejected":
					kind := "invalid_scope"
					if mode == "restorable-vault-refresh-rejected" {
						kind = "invalid_grant"
					}
					w.WriteHeader(http.StatusBadRequest)
					_ = json.NewEncoder(w).Encode(map[string]any{"error": kind})
					return
				case "restorable-vault-refresh-unknown":
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				case "restorable-vault-refresh-retained":
					_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "fixture-enterprise-renewed-access", "token_type": "Bearer", "expires_in": 3600})
					return
				case nativeOAuth2NarrowRetainedMode:
					_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "fixture-narrowed-retained-access", "token_type": "Bearer", "expires_in": 3600, "scope": "read:identity"})
					return
				case "restorable-vault-refresh-late-factor":
					updated, err := x.enable.f.pool.Raw().Exec(r.Context(), `UPDATE identity_mfa.factor_authorities SET version=version+1 WHERE tenant_id=$1 AND user_id='owner'`, string(x.config.TenantID))
					if err != nil || updated.RowsAffected() != 1 {
						t.Error("fixture could not advance factor authority during provider refresh", err)
						http.Error(w, "fixture failed", http.StatusInternalServerError)
						return
					}
				case nativeOAuth2RefreshRaceMode:
					select {
					case refreshEntered <- struct{}{}:
					default:
					}
					select {
					case <-refreshRelease:
					case <-r.Context().Done():
						return
					}
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "fixture-enterprise-rotated-access", "refresh_token": nativeOAuth2RotatedRefresh, "token_type": "Bearer", "expires_in": 3600, "scope": "read:identity"})
				return
			}
			posts.Add(1)
			verifier := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
			if r.PostForm.Get("grant_type") != "authorization_code" || r.PostForm.Get("code") != nativeOAuth2JourneyCode ||
				r.PostForm.Get("client_id") != x.profile.ClientID || r.PostForm.Get("client_secret") != strings.Repeat("9", 32) ||
				r.PostForm.Get("redirect_uri") != x.profile.ProtocolRedirectURI || base64.RawURLEncoding.EncodeToString(verifier[:]) != challenge {
				t.Error("provider exchange changed installed credentials or original code/redirect/PKCE")
				http.Error(w, "invalid grant", http.StatusBadRequest)
				return
			}
			if mode == "provider-unavailable" {
				w.WriteHeader(http.StatusServiceUnavailable)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": "temporarily_unavailable"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": nativeCallbackJourneyAccessToken, "refresh_token": nativeCallbackJourneyRefreshToken, "token_type": "Bearer", "expires_in": 3600, "scope": "read:identity email"})
		case "/identity":
			identities.Add(1)
			if r.Method != http.MethodGet || r.Host != "provider.example.com" || r.Header.Get("Authorization") != "Bearer "+nativeCallbackJourneyAccessToken {
				t.Error("identity endpoint did not authenticate with the exchanged access token")
				http.Error(w, "invalid bearer", http.StatusUnauthorized)
				return
			}
			if mode == "late-member-removal" {
				updated, err := x.enable.f.pool.Raw().Exec(r.Context(), `UPDATE organization.memberships SET state='removed',version=version+1 WHERE tenant_id=$1 AND organization_id=$2 AND user_id='owner'`, string(x.config.TenantID), string(x.profile.OrganizationID))
				if err != nil || updated.RowsAffected() != 1 {
					t.Error("fixture could not withdraw the linked member during identity lookup", err)
					http.Error(w, "fixture failed", http.StatusInternalServerError)
					return
				}
			}
			if mode == "numeric-subject" {
				_ = json.NewEncoder(w).Encode(map[string]any{"stable_id": 42})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"stable_id": nativeOAuth2JourneySubject})
		case "/revoke":
			revokes.Add(1)
			expected := nativeCallbackJourneyRefreshToken
			if mode == "restorable-vault-refresh" || mode == nativeOAuth2RefreshRaceMode {
				expected = nativeOAuth2RotatedRefresh
			}
			if mode == nativeOAuth2NarrowRotatedMode || mode == nativeOAuth2NarrowRetainedMode {
				expected = nativeOAuth2TwiceRotatedRefresh
			}
			if r.Method != http.MethodPost || r.Host != "provider.example.com" || r.ParseForm() != nil ||
				r.PostForm.Get("token") != expected || r.PostForm.Get("token_type_hint") != "refresh_token" ||
				r.PostForm.Get("client_id") != x.profile.ClientID || r.PostForm.Get("client_secret") != strings.Repeat("9", 32) {
				t.Error("revocation did not use the exact provider and original refresh custody")
				http.Error(w, "invalid request", http.StatusBadRequest)
				return
			}
			switch mode {
			case "restorable-vault-revoke-unknown":
				w.WriteHeader(http.StatusServiceUnavailable)
			case "restorable-vault-revoke-refused":
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": "unsupported_token_type"})
			case "restorable-vault-revoke-late-factor":
				updated, err := x.enable.f.pool.Raw().Exec(r.Context(), `UPDATE identity_mfa.factor_authorities SET version=version+1 WHERE tenant_id=$1 AND user_id='owner'`, string(x.config.TenantID))
				if err != nil || updated.RowsAffected() != 1 {
					t.Error("fixture could not advance the original factor generation during revocation", err)
					http.Error(w, "fixture failed", http.StatusInternalServerError)
					return
				}
				w.WriteHeader(http.StatusOK)
			default:
				w.WriteHeader(http.StatusOK)
			}
		default:
			t.Error("provider received an unconfigured endpoint")
			http.NotFound(w, r)
		}
	}))
	certificate, roots := nativeOAuth2JourneyTLSCertificate(t)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	t.Cleanup(server.Close)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "provider.example.com:443" {
			return nil, errors.New("fixture refuses a non-pinned provider endpoint")
		}
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, server.Listener.Addr().String())
	}}
	t.Cleanup(transport.CloseIdleConnections)
	lookup, err := session.NewDigestKey(1, bytes.Repeat([]byte{0xd1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := session.NewCSRFKey(1, bytes.Repeat([]byte{0xd2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_session", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	profile := oauth.OAuth2UserInfoProfile{Profile: oauth.ProviderProfile{
		ID: strings.ReplaceAll(namespace, ".", "-"), Version: x.profile.ProviderVersion, Issuer: nativeOAuth2JourneyIssuer, ClientID: x.profile.ClientID,
		AuthorizationEndpoint: "https://provider.example.com/authorize", TokenEndpoint: "https://provider.example.com/token", RedirectURI: x.profile.ProtocolRedirectURI,
		ClientAuthentication: oauth.ClientSecretPost, Scopes: x.profile.Scopes, ResponseMode: "query", PKCEMethod: "S256", StateBytes: 32,
		Timeout: time.Second, ClockSkew: time.Minute, MaxResponseBytes: 64 << 10, MaxTokenBytes: 16 << 10, MaxCodeBytes: 4096,
	}, Details: oauth.OAuth2UserInfoDetails{UserInfoEndpoint: "https://provider.example.com/identity", SubjectClaim: "stable_id", SubjectEncoding: oauth.OAuth2StringSubject, ProofLifetime: 20 * time.Second}}
	completionConfig := ssopg.ProviderLoginCompletionConfig{
		Audience: "native-enterprise-oauth2-app", PolicyNamespace: "users", CSRFKey: csrf,
		Issuer: session.IssuerConfig{Clock: clock.System{}, MaximumDuration: 3 * time.Second, LookupKey: lookup, TokenSize: 32, Cookie: cookie},
	}
	completionProfiles := []ssopg.StaticOAuth2CompletionProfile{{OrganizationID: x.profile.OrganizationID, ProviderID: x.profile.ProviderID, Profile: profile, HTTPClient: &http.Client{Transport: transport}}}
	var completion *ssopg.ProviderOAuth2LoginCompletionService
	if factory == nil {
		completion, err = ssopg.NewProviderOAuth2LoginCompletionService(x.service, completionConfig, completionProfiles)
	} else {
		completion, err = ssopg.NewProviderOAuth2LoginCompletionServiceWithAdapter(x.service, completionConfig, completionProfiles, factory)
	}
	if err != nil {
		t.Fatal("compose explicit installed OAuth2 linked-member completion", err)
	}
	query := url.Values{"code": {nativeOAuth2JourneyCode}, "state": {started.RedirectURI.Query().Get("state")}, "iss": {nativeOAuth2JourneyIssuer}}
	return nativeOAuth2JourneyFixture{start: x, completion: completion, completionConfig: completionConfig, request: ssopg.ProviderOAuth2LoginCallbackRequest{RawQuery: query.Encode(), Browser: x.browser, ReceivedRedirectURI: x.profile.ProtocolRedirectURI}, startedID: started.TransactionID, posts: posts, identities: identities, revokes: revokes, refreshes: refreshes, refreshEntered: refreshEntered, refreshRelease: refreshRelease, transport: completionProfiles[0], lookup: lookup, csrf: csrf}
}

type nativeRevocationManagedKeyFixture struct{ *keyring.Provider }

func (k nativeRevocationManagedKeyFixture) DecryptDataKey(ctx context.Context, key string, wire []byte, aad envelope.Context) ([]byte, error) {
	if aad.Values()["profile"] == "sso-provider-grant-revoke-outcome-v1" {
		return nil, errors.New("managed key provider unavailable for local settlement")
	}
	return k.Provider.DecryptDataKey(ctx, key, wire, aad)
}

func installNativeOAuth2JourneyMigrations(t *testing.T, f *orgFixture) {
	t.Helper()
	history := append(migrationList(nil), f.history...)
	known := make(map[migrations.Version]migrations.Checksum)
	for _, step := range history {
		known[step.Version()] = step.Checksum()
	}
	for _, source := range []migrations.Source{
		sessionpg.IssueMigrationSource{Base: sessionpg.RevocationMigrationSource{Base: sessionpg.MigrationSource{Schema: "organization_sessions", Version: 20}, Version: 341}, Version: 342},
		mfapg.MigrationSource{Version: 343}, sessionpg.CSRFMigrationSource{Schema: "organization_sessions", Version: 344},
		sessionpg.SSOOIDCSigninMigrationSource{Schema: "organization_sessions", Version: 345, ValidationVersion: 346, PreviousConstraint: "session_issuances_purpose_check"},
		ssopg.ProviderLoginTokenVaultMigrationSource{Version: 347},
		sessionpg.RevokeOneMigrationSource{Base: sessionpg.RevocationMigrationSource{Base: sessionpg.MigrationSource{Schema: "organization_sessions", Version: 20}, Version: 341}, Version: 348},
		ssopg.ProviderLoginTokenVaultProtocolMigrationSource{Version: 349, ValidationVersion: 350},
		sessionpg.SSOOAuth2SigninMigrationSource{Schema: "organization_sessions", Version: 351, ValidationVersion: 352},
	} {
		steps, err := source.Load(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, step := range steps {
			if checksum, exists := known[step.Version()]; exists {
				if checksum != step.Checksum() {
					t.Fatal("native OAuth2 migration sources disagree on installed history")
				}
				continue
			}
			history = append(history, step)
			known[step.Version()] = step.Checksum()
		}
	}
	complete, err := (kernel.SSOOIDCCallbackPreparationErasureMigrationSource{Base: history, Version: 353}).Load(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	complete, err = (kernel.SSOOAuth2CallbackPreparationErasureMigrationSource{Base: migrationList(complete), Version: 354}).Load(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	config, err := pgx.ParseConfig(f.dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.Database = f.database
	db := stdlib.OpenDB(*config)
	defer db.Close()
	backend, err := migrationpg.New(db)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := migrations.NewRunner(migrationList(complete), backend)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := runner.Up(f.ctx); err != nil {
			t.Fatal("install and replay native OAuth2 callback history", err)
		}
	}
	f.history = append(migrationList(nil), complete...)
}

func nativeOAuth2JourneyTLSCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"provider.example.com"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: certificate}, roots
}

func TestNativeOAuth2LoginCallbackCommitsLinkedSession(t *testing.T) {
	x := newNativeOAuth2JourneyFixture(t, "linked-member")
	got, err := x.completion.SigninCallbackOAuth2(x.start.enable.f.ctx, x.request)
	if err != nil || got.Completion.Outcome != identity.CommitOutcomeCommitted || got.Issuance.CommitOutcome != identity.CommitOutcomeCommitted || got.Issuance.Replayed || x.posts.Load() != 1 || x.identities.Load() != 1 {
		t.Fatalf("OAuth2 callback did not commit one linked session: %v; receipt=%v issuance=%v token-posts=%d identity-reads=%d", err, got.Completion.Outcome, got.Issuance.CommitOutcome, x.posts.Load(), x.identities.Load())
	}
	spec, err := got.Issuance.Session.Bindings()
	if err != nil || spec.UserID != "owner" || spec.TenantID != x.start.config.TenantID || spec.Authentication.Proof.Method != "sso-oauth2" || spec.Authentication.CredentialID != "enterprise-provider-credential" || got.RedirectURI != x.start.request.SuccessCallback.String() || spec.Remember != x.start.originalFlow.Intent.Remember {
		t.Fatal("OAuth2 issuance lost linked recipient, proof or original browser continuation", err)
	}
	if got.Issuance.Cookie.Name != "__Host-identity_session" || got.Issuance.Cookie.Value != "" || !got.Issuance.Cookie.Secure || !got.Issuance.Cookie.HttpOnly || got.Issuance.Cookie.Path != "/" || got.Issuance.Cookie.SameSite != http.SameSiteLaxMode {
		t.Fatal("acknowledged OAuth2 session did not return secure host-only cookie metadata")
	}
	bearer, err := got.Issuance.Token.Reveal()
	if err != nil || bearer == "" {
		t.Fatal("acknowledged OAuth2 callback withheld its original bearer", err)
	}
	csrf, err := got.CSRF.Reveal()
	if err != nil || csrf == "" || got.Issuance.Session.CSRFState().Check(session.CSRFBinding{TenantID: spec.TenantID, SessionID: spec.SessionID, SessionVersion: spec.Version}, got.CSRF, x.csrf) != nil {
		t.Fatal("OAuth2 session did not return matching session-bound CSRF custody", err)
	}
	if _, err := got.Issuance.Token.Reveal(); err == nil {
		t.Fatal("the original OAuth2 bearer was disclosed twice")
	}
	assertNativeOAuth2JourneyCommit(t, x, got, bearer, csrf)
	before := nativeProviderLoginCounts(t, x.start.providerLoginStartFixture)
	replayed, _ := x.completion.SigninCallbackOAuth2(x.start.enable.f.ctx, x.request)
	assertNativeOAuth2JourneyNoDisclosure(t, replayed)
	if x.posts.Load() != 1 || x.identities.Load() != 1 || nativeProviderLoginCounts(t, x.start.providerLoginStartFixture) != before {
		t.Fatal("terminal OAuth2 replay repeated provider exchange or durable effects")
	}
	assertNativeOAuth2JourneyCookieAndLogout(t, x, got, bearer, csrf)
}

func TestNativeOAuth2LoginVaultRestoresAfterCallbackErasure(t *testing.T) {
	x := newNativeOAuth2JourneyFixture(t, "restorable-vault")
	f := x.start.enable.f
	got, err := x.completion.SigninCallbackOAuth2(f.ctx, x.request)
	if err != nil || got.Completion.Outcome != identity.CommitOutcomeCommitted || got.Issuance.CommitOutcome != identity.CommitOutcomeCommitted {
		t.Fatal("commit OAuth2 callback and restorable grant", err)
	}
	row := f.pool.Raw().QueryRow(f.ctx, committedNativeOAuth2VaultRowForTest,
		string(x.start.config.TenantID), string(got.Completion.Binding.CommandID))
	digests, err := ssopg.RestoreOAuth2VaultFromRowForTest(f.ctx, x.start.config, row)
	want := [2][32]byte{
		sha256.Sum256([]byte(nativeCallbackJourneyAccessToken)),
		sha256.Sum256([]byte(nativeCallbackJourneyRefreshToken)),
	}
	if err != nil || digests != want || x.posts.Load() != 1 || x.identities.Load() != 1 {
		t.Fatal("restore original grant using only committed vault custody after erasure", err)
	}
}

const committedNativeOAuth2VaultRowForTest = `SELECT v.organization_id,v.provider_id,v.start_command_id,v.callback_command_id,v.callback_generation::bigint,
 v.tenant_id,v.user_id,v.account_id,v.account_provider,v.issuer,v.subject,v.account_version::bigint,v.social_link_version::bigint,
 v.token_version::bigint,v.provider_version::bigint,v.credential_generation::bigint,v.mapping_version::bigint,
 v.requested_scopes,v.granted_scopes,v.scope_reported,v.received_at_seconds,v.received_at_nanoseconds,
 v.access_expires_at_seconds,v.access_expires_at_nanoseconds,v.token_ciphertext
FROM sso_providers.provider_login_token_sets v
JOIN identity.commands j ON j.tenant_id=v.tenant_id AND j.purpose=v.origin_operation AND j.command_id=v.origin_command_id
JOIN sso_providers.login_transactions l ON l.start_command_id=v.start_command_id AND l.callback_command_id=v.callback_command_id
WHERE v.tenant_id=$1 AND v.callback_command_id=$2 AND v.origin_operation='identity.sso.oauth-callback'
 AND j.state='committed' AND j.preparation_ciphertext IS NULL AND j.preparation_ciphertext_generation IS NULL
 AND l.completed_at IS NOT NULL AND l.verifier_envelope IS NULL`

func assertNativeOAuth2JourneyNoDisclosure(t *testing.T, got ssopg.ProviderLoginCallbackResult) {
	t.Helper()
	if got.Issuance.Token != (session.Token{}) || got.Issuance.Cookie.Name != "" || got.CSRF != (session.CSRFToken{}) || got.RedirectURI != "" {
		t.Fatal("unacknowledged or replayed OAuth2 callback disclosed browser custody")
	}
}

func assertNativeOAuth2JourneyCommit(t *testing.T, x nativeOAuth2JourneyFixture, got ssopg.ProviderLoginCallbackResult, bearer, csrf string) {
	t.Helper()
	f, ctx := x.start.enable.f, x.start.enable.f.ctx
	spec, err := got.Issuance.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	callback := string(got.Completion.Binding.CommandID)
	binaryCommand, err := base64.RawURLEncoding.DecodeString(callback)
	if err != nil {
		t.Fatal(err)
	}
	var completed time.Time
	var verifier []byte
	var browser, capability string
	var uses int
	err = f.pool.Raw().QueryRow(ctx, `SELECT l.completed_at,l.verifier_envelope,p.state,c.state,c.uses
FROM sso_providers.login_transactions l
JOIN organization_sessions.preauth_transactions p ON p.tenant_id=l.tenant_id AND p.flow_id=$2
JOIN public.capability_identity_one_use c ON c.tenant_id=l.tenant_id AND c.command_id=l.callback_command_id AND c.purpose='identity.sso.oauth-callback'
WHERE l.start_command_id=$1 AND l.callback_command_id=$3 AND l.protocol='oauth2'`, x.startedID, string(x.start.browser.FlowID), callback).Scan(&completed, &verifier, &browser, &capability, &uses)
	if err != nil || completed.IsZero() || len(verifier) != 0 || browser != "consumed" || capability != "finalized" || uses != 1 {
		t.Fatal("OAuth2 commit did not consume original browser/capability and erase executable verifier custody", err)
	}
	var record, vault []byte
	var user, account, provider string
	var receipt, ciphertextErased, generationErased bool
	var issuances, audits, events int
	err = f.pool.Raw().QueryRow(ctx, `SELECT convert_to(s.record::text,'UTF8'),v.token_ciphertext,v.user_id,v.account_id,v.account_provider,
j.state='committed' AND j.result IS NOT NULL AND j.terminal_class='committed',j.preparation_ciphertext IS NULL,j.preparation_ciphertext_generation IS NULL,
(SELECT count(*) FROM organization_sessions.session_issuances WHERE tenant_id=$1 AND command_id=$3 AND purpose='identity.sso.oauth-callback'),
(SELECT count(*) FROM audit.records WHERE tenant_id=$1 AND action='identity.sso.login' AND correlation_id=$4 AND outcome=$5),
(SELECT count(*) FROM public.identity_outbox_bindings b JOIN public.outbox_messages m ON m.id=b.effect_id WHERE b.tenant_id=$1 AND b.command_id=$3 AND m.topic='session.created.v1')
FROM organization_sessions.sessions s
JOIN sso_providers.provider_login_token_sets v ON v.tenant_id=s.tenant_id AND v.callback_command_id=$4
JOIN identity.commands j ON j.tenant_id=s.tenant_id AND j.command_id=$3 AND j.purpose='identity.sso.oauth-callback'
WHERE s.tenant_id=$1 AND s.session_id=$2 AND s.state='active'`, string(spec.TenantID), spec.SessionID, binaryCommand, callback, int16(audit.OutcomeSucceeded)).Scan(&record, &vault, &user, &account, &provider, &receipt, &ciphertextErased, &generationErased, &issuances, &audits, &events)
	wantProvider, namespaceErr := ssopg.SSOOAuth2AccountProviderNamespace(x.start.profile.OrganizationID, x.start.profile.ProviderID)
	if err != nil || namespaceErr != nil || len(vault) == 0 || user != "owner" || account != "enterprise-linked-account" || provider != wantProvider || !receipt || !ciphertextErased || !generationErased || issuances != 1 || audits != 1 || events != 1 {
		t.Fatal("OAuth2 session/vault/receipt/audit/outbox did not commit once with temporary custody erased", err)
	}
	var durable struct {
		CSRF   session.CSRFStateSpec
		Lookup session.TokenDigest
	}
	if json.Unmarshal(record, &durable) != nil {
		t.Fatal("OAuth2 durable session lost digest-only browser bindings")
	}
	parsed, parseErr := session.ParseToken(bearer)
	digest, digestErr := parsed.Digest(x.lookup, string(spec.TenantID))
	if parseErr != nil || digestErr != nil || digest != spec.Lookup || durable.Lookup != digest {
		t.Fatal("OAuth2 session persisted a different bearer lookup")
	}
	for _, secret := range []string{nativeCallbackJourneyAccessToken, nativeCallbackJourneyRefreshToken, nativeOAuth2JourneyCode, strings.Repeat("9", 32), bearer, csrf, x.start.browser.FlowCookie.Token()} {
		if bytes.Contains(record, []byte(secret)) || bytes.Contains(vault, []byte(secret)) {
			t.Fatal("OAuth2 provider or browser material survived as plaintext session/vault custody")
		}
		var leaked bool
		err := f.pool.Raw().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM (
SELECT result AS wire FROM identity.commands WHERE result IS NOT NULL
UNION ALL SELECT preparation_ciphertext FROM identity.commands WHERE preparation_ciphertext IS NOT NULL
UNION ALL SELECT canonical_record FROM audit.records
UNION ALL SELECT payload FROM public.outbox_messages
UNION ALL SELECT binding_envelope FROM sso_providers.login_transactions
) stored WHERE position($1::bytea in wire)>0)`, []byte(secret)).Scan(&leaked)
		if err != nil || leaked {
			t.Fatal("OAuth2 secret escaped into retained command, audit, outbox or RP custody", err)
		}
	}
}

func assertNativeOAuth2JourneyCookieAndLogout(t *testing.T, x nativeOAuth2JourneyFixture, issued ssopg.ProviderLoginCallbackResult, bearer, csrfWire string) {
	t.Helper()
	f, ctx := x.start.enable.f, x.start.enable.f.ctx
	spec, err := issued.Issuance.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	organizations, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	selection := sessionpg.SSOOAuth2SessionAdmission{Profile: sessionpg.IdentifierAdmissionConfig{
		GlobalAuthorityID: x.start.config.GlobalAuthorityID, PolicyNamespace: "users", Audience: spec.Audience,
		AuthenticationMethod: "sso-oauth2", CredentialKind: identity.CredentialProvider, CredentialOwner: "sso",
	}, Authority: organizations}
	reader, err := sessionpg.NewSelectedSessionServiceWithSSOOAuth2(f.pool, sessionpg.SelectedSessionServiceConfig{
		Repository: x.start.config.Session, Validation: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: spec.Audience,
			Clock: clock.System{}, MaximumDuration: time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{x.lookup}},
	}, selection)
	if err != nil {
		t.Fatal("compose explicit native OAuth2 session reader", err)
	}
	token, err := session.ParseToken(bearer)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		t.Fatal(err)
	}
	request := session.GetRequest{TenantID: spec.TenantID, Credential: credential}
	current, err := reader.Get(ctx, request)
	if err != nil || !current.Authenticated || current.ValidateAt(time.Now().UTC()) != nil {
		t.Fatal("the actual OAuth2 cookie did not authenticate through current organization/account/factor authority", err)
	}
	actual, err := current.Session.Bindings()
	if err != nil || actual.SessionID != spec.SessionID || actual.UserID != spec.UserID || actual.FamilyID != spec.FamilyID || actual.Authentication.Proof.Method != "sso-oauth2" {
		t.Fatal("OAuth2 cookie read selected a different session or protocol", err)
	}
	execution := sessionpg.IssueExecutorConfig{Repository: x.start.config.Session, Profile: sessionpg.IssueAdmissionConfig(selection.Profile),
		Coordinator: kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute,
			CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {0xd3}}},
		Authorization: nativeCallbackJourneyLogoutPolicy{tenant: spec.TenantID, user: spec.UserID}, Clock: clock.System{}, PolicyID: "native-enterprise-oauth2-session", PolicyVersion: 1, AuditRetentionVersion: 1}
	executor, err := sessionpg.NewCookieRevokeOneExecutorWithSSOOAuth2(f.pool, sessionpg.RevokeOneExecutorConfig{Execution: execution, Sessions: reader}, []session.CSRFKey{x.csrf}, selection)
	if err != nil {
		t.Fatal("compose OAuth2 cookie revocation with original authority and CSRF selection", err)
	}
	cookie, err := session.NewCookiePolicy(session.CookieConfig{Name: issued.Issuance.Cookie.Name, SameSite: issued.Issuance.Cookie.SameSite})
	if err != nil {
		t.Fatal(err)
	}
	base, err := session.NewSignOutService(reader, executor, session.SignOutConfig{Cookie: cookie, PolicyID: execution.PolicyID, PolicyVersion: 1, MaximumDuration: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	logout, err := session.NewCookieSignOutService(base, []session.CSRFKey{x.csrf})
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := session.ParseCSRFToken(csrfWire)
	if err != nil {
		t.Fatal(err)
	}
	logoutID := commandID(t)
	logoutRequest := session.SignOutRequest{TenantID: spec.TenantID, CommandID: logoutID, CorrelationID: "native-oauth2-local-logout", Transport: session.CredentialCookie, Credential: credential}
	got, err := logout.SignOut(ctx, logoutRequest, csrf)
	if err != nil || !got.SignedOut || !got.ClearCookie || got.ClearBearer || got.CommitOutcome != identity.CommitOutcomeCommitted || got.Cookie.Name != issued.Issuance.Cookie.Name || got.Cookie.Value != "" || got.Cookie.MaxAge != -1 || !got.Cookie.Secure || !got.Cookie.HttpOnly || got.Cookie.Path != "/" {
		t.Fatal("OAuth2 local logout did not revoke the exact cookie and return secure deletion", err)
	}
	denied, err := reader.Get(ctx, request)
	if err != nil || denied.Authenticated || denied.Session != (session.Session{}) {
		t.Fatal("the original OAuth2 cookie still authenticates after local logout", err)
	}
	if repeated, err := logout.SignOut(ctx, logoutRequest, csrf); err != nil || !repeated.SignedOut || !repeated.ClearCookie || x.posts.Load() != 1 || x.identities.Load() != 1 {
		t.Fatal("OAuth2 local logout replay failed or contacted the provider", err)
	}
	command, err := base64.RawURLEncoding.DecodeString(string(logoutID))
	if err != nil {
		t.Fatal(err)
	}
	var state, family string
	var transitions, audits, events int
	err = f.pool.Raw().QueryRow(ctx, `SELECT s.state,f.state,
(SELECT count(*) FROM organization_sessions.session_revocations WHERE tenant_id=$1 AND command_id=$4 AND session_id=$2 AND before_version=1 AND after_version=2),
(SELECT count(*) FROM audit.records WHERE tenant_id=$1 AND action='identity.session.revoke' AND subject_id=$2 AND correlation_id='native-oauth2-local-logout' AND outcome=$5),
(SELECT count(*) FROM public.identity_outbox_bindings b JOIN public.outbox_messages m ON m.id=b.effect_id WHERE b.tenant_id=$1 AND b.command_id=$4 AND m.topic='session.revoked.v1')
FROM organization_sessions.sessions s JOIN organization_sessions.families f USING(tenant_id,family_id,user_id)
WHERE s.tenant_id=$1 AND s.session_id=$2 AND s.family_id=$3`, string(spec.TenantID), spec.SessionID, spec.FamilyID, command, int16(audit.OutcomeSucceeded)).Scan(&state, &family, &transitions, &audits, &events)
	if err != nil || state != "revoked" || family != "active" || transitions != 1 || audits != 1 || events != 1 {
		t.Fatal("OAuth2 local logout repeated or omitted its exact revocation, audit or lifecycle effect", err)
	}
}

func TestNativeOAuth2LoginCallbackRejectsMixupAndSubstitutedBrowserBeforeExchange(t *testing.T) {
	for _, mode := range []string{"missing-issuer", "duplicate-issuer", "malformed-issuer", "wrong-issuer-case", "wrong-issuer-and-browser", "wrong-state", "wrong-browser", "wrong-redirect"} {
		t.Run(mode, func(t *testing.T) {
			x := newNativeOAuth2JourneyFixture(t, "linked-member")
			request := x.request
			query, err := url.ParseQuery(request.RawQuery)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "missing-issuer", "malformed-issuer":
				query.Del("iss")
			case "duplicate-issuer":
				query.Add("iss", nativeOAuth2JourneyIssuer)
			case "wrong-issuer-case":
				query.Set("iss", "https://provider.example.com/enterprise")
			case "wrong-issuer-and-browser":
				query.Set("iss", "https://provider.example.com/enterprise")
				request.Browser.FlowCookie = authentication.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xd5}, 32)))
			case "wrong-state":
				query.Set("state", base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xd4}, 32)))
			case "wrong-browser":
				request.Browser.FlowCookie = authentication.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xd5}, 32)))
			case "wrong-redirect":
				request.ReceivedRedirectURI = "https://identity.example.test/not-original"
			}
			request.RawQuery = query.Encode()
			if mode == "malformed-issuer" {
				request.RawQuery += "&iss=%ZZ"
			}
			before := nativeOAuth2JourneySuccessEffects(t, x)
			got, err := x.completion.SigninCallbackOAuth2(x.start.enable.f.ctx, request)
			assertNativeOAuth2JourneyNoDisclosure(t, got)
			if err == nil || got.Completion.Outcome == identity.CommitOutcomeCommitted || x.posts.Load() != 0 || x.identities.Load() != 0 || nativeOAuth2JourneySuccessEffects(t, x) != before {
				t.Fatal("OAuth2 mix-up or substituted browser reached exchange or native success", err)
			}
			terminal := mode == "missing-issuer" || mode == "duplicate-issuer" || mode == "malformed-issuer" || mode == "wrong-issuer-case"
			var completed, hasVerifier bool
			err = x.start.enable.f.pool.Raw().QueryRow(x.start.enable.f.ctx, `SELECT completed_at IS NOT NULL,verifier_envelope IS NOT NULL FROM sso_providers.login_transactions WHERE start_command_id=$1`, x.startedID).Scan(&completed, &hasVerifier)
			if err != nil || completed != terminal || hasVerifier == terminal || terminal && got.Completion.Outcome != identity.CommitOutcomeNotCommitted {
				t.Fatalf("mix-up did not preserve the exact original-browser terminal policy: committed=%v want=%v verifier=%v outcome=%v err=%v", completed, terminal, hasVerifier, got.Completion.Outcome, err)
			}
			if terminal {
				replayed, replayErr := x.completion.SigninCallbackOAuth2(x.start.enable.f.ctx, x.request)
				assertNativeOAuth2JourneyNoDisclosure(t, replayed)
				if !errors.Is(replayErr, sso.ErrForbidden) || x.posts.Load() != 0 {
					t.Fatal("terminal issuer denial accepted corrected issuer after refusal", replayErr)
				}
			}
		})
	}
}

func nativeOAuth2JourneySuccessEffects(t *testing.T, x nativeOAuth2JourneyFixture) nativeCallbackJourneyEffects {
	t.Helper()
	var effects nativeCallbackJourneyEffects
	err := x.start.enable.f.pool.Raw().QueryRow(x.start.enable.f.ctx, `SELECT
(SELECT count(*) FROM organization_sessions.sessions WHERE tenant_id=$1),
(SELECT count(*) FROM sso_providers.provider_login_token_sets WHERE tenant_id=$1),
(SELECT count(*) FROM audit.records WHERE tenant_id=$1 AND action='identity.sso.login' AND subject_type='sso_login_transaction' AND subject_id=$2 AND outcome=$3),
(SELECT count(*) FROM public.outbox_messages WHERE topic='session.created.v1')`, string(x.start.config.TenantID), x.startedID, int16(audit.OutcomeSucceeded)).Scan(&effects.sessions, &effects.deposits, &effects.successAudits, &effects.sessionEvents)
	if err != nil {
		t.Fatal("read native OAuth2 domain success effects", err)
	}
	return effects
}

func TestNativeOAuth2LoginCallbackDoesNotCommitLateMemberLossOrNonStringSubject(t *testing.T) {
	for _, mode := range []string{"late-member-removal", "numeric-subject"} {
		t.Run(mode, func(t *testing.T) {
			x := newNativeOAuth2JourneyFixture(t, mode)
			before := nativeOAuth2JourneySuccessEffects(t, x)
			got, err := x.completion.SigninCallbackOAuth2(x.start.enable.f.ctx, x.request)
			assertNativeOAuth2JourneyNoDisclosure(t, got)
			if err == nil || got.Completion.Outcome == identity.CommitOutcomeCommitted || x.posts.Load() != 1 || x.identities.Load() != 1 || nativeOAuth2JourneySuccessEffects(t, x) != before {
				t.Fatal("late authority loss or a coerced numeric subject committed OAuth2 success", err)
			}
			if mode == "late-member-removal" {
				command, err := base64.RawURLEncoding.DecodeString(string(got.Completion.Binding.CommandID))
				if err != nil {
					t.Fatal(err)
				}
				var completed *time.Time
				var verifier []byte
				var aborted, outputErased bool
				err = x.start.enable.f.pool.Raw().QueryRow(x.start.enable.f.ctx, `SELECT l.completed_at,l.verifier_envelope,
j.state='aborted' AND j.result IS NOT NULL,j.preparation_ciphertext IS NULL AND j.preparation_ciphertext_generation IS NULL
FROM sso_providers.login_transactions l JOIN identity.commands j ON j.tenant_id=l.tenant_id AND j.command_id=$2 AND j.purpose='identity.sso.oauth-callback'
WHERE l.start_command_id=$1`, x.startedID, command).Scan(&completed, &verifier, &aborted, &outputErased)
				if err != nil || got.Completion.Outcome != identity.CommitOutcomeNotCommitted || completed == nil || len(verifier) != 0 || !aborted || !outputErased {
					t.Fatal("known-negative member loss did not terminalize its original receipt and erase executable custody", err)
				}
				replayed, _ := x.completion.SigninCallbackOAuth2(x.start.enable.f.ctx, x.request)
				assertNativeOAuth2JourneyNoDisclosure(t, replayed)
				if x.posts.Load() != 1 || x.identities.Load() != 1 || nativeOAuth2JourneySuccessEffects(t, x) != before {
					t.Fatal("terminal member-loss replay contacted the provider or created success")
				}
			}
		})
	}
}

func TestNativeOAuth2LoginCallbackRetainsAmbiguousExchangeWithoutResubmission(t *testing.T) {
	x := newNativeOAuth2JourneyFixture(t, "provider-unavailable")
	before := nativeOAuth2JourneySuccessEffects(t, x)
	var originalVerifier, originalBinding []byte
	var originalExpiry time.Time
	err := x.start.enable.f.pool.Raw().QueryRow(x.start.enable.f.ctx, `SELECT verifier_envelope,binding_envelope,expires_at FROM sso_providers.login_transactions WHERE start_command_id=$1`, x.startedID).Scan(&originalVerifier, &originalBinding, &originalExpiry)
	if err != nil || len(originalVerifier) == 0 || len(originalBinding) == 0 {
		t.Fatal("ambiguous exchange fixture lacked original pending custody", err)
	}
	got, err := x.completion.SigninCallbackOAuth2(x.start.enable.f.ctx, x.request)
	assertNativeOAuth2JourneyNoDisclosure(t, got)
	var unknown identity.UnknownCommitError
	if !errors.As(err, &unknown) || got.Completion.Outcome != identity.CommitOutcomeUnknown || string(unknown.CommandID) != string(got.Completion.Binding.CommandID) || x.posts.Load() != 1 || x.identities.Load() != 0 || nativeOAuth2JourneySuccessEffects(t, x) != before {
		t.Fatal("ambiguous OAuth2 token exchange lost its exact unknown outcome or created domain success", err)
	}
	var completed *time.Time
	var verifier, binding []byte
	var expiry time.Time
	err = x.start.enable.f.pool.Raw().QueryRow(x.start.enable.f.ctx, `SELECT completed_at,verifier_envelope,binding_envelope,expires_at FROM sso_providers.login_transactions WHERE start_command_id=$1`, x.startedID).Scan(&completed, &verifier, &binding, &expiry)
	if err != nil || completed != nil || !bytes.Equal(verifier, originalVerifier) || !bytes.Equal(binding, originalBinding) || !expiry.Equal(originalExpiry) {
		t.Fatal("ambiguous OAuth2 exchange erased recoverable original verifier custody", err)
	}
	replayed, _ := x.completion.SigninCallbackOAuth2(x.start.enable.f.ctx, x.request)
	assertNativeOAuth2JourneyNoDisclosure(t, replayed)
	if x.posts.Load() != 1 || x.identities.Load() != 0 || nativeOAuth2JourneySuccessEffects(t, x) != before {
		t.Fatal("ambiguous OAuth2 retry resubmitted the original code or committed domain success")
	}
	err = x.start.enable.f.pool.Raw().QueryRow(x.start.enable.f.ctx, `SELECT completed_at,verifier_envelope,binding_envelope,expires_at FROM sso_providers.login_transactions WHERE start_command_id=$1`, x.startedID).Scan(&completed, &verifier, &binding, &expiry)
	if err != nil || completed != nil || !bytes.Equal(verifier, originalVerifier) || !bytes.Equal(binding, originalBinding) || !expiry.Equal(originalExpiry) {
		t.Fatal("ambiguous OAuth2 replay terminalized, renewed or replaced original custody", err)
	}
}
