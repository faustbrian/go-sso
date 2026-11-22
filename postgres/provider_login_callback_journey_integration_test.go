//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
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
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

const nativeCallbackJourneyHost = "journey.example.com"
const nativeCallbackJourneyIssuer = "https://" + nativeCallbackJourneyHost
const nativeCallbackJourneySubject = "native-enterprise-linked-subject"
const nativeCallbackJourneyAccessToken = "fixture-enterprise-access-token-never-plaintext-in-storage"
const nativeCallbackJourneyRefreshToken = "fixture-enterprise-refresh-token-never-plaintext-in-storage"

type nativeCallbackJourneyPolicy struct{}

func (nativeCallbackJourneyPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	if c.PolicyRevision == 1 && c.Request.Tenant == authorization.TenantID(discoveryFixtureTenant) &&
		c.Request.Subject.Kind == authorization.SubjectServiceAccount && c.Request.Subject.ID == "native-sso-login" &&
		c.Request.Action == "identity.sso.oidc-callback" {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
	}
	return (providerLoginPolicy{}).Decide(ctx, c)
}

type nativeCallbackJourneyFixture struct {
	start            providerLoginStartFixture
	completion       *ssopg.ProviderLoginCompletionService
	completionConfig ssopg.ProviderLoginCompletionConfig
	request          ssopg.ProviderLoginCallbackRequest
	csrf             session.CSRFKey
	lookup           session.DigestKey
	started          sso.SigninStartResult
	posts            *atomic.Int32
	idToken          string
	newAttempt       func(*testing.T, string, *bool, time.Time) ssopg.ProviderLoginCallbackRequest
	linkBrowser      ssopg.ProviderLinkBrowser
}

func newNativeCallbackJourneyFixture(t *testing.T, mode string) nativeCallbackJourneyFixture {
	t.Helper()
	x := newProviderLoginStartFixture(t)
	const roleGrant = "native-enterprise-reader"
	rolesSelected := mode == "role-grant"
	jitFixture := strings.HasPrefix(mode, "jit")
	memberFixture := strings.HasPrefix(mode, "explicit-member")
	if rolesSelected {
		installNativeCallbackJourneyMigrations(t, x.enable.f)
		installProviderRoleSourceProjection(t, x.enable.f)
		prepareNativeCallbackJourneyProvider(t, &x, false)
		prepareNativeCallbackRole(t, x, roleGrant)
	} else {
		prepareNativeCallbackJourneyProvider(t, &x, jitFixture)
		installNativeCallbackJourneyMigrations(t, x.enable.f)
	}
	if jitFixture {
		installNativeCallbackJourneyJITMigrations(t, x.enable.f)
	} else if memberFixture {
		prepareNativeMemberJourneyIdentity(t, x)
	} else {
		seedNativeCallbackJourneyRecipient(t, x)
	}
	policy := kernel.CommandQueryPolicy{Authorization: nativeCallbackJourneyPolicy{}, Clock: clock.System{}, PolicyVersion: 1}
	x.config.Coordinator.AdmissionPolicy, x.config.Coordinator.QueryPolicy = &policy, &policy
	var err error
	x.service, err = ssopg.NewProviderLoginService(newProviderRouter(t, x.enable, 4), x.config)
	if err != nil {
		t.Fatal("compose native start with the exact callback service actor", err)
	}
	var linkBrowser ssopg.ProviderLinkBrowser
	var started sso.SigninStartResult
	if memberFixture {
		linkBrowser = prepareNativeMemberJourneyStart(t, &x)
		started, err = x.service.LinkStart(x.enable.f.ctx, x.request, linkBrowser)
	} else {
		started, err = x.service.SigninStart(x.enable.f.ctx, x.request, x.browser)
	}
	if err != nil || started.Completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("native start did not commit the original browser-bound transaction", err)
	}
	query := started.RedirectURI.Query()
	if query.Get("state") == "" || query.Get("nonce") == "" || query.Get("code_challenge_method") != "S256" {
		t.Fatal("native start did not return its original state, nonce and PKCE challenge")
	}
	if mode == "expired-flow" {
		router, err := ssopg.NewProviderRouter(x.enable.f.pool, ssopg.ProviderRouterConfig{
			Clock: fixedClock{at: x.originalFlow.ExpiresAt}, Envelope: x.enable.config.Envelope,
			MaximumDuration: 3 * time.Second, Lifetime: 8 * time.Second, PolicyVersion: 1, MaximumProviders: 4,
		})
		if err != nil {
			t.Fatal(err)
		}
		x.service, err = ssopg.NewProviderLoginService(router, x.config)
		if err != nil {
			t.Fatal("compose original durable login at its exclusive browser expiry", err)
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var projectView *bool
	if rolesSelected {
		value := true
		projectView = &value
	}
	var attributes map[string]any
	if jitFixture {
		attributes = nativeCallbackJourneyJITClaims(mode)
	}
	idToken := nativeCallbackJourneyIDToken(t, key, query.Get("nonce"), projectView, time.Now().UTC(), attributes)
	const originalCode = "native-enterprise-original-code"
	type providerReply struct{ challenge, token string }
	replies := map[string]providerReply{originalCode: {challenge: query.Get("code_challenge"), token: idToken}}
	var repliesMu sync.Mutex
	secret := nativeCallbackJourneyInstalledSecret(t, x)
	t.Cleanup(func() { clear(secret) })
	posts := &atomic.Int32{}
	var disable *ssopg.ProviderService
	var drain sso.ProviderDisableRequest
	if mode == "jit-provider-draining" {
		disable = nativeProviderDisableService(t, x, providerDisablePolicy{})
		drain = nativeProviderDisableRequest(t, x, sso.ActiveTransactionDrain)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		client, encodedSecret, authenticated := r.BasicAuth()
		decodedSecret, secretErr := url.QueryUnescape(encodedSecret)
		if r.Method != http.MethodPost || r.URL.Path != "/token" || r.Host != nativeCallbackJourneyHost ||
			!authenticated || client != "native-sso-client" || secretErr != nil || !bytes.Equal([]byte(decodedSecret), secret) || r.ParseForm() != nil {
			t.Error("provider did not receive the exact configured endpoint and installed credential")
			http.Error(w, "invalid client fixture", http.StatusUnauthorized)
			return
		}
		challenge := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		repliesMu.Lock()
		reply, registered := replies[r.PostForm.Get("code")]
		repliesMu.Unlock()
		if r.PostForm.Get("grant_type") != "authorization_code" || !registered ||
			r.PostForm.Get("redirect_uri") != x.config.Profiles[0].ProtocolRedirectURI ||
			base64.RawURLEncoding.EncodeToString(challenge[:]) != reply.challenge {
			t.Error("provider exchange substituted the original code, redirect or PKCE verifier")
			http.Error(w, "invalid grant fixture", http.StatusBadRequest)
			return
		}
		if mode == "jit-stale-owner" {
			// Callback authority was read before the provider POST. Simulate an
			// independent policy change during that external round trip.
			selected := x.config.Profiles[0]
			updated, err := x.enable.f.pool.Raw().Exec(r.Context(), `UPDATE organization.organizations SET version=version+1 WHERE tenant_id=$1 AND organization_id=$2`, string(x.config.TenantID), string(selected.OrganizationID))
			if err != nil || updated.RowsAffected() != 1 {
				t.Error("the fixture did not advance the observed organization revision")
				http.Error(w, "fixture could not advance authority", http.StatusInternalServerError)
				return
			}
		}
		if mode == "explicit-member-removed" {
			if err := removeNativeLinkMember(r.Context(), x); err != nil {
				t.Error("fixture could not withdraw the original member during the provider response", err)
				http.Error(w, "fixture could not withdraw membership", http.StatusInternalServerError)
				return
			}
		}
		if disable != nil {
			// The running callback saw an enabled provider. Keep its normal
			// drain disposition available, then let the callback check the fence.
			result, err := disable.ProviderDisable(r.Context(), drain)
			if err != nil || !result.Disabled || result.Completion.Outcome != identity.CommitOutcomeCommitted {
				t.Error("the fixture did not commit an actual provider drain", err)
				http.Error(w, "fixture did not commit disablement", http.StatusInternalServerError)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": nativeCallbackJourneyAccessToken,
			"refresh_token": nativeCallbackJourneyRefreshToken, "id_token": reply.token, "token_type": "Bearer", "expires_in": 3600, "scope": "openid email"})
	}))
	certificate, roots := nativeCallbackJourneyTLSCertificate(t)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	t.Cleanup(server.Close)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address != nativeCallbackJourneyHost+":443" {
				return nil, errors.New("fixture refuses a non-pinned provider endpoint")
			}
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, server.Listener.Addr().String())
		}}
	t.Cleanup(transport.CloseIdleConnections)
	lookup, err := session.NewDigestKey(1, bytes.Repeat([]byte{0xc1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := session.NewCSRFKey(1, bytes.Repeat([]byte{0xc2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_session", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	profile := x.config.Profiles[0]
	completionConfig := ssopg.ProviderLoginCompletionConfig{
		Audience: "native-enterprise-app", PolicyNamespace: "users", CSRFKey: csrf,
		Issuer: session.IssuerConfig{Clock: clock.System{}, MaximumDuration: 3 * time.Second, LookupKey: lookup, TokenSize: 32, Cookie: cookie},
		Profiles: []ssopg.StaticOIDCCompletionProfile{{OrganizationID: profile.OrganizationID, ProviderID: profile.ProviderID,
			Metadata: sso.OIDCStaticMetadataSpec{Issuer: nativeCallbackJourneyIssuer, AuthorizationEndpoint: nativeCallbackJourneyIssuer + "/authorize",
				TokenEndpoint: nativeCallbackJourneyIssuer + "/token", JWKSURI: nativeCallbackJourneyIssuer + "/keys"},
			ClientAuthentication: oauth.ClientSecretBasic, Algorithms: []string{"ES256"},
			Keys: &coreoidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}}, HTTPClient: &http.Client{Transport: transport}}},
	}
	var completion *ssopg.ProviderLoginCompletionService
	if jitFixture {
		completionConfig.Profiles[0].ClaimNames = []string{"work_mail", "verified_work_mail", "email", "email_verified"}
		if mode == "jit-disabled" {
			completion, err = ssopg.NewProviderLoginCompletionService(x.service, completionConfig)
		} else {
			jit := nativeCallbackJourneyJITConfig(t, x)
			if mode == "jit-at-capacity" {
				jit.Profiles[0].MaximumMembers = 1 // The existing organization owner fills the last seat.
			}
			completion, err = ssopg.NewProviderLoginCompletionServiceWithJIT(x.service, completionConfig, jit)
		}
	} else if rolesSelected {
		completionConfig.Profiles[0].ClaimNames = []string{"project_view"}
		completion, err = ssopg.NewProviderLoginCompletionServiceWithRoleSync(x.service, completionConfig, []ssopg.StaticOIDCRoleMapping{{
			OrganizationID: profile.OrganizationID, ProviderID: profile.ProviderID, MappingVersion: profile.MappingVersion,
			Rules: []ssopg.StaticOIDCRoleRule{{ClaimName: "project_view", RoleID: roleGrant}},
		}})
	} else {
		completion, err = ssopg.NewProviderLoginCompletionService(x.service, completionConfig)
	}
	if err != nil {
		t.Fatal("compose native existing-member completion using the pinned provider", err)
	}
	input, err := identity.NewOAuthCallbackInput([]byte(originalCode), query.Get("state"), identity.OAuthCallbackLimits{MaxCodeBytes: 4096, StateBytes: 32})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(input.Destroy)
	newAttempt := func(t *testing.T, code string, projectView *bool, assertedAt time.Time) ssopg.ProviderLoginCallbackRequest {
		t.Helper()
		browser, attempt := newNativeCallbackJourneyAttempt(t, x, code)
		authorize := attempt.RedirectURI.Query()
		if assertedAt.IsZero() {
			assertedAt = time.Now().UTC()
		}
		reply := providerReply{challenge: authorize.Get("code_challenge"), token: nativeCallbackJourneyIDToken(t, key, authorize.Get("nonce"), projectView, assertedAt, attributes)}
		repliesMu.Lock()
		replies[code] = reply
		repliesMu.Unlock()
		input, err := identity.NewOAuthCallbackInput([]byte(code), authorize.Get("state"), identity.OAuthCallbackLimits{MaxCodeBytes: 4096, StateBytes: 32})
		if err != nil {
			t.Fatal("bind new native provider callback", err)
		}
		t.Cleanup(input.Destroy)
		return ssopg.ProviderLoginCallbackRequest{Input: input, Browser: browser, ReceivedRedirectURI: profile.ProtocolRedirectURI}
	}
	return nativeCallbackJourneyFixture{start: x, completion: completion, completionConfig: completionConfig, csrf: csrf, lookup: lookup, started: started, posts: posts, idToken: idToken, newAttempt: newAttempt, linkBrowser: linkBrowser,
		request: ssopg.ProviderLoginCallbackRequest{Input: input, Browser: x.browser, ReceivedRedirectURI: profile.ProtocolRedirectURI}}
}

func newNativeCallbackJourneyAttempt(t *testing.T, x providerLoginStartFixture, code string) (ssopg.ProviderLoginBrowser, sso.SigninStartResult) {
	t.Helper()
	ctx := x.enable.f.ctx
	prepared, err := x.flowIssuer.Prepare(session.PreAuthPrepareInput{CommandID: commandID(t), TenantID: x.config.TenantID,
		CorrelationID: code, Remember: x.originalFlow.Intent.Remember})
	if err != nil {
		t.Fatal("prepare second real browser", err)
	}
	issued, err := x.flowIssuer.Issue(ctx, prepared)
	if err != nil || issued.CommitOutcome != identity.CommitOutcomeCommitted || issued.Replayed {
		t.Fatal("issue second real browser", err)
	}
	flow, err := issued.Flow.Bindings()
	if err != nil {
		t.Fatal("read issued browser", err)
	}
	secret, err := issued.Token.Reveal()
	if err != nil {
		t.Fatal("deliver issued browser", err)
	}
	browser := x.browser
	browser.FlowID, browser.FlowCookie = flow.Binding.ID, authentication.NewBearerCredential(secret)
	request := x.request
	request.CommandID = commandID(t)
	request.IdempotencyKey, err = identity.NewIdempotencyKey([]byte(code))
	if err != nil {
		t.Fatal("bind distinct login start key", err)
	}
	attempt, err := x.service.SigninStart(ctx, request, browser)
	if err != nil || attempt.Completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("commit second native provider start", err)
	}
	return browser, attempt
}

func prepareNativeCallbackJourneyProvider(t *testing.T, x *providerLoginStartFixture, jit bool) {
	t.Helper()
	ctx := x.enable.f.ctx
	registration := providerRequest(t, nativeCallbackJourneyIssuer, "native-callback-journey-register")
	if jit {
		mapping, err := sso.NewAttributeMapping(sso.AttributeMappingSpec{Version: 1, SubjectClaim: "sub", EmailClaim: "work_mail", VerifiedEmailClaim: "verified_work_mail"})
		if err != nil {
			t.Fatal("configure the installed verified enterprise mailbox mapping", err)
		}
		registration.Mapping = mapping
	}
	registered, err := x.enable.base.ProviderRegisterOidc(ctx, registration)
	if err != nil || registered.Provider.Enabled || registered.Provider.Version != 1 {
		t.Fatal("register the controlled provider through native disabled metadata custody", err)
	}
	provider := registered.Provider.ID
	at := time.Now().UTC().Truncate(time.Microsecond)
	binding := sso.CredentialReferenceContext{TenantID: string(x.config.TenantID), OrganizationID: registration.OrganizationID,
		ProviderID: provider, Protocol: "oidc", Purpose: "client-secret", Generation: 1, ProviderVersion: 1,
		Audience: "identity.sso.provider.credentials-rotate", EnvelopeKeyID: x.enable.config.KeyReference, IssuedAt: at, ExpiresAt: at.Add(time.Minute)}
	aad, err := binding.EncryptionContext()
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("native-enterprise-synthetic-client-secret")
	defer clear(secret)
	sealed, err := x.config.Envelope.Encrypt(ctx, envelope.EncryptRequest{Plaintext: secret, KeyReference: x.config.KeyReference, Context: aad})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := sealed.MarshalBinary()
	defer clear(wire)
	if err != nil {
		t.Fatal(err)
	}
	reference, err := sso.NewEncryptedCredentialReference(ctx, x.config.Envelope, wire, binding)
	if err != nil {
		t.Fatal(err)
	}
	credentials := nativeCredentialService(t, x.enable.base)
	rotated, err := credentials.ProviderCredentialsRotate(ctx, sso.ProviderCredentialsRotateRequest{
		CommandID: commandID(t), ProviderID: provider, ExpectedVersion: 1, CredentialReference: reference, OverlapPolicy: sso.NewNoCredentialOverlapPolicy(),
	})
	if err != nil || rotated.Version != 2 {
		t.Fatal("install the actual ASCII client credential while the provider is disabled", err)
	}
	request := x.enable.request
	request.ProviderID = provider
	request.CredentialCheckpoint, err = x.enable.service.ObserveProviderCredentialCheckpoint(ctx, provider, 2)
	if err != nil {
		t.Fatal(err)
	}
	request.IdempotencyKey, err = identity.NewIdempotencyKey([]byte("native-callback-journey-enable"))
	if err != nil {
		t.Fatal(err)
	}
	enabled, err := x.enable.service.ProviderEnable(ctx, request)
	if err != nil || !enabled.Provider.Enabled || enabled.Provider.Version != 3 {
		t.Fatal("enable the controlled provider with its actual verified domain and credential", err)
	}
	x.config.Profiles[0].ProviderID = sso.ProviderID(provider)
	x.request.ProviderID = provider
}

func installNativeCallbackJourneyMigrations(t *testing.T, f *orgFixture) {
	t.Helper()
	history := append(migrationList(nil), f.history...)
	known := make(map[migrations.Version]migrations.Checksum, len(history))
	for _, step := range history {
		known[step.Version()] = step.Checksum()
	}
	for _, source := range []migrations.Source{
		sessionpg.IssueMigrationSource{Base: sessionpg.RevocationMigrationSource{Base: sessionpg.MigrationSource{Schema: "organization_sessions", Version: 20}, Version: 337}, Version: 338},
		mfapg.MigrationSource{Version: 339},
		sessionpg.CSRFMigrationSource{Schema: "organization_sessions", Version: 340},
		sessionpg.SSOOIDCSigninMigrationSource{Schema: "organization_sessions", Version: 341, ValidationVersion: 342, PreviousConstraint: "session_issuances_purpose_check"},
		ssopg.ProviderLoginTokenVaultMigrationSource{Version: 343},
		sessionpg.RevokeOneMigrationSource{Base: sessionpg.RevocationMigrationSource{Base: sessionpg.MigrationSource{Schema: "organization_sessions", Version: 20}, Version: 337}, Version: 344},
	} {
		steps, err := source.Load(f.ctx)
		if err != nil {
			t.Fatal("load callback owner's actual migration history", err)
		}
		for _, step := range steps {
			if checksum, exists := known[step.Version()]; exists {
				if checksum != step.Checksum() {
					t.Fatal("callback consumer migration sources disagree on an installed predecessor")
				}
				continue
			}
			history = append(history, step)
			known[step.Version()] = step.Checksum()
		}
	}
	complete, err := (kernel.SSOOIDCCallbackPreparationErasureMigrationSource{Base: history, Version: 345}).Load(f.ctx)
	if err != nil {
		t.Fatal("load callback terminal preparation erasure after its complete prerequisite history", err)
	}
	history = migrationList(complete)
	configuration, err := pgx.ParseConfig(f.dsn)
	if err != nil {
		t.Fatal(err)
	}
	configuration.Database = f.database
	db := stdlib.OpenDB(*configuration)
	defer db.Close()
	backend, err := migrationpg.New(db)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := migrations.NewRunner(history, backend)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := runner.Up(f.ctx); err != nil {
			t.Fatal("install and replay native callback migration composition", err)
		}
	}
	f.history = append(migrationList(nil), history...)
}

func nativeCallbackJourneyExec(t *testing.T, x providerLoginStartFixture, sql string, args ...any) {
	t.Helper()
	if _, err := x.enable.f.pool.Raw().Exec(x.enable.f.ctx, sql, args...); err != nil {
		t.Fatal("prepare isolated native enterprise recipient fixture", err)
	}
}

func seedNativeCallbackJourneyRecipient(t *testing.T, x providerLoginStartFixture) {
	t.Helper()
	tenant := string(x.config.TenantID)
	provider, err := ssopg.SSOOIDCAccountProviderNamespace(x.config.Profiles[0].OrganizationID, x.config.Profiles[0].ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	nativeCallbackJourneyExec(t, x, `INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES($1,'owner','enterprise-provider-credential',3,'sso',1,true)`, tenant)
	nativeCallbackJourneyExec(t, x, `WITH a AS (SELECT $2::text AS provider,$3::text AS issuer,$4::text AS subject)
INSERT INTO identity.accounts(tenant_id,user_id,account_id,provider,issuer,subject,subject_key,version,social_link_version,linked)
SELECT $1,'owner','enterprise-linked-account',provider,issuer,subject,
sha256(convert_to(octet_length(provider)::text||':'||provider||octet_length(issuer)::text||':'||issuer||octet_length(subject)::text||':'||subject,'UTF8')),1,1,true FROM a`, tenant, provider, nativeCallbackJourneyIssuer, nativeCallbackJourneySubject)
	nativeCallbackJourneyExec(t, x, `INSERT INTO identity.account_credentials(tenant_id,user_id,credential_id,account_id) VALUES($1,'owner','enterprise-provider-credential','enterprise-linked-account')`, tenant)
	seedNativeCallbackJourneyFactors(t, x, "owner")
}

func seedNativeCallbackJourneyFactors(t *testing.T, x providerLoginStartFixture, member identity.UserID) {
	t.Helper()
	tenant := string(x.config.TenantID)
	// These are preexisting fixture records, not a claim that this journey ran
	// registration. The real factor table retains its original initializer FK.
	initialization, err := base64.RawURLEncoding.DecodeString(string(commandID(t)))
	if err != nil {
		t.Fatal(err)
	}
	nativeCallbackJourneyExec(t, x, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,$2,'identity.password.signup',$3,1,$4)`, initialization, tenant, bytes.Repeat([]byte{0xc3}, 32), []byte{1})
	nativeCallbackJourneyExec(t, x, `INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,$2,'identity.password.signup')`, initialization, tenant)
	nativeCallbackJourneyExec(t, x, `INSERT INTO identity_mfa.factor_authorities(tenant_id,user_id,version,active_factors,initialized_command_id,initialized_purpose) VALUES($1,$3,1,0,$2,'identity.password.signup')`, tenant, initialization, string(member))
}

func nativeCallbackJourneyInstalledSecret(t *testing.T, x providerLoginStartFixture) []byte {
	t.Helper()
	var wire, binding []byte
	err := x.enable.f.pool.Raw().QueryRow(x.enable.f.ctx, `SELECT envelope,credential_context FROM sso_providers.credentials WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`,
		string(x.config.TenantID), string(x.config.Profiles[0].OrganizationID), string(x.config.Profiles[0].ProviderID)).Scan(&wire, &binding)
	if err != nil {
		t.Fatal("read the exact installed fixture client credential", err)
	}
	defer clear(wire)
	defer clear(binding)
	var reference sso.CredentialReferenceContext
	if json.Unmarshal(binding, &reference) != nil {
		t.Fatal("decode installed fixture credential binding")
	}
	aad, err := reference.EncryptionContext()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := x.config.Envelope.Decrypt(x.enable.f.ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	if err != nil {
		t.Fatal("open installed fixture client credential for the controlled provider", err)
	}
	return secret
}

func nativeCallbackJourneyIDToken(t *testing.T, key *ecdsa.PrivateKey, nonce string, projectView *bool, assertedAt time.Time, attributes ...map[string]any) string {
	t.Helper()
	claimSet := map[string]any{"iss": nativeCallbackJourneyIssuer, "sub": nativeCallbackJourneySubject, "aud": "native-sso-client",
		"iat": assertedAt.Unix(), "exp": assertedAt.Add(5 * time.Minute).Unix(), "nonce": nonce}
	if projectView != nil {
		claimSet["project_view"] = *projectView
	}
	for _, selected := range attributes {
		for name, value := range selected {
			claimSet[name] = value
		}
	}
	claims, err := json.Marshal(claimSet)
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
	return message + "." + base64.RawURLEncoding.EncodeToString(signature[:])
}

func nativeCallbackJourneyTLSCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "native enterprise loopback fixture"},
		DNSNames: []string{nativeCallbackJourneyHost}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true}
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

func TestNativeProviderLoginCallbackJourneyCommitsLinkedMemberAndWithholdsReplay(t *testing.T) {
	x := newNativeCallbackJourneyFixture(t, "linked-member")
	ctx := x.start.enable.f.ctx
	before := nativeProviderLoginCounts(t, x.start)
	got, err := x.completion.SigninCallback(ctx, x.request)
	if err != nil || got.Completion.Outcome != identity.CommitOutcomeCommitted || got.Issuance.CommitOutcome != identity.CommitOutcomeCommitted || got.Issuance.Replayed || x.posts.Load() != 1 {
		logNativeCallbackJourneyFailure(t, x)
		t.Fatal("public callback did not acknowledge one native linked-member issuance", err)
	}
	spec, err := got.Issuance.Session.Bindings()
	if err != nil || spec.TenantID != x.start.config.TenantID || spec.UserID != "owner" || spec.Audience != "native-enterprise-app" ||
		spec.Authentication.Proof.Method != "sso-oidc" || spec.Authentication.CredentialID != "enterprise-provider-credential" ||
		got.RedirectURI != x.start.request.SuccessCallback.String() || spec.Remember != x.start.originalFlow.Intent.Remember {
		t.Fatal("public issuance lost the exact linked user, credential or original browser continuation", err)
	}
	if got.Issuance.Cookie.Name != "__Host-identity_session" || got.Issuance.Cookie.Value != "" || !got.Issuance.Cookie.Secure ||
		!got.Issuance.Cookie.HttpOnly || got.Issuance.Cookie.Path != "/" || got.Issuance.Cookie.SameSite != http.SameSiteLaxMode {
		t.Fatal("public issuance did not return the commit-gated host-only cookie transport")
	}
	bearer, err := got.Issuance.Token.Reveal()
	if err != nil || bearer == "" {
		t.Fatal("acknowledged native callback withheld its original session bearer", err)
	}
	csrfWire, err := got.CSRF.Reveal()
	if err != nil || csrfWire == "" || got.Issuance.Session.CSRFState().Check(session.CSRFBinding{TenantID: spec.TenantID, SessionID: spec.SessionID, SessionVersion: spec.Version}, got.CSRF, x.csrf) != nil {
		t.Fatal("acknowledged callback did not deliver matching session-bound CSRF custody", err)
	}
	if _, err := got.Issuance.Token.Reveal(); err == nil {
		t.Fatal("the same native session bearer could be disclosed twice")
	}
	assertNativeCallbackJourneyCommit(t, x, got, bearer, csrfWire)
	after := nativeProviderLoginCounts(t, x.start)
	if after.transactions != before.transactions || after.capabilities != before.capabilities || after.events != before.events+1 || after.audits <= before.audits {
		t.Fatal("one callback did not conserve its original transaction/capability and exactly one lifecycle effect")
	}
	replayed, replayErr := x.completion.SigninCallback(ctx, x.request)
	if replayErr == nil && replayed.Completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("replay reported a success without the original durable commit")
	}
	if x.posts.Load() != 1 || replayed.Issuance.Token != (session.Token{}) || replayed.Issuance.Cookie.Name != "" || replayed.CSRF != (session.CSRFToken{}) || replayed.RedirectURI != "" {
		t.Fatal("terminal callback replay repeated exchange or disclosed fresh browser custody")
	}
	if nativeProviderLoginCounts(t, x.start) != after {
		t.Fatal("terminal callback replay repeated a durable effect")
	}
	assertNativeCallbackJourneyLocalSessionAndLogout(t, x, got, bearer, csrfWire)
}

type nativeCallbackJourneyLogoutPolicy struct {
	tenant identity.TenantID
	user   identity.UserID
}

func (p nativeCallbackJourneyLogoutPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	decision := authorization.Decision{Outcome: authorization.Deny, Revision: 1}
	if c.PolicyRevision == 1 && c.Request.Tenant == authorization.TenantID(p.tenant) &&
		c.Request.Subject.Kind == authorization.SubjectUser && c.Request.Subject.ID == authorization.SubjectID(p.user) &&
		c.Request.Action == "identity.session.revoke-one" && c.Request.Resource.Type == "identity.user" &&
		c.Request.Resource.ID == authorization.ResourceID(p.user) {
		decision.Outcome = authorization.Allow
	}
	return decision, nil
}

func nativeCallbackJourneySessionReader(t *testing.T, x nativeCallbackJourneyFixture, audience string) (*session.SessionService, sessionpg.SSOOIDCSessionAdmission) {
	t.Helper()
	f := x.start.enable.f
	organizations, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	profile := sessionpg.IdentifierAdmissionConfig{GlobalAuthorityID: x.start.config.GlobalAuthorityID, PolicyNamespace: "users",
		Audience: audience, AuthenticationMethod: "sso-oidc", CredentialKind: identity.CredentialProvider, CredentialOwner: "sso"}
	selection := sessionpg.SSOOIDCSessionAdmission{Profile: profile, Authority: organizations}
	reader, err := sessionpg.NewSelectedSessionService(f.pool, sessionpg.SelectedSessionServiceConfig{
		Repository: x.start.config.Session, Admission: sessionpg.SelectedSessionAdmissionConfig{SSOOIDC: &selection},
		Validation: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: audience, Clock: clock.System{},
			MaximumDuration: time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{x.lookup}},
	})
	if err != nil {
		t.Fatal("compose exact enterprise session reader with the actual organization owner", err)
	}
	return reader, selection
}

func assertNativeCallbackJourneyLocalSessionAndLogout(t *testing.T, x nativeCallbackJourneyFixture, issued ssopg.ProviderLoginCallbackResult, bearer, csrfWire string) {
	t.Helper()
	f, ctx := x.start.enable.f, x.start.enable.f.ctx
	spec, _ := issued.Issuance.Session.Bindings()
	reader, selection := nativeCallbackJourneySessionReader(t, x, spec.Audience)
	token, err := session.ParseToken(bearer)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		t.Fatal(err)
	}
	request := session.GetRequest{TenantID: spec.TenantID, Credential: credential}
	authenticated, err := reader.Get(ctx, request)
	if err != nil || !authenticated.Authenticated || authenticated.ValidateAt(time.Now().UTC()) != nil {
		t.Fatal("the callback's exact issued cookie did not authenticate through current native enterprise authority", err)
	}
	actual, err := authenticated.Session.Bindings()
	if err != nil || actual.SessionID != spec.SessionID || actual.UserID != spec.UserID || actual.TenantID != spec.TenantID ||
		actual.FamilyID != spec.FamilyID || actual.Authentication.CredentialID != spec.Authentication.CredentialID {
		t.Fatal("native cookie access selected another session or enterprise account", err)
	}
	policy := nativeCallbackJourneyLogoutPolicy{tenant: spec.TenantID, user: spec.UserID}
	execution := sessionpg.IssueExecutorConfig{Repository: x.start.config.Session, Profile: sessionpg.IssueAdmissionConfig(selection.Profile),
		Coordinator: kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute,
			CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {0xc4}}},
		Authorization: policy, Clock: clock.System{}, PolicyID: "native-enterprise-session", PolicyVersion: 1, AuditRetentionVersion: 1}
	executor, err := sessionpg.NewCookieRevokeOneExecutor(f.pool, sessionpg.RevokeOneExecutorConfig{Execution: execution, Sessions: reader, SSOOIDC: &selection}, []session.CSRFKey{x.csrf})
	if err != nil {
		t.Fatal("compose native enterprise cookie revocation with the same owner selection", err)
	}
	cookie, err := session.NewCookiePolicy(session.CookieConfig{Name: issued.Issuance.Cookie.Name, SameSite: issued.Issuance.Cookie.SameSite})
	if err != nil {
		t.Fatal(err)
	}
	base, err := session.NewSignOutService(reader, executor, session.SignOutConfig{Cookie: cookie, PolicyID: execution.PolicyID, PolicyVersion: execution.PolicyVersion, MaximumDuration: 3 * time.Second})
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
	logoutRequest := session.SignOutRequest{TenantID: spec.TenantID, CommandID: logoutID, CorrelationID: "native-enterprise-local-logout", Transport: session.CredentialCookie, Credential: credential}
	signedOut, err := logout.SignOut(ctx, logoutRequest, csrf)
	if err != nil || !signedOut.SignedOut || !signedOut.ClearCookie || signedOut.ClearBearer || signedOut.CommitOutcome != identity.CommitOutcomeCommitted ||
		signedOut.Cookie.Name != issued.Issuance.Cookie.Name || signedOut.Cookie.Value != "" || signedOut.Cookie.MaxAge != -1 ||
		!signedOut.Cookie.Secure || !signedOut.Cookie.HttpOnly || signedOut.Cookie.Path != "/" {
		t.Fatal("native local logout did not revoke the exact session and return secure cookie deletion", err)
	}
	denied, err := reader.Get(ctx, request)
	if err != nil || denied.Authenticated || denied.Session != (session.Session{}) {
		t.Fatal("the exact issued bearer still authenticates after local cookie logout", err)
	}
	repeated, err := logout.SignOut(ctx, logoutRequest, csrf)
	if err != nil || !repeated.SignedOut || !repeated.ClearCookie || x.posts.Load() != 1 {
		t.Fatal("repeated local logout failed or attempted another provider exchange", err)
	}
	logoutBytes, err := base64.RawURLEncoding.DecodeString(string(logoutID))
	if err != nil {
		t.Fatal(err)
	}
	var transitions, successAudits, events int
	var sessionState, familyState string
	err = f.pool.Raw().QueryRow(ctx, `SELECT s.state,f.state,
(SELECT count(*) FROM organization_sessions.session_revocations WHERE tenant_id=$1 AND command_id=$4 AND session_id=$2 AND before_version=1 AND after_version=2),
(SELECT count(*) FROM audit.records WHERE tenant_id=$1 AND action='identity.session.revoke' AND subject_type='session' AND subject_id=$2 AND correlation_id='native-enterprise-local-logout' AND outcome=$5),
(SELECT count(*) FROM public.identity_outbox_bindings b JOIN public.outbox_messages m ON m.id=b.effect_id WHERE b.tenant_id=$1 AND b.command_id=$4 AND m.topic='session.revoked.v1')
FROM organization_sessions.sessions s JOIN organization_sessions.families f USING(tenant_id,family_id,user_id)
WHERE s.tenant_id=$1 AND s.session_id=$2 AND s.family_id=$3`, string(spec.TenantID), spec.SessionID, spec.FamilyID, logoutBytes, int16(audit.OutcomeSucceeded)).
		Scan(&sessionState, &familyState, &transitions, &successAudits, &events)
	if err != nil || sessionState != "revoked" || familyState != "active" || transitions != 1 || successAudits != 1 || events != 1 {
		t.Fatal("local cookie logout duplicated or omitted exact session, audit or lifecycle effects", err)
	}
}

func logNativeCallbackJourneyFailure(t *testing.T, x nativeCallbackJourneyFixture) {
	t.Helper()
	f, ctx := x.start.enable.f, x.start.enable.f.ctx
	var callback, browser string
	var completed, verifierPresent bool
	err := f.pool.Raw().QueryRow(ctx, `SELECT l.callback_command_id,l.completed_at IS NOT NULL,l.verifier_envelope IS NOT NULL,p.state
FROM sso_providers.login_transactions l JOIN organization_sessions.preauth_transactions p ON p.tenant_id=l.tenant_id AND p.flow_id=$2
WHERE l.start_command_id=$1`, x.started.TransactionID, string(x.start.browser.FlowID)).Scan(&callback, &completed, &verifierPresent, &browser)
	if err != nil {
		t.Logf("callback failure diagnostic: provider_posts=%d; original native custody observation unavailable", x.posts.Load())
		return
	}
	binaryCommand, err := base64.RawURLEncoding.DecodeString(callback)
	if err != nil {
		t.Log("callback failure diagnostic: stored callback identifier is malformed")
		return
	}
	var state, generation, started, ciphertextGeneration, terminal string
	var profile int
	var outputPresent, planPresent, resultPresent bool
	err = f.pool.Raw().QueryRow(ctx, `SELECT COALESCE(state,'foundation'),COALESCE(generation::text,'none'),
COALESCE(preparation_profile::integer,0),COALESCE(preparation_started_generation::text,'none'),
COALESCE(preparation_ciphertext_generation::text,'none'),preparation_ciphertext IS NOT NULL,command_plan IS NOT NULL,result IS NOT NULL,COALESCE(terminal_class,'none')
FROM identity.commands WHERE tenant_id=$1 AND purpose='identity.sso.oidc-callback' AND command_id=$2`, string(x.start.config.TenantID), binaryCommand).
		Scan(&state, &generation, &profile, &started, &ciphertextGeneration, &outputPresent, &planPresent, &resultPresent, &terminal)
	if err != nil {
		t.Logf("callback failure diagnostic: provider_posts=%d; completed=%t; verifier_present=%t; browser=%s; callback journal observation unavailable", x.posts.Load(), completed, verifierPresent, browser)
		return
	}
	t.Logf("callback failure diagnostic: provider_posts=%d; journal=%s; generation=%s; preparation_profile=%d; preparation_started=%s; ciphertext_generation=%s; output_present=%t; plan_present=%t; result_present=%t; terminal=%s; completed=%t; verifier_present=%t; browser=%s",
		x.posts.Load(), state, generation, profile, started, ciphertextGeneration, outputPresent, planPresent, resultPresent, terminal, completed, verifierPresent, browser)
}

func assertNativeCallbackJourneyCommit(t *testing.T, x nativeCallbackJourneyFixture, got ssopg.ProviderLoginCallbackResult, bearer, csrf string) {
	t.Helper()
	f, ctx := x.start.enable.f, x.start.enable.f.ctx
	spec, _ := got.Issuance.Session.Bindings()
	callback := string(got.Completion.Binding.CommandID)
	binaryCommand, err := base64.RawURLEncoding.DecodeString(callback)
	if err != nil {
		t.Fatal(err)
	}
	var completed time.Time
	var verifier []byte
	var callbackID, browserState, grantState string
	var uses int
	err = f.pool.Raw().QueryRow(ctx, `SELECT l.callback_command_id,l.completed_at,l.verifier_envelope,p.state,c.state,c.uses
FROM sso_providers.login_transactions l
JOIN organization_sessions.preauth_transactions p ON p.tenant_id=l.tenant_id AND p.flow_id=$2
JOIN public.capability_identity_one_use c ON c.tenant_id=l.tenant_id AND c.command_id=l.callback_command_id AND c.purpose='identity.sso.oidc-callback'
WHERE l.start_command_id=$1`, x.started.TransactionID, string(x.start.browser.FlowID)).Scan(&callbackID, &completed, &verifier, &browserState, &grantState, &uses)
	if err != nil || callbackID != callback || completed.IsZero() || len(verifier) != 0 || browserState != "consumed" || grantState != "finalized" || uses != 1 {
		t.Fatal("session commit did not consume original browser/state and erase its verifier atomically", err)
	}
	var persisted []byte
	var sessions, families, issuances, audits, events int
	err = f.pool.Raw().QueryRow(ctx, `SELECT convert_to(s.record::text,'UTF8'),
(SELECT count(*) FROM organization_sessions.sessions WHERE tenant_id=$1 AND session_id=$2 AND user_id='owner' AND state='active'),
(SELECT count(*) FROM organization_sessions.families WHERE tenant_id=$1 AND family_id=$3 AND user_id='owner' AND state='active'),
(SELECT count(*) FROM organization_sessions.session_issuances WHERE tenant_id=$1 AND command_id=$4 AND purpose='identity.sso.oidc-callback'),
(SELECT count(*) FROM audit.records WHERE tenant_id=$1 AND action='identity.sso.login' AND correlation_id=$5 AND outcome=$6),
(SELECT count(*) FROM public.identity_outbox_bindings b JOIN public.outbox_messages m ON m.id=b.effect_id WHERE b.tenant_id=$1 AND b.command_id=$4 AND m.topic='session.created.v1')
FROM organization_sessions.sessions s WHERE s.tenant_id=$1 AND s.session_id=$2`, string(spec.TenantID), spec.SessionID, spec.FamilyID, binaryCommand, callback, int16(audit.OutcomeSucceeded)).Scan(&persisted, &sessions, &families, &issuances, &audits, &events)
	if err != nil || sessions != 1 || families != 1 || issuances != 1 || audits != 1 || events != 1 || !bytes.Contains(persisted, []byte(`"CSRF"`)) {
		t.Fatal("native session, CSRF, issuance, success audit and lifecycle did not commit together exactly once", err)
	}
	var durable struct {
		CSRF   session.CSRFStateSpec
		Lookup session.TokenDigest
	}
	if json.Unmarshal(persisted, &durable) != nil {
		t.Fatal("persisted native session lost its digest-only browser metadata")
	}
	csrfState, csrfErr := session.NewCSRFState(durable.CSRF)
	if csrfErr != nil || csrfState.Check(session.CSRFBinding{TenantID: spec.TenantID, SessionID: spec.SessionID, SessionVersion: spec.Version}, got.CSRF, x.csrf) != nil {
		t.Fatal("persisted synchronizer state does not match the disclosed original CSRF token", csrfErr)
	}
	parsed, parseErr := session.ParseToken(bearer)
	digest, digestErr := parsed.Digest(x.lookup, string(spec.TenantID))
	if parseErr != nil || digestErr != nil || digest != spec.Lookup || durable.Lookup != digest {
		t.Fatal("persisted session lookup does not match the disclosed original session bearer")
	}
	var ciphertext []byte
	var user, account, provider, grantVersion, accountVersion string
	err = f.pool.Raw().QueryRow(ctx, `SELECT user_id,account_id,account_provider,token_version::text,account_version::text,token_ciphertext FROM sso_providers.provider_login_token_sets WHERE tenant_id=$1 AND callback_command_id=$2`,
		string(spec.TenantID), callback).Scan(&user, &account, &provider, &grantVersion, &accountVersion, &ciphertext)
	wantProvider, namespaceErr := ssopg.SSOOIDCAccountProviderNamespace(x.start.config.Profiles[0].OrganizationID, x.start.config.Profiles[0].ProviderID)
	if err != nil || namespaceErr != nil || user != "owner" || account != "enterprise-linked-account" || provider != wantProvider || grantVersion != "1" || accountVersion != "1" || len(ciphertext) == 0 {
		t.Fatal("native callback failed to deposit one encrypted grant for its exact linked account", err)
	}
	var finalReceipt, temporaryCiphertextErased, temporaryGenerationErased, vaultRetained bool
	err = f.pool.Raw().QueryRow(ctx, `SELECT j.state='committed' AND j.result_version=1 AND j.terminal_class='committed' AND j.result IS NOT NULL AND j.terminal_at IS NOT NULL,
j.preparation_ciphertext IS NULL,j.preparation_ciphertext_generation IS NULL,octet_length(v.token_ciphertext)>0
FROM identity.commands j JOIN sso_providers.provider_login_token_sets v ON v.tenant_id=j.tenant_id AND v.callback_command_id=$2
WHERE j.tenant_id=$1 AND j.purpose='identity.sso.oidc-callback' AND j.command_id=$3`, string(spec.TenantID), callback, binaryCommand).
		Scan(&finalReceipt, &temporaryCiphertextErased, &temporaryGenerationErased, &vaultRetained)
	if err != nil || !finalReceipt || !temporaryCiphertextErased || !temporaryGenerationErased || !vaultRetained {
		t.Fatal("committed callback retained duplicate temporary token custody or lost the authoritative encrypted vault deposit", err)
	}
	for _, secret := range []string{nativeCallbackJourneyAccessToken, nativeCallbackJourneyRefreshToken, x.idToken, bearer, csrf,
		x.start.browser.FlowCookie.Token(), "native-enterprise-original-code", "native-enterprise-synthetic-client-secret"} {
		if bytes.Contains(ciphertext, []byte(secret)) || bytes.Contains(persisted, []byte(secret)) {
			t.Fatal("provider or browser secret survived in plaintext durable session/token custody")
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
			t.Fatal("provider or browser secret escaped into retained command, audit, outbox or RP custody", err)
		}
	}
}

func TestNativeProviderLoginCallbackJourneyDeniesIneligibleRecipientAndWrongBrowser(t *testing.T) {
	for _, mode := range []string{"missing-link", "social-owned-link", "removed-member", "enrolled-mfa", "missing-mfa", "missing-policy", "wrong-browser", "wrong-redirect", "expired-flow"} {
		t.Run(mode, func(t *testing.T) {
			x := newNativeCallbackJourneyFixture(t, mode)
			request := x.request
			tenant := string(x.start.config.TenantID)
			wantPosts := int32(1)
			switch mode {
			case "missing-link":
				nativeCallbackJourneyExec(t, x.start, `UPDATE identity.accounts SET linked=false WHERE tenant_id=$1 AND account_id='enterprise-linked-account'`, tenant)
			case "social-owned-link":
				nativeCallbackJourneyExec(t, x.start, `UPDATE identity.credential_references SET owner='identity/oauth' WHERE tenant_id=$1 AND credential_id='enterprise-provider-credential'`, tenant)
			case "removed-member":
				nativeCallbackJourneyExec(t, x.start, `UPDATE organization.memberships SET state='removed' WHERE tenant_id=$1 AND organization_id=$2 AND user_id='owner'`, tenant, string(x.start.config.Profiles[0].OrganizationID))
			case "enrolled-mfa":
				nativeCallbackJourneyExec(t, x.start, `UPDATE identity_mfa.factor_authorities SET active_factors=1,version=2 WHERE tenant_id=$1 AND user_id='owner'`, tenant)
			case "missing-mfa":
				nativeCallbackJourneyExec(t, x.start, `DELETE FROM identity_mfa.factor_authorities WHERE tenant_id=$1 AND user_id='owner'`, tenant)
			case "missing-policy":
				nativeCallbackJourneyExec(t, x.start, `DELETE FROM authorization_subject_authorities WHERE tenant_id=$1 AND policy_namespace='users' AND subject_id='owner'`, tenant)
			case "wrong-browser":
				wire := []byte(request.Browser.FlowCookie.Token())
				wire[len(wire)/2] = 'A'
				if bytes.Equal(wire, []byte(request.Browser.FlowCookie.Token())) {
					wire[len(wire)/2] = 'B'
				}
				request.Browser.FlowCookie = authentication.NewBearerCredential(string(wire))
				clear(wire)
				wantPosts = 0
			case "wrong-redirect":
				request.ReceivedRedirectURI = "https://identity.example.test/not-the-original-callback"
				wantPosts = 0
			case "expired-flow":
				wantPosts = 0
			}
			before := nativeProviderLoginCounts(t, x.start)
			var callback string
			if err := x.start.enable.f.pool.Raw().QueryRow(x.start.enable.f.ctx,
				`SELECT callback_command_id FROM sso_providers.login_transactions WHERE start_command_id=$1`, x.started.TransactionID).Scan(&callback); err != nil {
				t.Fatal("read original callback correlation for the denial oracle", err)
			}
			binaryCommand, err := base64.RawURLEncoding.DecodeString(callback)
			if err != nil {
				t.Fatal(err)
			}
			effectsBefore := nativeCallbackJourneyDenialEffects(t, x, callback, binaryCommand)
			if effectsBefore.deposits != 0 || effectsBefore.successAudits != 0 || effectsBefore.sessionEvents != 0 {
				t.Fatal("new pending callback already has success effects before invocation")
			}
			definitiveRecipient := mode == "missing-link" || mode == "removed-member"
			var originalCustody nativeCallbackRefusalCustody
			if definitiveRecipient {
				originalCustody = readNativeCallbackRefusalCustody(t, x, callback, binaryCommand)
				if originalCustody.completed != nil || len(originalCustody.verifier) == 0 {
					t.Fatal("known-negative recipient fixture has no original pending verifier custody")
				}
			}
			got, err := x.completion.SigninCallback(x.start.enable.f.ctx, request)
			if err == nil || got.Completion.Outcome == identity.CommitOutcomeCommitted || got.Issuance.Token != (session.Token{}) ||
				got.Issuance.Cookie.Name != "" || got.CSRF != (session.CSRFToken{}) || got.RedirectURI != "" || x.posts.Load() != wantPosts {
				t.Fatal("ineligible recipient or substituted browser produced successful native issuance", err)
			}
			effectsAfter := nativeCallbackJourneyDenialEffects(t, x, callback, binaryCommand)
			if effectsAfter != effectsBefore || nativeProviderLoginCounts(t, x.start).events != before.events {
				t.Fatalf("denied callback changed durable success effects: sessions=%d/%d; callback_deposits=%d/%d; callback_success_audits=%d/%d; callback_session_events=%d/%d",
					effectsBefore.sessions, effectsAfter.sessions, effectsBefore.deposits, effectsAfter.deposits,
					effectsBefore.successAudits, effectsAfter.successAudits, effectsBefore.sessionEvents, effectsAfter.sessionEvents)
			}
			if definitiveRecipient {
				assertNativeCallbackRefusalWithholdsIssuance(t, got)
				if got.Completion.Outcome != identity.CommitOutcomeNotCommitted || got.Completion.Validate() != nil || string(got.Completion.Binding.CommandID) != callback {
					t.Fatal("verified provider with a known missing link/member did not return its original native NotCommitted receipt", err)
				}
				terminal := readNativeCallbackRefusalCustody(t, x, callback, binaryCommand)
				assertNativeCallbackRefusalOriginalBinding(t, originalCustody, terminal)
				if terminal.completed == nil || len(terminal.verifier) != 0 || len(terminal.binding) == 0 || len(terminal.binding) > 65536 ||
					terminal.journalState != "aborted" || !terminal.finalReceipt || terminal.output || terminal.outputGeneration {
					t.Fatal("known-negative recipient failed to atomically terminalize original RP/journal custody and erase its verifier/temporary output")
				}
				if _, err := envelope.ParseEnvelope(terminal.binding); err != nil {
					t.Fatal("known-negative recipient lost bounded encrypted original correlation", err)
				}
				replayed, _ := x.completion.SigninCallback(x.start.enable.f.ctx, request)
				assertNativeCallbackRefusalWithholdsIssuance(t, replayed)
				if x.posts.Load() != 1 || replayed.Completion.Outcome == identity.CommitOutcomeCommitted ||
					nativeCallbackJourneyDenialEffects(t, x, callback, binaryCommand) != effectsBefore {
					t.Fatal("known-negative recipient retry exchanged again, disclosed credentials or created domain success")
				}
				replayedCustody := readNativeCallbackRefusalCustody(t, x, callback, binaryCommand)
				assertNativeCallbackRefusalOriginalBinding(t, terminal, replayedCustody)
				if replayedCustody.completed == nil || !terminal.completed.Equal(*replayedCustody.completed) ||
					!bytes.Equal(terminal.binding, replayedCustody.binding) || len(replayedCustody.verifier) != 0 ||
					replayedCustody.journalState != "aborted" || !replayedCustody.finalReceipt || replayedCustody.output || replayedCustody.outputGeneration {
					t.Fatal("known-negative recipient retry changed its original terminal correlation or restored erased custody")
				}
			}
		})
	}
}

type nativeCallbackJourneyEffects struct{ sessions, deposits, successAudits, sessionEvents int }

func nativeCallbackJourneyDenialEffects(t *testing.T, x nativeCallbackJourneyFixture, callback string, binaryCommand []byte) nativeCallbackJourneyEffects {
	t.Helper()
	var effects nativeCallbackJourneyEffects
	// Start also records identity.sso.login for successful initiation, and risk
	// admission has its separate decision audit even if later lookup denies.
	// Callback success needs its exact command correlation and bound lifecycle.
	err := x.start.enable.f.pool.Raw().QueryRow(x.start.enable.f.ctx, `SELECT
(SELECT count(*) FROM organization_sessions.sessions WHERE tenant_id=$1),
(SELECT count(*) FROM sso_providers.provider_login_token_sets WHERE tenant_id=$1 AND callback_command_id=$2),
(SELECT count(*) FROM audit.records WHERE tenant_id=$1 AND action='identity.sso.login' AND subject_type='sso_login_transaction' AND subject_id=$3 AND correlation_id=$2 AND outcome=$4),
(SELECT count(*) FROM public.identity_outbox_bindings b JOIN public.outbox_messages m ON m.id=b.effect_id
 WHERE b.tenant_id=$1 AND b.command_id=$5 AND m.topic='session.created.v1')`,
		string(x.start.config.TenantID), callback, x.started.TransactionID, int16(audit.OutcomeSucceeded), binaryCommand).
		Scan(&effects.sessions, &effects.deposits, &effects.successAudits, &effects.sessionEvents)
	if err != nil {
		t.Fatal("inspect exact callback success effects around native denial", err)
	}
	return effects
}
