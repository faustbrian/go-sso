//go:build integration

package postgres_test

import (
	"bytes"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	organization "github.com/faustbrian/go-organization"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

type providerOAuthLoginStartFixture struct {
	providerLoginStartFixture
	profile     ssopg.StaticOAuth2LoginProfile
	router      *ssopg.ProviderRouter
	providers   *ssopg.ProviderService
	oidcBrowser ssopg.ProviderLoginBrowser
}

func newProviderOAuthLoginStartFixture(t *testing.T) providerOAuthLoginStartFixture {
	t.Helper()
	x := newProviderLoginStartFixture(t)
	installProviderOAuthLoginStartHistory(t, x.enable.f)
	providers, err := x.enable.service.WithOAuthRegistration()
	if err != nil {
		t.Fatal("select native OAuth registry", err)
	}
	providers, err = providers.WithProviderDisableAuthorization(providerDisablePolicy{})
	if err != nil {
		t.Fatal("select native OAuth lifecycle authority", err)
	}
	registered, err := providers.ProviderRegisterOauth(x.enable.f.ctx, providerOAuthRegistrationRequest(t, string(x.enable.proof.OrganizationID)))
	if err != nil || registered.Completion.Outcome != identity.CommitOutcomeCommitted || registered.Provider.Protocol != "oauth2" || registered.Provider.Enabled {
		t.Fatal("commit disabled OAuth provider", err)
	}
	credential := nativeCredentialRequestForTenant(t, x.enable.f, x.config.TenantID, x.enable.config, registered.Provider.ID, 1, 1)
	binding := credential.CredentialReference.Context()
	binding.Protocol = "oauth2"
	aad, err := binding.EncryptionContext()
	if err != nil {
		t.Fatal(err)
	}
	secret := bytes.Repeat([]byte{0x39}, 32)
	defer clear(secret)
	sealed, err := x.config.Envelope.Encrypt(x.enable.f.ctx, envelope.EncryptRequest{Plaintext: secret, KeyReference: binding.EnvelopeKeyID, Context: aad})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := sealed.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	credential.CredentialReference, err = sso.NewEncryptedCredentialReference(x.enable.f.ctx, x.config.Envelope, wire, binding)
	if err != nil {
		t.Fatal(err)
	}
	installed, err := nativeCredentialService(t, providers).ProviderCredentialsRotate(x.enable.f.ctx, credential)
	if err != nil || installed.Completion.Outcome != identity.CommitOutcomeCommitted || installed.Version != 2 {
		t.Fatal("commit OAuth credential installation", err)
	}
	checkpoint, err := providers.ObserveOAuth2ProviderCredentialCheckpoint(x.enable.f.ctx, registered.Provider.ID, 2)
	if err != nil {
		t.Fatal("observe installed OAuth credential", err)
	}
	key, err := identity.NewIdempotencyKey([]byte("oauth-login-start-provider-enable"))
	if err != nil {
		t.Fatal(err)
	}
	enabled, err := providers.ProviderEnable(x.enable.f.ctx, sso.ProviderEnableRequest{
		ProviderID: registered.Provider.ID, ExpectedVersion: 2, CredentialCheckpoint: checkpoint, IdempotencyKey: key,
		DomainProofCheckpoint: sso.DomainProofCheckpoint{Key: organization.DomainProofKey(x.enable.proof), ProofVersion: x.enable.proof.ProofVersion},
	})
	if err != nil || enabled.Completion.Outcome != identity.CommitOutcomeCommitted || !enabled.Provider.Enabled || enabled.Provider.Version != 3 {
		t.Fatal("commit OAuth provider activation", err)
	}
	router, err := newProviderRouter(t, x.enable, 4).WithProtocolRegistry()
	if err != nil {
		t.Fatal(err)
	}
	profile := ssopg.StaticOAuth2LoginProfile{
		ProviderID: sso.ProviderID(enabled.Provider.ID), OrganizationID: x.enable.proof.OrganizationID, Domain: x.enable.proof.Domain,
		ClientID: "native-oauth-client", ProtocolRedirectURI: "https://identity.example.test/sso/oauth/callback",
		ProviderVersion: 3, CredentialGeneration: 1, MappingVersion: 2, Scopes: []string{"read:identity", "email"},
	}
	oidcBrowser := x.browser
	x.browser, x.originalFlow = issueProviderOAuthLoginBrowser(t, x)
	x.request.ProviderID = enabled.Provider.ID
	x.config.Profiles = nil
	x.service, err = ssopg.NewProviderLoginServiceWithOAuth2(router, x.config, []ssopg.StaticOAuth2LoginProfile{profile})
	if err != nil {
		t.Fatal("compose OAuth-only native login with explicit protocol registry", err)
	}
	return providerOAuthLoginStartFixture{providerLoginStartFixture: x, profile: profile, router: router, providers: providers, oidcBrowser: oidcBrowser}
}

func issueProviderOAuthLoginBrowser(t *testing.T, x providerLoginStartFixture) (ssopg.ProviderLoginBrowser, session.PreAuthBinding) {
	t.Helper()
	const action = "identity.sso.oauth-callback"
	c := x.config
	executor, err := sessionpg.NewPreAuthIssueExecutor(x.enable.f.pool, sessionpg.PreAuthIssueExecutorConfig{
		Repository: c.Session, Coordinator: c.Coordinator, Authorization: providerLoginPolicy{}, Clock: clock.System{},
		ActorID: c.ActorID, Action: action, Origin: c.Origin, CallbackURL: x.request.SuccessCallback.String(),
		PolicyID: c.PolicyID, PolicyVersion: 1, AuditRetentionVersion: 1,
	})
	if err != nil {
		t.Fatal("compose original OAuth browser issuance", err)
	}
	cookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_flow", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := session.NewPreAuthIssuer(executor, session.PreAuthIssuerConfig{
		ActorID: c.ActorID, Action: action, Origin: c.Origin, CallbackURL: x.request.SuccessCallback.String(),
		PolicyID: c.PolicyID, PolicyVersion: 1, Clock: clock.System{}, MaximumDuration: 4 * time.Second,
		FlowTTL: 5 * time.Minute, LookupKey: c.FlowKeys[0], TokenSize: 32, Cookie: cookie,
	})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := issuer.Prepare(session.PreAuthPrepareInput{
		CommandID: commandID(t), TenantID: c.TenantID, CorrelationID: "native-oauth-original-browser", Remember: x.originalFlow.Intent.Remember,
	})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := issuer.Issue(x.enable.f.ctx, prepared)
	if err != nil || issued.CommitOutcome != identity.CommitOutcomeCommitted || issued.Replayed {
		t.Fatal("commit original OAuth preauth browser", err)
	}
	flow, err := issued.Flow.Bindings()
	if err != nil || flow.Binding.Intent.Action != action || flow.Binding.Intent.CallbackURL != x.request.SuccessCallback.String() || flow.Binding.Intent.Remember != x.originalFlow.Intent.Remember {
		t.Fatal("OAuth preauth lost original callback, action or remember intent", err)
	}
	wire, err := issued.Token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	browser := x.browser
	browser.FlowID, browser.FlowCookie = flow.Binding.ID, authentication.NewBearerCredential(wire)
	return browser, flow.Binding
}

func installProviderOAuthLoginStartHistory(t *testing.T, f *orgFixture) {
	t.Helper()
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
	history := append(migrationList(nil), f.history...)
	for _, source := range []migrations.Source{
		ssopg.ProviderProtocolMigrationSource{Version: 337, ValidationVersion: 338},
		ssopg.LoginTransactionProtocolMigrationSource{Version: 339, ValidationVersion: 340},
	} {
		loaded, err := source.Load(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		history = append(history, loaded...)
	}
	runner, err := migrations.NewRunner(history, backend)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := runner.Up(f.ctx); err != nil {
			t.Fatal("install or replay additive provider and login protocol history", err)
		}
	}
	f.history = history
}

func TestNativeOAuth2SigninStartCommitsExactRedirectCustodyAndRestartReplay(t *testing.T) {
	x := newProviderOAuthLoginStartFixture(t)
	f := x.enable.f
	before := nativeProviderLoginCounts(t, x.providerLoginStartFixture)
	started, err := x.service.SigninStartOAuth2(f.ctx, x.request, x.browser)
	if err != nil || started.Completion.Outcome != identity.CommitOutcomeCommitted || started.ProviderID != x.request.ProviderID || started.Protocol != "oauth2" {
		t.Fatal("OAuth start did not acknowledge committed native custody", err)
	}
	canonical, err := identity.ParseCommandID(started.TransactionID)
	if err != nil || canonical == x.request.CommandID || canonical != started.Completion.Binding.CommandID || started.TransactionID != started.Completion.Binding.RecordID || started.Completion.Binding.SchemaID != "identity.sso.signin-start.oauth2-v1" {
		t.Fatal("OAuth start lost its sole canonical server-owned command", err)
	}
	redirect := started.RedirectURI
	query := redirect.Query()
	want := url.Values{
		"client_id": {x.profile.ClientID}, "redirect_uri": {x.profile.ProtocolRedirectURI}, "scope": {"read:identity email"},
		"response_type": {"code"}, "response_mode": {"query"}, "code_challenge_method": {"S256"},
		"state": {query.Get("state")}, "code_challenge": {query.Get("code_challenge")},
	}
	if redirect.Scheme != "https" || redirect.Host != "provider.example.com" || redirect.Path != "/authorize" ||
		query.Encode() != want.Encode() || len(query.Get("state")) != 43 || len(query.Get("code_challenge")) != 43 || query.Has("nonce") {
		t.Fatal("OAuth redirect changed exact code/query/S256 selection or emitted OIDC material")
	}
	var tenant, organizationID, provider, version, generation, mapping, protocol, callback string
	var stateKey, pkceKey int64
	var stateDigest, commitment, binding, verifier []byte
	var issued, expires time.Time
	err = f.pool.Raw().QueryRow(f.ctx, `SELECT tenant_id,organization_id,provider_id,provider_version::text,credential_generation::text,mapping_version::text,protocol,callback_command_id,state_key_version,state_digest,pkce_key_version,pkce_commitment,binding_envelope,verifier_envelope,issued_at,expires_at
FROM sso_providers.login_transactions WHERE start_command_id=$1`, started.TransactionID).Scan(
		&tenant, &organizationID, &provider, &version, &generation, &mapping, &protocol, &callback, &stateKey, &stateDigest, &pkceKey, &commitment, &binding, &verifier, &issued, &expires)
	if err != nil || tenant != string(x.config.TenantID) || organizationID != string(x.profile.OrganizationID) || provider != x.request.ProviderID ||
		version != "3" || generation != "1" || mapping != "2" || protocol != "oauth2" || callback == started.TransactionID ||
		stateKey != 1 || pkceKey != 1 || len(stateDigest) != 32 || len(commitment) != 32 || len(binding) == 0 || len(verifier) == 0 || bytes.Equal(binding, verifier) {
		t.Fatal("OAuth custody lost exact tenant/provider/protocol/version or separate verifier ownership", err)
	}
	if _, err := identity.ParseCommandID(callback); err != nil {
		t.Fatal("OAuth custody did not reserve a distinct canonical callback command", err)
	}
	for _, ciphertext := range [][]byte{binding, verifier} {
		if _, err := envelope.ParseEnvelope(ciphertext); err != nil || bytes.Contains(ciphertext, []byte(query.Get("state"))) || bytes.Contains(ciphertext, []byte(query.Get("code_challenge"))) || bytes.Contains(ciphertext, []byte(x.browser.FlowCookie.Token())) {
			t.Fatal("OAuth custody exposed browser/protocol material instead of sealed envelopes", err)
		}
	}
	wantExpiry := issued.Add(x.config.StateLifetime)
	if x.originalFlow.ExpiresAt.Before(wantExpiry) {
		wantExpiry = x.originalFlow.ExpiresAt
	}
	if !issued.Equal(issued.UTC().Truncate(time.Second)) || issued.Before(x.originalFlow.IssuedAt.Truncate(time.Second)) || !expires.Equal(wantExpiry.UTC().Truncate(time.Second)) || !expires.After(issued) {
		t.Fatal("OAuth start renewed or exceeded the original browser expiry")
	}
	var grants, oidcGrants, audits, events int
	err = f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT count(*) FROM public.capability_identity_one_use WHERE tenant_id=$1 AND purpose='identity.sso.oauth-callback' AND expires_at=$2),
 (SELECT count(*) FROM public.capability_identity_one_use WHERE tenant_id=$1 AND purpose='identity.sso.oidc-callback'),
 (SELECT count(*) FROM audit.records WHERE tenant_id=$1 AND action='identity.sso.login' AND correlation_id=$3 AND outcome=1),
 (SELECT count(*) FROM outbox_messages WHERE topic='oauth.rp_transaction.created.v1')`, tenant, expires, started.TransactionID).Scan(&grants, &oidcGrants, &audits, &events)
	if err != nil || grants != 1 || oidcGrants != 0 || audits != 1 || events != 1 {
		t.Fatal("OAuth start omitted or duplicated its matching capability, login audit or lifecycle event", err)
	}
	after := nativeProviderLoginCounts(t, x.providerLoginStartFixture)
	if after.transactions != before.transactions+1 || after.capabilities != before.capabilities+1 || after.events != before.events+1 || after.attempts != before.attempts+1 {
		t.Fatal("OAuth start did not conserve one durable native admission")
	}
	restarted, err := ssopg.NewProviderLoginServiceWithOAuth2(x.router, x.config, []ssopg.StaticOAuth2LoginProfile{x.profile})
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := restarted.SigninStartOAuth2(f.ctx, x.request, x.browser)
	if err != nil || !reflect.DeepEqual(started, replayed) || nativeProviderLoginCounts(t, x.providerLoginStartFixture) != after {
		t.Fatal("restart replay changed redirect or repeated durable OAuth custody", err)
	}
	var replayIssued, replayExpires time.Time
	var replayBinding, replayVerifier []byte
	err = f.pool.Raw().QueryRow(f.ctx, `SELECT issued_at,expires_at,binding_envelope,verifier_envelope FROM sso_providers.login_transactions WHERE start_command_id=$1`, started.TransactionID).Scan(&replayIssued, &replayExpires, &replayBinding, &replayVerifier)
	if err != nil || !issued.Equal(replayIssued) || !expires.Equal(replayExpires) || !bytes.Equal(binding, replayBinding) || !bytes.Equal(verifier, replayVerifier) {
		t.Fatal("restart replay renewed or replaced original OAuth material", err)
	}
	changed := x.request
	changed.ErrorCallback = x.request.SuccessCallback
	denied, err := restarted.SigninStartOAuth2(f.ctx, changed, x.browser)
	if err == nil || denied.RedirectURI != (url.URL{}) || denied.TransactionID != "" {
		t.Fatal("changed continuation recovered the original OAuth redirect", err)
	}
	if got := nativeProviderLoginCounts(t, x.providerLoginStartFixture); got.transactions != after.transactions || got.capabilities != after.capabilities || got.events != after.events {
		t.Fatal("changed continuation created replacement OAuth authority")
	}
}

func TestNativeOAuth2SigninStartRollsBackWhenOutboxRejects(t *testing.T) {
	x := newProviderOAuthLoginStartFixture(t)
	f := x.enable.f
	if _, err := f.pool.Raw().Exec(f.ctx, `CREATE SEQUENCE sso_providers.oauth_start_effect_fault;
CREATE FUNCTION sso_providers.reject_oauth_start_effect() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 PERFORM nextval('sso_providers.oauth_start_effect_fault');
 RAISE EXCEPTION 'controlled OAuth start effect rollback';
END $$;
CREATE TRIGGER reject_oauth_start_effect BEFORE INSERT ON public.outbox_messages FOR EACH ROW
 WHEN (NEW.topic='oauth.rp_transaction.created.v1')
 EXECUTE FUNCTION sso_providers.reject_oauth_start_effect()`); err != nil {
		t.Fatal(err)
	}
	before := nativeProviderLoginCounts(t, x.providerLoginStartFixture)
	out, err := x.service.SigninStartOAuth2(f.ctx, x.request, x.browser)
	if err == nil || out.Completion.Outcome == identity.CommitOutcomeCommitted || out.RedirectURI != (url.URL{}) || out.TransactionID != "" {
		t.Fatal("failed transactional outbox disclosed an OAuth redirect", err)
	}
	var reached bool
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT is_called FROM sso_providers.oauth_start_effect_fault`).Scan(&reached); err != nil || !reached {
		t.Fatal("outbox failure was not reached by native OAuth start", err)
	}
	after := nativeProviderLoginCounts(t, x.providerLoginStartFixture)
	if after.transactions != before.transactions || after.capabilities != before.capabilities || after.events != before.events || nativeProviderLoginSuccessAudits(t, x.providerLoginStartFixture) != 0 {
		t.Fatal("failed transactional outbox left partial OAuth custody or success effects")
	}
}

func TestNativeOAuth2SigninStartRecoversLostAcknowledgement(t *testing.T) {
	x := newProviderOAuthLoginStartFixture(t)
	router, fault := providerLoginLossRouter(t, x.providerLoginStartFixture)
	router, err := router.WithProtocolRegistry()
	if err != nil {
		t.Fatal(err)
	}
	service, err := ssopg.NewProviderLoginServiceWithOAuth2(router, x.config, []ssopg.StaticOAuth2LoginProfile{x.profile})
	if err != nil {
		t.Fatal(err)
	}
	ctx := x.enable.f.ctx
	before := nativeProviderLoginCounts(t, x.providerLoginStartFixture)
	out, err := service.SigninStartOAuth2(ctx, x.request, x.browser)
	var unknown identity.UnknownCommitError
	if !fault.seen.Load() || !fault.lost.Load() || !errors.As(err, &unknown) || out.Completion.Outcome != identity.CommitOutcomeUnknown || out.RedirectURI != (url.URL{}) || out.TransactionID != "" {
		t.Fatal("lost OAuth commit acknowledgement returned a redirect or lost its authoritative outcome", err)
	}
	command := out.Completion.Binding.CommandID
	if command == "" || unknown.CommandID != command || out.Completion.Binding.RecordID != string(command) {
		t.Fatal("lost OAuth acknowledgement lost the original canonical command")
	}
	committed := nativeProviderLoginCounts(t, x.providerLoginStartFixture)
	if committed.transactions != before.transactions+1 || committed.capabilities != before.capabilities+1 || committed.events != before.events+1 || committed.attempts != before.attempts+1 || nativeProviderLoginSuccessAudits(t, x.providerLoginStartFixture) != 1 {
		t.Fatal("lost OAuth acknowledgement did not leave exactly one durable start")
	}
	original := nativeProviderLoginCustody(t, x.providerLoginStartFixture, command)
	recovered, err := x.service.SigninStartOAuth2(ctx, x.request, x.browser)
	if err != nil || recovered.Completion.Outcome != identity.CommitOutcomeCommitted || recovered.Completion.Binding != out.Completion.Binding || recovered.TransactionID != string(command) || recovered.Protocol != "oauth2" || len(recovered.RedirectURI.Query().Get("state")) != 43 || recovered.RedirectURI.Query().Has("nonce") {
		t.Fatal("OAuth retry did not recover the original committed redirect", err)
	}
	if nativeProviderLoginCounts(t, x.providerLoginStartFixture) != committed || !reflect.DeepEqual(nativeProviderLoginCustody(t, x.providerLoginStartFixture, command), original) {
		t.Fatal("OAuth retry repeated effects or renewed original custody")
	}
}

func TestNativeOAuth2SigninStartRejectsWrongBrowserProtocolAndImplicitSelection(t *testing.T) {
	x := newProviderOAuthLoginStartFixture(t)
	if service, err := ssopg.NewProviderLoginServiceWithOAuth2(newProviderRouter(t, x.enable, 4), x.config, []ssopg.StaticOAuth2LoginProfile{x.profile}); err == nil || service != nil {
		t.Fatal("OAuth constructor silently selected an unconfigured protocol registry", err)
	}
	wrongCookie := x.browser
	wrongCookie.FlowCookie = x.oidcBrowser.FlowCookie
	missingProvider, missingDomain, oidcProvider := x.request, x.request, x.request
	missingProvider.ProviderID, missingDomain.Domain = "", ""
	oidcProvider.ProviderID = x.enable.request.ProviderID
	before := nativeProviderLoginCounts(t, x.providerLoginStartFixture)
	for _, test := range []struct {
		name    string
		request sso.SigninStartRequest
		browser ssopg.ProviderLoginBrowser
	}{
		{"OIDC original flow", x.request, x.oidcBrowser},
		{"wrong original cookie", x.request, wrongCookie},
		{"missing explicit provider", missingProvider, x.browser},
		{"missing explicit domain", missingDomain, x.browser},
		{"OIDC provider selection", oidcProvider, x.browser},
	} {
		t.Run(test.name, func(t *testing.T) {
			denied, err := x.service.SigninStartOAuth2(x.enable.f.ctx, test.request, test.browser)
			if err == nil || denied.RedirectURI != (url.URL{}) || denied.TransactionID != "" {
				t.Fatal("unbound or cross-protocol input received an OAuth redirect", err)
			}
		})
	}
	if denied, err := x.service.SigninStart(x.enable.f.ctx, x.request, x.browser); err == nil || denied.RedirectURI != (url.URL{}) || denied.TransactionID != "" {
		t.Fatal("OIDC entry point admitted OAuth provider/browser authority", err)
	}
	after := nativeProviderLoginCounts(t, x.providerLoginStartFixture)
	if after.transactions != before.transactions || after.capabilities != before.capabilities || after.events != before.events {
		t.Fatal("rejected OAuth browser or implicit selection created login authority")
	}
}

func TestNativeOAuth2SigninStartRejectsStaleProfileAndDisabledProvider(t *testing.T) {
	x := newProviderOAuthLoginStartFixture(t)
	before := nativeProviderLoginCounts(t, x.providerLoginStartFixture)
	for _, field := range []string{"provider version", "credential generation", "mapping version"} {
		t.Run(field, func(t *testing.T) {
			stale := x.profile
			switch field {
			case "provider version":
				stale.ProviderVersion++
			case "credential generation":
				stale.CredentialGeneration++
			case "mapping version":
				stale.MappingVersion++
			}
			service, err := ssopg.NewProviderLoginServiceWithOAuth2(x.router, x.config, []ssopg.StaticOAuth2LoginProfile{stale})
			if err != nil {
				t.Fatal("compose stale deployment for current-authority refusal", err)
			}
			denied, err := service.SigninStartOAuth2(x.enable.f.ctx, x.request, x.browser)
			if !errors.Is(err, sso.ErrForbidden) || denied.RedirectURI != (url.URL{}) || denied.TransactionID != "" {
				t.Fatal("stale OAuth deployment received a redirect", err)
			}
		})
	}
	after := nativeProviderLoginCounts(t, x.providerLoginStartFixture)
	if after.transactions != before.transactions || after.capabilities != before.capabilities || after.events != before.events {
		t.Fatal("stale OAuth deployment created login authority")
	}
	disabled, err := x.providers.ProviderDisableOAuth2(x.enable.f.ctx, nativeProviderDisableRequest(t, x.providerLoginStartFixture, sso.ActiveTransactionRevoke))
	if err != nil || disabled.Completion.Outcome != identity.CommitOutcomeCommitted || !disabled.Disabled {
		t.Fatal("commit real OAuth provider disablement", err)
	}
	before = nativeProviderLoginCounts(t, x.providerLoginStartFixture)
	denied, err := x.service.SigninStartOAuth2(x.enable.f.ctx, x.request, x.browser)
	if !errors.Is(err, sso.ErrForbidden) || denied.RedirectURI != (url.URL{}) || denied.TransactionID != "" {
		t.Fatal("disabled OAuth provider received a redirect", err)
	}
	after = nativeProviderLoginCounts(t, x.providerLoginStartFixture)
	if after.transactions != before.transactions || after.capabilities != before.capabilities || after.events != before.events {
		t.Fatal("disabled OAuth provider created login authority")
	}
}
