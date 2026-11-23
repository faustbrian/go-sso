//go:build integration

package postgres_test

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	"github.com/faustbrian/go-sso"
	"github.com/faustbrian/go-sso/oidc"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

const nativeLogoutFinalRedirect = "https://app.example.test/signed-out"

func nativeProviderLogoutCallback(x nativeCallbackJourneyFixture) string {
	return x.start.config.Origin + "/sso/oidc/" + string(x.start.config.Profiles[0].ProviderID) + "/logout/callback"
}

type nativeProviderLogoutPolicy struct{}

func (nativeProviderLogoutPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	if c.PolicyRevision == 1 && c.Request.Tenant == authorization.TenantID(discoveryFixtureTenant) &&
		c.Request.Subject.Kind == authorization.SubjectServiceAccount && c.Request.Subject.ID == "native-sso-login" &&
		c.Request.Action == "identity.sso.oidc-logout-complete" &&
		c.Request.Resource.Type == "identity.user" && c.Request.Resource.ID == "owner" {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
	}
	if c.PolicyRevision == 1 && c.Request.Tenant == authorization.TenantID(discoveryFixtureTenant) &&
		c.Request.Subject.Kind == authorization.SubjectUser && c.Request.Subject.ID == "owner" &&
		c.Request.Action == "identity.sso.oidc-logout" {
		resource := c.Request.Resource
		if resource.Type == "identity.request-admission" && resource.ID == "identity.sso.oidc-logout" ||
			resource.Type == "identity.user" && resource.ID == "owner" {
			return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
		}
	}
	return (nativeCallbackJourneyPolicy{}).Decide(ctx, c)
}

type nativeProviderLogoutFixture struct {
	journey      nativeCallbackJourneyFixture
	service      *ssopg.ProviderLogoutService
	loginConfig  ssopg.ProviderLoginConfig
	logoutConfig ssopg.ProviderLogoutConfig
	reader       *session.SessionService
	request      ssopg.ProviderLogoutStartRequest
	browser      ssopg.ProviderLogoutBrowser
	session      session.SessionSpec
	get          session.GetRequest
	other        session.GetRequest
}

func newNativeProviderLogoutFixture(t *testing.T, remoteProfile bool, traces ...*providerTrace) nativeProviderLogoutFixture {
	t.Helper()
	x := newNativeCallbackJourneyFixture(t, "linked-member")
	installNativeProviderLogoutStartMigrations(t, x.start.enable.f)
	issued, err := x.completion.SigninCallback(x.start.enable.f.ctx, x.request)
	if err != nil || issued.Completion.Outcome != identity.CommitOutcomeCommitted || issued.Issuance.CommitOutcome != identity.CommitOutcomeCommitted {
		t.Fatal("issue the original enterprise cookie through the real linked-member callback", err)
	}
	spec, err := issued.Issuance.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	bearer, err := issued.Issuance.Token.Reveal()
	if err != nil || bearer == "" {
		t.Fatal("disclose the acknowledged native enterprise cookie", err)
	}
	reader, admission := nativeCallbackJourneySessionReader(t, x, spec.Audience)
	get := nativeProviderLogoutGetRequest(t, spec.TenantID, bearer)
	otherCallback := x.newAttempt(t, "native-logout-unrelated-session", nil, time.Time{})
	other, err := x.completion.SigninCallback(x.start.enable.f.ctx, otherCallback)
	if err != nil || other.Issuance.CommitOutcome != identity.CommitOutcomeCommitted {
		t.Fatal("issue a second real cookie to prove logout is session-scoped", err)
	}
	otherBearer, err := other.Issuance.Token.Reveal()
	if err != nil || otherBearer == "" {
		t.Fatal("disclose the independent session cookie", err)
	}
	policy := kernel.CommandQueryPolicy{Authorization: nativeProviderLogoutPolicy{}, Clock: clock.System{}, PolicyVersion: 1}
	config := x.start.config
	config.Coordinator.AdmissionPolicy, config.Coordinator.QueryPolicy = &policy, &policy
	config.RequestKeys, err = kernel.NewRequestKeyConfig("native-sso-login", [32]byte{0xa2}, policy)
	if err != nil {
		t.Fatal(err)
	}
	router := newProviderRouter(t, x.start.enable, 4)
	if len(traces) > 0 {
		router = nativeProviderLogoutTracedRouter(t, x.start.enable, traces[0])
	}
	login, err := ssopg.NewProviderLoginService(router, config)
	if err != nil {
		t.Fatal("compose native logout with exact user request-admission and self policy", err)
	}
	logoutConfig := ssopg.ProviderLogoutConfig{
		Session: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: spec.Audience,
			Clock: clock.System{}, MaximumDuration: time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{x.lookup}},
		Admission: admission, CSRFKeys: []session.CSRFKey{x.csrf}, FinalRedirectAllowlist: []string{nativeLogoutFinalRedirect},
	}
	if remoteProfile {
		profile := config.Profiles[0]
		logoutConfig.Profiles = []ssopg.ProviderLogoutProfile{{OrganizationID: profile.OrganizationID, ProviderID: profile.ProviderID,
			Protocol: oidc.RPLogoutProfileConfig{Issuer: nativeCallbackJourneyIssuer, ClientID: profile.ClientID,
				EndSessionEndpoint: nativeCallbackJourneyIssuer + "/end-session", CallbackURI: nativeProviderLogoutCallback(x)}}}
	}
	service, err := ssopg.NewProviderLogoutService(login, logoutConfig)
	if err != nil {
		t.Fatal("compose native cookie logout using the installed provider and actual session owner", err)
	}
	key, err := identity.NewIdempotencyKey([]byte("native-enterprise-logout-start"))
	if err != nil {
		t.Fatal(err)
	}
	return nativeProviderLogoutFixture{journey: x, service: service, loginConfig: config, logoutConfig: logoutConfig, reader: reader, session: spec, get: get,
		other:   nativeProviderLogoutGetRequest(t, spec.TenantID, otherBearer),
		request: ssopg.ProviderLogoutStartRequest{ProviderID: string(config.Profiles[0].ProviderID), IdempotencyKey: key, FinalRedirect: nativeLogoutFinalRedirect},
		browser: ssopg.ProviderLogoutBrowser{Session: authentication.NewBearerCredential(bearer), CSRF: issued.CSRF, Origin: config.Origin}}
}

func nativeProviderLogoutGetRequest(t *testing.T, tenant identity.TenantID, bearer string) session.GetRequest {
	t.Helper()
	token, err := session.ParseToken(bearer)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		t.Fatal(err)
	}
	return session.GetRequest{TenantID: tenant, Credential: credential}
}

func installNativeProviderLogoutStartMigrations(t *testing.T, f *orgFixture) {
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
		sessionpg.SSOOIDCLogoutMigrationSource{Schema: "organization_sessions", Version: 357, ValidationVersion: 358, PreviousConstraint: "session_revocations_purpose_check"},
		ssopg.ProviderLogoutMigrationSource{Version: 360},
	} {
		steps, err := source.Load(f.ctx)
		if err != nil {
			t.Fatal("load additive native logout prerequisites", err)
		}
		history = append(history, steps...)
	}
	runner, err := migrations.NewRunner(history, backend)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := runner.Up(f.ctx); err != nil {
			t.Fatal("install and replay native logout consumer migration composition", err)
		}
	}
}

func TestNativeProviderLogoutStartRevokesExactCookieBeforeDisclosingProviderRedirect(t *testing.T) {
	x := newNativeProviderLogoutFixture(t, true)
	ctx := x.journey.start.enable.f.ctx
	got, err := x.service.Start(ctx, x.request, x.browser)
	if err != nil || got.Validate() != nil || got.Outcome() != oidc.OIDCLogoutRedirect {
		t.Fatal("native logout did not acknowledge the provider redirect after local revocation", err)
	}
	redirect, present := got.RedirectURI()
	query := redirect.Query()
	if !present || redirect.Scheme != "https" || redirect.Host != nativeCallbackJourneyHost || redirect.Path != "/end-session" ||
		len(query) != 3 || query.Get("client_id") != "native-sso-client" || query.Get("post_logout_redirect_uri") != nativeProviderLogoutCallback(x.journey) || len(query.Get("state")) != 43 {
		t.Fatal("logout substituted the pinned end-session endpoint, client, callback or original opaque state")
	}
	completion, err := got.Completion()
	if err != nil || completion.Outcome != identity.CommitOutcomeCommitted || completion.Binding.OperationID != "identity.sso.oidc-logout" ||
		completion.Binding.UserID != x.session.UserID || completion.Binding.RecordID != x.session.SessionID {
		t.Fatal("logout did not retain the original exact-session native command receipt", err)
	}
	assertNativeProviderLogoutCookieState(t, x, false)
	assertNativeProviderLogoutStartCommit(t, x, completion, query.Get("state"), true)
	before := nativeProviderLogoutStartCounts(t, x)
	repeated, err := x.service.Start(ctx, x.request, x.browser)
	if err != nil || repeated.Validate() != nil || repeated.Outcome() != oidc.OIDCLogoutRedirect {
		t.Fatal("exact start retry lost the original committed logout authorization", err)
	}
	repeatedRedirect, present := repeated.RedirectURI()
	repeatedCompletion, receiptErr := repeated.Completion()
	if !present || repeatedRedirect.String() != redirect.String() || receiptErr != nil || repeatedCompletion.Binding != completion.Binding ||
		nativeProviderLogoutStartCounts(t, x) != before || x.journey.posts.Load() != 2 {
		t.Fatal("exact logout retry replaced state, repeated durable work or contacted the provider")
	}
}

func TestNativeProviderLogoutStartLostCommitRecoversOnlyOriginalState(t *testing.T) {
	x := newNativeProviderLogoutFixture(t, true)
	ctx := x.journey.start.enable.f.ctx
	service, fault := nativeProviderLogoutWithCommitFault(t, x, "INSERT INTO sso_providers.logout_transactions")
	got, err := service.Start(ctx, x.request, x.browser)
	if err != nil || !fault.seen.Load() || !fault.lost.Load() || got.Validate() != nil || got.Outcome() != oidc.OIDCLogoutUnknownReconciliation {
		t.Fatal("lost start COMMIT acknowledgement did not preserve uncertainty", err)
	}
	if _, present := got.RedirectURI(); present {
		t.Fatal("start disclosed provider state without acknowledgement")
	}
	unknown, err := got.Completion()
	if err != nil || unknown.Outcome != identity.CommitOutcomeUnknown {
		t.Fatal("unacknowledged start lost its original command identity", err)
	}
	assertNativeProviderLogoutCookieState(t, x, false)
	before := nativeProviderLogoutStartCounts(t, x)
	changed := x.request
	changed.IdempotencyKey, err = identity.NewIdempotencyKey([]byte("other-enterprise-logout-start"))
	if err != nil {
		t.Fatal(err)
	}
	if other, err := x.service.Start(ctx, changed, x.browser); !errors.Is(err, sso.ErrForbidden) || other.Validate() == nil {
		t.Fatal("revoked original cookie authorized a different logout command", err)
	}
	got, err = x.service.Start(ctx, x.request, x.browser)
	if err != nil || got.Validate() != nil || got.Outcome() != oidc.OIDCLogoutRedirect {
		t.Fatal("keyed retry failed to recover the original committed provider redirect", err)
	}
	redirect, present := got.RedirectURI()
	recovered, err := got.Completion()
	if err != nil || !present || len(redirect.Query().Get("state")) != 43 || recovered.Binding != unknown.Binding || nativeProviderLogoutStartCounts(t, x) != before {
		t.Fatal("keyed retry disclosed a different command or created extra durable effects", err)
	}
	assertNativeProviderLogoutStartCommit(t, x, recovered, redirect.Query().Get("state"), true)
}

func nativeProviderLogoutWithCommitFault(t *testing.T, x nativeProviderLogoutFixture, target string) (*ssopg.ProviderLogoutService, *providerCommitFault) {
	t.Helper()
	pool, fault := providerLossPool(t, x.journey.start.enable.f, target)
	f := *x.journey.start.enable.f
	f.pool = pool
	enabled := x.journey.start.enable
	enabled.f = &f
	login, err := ssopg.NewProviderLoginService(newProviderRouter(t, enabled, 4), x.loginConfig)
	if err != nil {
		t.Fatal("compose logout with a controlled lost database acknowledgement", err)
	}
	service, err := ssopg.NewProviderLogoutService(login, x.logoutConfig)
	if err != nil {
		t.Fatal(err)
	}
	return service, fault
}

func TestNativeProviderLogoutStartDeniesWrongBrowserOrProviderWithoutConsumingCookie(t *testing.T) {
	x := newNativeProviderLogoutFixture(t, true)
	wrongCSRF, err := session.NewCSRFToken()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"wrong-csrf", "wrong-provider", "wrong-origin", "unregistered-final-redirect"} {
		t.Run(mode, func(t *testing.T) {
			request, browser := x.request, x.browser
			switch mode {
			case "wrong-csrf":
				browser.CSRF = wrongCSRF
			case "wrong-provider":
				request.ProviderID = "another-enterprise-provider"
			case "wrong-origin":
				browser.Origin = "https://another-app.example.test"
			case "unregistered-final-redirect":
				request.FinalRedirect = "https://another-app.example.test/signed-out"
			}
			before := nativeProviderLogoutStartCounts(t, x)
			got, err := x.service.Start(x.journey.start.enable.f.ctx, request, browser)
			if _, disclosed := got.RedirectURI(); err == nil || disclosed || got.Outcome() != oidc.OIDCLogoutInvalid || got.Validate() == nil {
				t.Fatal("invalid logout input disclosed a provider redirect or claimed local success")
			}
			after := nativeProviderLogoutStartCounts(t, x)
			if after.states != before.states || after.revocations != before.revocations || x.journey.posts.Load() != 2 {
				t.Fatal("denied logout created state, revoked a session or contacted the provider")
			}
			assertNativeProviderLogoutCookieState(t, x, true)
		})
	}
	got, err := x.service.Start(x.journey.start.enable.f.ctx, x.request, x.browser)
	if err != nil || got.Outcome() != oidc.OIDCLogoutRedirect {
		t.Fatal("denied attempts consumed the original cookie or idempotency key", err)
	}
	assertNativeProviderLogoutCookieState(t, x, false)
}

func TestNativeProviderLogoutStartWithoutSelectedRemoteProfileIsLocalOnly(t *testing.T) {
	x := newNativeProviderLogoutFixture(t, false)
	got, err := x.service.Start(x.journey.start.enable.f.ctx, x.request, x.browser)
	if err != nil || got.Validate() != nil || got.Outcome() != oidc.OIDCLogoutLocalOnly {
		t.Fatal("an enabled provider without a selected logout profile did not settle local-only", err)
	}
	if _, disclosed := got.RedirectURI(); disclosed {
		t.Fatal("local-only logout claimed a provider redirect")
	}
	completion, err := got.Completion()
	if err != nil || completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("local-only logout omitted the native local-revocation receipt", err)
	}
	assertNativeProviderLogoutCookieState(t, x, false)
	assertNativeProviderLogoutStartCommit(t, x, completion, "", false)
	if nativeProviderLogoutStartCounts(t, x).states != 0 || x.journey.posts.Load() != 2 {
		t.Fatal("local-only logout retained provider state or made a provider call")
	}
}

func assertNativeProviderLogoutCookieState(t *testing.T, x nativeProviderLogoutFixture, active bool) {
	t.Helper()
	ctx := x.journey.start.enable.f.ctx
	got, err := x.reader.Get(ctx, x.get)
	if err != nil || got.Authenticated != active || !active && got.Session != (session.Session{}) {
		t.Fatal("original cookie usability disagrees with the native logout disposition", err)
	}
	other, err := x.reader.Get(ctx, x.other)
	if err != nil || !other.Authenticated || other.ValidateAt(time.Now().UTC()) != nil {
		t.Fatal("logout invalidated another session or its shared family/member authority", err)
	}
}

type nativeProviderLogoutCounts struct{ states, revocations, commands, audits, events int }

func nativeProviderLogoutStartCounts(t *testing.T, x nativeProviderLogoutFixture) nativeProviderLogoutCounts {
	t.Helper()
	var n nativeProviderLogoutCounts
	err := x.journey.start.enable.f.pool.Raw().QueryRow(x.journey.start.enable.f.ctx, `SELECT
 (SELECT count(*) FROM sso_providers.logout_transactions),
 (SELECT count(*) FROM organization_sessions.session_revocations WHERE purpose='identity.sso.oidc-logout'),
 (SELECT count(*) FROM identity.commands WHERE purpose='identity.sso.oidc-logout'),
 (SELECT count(*) FROM audit.records),
 (SELECT count(*) FROM public.outbox_messages)`).Scan(&n.states, &n.revocations, &n.commands, &n.audits, &n.events)
	if err != nil {
		t.Fatal("observe durable native logout effects without exposing browser state", err)
	}
	return n
}

func assertNativeProviderLogoutStartCommit(t *testing.T, x nativeProviderLogoutFixture, completion identity.CommandResult, state string, remote bool) {
	t.Helper()
	command, err := base64.RawURLEncoding.DecodeString(string(completion.Binding.CommandID))
	if err != nil {
		t.Fatal(err)
	}
	var revoked, audits, events, states int
	var family string
	err = x.journey.start.enable.f.pool.Raw().QueryRow(x.journey.start.enable.f.ctx, `SELECT
 (SELECT count(*) FROM organization_sessions.session_revocations WHERE tenant_id=$1 AND session_id=$2 AND command_id=$3 AND purpose='identity.sso.oidc-logout' AND before_version=1 AND after_version=2),
 (SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.tenant_id=$1 AND b.command_id=$3 AND r.action='identity.sso.logout_oidc' AND r.outcome=$4),
 (SELECT count(*) FROM public.identity_outbox_bindings b JOIN public.outbox_messages m ON m.id=b.effect_id WHERE b.tenant_id=$1 AND b.command_id=$3 AND m.topic='session.revoked.v1'),
 (SELECT count(*) FROM sso_providers.logout_transactions WHERE tenant_id=$1 AND start_command_id=$3 AND octet_length(binding_envelope)>0 AND completed_at IS NULL),
 (SELECT state FROM organization_sessions.families WHERE tenant_id=$1 AND family_id=$5)`,
		string(x.session.TenantID), x.session.SessionID, command, int16(audit.OutcomeSucceeded), x.session.FamilyID).
		Scan(&revoked, &audits, &events, &states, &family)
	wantStates := 0
	if remote {
		wantStates = 1
	}
	if err != nil || revoked != 1 || audits != 1 || events != 1 || states != wantStates || family != "active" {
		t.Fatal("logout did not atomically retain one scoped revocation, protected audit, lifecycle and encrypted provider state", err)
	}
	csrf, err := x.browser.CSRF.Reveal()
	if err != nil {
		t.Fatal("read the original synchronizer token for plaintext exclusion", err)
	}
	secrets := [][]byte{[]byte(x.browser.Session.Token()), []byte(csrf), []byte(nativeCallbackJourneyAccessToken), []byte(nativeCallbackJourneyRefreshToken), []byte(x.journey.idToken)}
	if state != "" {
		raw, err := base64.RawURLEncoding.Strict().DecodeString(state)
		if err != nil || len(raw) != 32 {
			t.Fatal("provider redirect state was not canonical 32-byte entropy", err)
		}
		secrets = append(secrets, []byte(state), raw)
	}
	for _, secret := range secrets {
		var leaked bool
		err := x.journey.start.enable.f.pool.Raw().QueryRow(x.journey.start.enable.f.ctx, `SELECT EXISTS(SELECT 1 FROM (
 SELECT result AS wire FROM identity.commands WHERE result IS NOT NULL
 UNION ALL SELECT preparation_ciphertext FROM identity.commands WHERE preparation_ciphertext IS NOT NULL
 UNION ALL SELECT canonical_record FROM audit.records
 UNION ALL SELECT payload FROM public.outbox_messages
 UNION ALL SELECT binding_envelope FROM sso_providers.logout_transactions
 UNION ALL SELECT state_digest FROM sso_providers.logout_transactions
 ) stored WHERE position($1::bytea in wire)>0)`, secret).Scan(&leaked)
		if err != nil || leaked {
			t.Fatal("native logout persisted plaintext provider state or browser/provider credentials", err)
		}
	}
}
