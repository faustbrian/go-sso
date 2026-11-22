//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

const providerLoginRiskSchema = "provider_login_risk"

type providerLoginPolicy struct{}

func (providerLoginPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	decision := authorization.Decision{Outcome: authorization.Deny, Revision: 1}
	if c.PolicyRevision == 1 && c.Request.Tenant == authorization.TenantID(discoveryFixtureTenant) &&
		c.Request.Subject.Kind == authorization.SubjectServiceAccount && c.Request.Subject.ID == "native-sso-login" &&
		(c.Request.Action == "identity.session.preauth-issue" || c.Request.Action == "identity.sso.signin-start") {
		decision.Outcome = authorization.Allow
	}
	return decision, nil
}

type providerLoginStartFixture struct {
	enable       providerEnableFixture
	service      *ssopg.ProviderLoginService
	request      sso.SigninStartRequest
	browser      ssopg.ProviderLoginBrowser
	config       ssopg.ProviderLoginConfig
	originalFlow session.PreAuthBinding
	flowIssuer   *session.PreAuthIssuer
}

func newProviderLoginStartFixture(t *testing.T) providerLoginStartFixture {
	t.Helper()
	x := newProviderEnableFixtureForTenant(t, discoveryFixtureTenant,
		riskpg.DurableCounterMigrationSource{Schema: providerLoginRiskSchema, Version: 318},
	)
	provider := enableRouteFixture(t, x, false)
	installProviderLoginStartMigrations(t, x.f)

	const origin = "https://app.example.test"
	callback := url.URL{Scheme: "https", Host: "app.example.test", Path: "/sso/complete", RawQuery: "next=exact%2Fpath"}
	failure := url.URL{Scheme: "https", Host: "app.example.test", Path: "/sso/error"}
	remember, err := session.NewRememberPolicy(session.RememberPolicySpec{
		Choice: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute,
		RefreshAfter: 5 * time.Minute, FreshFor: 15 * time.Minute,
	})
	if err != nil {
		t.Fatal("resolve original login intent", err)
	}
	intent, err := sso.NewLoginIntent(remember)
	if err != nil {
		t.Fatal(err)
	}
	policy := kernel.CommandQueryPolicy{Authorization: providerLoginPolicy{}, Clock: clock.System{}, PolicyVersion: 1}
	coordinator := kernel.CoordinatorConfig{
		MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute,
		CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {0xa1}},
		QueryPolicy: &policy, AdmissionPolicy: &policy,
	}
	requestKeys, err := kernel.NewRequestKeyConfig("native-sso-login", [32]byte{0xa2}, policy)
	if err != nil {
		t.Fatal(err)
	}
	flowKey, err := session.NewDigestKey(1, bytes.Repeat([]byte{0xa3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	sessionConfig := sessionpg.Config{Schema: "organization_sessions", MaximumDuration: time.Second}
	executor, err := sessionpg.NewPreAuthIssueExecutor(x.f.pool, sessionpg.PreAuthIssueExecutorConfig{
		Repository: sessionConfig, Coordinator: coordinator, Authorization: providerLoginPolicy{}, Clock: clock.System{},
		ActorID: "native-sso-login", Action: "identity.sso.oidc-callback", Origin: origin, CallbackURL: callback.String(),
		PolicyID: "native-sso-login", PolicyVersion: 1, AuditRetentionVersion: 1,
	})
	if err != nil {
		t.Fatal("compose original native preauth issuance", err)
	}
	cookiePolicy, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_flow", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := session.NewPreAuthIssuer(executor, session.PreAuthIssuerConfig{
		ActorID: "native-sso-login", Action: "identity.sso.oidc-callback", Origin: origin, CallbackURL: callback.String(),
		PolicyID: "native-sso-login", PolicyVersion: 1, Clock: clock.System{}, MaximumDuration: 4 * time.Second,
		FlowTTL: 5 * time.Minute, LookupKey: flowKey, TokenSize: 32, Cookie: cookiePolicy,
	})
	if err != nil {
		t.Fatal("compose commit-gated browser cookie", err)
	}
	prepared, err := issuer.Prepare(session.PreAuthPrepareInput{
		CommandID: commandID(t), TenantID: x.proof.TenantID, CorrelationID: "native-sso-original-browser", Remember: remember,
	})
	if err != nil {
		t.Fatal("prepare original browser", err)
	}
	issued, err := issuer.Issue(x.f.ctx, prepared)
	if err != nil || issued.CommitOutcome != identity.CommitOutcomeCommitted || issued.Replayed {
		t.Fatal("issue original browser through native coordinator", err)
	}
	flow, err := issued.Flow.Bindings()
	if err != nil || flow.Binding.Intent.Action != "identity.sso.oidc-callback" || flow.Binding.Intent.CallbackURL != callback.String() || flow.Binding.Intent.Remember != remember {
		t.Fatal("original browser lost exact callback or session intent", err)
	}
	wire, err := issued.Token.Reveal()
	if err != nil {
		t.Fatal(err)
	}

	signing := bytes.Repeat([]byte{0xa4}, 32)
	signer, err := capability.NewHMACSHA256Signer("native-sso-signing", signing)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := capability.NewHMACSHA256Verifier(signing)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := capability.NewKeySet([]capability.Key{{Issuer: "https://identity.example.test", ID: "native-sso-signing", Verifier: verifier}})
	if err != nil {
		t.Fatal(err)
	}
	wall := func() time.Time { return time.Now().UTC() }
	config := ssopg.ProviderLoginConfig{
		TenantID: x.proof.TenantID, ActorID: "native-sso-login", Origin: origin, PolicyID: "native-sso-login",
		GlobalAuthorityID: "organization-tests", ConfigurationID: "native-sso-login-v1",
		CallbackAllowlist: []string{callback.String(), failure.String()},
		Profiles: []ssopg.StaticOIDCLoginProfile{{
			ProviderID: provider, OrganizationID: x.proof.OrganizationID, Domain: x.proof.Domain,
			ClientID: "native-sso-client", ProtocolRedirectURI: "https://identity.example.test/sso/callback",
			ProviderVersion: 3, CredentialGeneration: 1, MappingVersion: 1, Scopes: []string{"openid", "email"},
		}},
		Session: sessionConfig, FlowKeys: []session.DigestKey{flowKey},
		Risk: providerLoginAdmission(t, x), Coordinator: coordinator, RequestKeys: requestKeys,
		Capability: capabilitypg.IssuerConfig{
			Crypto:   capability.ServiceConfig{Issuer: "https://identity.example.test", Signer: signer, Resolver: keys, Clock: wall, Limits: capability.DefaultLimits()},
			Audience: "identity", CurrentReplayKeyVersion: 1, RetainedReplayKeys: map[uint32][32]byte{1: {0xa5}}, PreparationTimeout: time.Second,
		},
		CapabilityPreparation: capabilitypg.IssuancePreparationConfig{
			Deployment: "native-sso-login", ActiveEnvelopeKey: "checkpoint", EnvelopeKeys: map[string][]byte{"checkpoint": bytes.Repeat([]byte{0xa6}, 32)},
			VerificationKeys: []capabilitypg.PreparationVerificationKey{{ID: "native-sso-signing", HMAC: signing}}, Clock: wall,
		},
		Envelope: x.config.Envelope, KeyReference: x.config.KeyReference,
		StateKeys: map[uint32][32]byte{1: {0xa7}}, CurrentStateKey: 1,
		PKCEKeys: map[uint32][32]byte{1: {0xa8}}, CurrentPKCEKey: 1,
		AuditRetentionPolicyVersion: 1, StateLifetime: 10 * time.Minute,
	}
	service, err := ssopg.NewProviderLoginService(newProviderRouter(t, x, 4), config)
	if err != nil {
		t.Fatal("compose native provider login", err)
	}
	idempotency, err := identity.NewIdempotencyKey([]byte("native-sso-original-start"))
	if err != nil {
		t.Fatal(err)
	}
	return providerLoginStartFixture{
		enable: x, service: service, config: config, originalFlow: flow.Binding, flowIssuer: issuer,
		request: sso.SigninStartRequest{CommandID: commandID(t), ProviderID: string(provider), Domain: x.proof.Domain, SuccessCallback: callback, ErrorCallback: failure, LoginIntent: intent, IdempotencyKey: idempotency},
		browser: ssopg.ProviderLoginBrowser{FlowID: flow.Binding.ID, FlowCookie: authentication.NewBearerCredential(wire), Origin: origin, Network: netip.MustParseAddr("192.0.2.84"), Device: "verified-native-login-browser"},
	}
}

func installProviderLoginStartMigrations(t *testing.T, f *orgFixture) {
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
	history := append(migrationList{}, f.history...)
	for _, source := range []migrations.Source{
		ssopg.ProviderUpdateMigrationSource{Version: 321},
		ssopg.ProviderCredentialsMigrationSource{Version: 322},
		ssopg.ProviderEnableMigrationSource{Version: 323},
		ssopg.LoginTransactionMigrationSource{Version: 324},
		sessionpg.PreAuthMigrationSource{Schema: "organization_sessions", Version: 325},
		sessionpg.PreAuthIssueMigrationSource{Schema: "organization_sessions", Version: 326},
	} {
		loaded, err := source.Load(f.ctx)
		if err != nil {
			t.Fatal("load ordered native login migration", err)
		}
		history = append(history, loaded...)
	}
	history = append(history, migrationBundle(t, 327, "native_sso_login_capability", capabilitypg.Migrations(), ""))
	accounts := kernel.AccountMigrationSource{Base: history, Version: 328}
	preparedLink := kernel.AccountLinkPreparationMigrationSource{Base: accounts, Version: 329}
	rpErasure := kernel.OAuthRPPreparationErasureMigrationSource{Base: preparedLink, Version: 330}
	linkErasure := kernel.AccountLinkPreparationErasureMigrationSource{Base: rpErasure, Version: 331}
	linkValidated := kernel.AccountLinkPreparationErasureValidationMigrationSource{Base: linkErasure, Version: 332}
	unlink := kernel.AccountUnlinkPreparationMigrationSource{Base: linkValidated, Version: 333}
	unlinkValidated := kernel.AccountUnlinkPreparationValidationMigrationSource{Base: unlink, Version: 334}
	refreshErasure := kernel.OAuthProviderRefreshErasureMigrationSource{Base: unlinkValidated, Version: 335}
	complete, err := (kernel.SSOOIDCPreparationErasureMigrationSource{Base: refreshErasure, Version: 336}).Load(f.ctx)
	if err != nil {
		t.Fatal("load original provider preparation erasure history", err)
	}
	runner, err := migrations.NewRunner(migrationList(complete), backend)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := runner.Up(f.ctx); err != nil {
			t.Fatal("install or replay ordered native login migrations", err)
		}
	}
	f.history = append(migrationList(nil), complete...)
}

func providerLoginAdmission(t *testing.T, x providerEnableFixture) risk.AuthenticationAdmissionCustodyConfig {
	t.Helper()
	policy, err := risk.NewPolicy(risk.PolicyConfig{Version: 1,
		Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour},
		Profiles: []risk.Profile{
			{Class: risk.Authentication, Phase: risk.BeforeCredential, Dimensions: []risk.Dimension{risk.TenantDimension, risk.NetworkDimension, risk.DeviceDimension, risk.IdentifierDimension}, Window: 5 * time.Minute, Limit: 10, ThresholdAction: risk.Throttle, EvidenceTTL: 20 * time.Second, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status", "velocity"}},
			{Class: risk.CredentialMutation, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectDimension, risk.SessionDimension, risk.NetworkDimension}, Window: 15 * time.Minute, Limit: 5, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status", "velocity"}},
			{Class: risk.Privileged, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.ActorDimension, risk.ResourceDimension, risk.NetworkDimension}, Window: time.Hour, Limit: 20, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status", "velocity"}},
			{Class: risk.StateNeutralRead, Phase: risk.BeforeReturn, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectOrNetworkDimension}, Window: time.Minute, Limit: 120, ThresholdAction: risk.Throttle, EvidenceTTL: time.Minute, Unknown: risk.StepUpWithIndependentFactor, MaxCounters: 2, RequiredSignals: []string{"status", "velocity"}},
		},
	})
	if err != nil {
		t.Fatal("construct native login risk policy", err)
	}
	counterKey, err := risk.NewCounterDigestKey(1, bytes.Repeat([]byte{0xb1}, 32))
	if err != nil {
		t.Fatal("construct native login risk dimension key", err)
	}
	counters, err := riskpg.NewDurableCounterStore(riskpg.DurableCounterConfig{
		Pool: x.f.pool, Schema: providerLoginRiskSchema, Namespace: "native-sso-login", Policy: policy,
		Keys: []risk.CounterDigestKey{counterKey}, ReplayKey: bytes.Repeat([]byte{0xb2}, 32),
		Tenants: []string{string(x.proof.TenantID)}, MaximumRecords: 64, Timeout: time.Second,
	})
	if err != nil {
		t.Fatal("construct native login durable risk counters", err)
	}
	wall := func() time.Time { return time.Now().UTC() }
	coordinator, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: policy, Store: counters, Clock: wall, Keys: []risk.CounterDigestKey{counterKey}, Timeout: time.Second})
	if err != nil {
		t.Fatal("construct native login risk counter coordinator", err)
	}
	audits, err := auditpg.New(x.f.pool.Raw(), auditpg.Config{})
	if err != nil {
		t.Fatal("construct native login risk audit sink", err)
	}
	policyID := commandID(t)
	evaluator, err := risk.NewEvaluator(risk.EvaluatorConfig{
		Policy: policy, Clock: wall, Timeout: 2 * time.Second, Counters: &coordinator,
		Sources: []risk.Source{{Name: "status", Version: "native-login-status-v1", Timeout: time.Second, Read: func(ctx context.Context, c risk.Context) (risk.Signal, error) {
			if err := ctx.Err(); err != nil {
				return risk.Signal{}, err
			}
			return risk.Signal{Tenant: c.Tenant, Operation: c.Operation, Attempt: c.Attempt, Name: "status", State: risk.SignalClean, Trust: risk.ServerVerified, ObservedAt: c.Now, ExpiresAt: c.Now.Add(20 * time.Second)}, nil
		}}},
		DecisionAudit: &risk.DecisionAuditConfig{
			PolicyID: string(policyID), Timeout: time.Second, Delivery: audit.RecorderConfig{Sink: audits, Mode: audit.DeliveryFailClosed},
			OnLoss: func(context.Context, risk.DecisionDelivery) error {
				return errors.New("native login audit unavailable")
			},
		},
	})
	if err != nil {
		t.Fatal("construct native login counted audited risk evaluator", err)
	}
	evidence, err := risk.NewEvidenceKey(1, bytes.Repeat([]byte{0xb3}, 32), bytes.Repeat([]byte{0xb4}, 32))
	if err != nil {
		t.Fatal("construct native login risk custody key", err)
	}
	return risk.AuthenticationAdmissionCustodyConfig{Evaluation: evaluator, ConfigurationID: "native-sso-login-risk-v1", Keys: []risk.EvidenceKey{evidence}}
}

type providerLoginCounts struct{ transactions, capabilities, audits, events, attempts int }

func nativeProviderLoginCounts(t *testing.T, x providerLoginStartFixture) providerLoginCounts {
	t.Helper()
	var counts providerLoginCounts
	err := x.enable.f.pool.Raw().QueryRow(x.enable.f.ctx, `SELECT
 (SELECT count(*) FROM sso_providers.login_transactions),
 (SELECT count(*) FROM public.capability_identity_one_use),
 (SELECT count(*) FROM audit.records),
 (SELECT count(*) FROM public.outbox_messages),
 (SELECT count(*) FROM provider_login_risk.durable_counter_attempts)`).Scan(&counts.transactions, &counts.capabilities, &counts.audits, &counts.events, &counts.attempts)
	if err != nil {
		t.Fatal("inspect native login effects", err)
	}
	return counts
}

func TestNativeProviderSigninStartCommitsExactBrowserBoundRedirectAndReplay(t *testing.T) {
	x := newProviderLoginStartFixture(t)
	ctx := x.enable.f.ctx
	before := nativeProviderLoginCounts(t, x)
	started, err := x.service.SigninStart(ctx, x.request, x.browser)
	if err != nil || started.Completion.Outcome != identity.CommitOutcomeCommitted || started.ProviderID != x.request.ProviderID || started.Protocol != "oidc" {
		t.Fatal("current native provider did not commit the original browser login", err)
	}
	canonicalCommand, err := identity.ParseCommandID(started.TransactionID)
	if err != nil || canonicalCommand == x.request.CommandID || canonicalCommand != started.Completion.Binding.CommandID || started.TransactionID != started.Completion.Binding.RecordID {
		t.Fatal("login transaction did not use the sole server-owned command identity", err)
	}
	redirect := started.RedirectURI
	query := redirect.Query()
	if redirect.Scheme != "https" || redirect.Host != "enable.example.com" || redirect.Path != "/authorize" ||
		query.Get("client_id") != "native-sso-client" || query.Get("redirect_uri") != x.config.Profiles[0].ProtocolRedirectURI ||
		query.Get("response_type") != "code" || query.Get("scope") != "openid email" || query.Get("code_challenge_method") != "S256" ||
		query.Get("state") == "" || query.Get("nonce") == "" || len(query.Get("code_challenge")) != 43 {
		t.Fatal("committed redirect lost exact OIDC or S256 binding")
	}
	var tenant, organization, provider, version, generation, mapping, start, callback string
	var stateKey, pkceKey int64
	var stateDigest, commitment, binding, verifier []byte
	var issued, expires time.Time
	err = x.enable.f.pool.Raw().QueryRow(ctx, `SELECT tenant_id,organization_id,provider_id,provider_version::text,credential_generation::text,mapping_version::text,start_command_id,callback_command_id,state_key_version,state_digest,pkce_key_version,pkce_commitment,binding_envelope,verifier_envelope,issued_at,expires_at FROM sso_providers.login_transactions WHERE start_command_id=$1`, string(canonicalCommand)).Scan(&tenant, &organization, &provider, &version, &generation, &mapping, &start, &callback, &stateKey, &stateDigest, &pkceKey, &commitment, &binding, &verifier, &issued, &expires)
	if err != nil || tenant != string(x.enable.proof.TenantID) || organization != string(x.enable.proof.OrganizationID) || provider != x.request.ProviderID || version != "3" || generation != "1" || mapping != "1" || start != string(canonicalCommand) || callback == start || stateKey != 1 || pkceKey != 1 || len(stateDigest) != 32 || len(commitment) != 32 || len(binding) == 0 || len(verifier) == 0 {
		t.Fatal("login custody did not retain the exact selected provider generation", err)
	}
	wantExpiry := issued.Add(x.config.StateLifetime)
	if x.originalFlow.ExpiresAt.Before(wantExpiry) {
		wantExpiry = x.originalFlow.ExpiresAt
	}
	wantExpiry = wantExpiry.UTC().Truncate(time.Second)
	if !issued.Equal(issued.UTC().Truncate(time.Second)) || issued.Before(x.originalFlow.IssuedAt.Truncate(time.Second)) || !expires.Equal(wantExpiry) || !expires.After(issued) {
		t.Fatal("state lifetime outlived or renewed the original browser-flow deadline")
	}
	if _, err := identity.ParseCommandID(callback); err != nil || bytes.Contains(binding, []byte(query.Get("state"))) || bytes.Contains(verifier, []byte(query.Get("code_challenge"))) {
		t.Fatal("login custody exposed protocol material or lost callback identity")
	}
	origin, success, failure, remember, err := ssopg.InspectOriginalLoginIntentForTest(ctx, x.service, x.config.TenantID, query.Get("state"))
	wantRemember, rememberErr := x.originalFlow.Intent.Remember.Bindings()
	if err != nil || rememberErr != nil || origin != x.browser.Origin || success != x.request.SuccessCallback.String() ||
		failure != x.request.ErrorCallback.String() || remember != wantRemember {
		t.Fatal("tenant and returned state could not select the original sealed continuation", err)
	}
	if _, _, _, _, err := ssopg.InspectOriginalLoginIntentForTest(ctx, x.service, "foreign-login-tenant", query.Get("state")); err == nil {
		t.Fatal("another tenant found the original login continuation")
	}
	after := nativeProviderLoginCounts(t, x)
	if after.transactions != before.transactions+1 || after.capabilities != before.capabilities+1 || after.audits <= before.audits || after.events != before.events+1 || after.attempts != before.attempts+1 {
		t.Fatal("one start did not conserve native transaction, capability, audit, lifecycle and risk effects")
	}
	replayService, err := ssopg.NewProviderLoginService(newProviderRouter(t, x.enable, 4), x.config)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := replayService.SigninStart(ctx, x.request, x.browser)
	if err != nil || !reflect.DeepEqual(started, replayed) {
		t.Fatal("same complete command did not recover the identical redirect and transaction", err)
	}
	if nativeProviderLoginCounts(t, x) != after {
		t.Fatal("same-command restart replay repeated native durable effects")
	}
	var replayIssued, replayExpires time.Time
	err = x.enable.f.pool.Raw().QueryRow(ctx, `SELECT issued_at,expires_at FROM sso_providers.login_transactions WHERE start_command_id=$1`, string(canonicalCommand)).Scan(&replayIssued, &replayExpires)
	if err != nil || !replayIssued.Equal(issued) || !replayExpires.Equal(expires) {
		t.Fatal("same-command restart replay renewed original state custody", err)
	}

	changed := x.request
	changedRemember, err := session.NewRememberPolicy(session.RememberPolicySpec{Choice: session.PersistentSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: 5 * time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	changed.LoginIntent, err = sso.NewLoginIntent(changedRemember)
	if err != nil {
		t.Fatal(err)
	}
	if denied, err := replayService.SigninStart(ctx, changed, x.browser); err == nil || denied.RedirectURI != (url.URL{}) || denied.TransactionID != "" {
		t.Fatal("changed remembered login intent recovered an original redirect", err)
	}
	wrongBrowser := x.browser
	wrongToken, err := session.NewToken(32)
	if err != nil {
		t.Fatal(err)
	}
	wrongWire, err := wrongToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	wrongBrowser.FlowCookie = authentication.NewBearerCredential(wrongWire)
	if denied, err := replayService.SigninStart(ctx, x.request, wrongBrowser); err == nil || denied.RedirectURI != (url.URL{}) || denied.TransactionID != "" {
		t.Fatal("another browser cookie recovered an original redirect", err)
	}
	if got := nativeProviderLoginCounts(t, x); got.transactions != after.transactions || got.capabilities != after.capabilities || got.events != after.events {
		t.Fatal("rejected changed intent or wrong browser created login authority")
	}
}

func TestNativeProviderSigninStartRejectsRevokedDomainProof(t *testing.T) {
	x := newProviderLoginStartFixture(t)
	revokeEnableTestProof(t, x.enable)
	before := nativeProviderLoginCounts(t, x)
	result, err := x.service.SigninStart(x.enable.f.ctx, x.request, x.browser)
	if !errors.Is(err, sso.ErrForbidden) || result.RedirectURI != (url.URL{}) || result.TransactionID != "" {
		t.Fatal("historical provider proof admitted a native protocol redirect", err)
	}
	after := nativeProviderLoginCounts(t, x)
	if after.transactions != before.transactions || after.capabilities != before.capabilities || after.events != before.events {
		t.Fatal("revoked proof created a transaction, capability or lifecycle effect")
	}
}
