//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
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

type samlStartPolicy struct{ tenant identity.TenantID }

func (p samlStartPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	decision := authorization.Decision{Outcome: authorization.Deny, Revision: 1}
	if c.PolicyRevision == 1 && c.Request.Tenant == authorization.TenantID(p.tenant) &&
		c.Request.Subject.Kind == authorization.SubjectServiceAccount && c.Request.Subject.ID == "native-sso-login" &&
		(c.Request.Action == "identity.session.preauth-issue" || c.Request.Action == "identity.sso.saml-start") {
		decision.Outcome = authorization.Allow
	}
	return decision, nil
}

type samlStartFixture struct {
	start    providerLoginStartFixture
	request  ssopg.SAMLSigninStartRequest
	profiles []ssopg.StaticSAMLLoginProfile
	router   *ssopg.ProviderRouter
	sign     ssopg.SAMLAuthnRedirectSigner
	inputs   []ssopg.SAMLAuthnRedirectInput
	public   *rsa.PublicKey
}

func newSAMLStartFixture(t *testing.T) *samlStartFixture {
	t.Helper()
	return newSAMLStartFixtureWithBundle(t, nil)
}

func newSAMLStartFixtureWithBundle(t *testing.T, signingBundle []byte) *samlStartFixture {
	t.Helper()
	// The canonical risk audit accepts opaque tenant IDs, not the legacy
	// human-readable tenant label used in the activation-only fixture.
	x := newProviderSAMLActivationFixtureWithBundle(t, discoveryFixtureTenant, signingBundle)
	installSAMLStartHistory(t, x.f)
	enabled, err := x.service.ProviderEnable(x.f.ctx, x.request)
	if err != nil || enabled.Completion.Outcome != identity.CommitOutcomeCommitted || !enabled.Provider.Enabled {
		t.Fatal("enable the installed encrypted SAML provider", err)
	}
	const origin = "https://sso.example.com"
	acs := origin + "/saml2/" + enabled.Provider.ID + "/acs"
	callback := url.URL{Scheme: "https", Host: "app.example.test", Path: "/sso/complete", RawQuery: "next=exact%2Fpath"}
	failure := url.URL{Scheme: "https", Host: "app.example.test", Path: "/sso/error"}
	remember, err := session.NewRememberPolicy(session.RememberPolicySpec{
		Choice: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute,
		RefreshAfter: 5 * time.Minute, FreshFor: 15 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	intent, err := sso.NewLoginIntent(remember)
	if err != nil {
		t.Fatal(err)
	}
	authorizationPolicy := samlStartPolicy{tenant: x.proof.TenantID}
	policy := kernel.CommandQueryPolicy{Authorization: authorizationPolicy, Clock: clock.System{}, PolicyVersion: 1}
	coordinator := kernel.CoordinatorConfig{
		MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute,
		CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {0xc1}},
		QueryPolicy: &policy, AdmissionPolicy: &policy,
	}
	requestKeys, err := kernel.NewRequestKeyConfig("native-saml-start", [32]byte{0xc2}, policy)
	if err != nil {
		t.Fatal(err)
	}
	flowKey, err := session.NewDigestKey(1, bytes.Repeat([]byte{0xc3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	sessionConfig := sessionpg.Config{Schema: "organization_sessions", MaximumDuration: time.Second}
	executor, err := sessionpg.NewPreAuthIssueExecutor(x.f.pool, sessionpg.PreAuthIssueExecutorConfig{
		Repository: sessionConfig, Coordinator: coordinator, Authorization: authorizationPolicy, Clock: clock.System{},
		ActorID: "native-sso-login", Action: "identity.sso.saml-acs", Origin: origin, CallbackURL: acs,
		PolicyID: "native-sso-login", PolicyVersion: 1, AuditRetentionVersion: 1,
	})
	if err != nil {
		t.Fatal("compose native exact ACS issuance", err)
	}
	issuer, err := session.NewSAMLFrontchannelIssuer(executor, session.PreAuthIssuerConfig{
		ActorID: "native-sso-login", Action: "identity.sso.saml-acs", Origin: origin, CallbackURL: acs,
		PolicyID: "native-sso-login", PolicyVersion: 1, Clock: clock.System{}, MaximumDuration: 4 * time.Second,
		FlowTTL: 5 * time.Minute, LookupKey: flowKey, TokenSize: 32,
	})
	if err != nil {
		t.Fatal("compose separate SAML frontchannel issuer", err)
	}
	prepared, err := issuer.Prepare(session.PreAuthPrepareInput{
		CommandID: commandID(t), TenantID: x.proof.TenantID, CorrelationID: "native-saml-browser", Remember: remember,
	})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := issuer.Issue(x.f.ctx, prepared)
	if err != nil || issued.CommitOutcome != identity.CommitOutcomeCommitted || issued.Replayed ||
		issued.Cookie.Path != "/saml2/"+enabled.Provider.ID+"/acs" || issued.Cookie.SameSite != http.SameSiteNoneMode {
		t.Fatal("issue original committed exact ACS browser custody", err)
	}
	flow, err := issued.Flow.Bindings()
	if err != nil || flow.Binding.Intent.Action != "identity.sso.saml-acs" || flow.Binding.Intent.CallbackURL != acs {
		t.Fatal("SAML browser flow lost its exact ACS", err)
	}
	wire, err := issued.Token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	signing := bytes.Repeat([]byte{0xc4}, 32)
	capSigner, err := capability.NewHMACSHA256Signer("native-saml-capability", signing)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := capability.NewHMACSHA256Verifier(signing)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := capability.NewKeySet([]capability.Key{{Issuer: "https://identity.example.test", ID: "native-saml-capability", Verifier: verifier}})
	if err != nil {
		t.Fatal(err)
	}
	wall := func() time.Time { return time.Now().UTC() }
	config := ssopg.ProviderLoginConfig{
		TenantID: x.proof.TenantID, ActorID: "native-sso-login", Origin: origin, PolicyID: "native-sso-login",
		GlobalAuthorityID: "organization-tests", ConfigurationID: "native-saml-login-v1",
		CallbackAllowlist: []string{callback.String(), failure.String()},
		Session:           sessionConfig, FlowKeys: []session.DigestKey{flowKey},
		Risk: providerLoginAdmission(t, x), Coordinator: coordinator, RequestKeys: requestKeys,
		Capability: capabilitypg.IssuerConfig{
			Crypto:   capability.ServiceConfig{Issuer: "https://identity.example.test", Signer: capSigner, Resolver: keys, Clock: wall, Limits: capability.DefaultLimits()},
			Audience: "identity", CurrentReplayKeyVersion: 1, RetainedReplayKeys: map[uint32][32]byte{1: {0xc5}}, PreparationTimeout: time.Second,
		},
		CapabilityPreparation: capabilitypg.IssuancePreparationConfig{
			Deployment: "native-saml-login", ActiveEnvelopeKey: "checkpoint", EnvelopeKeys: map[string][]byte{"checkpoint": bytes.Repeat([]byte{0xc6}, 32)},
			VerificationKeys: []capabilitypg.PreparationVerificationKey{{ID: "native-saml-capability", HMAC: signing}}, Clock: wall,
		},
		Envelope: x.config.Envelope, KeyReference: x.config.KeyReference,
		StateKeys: map[uint32][32]byte{1: {0xc7}}, CurrentStateKey: 1,
		AuditRetentionPolicyVersion: 1, StateLifetime: 5 * time.Minute,
	}
	fixture := &samlStartFixture{
		start: providerLoginStartFixture{enable: x, config: config, originalFlow: flow.Binding, flowIssuer: issuer,
			browser: ssopg.ProviderLoginBrowser{FlowID: flow.Binding.ID, FlowCookie: authentication.NewBearerCredential(wire), Origin: origin,
				Network: netip.MustParseAddr("192.0.2.84"), Device: "verified-native-saml-browser"}},
		request: ssopg.SAMLSigninStartRequest{ProviderID: sso.ProviderID(enabled.Provider.ID), SuccessCallback: callback, ErrorCallback: failure, LoginIntent: intent},
		profiles: []ssopg.StaticSAMLLoginProfile{{ProviderID: sso.ProviderID(enabled.Provider.ID), OrganizationID: x.proof.OrganizationID,
			Domain: x.proof.Domain, TrustedOrigin: origin, ProviderVersion: enabled.Provider.Version, CredentialGeneration: 1, MappingVersion: enabled.Provider.MappingVersion}},
	}
	expectedBundle := bytes.Clone(signingBundle)
	if expectedBundle == nil {
		expectedBundle = bytes.Repeat([]byte("fixture-activation-SP-signing/"), 2)
	}
	t.Cleanup(func() { clear(expectedBundle) })
	cutoff := time.Now().UTC().Add(30 * time.Minute).Truncate(time.Microsecond)
	router, err := newProviderRouter(t, x, 4).WithProtocolRegistry()
	if err != nil {
		t.Fatal(err)
	}
	fixture.router, err = router.WithSAMLRouteValidation(func(ctx context.Context, bundle []byte, at time.Time) (time.Time, error) {
		if _, bounded := ctx.Deadline(); !bounded || ctx.Err() != nil || !bytes.Equal(bundle, expectedBundle) || !at.Before(cutoff) {
			return time.Time{}, sso.ErrInvalidInput
		}
		return cutoff, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	fixture.public = &private.PublicKey
	// Only the external signing port is a fixture. Its signed JSON binds the
	// native projection without reimplementing SAML XML, compression or binding
	// rules; the optional SAML adapter owns the actual wire conformance proof.
	fixture.sign = func(ctx context.Context, input ssopg.SAMLAuthnRedirectInput, bundle []byte, at time.Time) (url.URL, time.Time, error) {
		if _, bounded := ctx.Deadline(); !bounded || ctx.Err() != nil || !bytes.Equal(bundle, expectedBundle) || !at.Before(cutoff) {
			return url.URL{}, time.Time{}, sso.ErrInvalidInput
		}
		fixture.inputs = append(fixture.inputs, input)
		payload, err := json.Marshal(struct {
			Entity, ACS, Destination, ID, Relay string
			Issued                              time.Time
		}{
			input.SPEntityID, input.AssertionConsumerURL, input.IdentityProviderURL, input.RequestID, input.RelayState, input.IssuedAt,
		})
		if err != nil {
			return url.URL{}, time.Time{}, err
		}
		redirect, err := url.Parse(input.IdentityProviderURL)
		if err != nil {
			return url.URL{}, time.Time{}, err
		}
		query := "SAMLRequest=" + url.QueryEscape(base64.StdEncoding.EncodeToString(payload)) + "&RelayState=" + url.QueryEscape(input.RelayState) +
			"&SigAlg=" + url.QueryEscape("http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1")
		digest := sha256.Sum256([]byte(query))
		signature, err := rsa.SignPSS(rand.Reader, private, crypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		if err != nil {
			return url.URL{}, time.Time{}, err
		}
		redirect.RawQuery += "&" + query + "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(signature))
		return *redirect, cutoff, nil
	}
	fixture.start.service, err = ssopg.NewProviderLoginServiceWithSAML(fixture.router, config, fixture.profiles, fixture.sign)
	if err != nil {
		t.Fatal("compose selected native SAML start consumer", err)
	}
	return fixture
}

func installSAMLStartHistory(t *testing.T, f *orgFixture) {
	t.Helper()
	history := append(migrationList(nil), f.history...)
	// The activation fixture applied this prefix without replacing f.history.
	// Retain its exact versions and SQL before adding the selected consumer.
	for _, source := range []migrations.Source{
		ssopg.ProviderUpdateMigrationSource{Version: 321}, ssopg.ProviderCredentialsMigrationSource{Version: 322},
		ssopg.ProviderProtocolMigrationSource{Version: 323, ValidationVersion: 324},
		ssopg.ProviderSAMLProtocolMigrationSource{Version: 325, ValidationVersion: 326},
		ssopg.ProviderEnableMigrationSource{Version: 327}, ssopg.LoginTransactionMigrationSource{Version: 328},
		ssopg.LoginTransactionProtocolMigrationSource{Version: 329, ValidationVersion: 330},
		ssopg.LoginTransactionSAMLProtocolMigrationSource{Version: 331, ValidationVersion: 332},
		riskpg.DurableCounterMigrationSource{Schema: providerLoginRiskSchema, Version: 333},
		sessionpg.PreAuthMigrationSource{Schema: "organization_sessions", Version: 334},
		sessionpg.PreAuthIssueMigrationSource{Schema: "organization_sessions", Version: 335},
	} {
		loaded, err := source.Load(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		history = append(history, loaded...)
	}
	history = append(history, migrationBundle(t, 336, "native_saml_login_capability", capabilitypg.Migrations(), ""))
	accounts := kernel.AccountMigrationSource{Base: history, Version: 337}
	link := kernel.AccountLinkPreparationMigrationSource{Base: accounts, Version: 338}
	rpErasure := kernel.OAuthRPPreparationErasureMigrationSource{Base: link, Version: 339}
	linkErasure := kernel.AccountLinkPreparationErasureMigrationSource{Base: rpErasure, Version: 340}
	linkValidation := kernel.AccountLinkPreparationErasureValidationMigrationSource{Base: linkErasure, Version: 341}
	unlink := kernel.AccountUnlinkPreparationMigrationSource{Base: linkValidation, Version: 342}
	unlinkValidation := kernel.AccountUnlinkPreparationValidationMigrationSource{Base: unlink, Version: 343}
	refresh := kernel.OAuthProviderRefreshErasureMigrationSource{Base: unlinkValidation, Version: 344}
	ssoErasure := kernel.SSOOIDCPreparationErasureMigrationSource{Base: refresh, Version: 345}
	oidcCallback := kernel.SSOOIDCCallbackPreparationErasureMigrationSource{Base: ssoErasure, Version: 346}
	oauthCallback := kernel.SSOOAuth2CallbackPreparationErasureMigrationSource{Base: oidcCallback, Version: 347}
	grantRefresh := kernel.SSOEnterpriseGrantRefreshPreparationErasureMigrationSource{Base: oauthCallback, Version: 348}
	samlCallback := kernel.SSOSAMLCallbackPreparationErasureMigrationSource{Base: grantRefresh, Version: 349}
	samlStart := kernel.SSOSAMLStartPreparationErasureMigrationSource{Base: samlCallback, Version: 350}
	aliases := kernel.CanonicalRequestMigrationSource{Base: samlStart, Version: 351}
	complete, err := (kernel.CanonicalSAMLStartRequestMigrationSource{Base: aliases, Version: 352}).Load(f.ctx)
	if err != nil {
		t.Fatal("append canonical SAML start history without changing its prefix", err)
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
			t.Fatal("install or replay complete selected SAML start history", err)
		}
	}
	f.history = append(migrationList(nil), complete...)
}

func TestNativeSAMLSigninStartRetainsHeaderlessCommandSignedRedirectAndOptionalAlias(t *testing.T) {
	x := newSAMLStartFixture(t)
	ctx := x.start.enable.f.ctx
	before := nativeProviderLoginCounts(t, x.start)
	started, err := x.start.service.SigninStartSAML(ctx, x.request, x.start.browser)
	if err != nil || started.Completion.Outcome != identity.CommitOutcomeCommitted || started.Protocol != "saml" || started.ProviderID != string(x.request.ProviderID) {
		t.Fatalf("headerless selected SAML start did not commit native authority: error=%v outcome=%v signs=%d before=%+v after=%+v",
			err, started.Completion.Outcome, len(x.inputs), before, nativeProviderLoginCounts(t, x.start))
	}
	command, err := identity.ParseCommandID(started.TransactionID)
	if err != nil || command != started.Completion.Binding.CommandID || started.TransactionID != started.Completion.Binding.RecordID || len(x.inputs) != 1 {
		t.Fatal("SAML start did not retain one server-owned command and signing operation", err)
	}
	input := x.inputs[0]
	if input.RequestID != "_"+string(command) || input.RelayState == "" || input.SPEntityID != "https://sso.example.com/saml2/"+string(x.request.ProviderID)+"/metadata" ||
		input.AssertionConsumerURL != x.start.originalFlow.Intent.CallbackURL || input.IdentityProviderURL != "https://idp.example.com/saml/redirect?tenant=enterprise" {
		t.Fatal("signer did not receive the exact installed provider and original ACS projection")
	}
	query := started.RedirectURI.Query()
	signed := "SAMLRequest=" + url.QueryEscape(query.Get("SAMLRequest")) + "&RelayState=" + url.QueryEscape(query.Get("RelayState")) +
		"&SigAlg=" + url.QueryEscape(query.Get("SigAlg"))
	digest := sha256.Sum256([]byte(signed))
	signature, err := base64.StdEncoding.DecodeString(query.Get("Signature"))
	if err != nil || rsa.VerifyPSS(x.public, crypto.SHA256, digest[:], signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) != nil ||
		query.Get("RelayState") != input.RelayState || query.Get("tenant") != "enterprise" {
		t.Fatal("returned redirect changed the original signed fixture binding", err)
	}
	var protocol, provider, start, callback string
	var version, generation, mapping uint64
	var binding []byte
	var noPKCE bool
	var issued, expires time.Time
	err = x.start.enable.f.pool.Raw().QueryRow(ctx, `SELECT protocol,provider_id,provider_version,credential_generation,mapping_version,start_command_id,callback_command_id,binding_envelope,
 pkce_key_version IS NULL AND pkce_commitment IS NULL AND verifier_envelope IS NULL,issued_at,expires_at
 FROM sso_providers.login_transactions WHERE start_command_id=$1`, string(command)).Scan(&protocol, &provider, &version, &generation, &mapping, &start, &callback, &binding, &noPKCE, &issued, &expires)
	if err != nil || protocol != "saml" || provider != string(x.request.ProviderID) || version != 3 || generation != 1 || mapping != 3 ||
		start != string(command) || callback == start || len(binding) == 0 || !noPKCE || !issued.Equal(input.IssuedAt) || expires.After(x.start.originalFlow.ExpiresAt) ||
		expires.After(issued.Add(5*time.Minute)) || bytes.Contains(binding, []byte(input.RelayState)) {
		t.Fatal("durable SAML custody changed command, provider, timing, encryption or PKCE absence", err)
	}
	if _, err := identity.ParseCommandID(callback); err != nil {
		t.Fatal("SAML transaction did not allocate a separate native callback command", err)
	}
	after := nativeProviderLoginCounts(t, x.start)
	if after.transactions != before.transactions+1 || after.capabilities != before.capabilities+1 || after.audits <= before.audits ||
		after.events != before.events+1 || after.attempts != before.attempts+1 {
		t.Fatal("SAML start did not commit one transaction, native grant, audited risk admission and lifecycle event")
	}
	restarted, err := ssopg.NewProviderLoginServiceWithSAML(x.router, x.start.config, x.profiles, x.sign)
	if err != nil {
		t.Fatal(err)
	}
	aliased := x.request
	aliased.IdempotencyKey, err = identity.NewIdempotencyKey([]byte("optional-saml-start-alias"))
	if err != nil {
		t.Fatal(err)
	}
	for _, request := range []ssopg.SAMLSigninStartRequest{x.request, aliased, x.request, aliased} {
		replayed, err := restarted.SigninStartSAML(ctx, request, x.start.browser)
		if err != nil || !reflect.DeepEqual(started, replayed) || replayed.RedirectURI.RawQuery != started.RedirectURI.RawQuery || len(x.inputs) != 1 {
			t.Fatal("restart or optional alias changed the original command or signed bytes, or signed again", err)
		}
	}
	var mappings, aliases int
	var mappedCommand []byte
	err = x.start.enable.f.pool.Raw().QueryRow(ctx, `SELECT
 (SELECT count(*) FROM identity.request_key_mappings WHERE route_id='identity.sso.saml-start'),
 (SELECT count(*) FROM identity.request_key_aliases WHERE route_id='identity.sso.saml-start'),
 (SELECT command_id FROM identity.request_key_mappings WHERE route_id='identity.sso.saml-start')`).Scan(&mappings, &aliases, &mappedCommand)
	if err != nil || mappings != 1 || aliases != 1 || base64.RawURLEncoding.EncodeToString(mappedCommand) != string(command) || nativeProviderLoginCounts(t, x.start) != after {
		t.Fatal("optional client key allocated another command or replay repeated native effects", err)
	}
}

func TestNativeSAMLSigninStartDeniesAbsentForeignBrowserAndDisabledProvider(t *testing.T) {
	x := newSAMLStartFixture(t)
	ctx := x.start.enable.f.ctx
	before := nativeProviderLoginCounts(t, x.start)
	foreign := x.start.browser
	foreignToken, err := session.NewToken(32)
	if err != nil {
		t.Fatal(err)
	}
	foreignWire, err := foreignToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	foreign.FlowCookie = authentication.NewBearerCredential(foreignWire)
	for name, browser := range map[string]ssopg.ProviderLoginBrowser{"absent": {}, "foreign": foreign} {
		t.Run(name, func(t *testing.T) {
			got, err := x.start.service.SigninStartSAML(ctx, x.request, browser)
			if err == nil || got.RedirectURI != (url.URL{}) || got.TransactionID != "" || len(x.inputs) != 0 {
				t.Fatal("unbound SAML browser obtained a signed redirect or transaction", err)
			}
		})
	}
	if nativeProviderLoginCounts(t, x.start) != before {
		t.Fatal("absent or foreign browser created native durable effects")
	}
	disposition, err := sso.NewActiveTransactionDisposition(x.request.ProviderID, 3, sso.ActiveTransactionRevoke)
	if err != nil {
		t.Fatal(err)
	}
	disabled, err := x.start.enable.service.ProviderDisableSAML(ctx, sso.ProviderDisableRequest{
		ProviderID: string(x.request.ProviderID), ExpectedVersion: 3, Reason: "Stop new SAML browser starts", ActiveTransactionDisposition: disposition,
	})
	if err != nil || !disabled.Disabled || disabled.Completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("disable selected provider through its native lifecycle", err)
	}
	before = nativeProviderLoginCounts(t, x.start)
	got, err := x.start.service.SigninStartSAML(ctx, x.request, x.start.browser)
	if !errors.Is(err, sso.ErrForbidden) || got.RedirectURI != (url.URL{}) || got.TransactionID != "" || len(x.inputs) != 0 {
		t.Fatal("disabled selected SAML provider returned a signed redirect", err)
	}
	after := nativeProviderLoginCounts(t, x.start)
	if after.transactions != before.transactions || after.capabilities != before.capabilities || after.events != before.events {
		t.Fatal("disabled SAML provider created login authority")
	}
}
