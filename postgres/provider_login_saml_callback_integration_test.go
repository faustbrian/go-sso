//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

const nativeSAMLCallbackIssuer = "urn:example:enterprise-idp"
const nativeSAMLCallbackSubject = "native-saml-linked-member"
const nativeSAMLCallbackResponse = "synthetic-trusted-protocol-response-not-XML"
const nativeSAMLCallbackResponseID = "_native-saml-response"
const nativeSAMLCallbackAssertionID = "_native-saml-assertion"

type nativeSAMLCallbackPolicy struct{ tenant identity.TenantID }

func (p nativeSAMLCallbackPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	if c.PolicyRevision == 1 && c.Request.Tenant == authorization.TenantID(p.tenant) &&
		c.Request.Subject.Kind == authorization.SubjectServiceAccount && c.Request.Subject.ID == "native-sso-login" &&
		c.Request.Action == "identity.sso.saml-acs" {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
	}
	return (samlStartPolicy{tenant: p.tenant}).Decide(ctx, c)
}

type nativeSAMLCallbackFixture struct {
	start      *samlStartFixture
	completion *ssopg.ProviderSAMLLoginCompletionService
	request    ssopg.SAMLSigninCallbackRequest
	started    sso.SigninStartResult
	lookup     session.DigestKey
	csrf       session.CSRFKey
	calls      int
	reject     bool
	callback   string
	binary     []byte
	expires    time.Time
}

func newNativeSAMLCallbackFixture(t *testing.T) *nativeSAMLCallbackFixture {
	t.Helper()
	x := newSAMLStartFixture(t)
	installNativeSAMLCallbackHistory(t, x.start.enable.f)
	profile := x.profiles[0]
	provider, err := ssopg.SSOSAMLAccountProviderNamespace(profile.OrganizationID, profile.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	tenant := string(x.start.config.TenantID)
	nativeCallbackJourneyExec(t, x.start, `INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES($1,'owner','saml-provider-credential',3,'sso',1,true)`, tenant)
	nativeCallbackJourneyExec(t, x.start, `WITH a AS (SELECT $2::text AS provider,$3::text AS issuer,$4::text AS subject)
INSERT INTO identity.accounts(tenant_id,user_id,account_id,provider,issuer,subject,subject_key,version,social_link_version,linked)
SELECT $1,'owner','saml-linked-account',provider,issuer,subject,
sha256(convert_to(octet_length(provider)::text||':'||provider||octet_length(issuer)::text||':'||issuer||octet_length(subject)::text||':'||subject,'UTF8')),1,1,true FROM a`, tenant, provider, nativeSAMLCallbackIssuer, nativeSAMLCallbackSubject)
	nativeCallbackJourneyExec(t, x.start, `INSERT INTO identity.account_credentials(tenant_id,user_id,credential_id,account_id) VALUES($1,'owner','saml-provider-credential','saml-linked-account')`, tenant)
	seedNativeCallbackJourneyFactors(t, x.start, "owner")
	policy := kernel.CommandQueryPolicy{Authorization: nativeSAMLCallbackPolicy{tenant: x.start.config.TenantID}, Clock: clock.System{}, PolicyVersion: 1}
	x.start.config.Coordinator.AdmissionPolicy, x.start.config.Coordinator.QueryPolicy = &policy, &policy
	x.start.service, err = ssopg.NewProviderLoginServiceWithSAML(x.router, x.start.config, x.profiles, x.sign)
	if err != nil {
		t.Fatal("compose the original SAML start and callback policy", err)
	}
	started, err := x.start.service.SigninStartSAML(x.start.enable.f.ctx, x.request, x.start.browser)
	if err != nil || started.Completion.Outcome != identity.CommitOutcomeCommitted || len(x.inputs) != 1 {
		t.Fatal("commit native SAML start for the original browser", err)
	}
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
	f := &nativeSAMLCallbackFixture{start: x, started: started, lookup: lookup, csrf: csrf}
	err = x.start.enable.f.pool.Raw().QueryRow(x.start.enable.f.ctx, `SELECT callback_command_id,expires_at FROM sso_providers.login_transactions WHERE start_command_id=$1`, started.TransactionID).Scan(&f.callback, &f.expires)
	if err != nil {
		t.Fatal("read original native callback correlation", err)
	}
	f.binary, err = base64.RawURLEncoding.DecodeString(f.callback)
	if err != nil {
		t.Fatal(err)
	}
	acs := profile.TrustedOrigin + "/saml2/" + string(profile.ProviderID) + "/acs"
	f.request = ssopg.SAMLSigninCallbackRequest{ProviderID: profile.ProviderID, ReceivedAssertionConsumerURL: acs,
		RelayState: started.RedirectURI.Query().Get("RelayState"), SAMLResponse: nativeSAMLCallbackResponse, Browser: x.start.browser}
	assertionExpires := time.Now().UTC().Add(2 * time.Minute).Truncate(time.Second)
	// The optional wire adapter owns XML and signature conformance. This trusted
	// external port checks native projection, not a second implementation of SAML.
	verify := func(ctx context.Context, input ssopg.SAMLResponseVerificationInput) (ssopg.SAMLVerifiedResponse, error) {
		f.calls++
		original := x.inputs[0]
		deadline, bounded := ctx.Deadline()
		if !bounded || ctx.Err() != nil || !input.Now.Before(deadline) ||
			input.SPEntityID != original.SPEntityID || input.IdentityProviderEntityID != nativeSAMLCallbackIssuer ||
			input.AssertionConsumerURL != acs || input.RequestID != original.RequestID ||
			!input.IssuedAt.Equal(original.IssuedAt) || !input.ExpiresAt.Equal(f.expires) ||
			input.Now.Before(input.IssuedAt) || !input.Now.Before(input.ExpiresAt) || input.SAMLResponse != nativeSAMLCallbackResponse ||
			len(input.SigningCertificates) != 1 {
			t.Error("external verifier did not receive the original provider, request, ACS and bounded time")
			return ssopg.SAMLVerifiedResponse{}, sso.ErrInvalidInput
		}
		certificate, err := x509.ParseCertificate(input.SigningCertificates[0])
		if err != nil {
			t.Error("external verifier did not receive installed DER signing pin")
			return ssopg.SAMLVerifiedResponse{}, sso.ErrInvalidInput
		}
		_, ecdsaPin := certificate.PublicKey.(*ecdsa.PublicKey)
		if !ecdsaPin || certificate.SerialNumber.Int64() != 1 || certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 ||
			input.Now.Before(certificate.NotBefore) || !input.Now.Before(certificate.NotAfter) ||
			certificate.CheckSignature(certificate.SignatureAlgorithm, certificate.RawTBSCertificate, certificate.Signature) != nil {
			t.Error("external verifier received a substituted or unusable signing fixture")
			return ssopg.SAMLVerifiedResponse{}, sso.ErrInvalidInput
		}
		if f.reject {
			return ssopg.SAMLVerifiedResponse{}, sso.ErrForbidden
		}
		return ssopg.SAMLVerifiedResponse{ResponseID: nativeSAMLCallbackResponseID, AssertionID: nativeSAMLCallbackAssertionID,
			ProviderSubject: nativeSAMLCallbackSubject, SubjectFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
			SessionIndex: "native-saml-session-index", AssertionExpiresAt: assertionExpires, ValidUntil: assertionExpires}, nil
	}
	f.completion, err = ssopg.NewProviderSAMLLoginCompletionService(x.start.service, ssopg.ProviderSAMLLoginCompletionConfig{
		Audience: "native-saml-app", PolicyNamespace: "users", CSRFKey: csrf, Verify: verify,
		Issuer: session.IssuerConfig{Clock: clock.System{}, MaximumDuration: 3 * time.Second, LookupKey: lookup, TokenSize: 32, Cookie: cookie},
	})
	if err != nil {
		t.Fatal("compose public native SAML completion", err)
	}
	return f
}

func installNativeSAMLCallbackHistory(t *testing.T, f *orgFixture) {
	t.Helper()
	history := append(migrationList(nil), f.history...)
	issuance, err := (sessionpg.IssueMigrationSource{Base: sessionpg.RevocationMigrationSource{
		Base: sessionpg.MigrationSource{Schema: "organization_sessions", Version: 20}, Version: 370,
	}, Version: 371}).Load(f.ctx)
	if err != nil || len(issuance) != 3 || issuance[0].Version() != 20 || issuance[1].Version() != 370 || issuance[2].Version() != 371 {
		t.Fatal("load the public session issuance tail after the installed SAML start history", err)
	}
	// The start fixture already installed its exact session base at version 20.
	// Preserve that history and append only the revocation and issuance steps.
	history = append(history, issuance[1:]...)
	known := make(map[migrations.Version]migrations.Checksum, len(history))
	for _, step := range history {
		known[step.Version()] = step.Checksum()
	}
	for _, source := range []migrations.Source{
		mfapg.MigrationSource{Version: 372},
		sessionpg.CSRFMigrationSource{Schema: "organization_sessions", Version: 373},
		sessionpg.SSOOIDCSigninMigrationSource{Schema: "organization_sessions", Version: 374, ValidationVersion: 375, PreviousConstraint: "session_issuances_purpose_check"},
		sessionpg.SSOOAuth2SigninMigrationSource{Schema: "organization_sessions", Version: 376, ValidationVersion: 377},
		sessionpg.SSOSAMLSigninMigrationSource{Schema: "organization_sessions", Version: 378, ValidationVersion: 379},
		ssopg.SAMLReplayMigrationSource{Version: 380},
	} {
		steps, err := source.Load(f.ctx)
		if err != nil {
			t.Fatal("load public native SAML callback migration", err)
		}
		for _, step := range steps {
			if checksum, exists := known[step.Version()]; exists {
				if checksum != step.Checksum() {
					t.Fatal("SAML callback migration changed an installed predecessor")
				}
				continue
			}
			history = append(history, step)
			known[step.Version()] = step.Checksum()
		}
	}
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
			t.Fatal("install and replay complete native SAML callback history", err)
		}
	}
	f.history = history
}

func TestNativeSAMLCallbackCommitsLinkedMemberSessionAndReplayPairOnce(t *testing.T) {
	x := newNativeSAMLCallbackFixture(t)
	ctx := x.start.start.enable.f.ctx
	before := nativeProviderLoginCounts(t, x.start.start)
	got, err := x.completion.SigninCallback(ctx, x.request)
	if err != nil || got.Completion.Outcome != identity.CommitOutcomeCommitted ||
		got.Issuance.CommitOutcome != identity.CommitOutcomeCommitted || got.Issuance.Replayed || x.calls != 1 {
		t.Fatal("public SAML callback did not acknowledge one native linked-member session", err)
	}
	spec, err := got.Issuance.Session.Bindings()
	if err != nil || spec.TenantID != x.start.start.config.TenantID || spec.UserID != "owner" ||
		spec.Authentication.Proof.Method != "sso-saml" || spec.Authentication.CredentialID != "saml-provider-credential" ||
		spec.Audience != "native-saml-app" || spec.Remember != x.start.start.originalFlow.Intent.Remember ||
		got.RedirectURI != x.start.request.SuccessCallback.String() || string(got.Completion.Binding.CommandID) != x.callback {
		t.Fatal("SAML session lost its original member, credential, intent or continuation", err)
	}
	cookie := got.Issuance.Cookie
	if cookie.Name != "__Host-identity_session" || cookie.Value != "" || !cookie.Secure || !cookie.HttpOnly ||
		cookie.Path != "/" || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatal("normal session transport did not remain separate from the exact-ACS frontchannel cookie")
	}
	bearer, err := got.Issuance.Token.Reveal()
	if err != nil || bearer == "" {
		t.Fatal("committed SAML callback withheld the original bearer", err)
	}
	csrf, err := got.CSRF.Reveal()
	if err != nil || csrf == "" || got.Issuance.Session.CSRFState().Check(session.CSRFBinding{
		TenantID: spec.TenantID, SessionID: spec.SessionID, SessionVersion: spec.Version}, got.CSRF, x.csrf) != nil {
		t.Fatal("committed SAML callback withheld matching session-bound CSRF", err)
	}
	if _, err := got.Issuance.Token.Reveal(); err == nil {
		t.Fatal("SAML callback bearer was disclosed twice")
	}
	assertNativeSAMLCallbackCommit(t, x, got, bearer, csrf)
	after := nativeProviderLoginCounts(t, x.start.start)
	if after.transactions != before.transactions || after.capabilities != before.capabilities || after.events != before.events+1 {
		t.Fatal("SAML callback did not conserve its original transaction and capability with one lifecycle effect")
	}
	repeated, _ := x.completion.SigninCallback(ctx, x.request)
	assertNativeSAMLCallbackWithholdsIssuance(t, repeated)
	if x.calls != 1 || nativeProviderLoginCounts(t, x.start.start) != after {
		t.Fatal("terminal SAML retry repeated protocol verification or a durable effect")
	}
	assertNativeSAMLCallbackCommit(t, x, got, bearer, csrf)
}

func TestNativeSAMLCallbackRollsBackReplayAndBrowserWhenSessionFails(t *testing.T) {
	x := newNativeSAMLCallbackFixture(t)
	f := x.start.start.enable.f
	before := nativeSAMLCallbackSuccessCounts(t, x)
	custodyBefore := nativeSAMLCallbackPendingCustody(t, x)
	var bindingBefore []byte
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT binding_envelope FROM sso_providers.login_transactions WHERE start_command_id=$1`, x.started.TransactionID).Scan(&bindingBefore); err != nil {
		t.Fatal("read original encrypted SAML continuation before session failure", err)
	}

	// Sequence advancement survives rollback and proves the real issuance write
	// reached the scoped failure after replay, browser and session reservation.
	nativeCallbackJourneyExec(t, x.start.start, `CREATE SEQUENCE organization_sessions.fixture_saml_issuance_attempts`)
	nativeCallbackJourneyExec(t, x.start.start, `CREATE FUNCTION organization_sessions.fixture_saml_issuance_failure() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.tenant_id::text=TG_ARGV[0] AND encode(NEW.command_id,'hex')=TG_ARGV[1] AND NEW.purpose='identity.sso.saml-acs' THEN
  PERFORM nextval('organization_sessions.fixture_saml_issuance_attempts');
  RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='fixture refuses exact SAML session issuance';
 END IF;
 RETURN NEW;
END $$`)
	var trigger string
	err := f.pool.Raw().QueryRow(f.ctx, `SELECT format('CREATE TRIGGER fixture_saml_issuance_failure BEFORE INSERT ON organization_sessions.session_issuances FOR EACH ROW EXECUTE FUNCTION organization_sessions.fixture_saml_issuance_failure(%L,%L)',$1::text,encode($2::bytea,'hex'))`, string(x.start.start.config.TenantID), x.binary).Scan(&trigger)
	if err != nil {
		t.Fatal("bind session failure to the exact original SAML callback", err)
	}
	nativeCallbackJourneyExec(t, x.start.start, trigger)

	got, callbackErr := x.completion.SigninCallback(f.ctx, x.request)
	assertNativeSAMLCallbackWithholdsIssuance(t, got)
	var reachedIssuance bool
	err = f.pool.Raw().QueryRow(f.ctx, `SELECT is_called FROM organization_sessions.fixture_saml_issuance_attempts`).Scan(&reachedIssuance)
	if err != nil || !reachedIssuance || callbackErr == nil || x.calls != 1 || got.Completion.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("native SAML callback did not reach and propagate the scoped session failure", err, callbackErr)
	}
	if after := nativeSAMLCallbackSuccessCounts(t, x); after != before {
		t.Fatalf("failed SAML issuance changed success effects: before %v, after %v", before, after)
	}
	// Unanimous known-noncommit recovery terminal-releases the exact grant
	// without counting a use or making that grant reusable. The browser and
	// original continuation stay pending after the failed Work rolls back.
	if custodyAfter := nativeSAMLCallbackPendingCustody(t, x); custodyBefore != "issued:issued:0:true" || custodyAfter != "issued:released:0:true" {
		t.Fatalf("failed SAML issuance changed browser/capability custody: before %s, after %s", custodyBefore, custodyAfter)
	}
	var exactRelease bool
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM public.capability_identity_one_use
WHERE tenant_id=$1 AND purpose='identity.sso.saml-acs' AND origin_command_id=$2 AND command_id=$3 AND state='released' AND uses=0)`,
		string(x.start.start.config.TenantID), x.started.TransactionID, x.callback).Scan(&exactRelease); err != nil || !exactRelease {
		t.Fatal("known noncommit did not terminal-release the exact unused callback grant", err)
	}
	var bindingAfter []byte
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT binding_envelope FROM sso_providers.login_transactions WHERE start_command_id=$1 AND completed_at IS NULL`, x.started.TransactionID).Scan(&bindingAfter); err != nil || !bytes.Equal(bindingBefore, bindingAfter) {
		t.Fatal("failed SAML issuance replaced or terminalized the original encrypted continuation", err)
	}
}

func assertNativeSAMLCallbackWithholdsIssuance(t *testing.T, got ssopg.ProviderLoginCallbackResult) {
	t.Helper()
	if got.Issuance.Token != (session.Token{}) || got.Issuance.Cookie.Name != "" ||
		got.CSRF != (session.CSRFToken{}) || got.RedirectURI != "" {
		t.Fatal("unacknowledged or repeated SAML callback disclosed browser custody")
	}
}

func assertNativeSAMLCallbackCommit(t *testing.T, x *nativeSAMLCallbackFixture, got ssopg.ProviderLoginCallbackResult, bearer, csrf string) {
	t.Helper()
	f := x.start.start.enable.f
	spec, _ := got.Issuance.Session.Bindings()
	var callback, browserState, capabilityState string
	var completed, noOAuthCustody, terminal, erased bool
	var uses, members, responses, assertions, sessions, families, issuances, audits, events int
	var persisted []byte
	err := f.pool.Raw().QueryRow(f.ctx, `SELECT l.callback_command_id,l.completed_at IS NOT NULL,
l.pkce_key_version IS NULL AND l.pkce_commitment IS NULL AND l.verifier_envelope IS NULL,
p.state,c.state,c.uses,
j.state='committed' AND j.result_version=1 AND j.terminal_class='committed' AND j.result IS NOT NULL AND j.terminal_at IS NOT NULL,
j.preparation_ciphertext IS NULL AND j.preparation_ciphertext_generation IS NULL,
(SELECT count(*) FROM sso_providers.saml_replay_members WHERE tenant_id=l.tenant_id AND callback_command_id=$3),
(SELECT count(*) FROM sso_providers.saml_replay_members WHERE tenant_id=l.tenant_id AND callback_command_id=$3 AND member_kind=1 AND member_digest=$4
 AND organization_id=l.organization_id AND provider_id=l.provider_id AND issuer_digest=$6 AND callback_purpose='identity.sso.saml-acs'),
(SELECT count(*) FROM sso_providers.saml_replay_members WHERE tenant_id=l.tenant_id AND callback_command_id=$3 AND member_kind=2 AND member_digest=$5
 AND organization_id=l.organization_id AND provider_id=l.provider_id AND issuer_digest=$6 AND callback_purpose='identity.sso.saml-acs')
FROM sso_providers.login_transactions l
JOIN organization_sessions.preauth_transactions p ON p.tenant_id=l.tenant_id AND p.flow_id=$2
JOIN public.capability_identity_one_use c ON c.tenant_id=l.tenant_id AND c.command_id=l.callback_command_id AND c.purpose='identity.sso.saml-acs'
JOIN identity.commands j ON j.tenant_id=l.tenant_id AND j.command_id=$3 AND j.purpose='identity.sso.saml-acs'
WHERE l.start_command_id=$1`, x.started.TransactionID, string(x.start.start.browser.FlowID), x.binary,
		nativeSAMLCallbackDigest(nativeSAMLCallbackResponseID), nativeSAMLCallbackDigest(nativeSAMLCallbackAssertionID), nativeSAMLCallbackDigest(nativeSAMLCallbackIssuer)).Scan(
		&callback, &completed, &noOAuthCustody, &browserState, &capabilityState, &uses, &terminal, &erased, &members, &responses, &assertions)
	if err != nil || callback != x.callback || !completed || !noOAuthCustody || browserState != "consumed" || capabilityState != "finalized" ||
		uses != 1 || !terminal || !erased || members != 2 || responses != 1 || assertions != 1 {
		t.Fatal("SAML commit did not atomically consume original browser/capability, reserve both replay members and erase temporary output", err)
	}
	err = f.pool.Raw().QueryRow(f.ctx, `SELECT convert_to(s.record::text,'UTF8'),
(SELECT count(*) FROM organization_sessions.sessions WHERE tenant_id=$1 AND session_id=$2 AND user_id='owner' AND state='active'),
(SELECT count(*) FROM organization_sessions.families WHERE tenant_id=$1 AND family_id=$3 AND user_id='owner' AND state='active'),
(SELECT count(*) FROM organization_sessions.session_issuances WHERE tenant_id=$1 AND command_id=$4 AND purpose='identity.sso.saml-acs'),
(SELECT count(*) FROM audit.records WHERE tenant_id=$1 AND action='identity.sso.login' AND correlation_id=$5 AND outcome=$6),
(SELECT count(*) FROM public.identity_outbox_bindings b JOIN public.outbox_messages m ON m.id=b.effect_id WHERE b.tenant_id=$1 AND b.command_id=$4 AND m.topic='session.created.v1')
FROM organization_sessions.sessions s WHERE s.tenant_id=$1 AND s.session_id=$2`, string(spec.TenantID), spec.SessionID, spec.FamilyID, x.binary, x.callback, int16(audit.OutcomeSucceeded)).Scan(
		&persisted, &sessions, &families, &issuances, &audits, &events)
	if err != nil || sessions != 1 || families != 1 || issuances != 1 || audits != 1 || events != 1 {
		t.Fatal("SAML session, family, issuance, success audit and lifecycle did not commit exactly once", err)
	}
	var durable struct {
		CSRF   session.CSRFStateSpec
		Lookup session.TokenDigest
	}
	if json.Unmarshal(persisted, &durable) != nil {
		t.Fatal("persisted SAML session lost digest-only browser state")
	}
	parsed, parseErr := session.ParseToken(bearer)
	digest, digestErr := parsed.Digest(x.lookup, string(spec.TenantID))
	csrfState, csrfErr := session.NewCSRFState(durable.CSRF)
	if parseErr != nil || digestErr != nil || digest != spec.Lookup || durable.Lookup != digest || csrfErr != nil ||
		csrfState.Check(session.CSRFBinding{TenantID: spec.TenantID, SessionID: spec.SessionID, SessionVersion: spec.Version}, got.CSRF, x.csrf) != nil {
		t.Fatal("persisted SAML session does not match its original bearer and CSRF")
	}
	for _, secret := range []string{nativeSAMLCallbackResponse, nativeSAMLCallbackResponseID, nativeSAMLCallbackAssertionID,
		x.request.RelayState, x.start.start.browser.FlowCookie.Token(), bearer, csrf} {
		var leaked bool
		err := f.pool.Raw().QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM (
SELECT result AS wire FROM identity.commands WHERE result IS NOT NULL
UNION ALL SELECT preparation_ciphertext FROM identity.commands WHERE preparation_ciphertext IS NOT NULL
UNION ALL SELECT canonical_record FROM audit.records
UNION ALL SELECT payload FROM public.outbox_messages
UNION ALL SELECT binding_envelope FROM sso_providers.login_transactions
UNION ALL SELECT convert_to(record::text,'UTF8') FROM organization_sessions.sessions
) retained WHERE position($1::bytea in wire)>0)`, []byte(secret)).Scan(&leaked)
		if err != nil || leaked {
			t.Fatal("SAML response, identifiers or browser secret escaped into durable plaintext", err)
		}
	}
}

func nativeSAMLCallbackDigest(value string) []byte {
	digest := sha256.Sum256([]byte(value))
	return digest[:]
}

func TestNativeSAMLCallbackRejectsUnverifiedResponseAndSubstitutedBrowserOrACS(t *testing.T) {
	for _, mode := range []string{"verifier-rejection", "foreign-cookie", "wrong-acs"} {
		t.Run(mode, func(t *testing.T) {
			x := newNativeSAMLCallbackFixture(t)
			request := x.request
			wantCalls := 0
			switch mode {
			case "verifier-rejection":
				x.reject, wantCalls = true, 1
			case "foreign-cookie":
				wire := []byte(request.Browser.FlowCookie.Token())
				wire[len(wire)/2] ^= 1
				request.Browser.FlowCookie = authentication.NewBearerCredential(string(wire))
				clear(wire)
			case "wrong-acs":
				request.ReceivedAssertionConsumerURL += "/other"
			}
			f := x.start.start.enable.f
			before := nativeSAMLCallbackSuccessCounts(t, x)
			custodyBefore := nativeSAMLCallbackPendingCustody(t, x)
			got, err := x.completion.SigninCallback(f.ctx, request)
			assertNativeSAMLCallbackWithholdsIssuance(t, got)
			if err == nil || got.Completion.Outcome == identity.CommitOutcomeCommitted || x.calls != wantCalls ||
				nativeSAMLCallbackSuccessCounts(t, x) != before || nativeSAMLCallbackPendingCustody(t, x) != custodyBefore {
				t.Fatal("rejected SAML callback verified substituted custody or persisted a success effect", err)
			}
			repeated, repeatErr := x.completion.SigninCallback(f.ctx, request)
			assertNativeSAMLCallbackWithholdsIssuance(t, repeated)
			if repeatErr == nil || repeated.Completion.Outcome == identity.CommitOutcomeCommitted ||
				x.calls != 2*wantCalls || nativeSAMLCallbackSuccessCounts(t, x) != before ||
				nativeSAMLCallbackPendingCustody(t, x) != custodyBefore {
				t.Fatal("rejected SAML retry disclosed custody or persisted a success effect", repeatErr)
			}
		})
	}
}

func nativeSAMLCallbackPendingCustody(t *testing.T, x *nativeSAMLCallbackFixture) string {
	t.Helper()
	f := x.start.start.enable.f
	var custody string
	err := f.pool.Raw().QueryRow(f.ctx, `SELECT p.state||':'||c.state||':'||c.uses::text||':'||(l.completed_at IS NULL)::text
FROM sso_providers.login_transactions l
JOIN organization_sessions.preauth_transactions p ON p.tenant_id=l.tenant_id AND p.flow_id=$2
JOIN public.capability_identity_one_use c ON c.tenant_id=l.tenant_id AND c.origin_command_id=l.start_command_id AND c.purpose='identity.sso.saml-acs'
WHERE l.start_command_id=$1`, x.started.TransactionID, string(x.start.start.browser.FlowID)).Scan(&custody)
	if err != nil {
		t.Fatal("read original SAML browser and capability custody", err)
	}
	return custody
}

func nativeSAMLCallbackSuccessCounts(t *testing.T, x *nativeSAMLCallbackFixture) [6]int {
	t.Helper()
	var counts [6]int
	f := x.start.start.enable.f
	err := f.pool.Raw().QueryRow(f.ctx, `SELECT
(SELECT count(*) FROM organization_sessions.sessions),
(SELECT count(*) FROM organization_sessions.families),
(SELECT count(*) FROM organization_sessions.session_issuances WHERE command_id=$1),
(SELECT count(*) FROM sso_providers.saml_replay_members WHERE callback_command_id=$1),
(SELECT count(*) FROM audit.records WHERE correlation_id=$2 AND action='identity.sso.login' AND outcome=$3),
(SELECT count(*) FROM public.identity_outbox_bindings b JOIN public.outbox_messages m ON m.id=b.effect_id WHERE b.command_id=$1 AND m.topic='session.created.v1')`, x.binary, x.callback, int16(audit.OutcomeSucceeded)).Scan(
		&counts[0], &counts[1], &counts[2], &counts[3], &counts[4], &counts[5])
	if err != nil {
		t.Fatal("read exact SAML callback success effects", err)
	}
	return counts
}
