//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestNativeSAMLIDPConfirmationCommitsLinkedMemberSessionAndReplayPairOnce(t *testing.T) {
	x := newNativeSAMLIDPAdmissionFixture(t)
	seedSAMLIDPLinkedRecipient(t, x)
	f, tenant := x.enable.f, x.enable.proof.TenantID
	installSAMLIDPStorage(t, f, ssopg.SAMLIDPConfirmationMigrationSource{Version: 392})
	installSAMLIDPStorage(t, f, migrationList{migrationBundle(t, 393, "native_saml_idp_capability", capabilitypg.Migrations(), "")})

	issuance, err := (sessionpg.IssueMigrationSource{Base: sessionpg.RevocationMigrationSource{
		Base: sessionpg.MigrationSource{Schema: "organization_sessions", Version: 20}, Version: 394,
	}, Version: 395}).Load(f.ctx)
	if err != nil || len(issuance) != 3 || issuance[0].Version() != 20 {
		t.Fatal("load session issuance after the already installed session base", err)
	}
	installSAMLIDPStorage(t, f, migrationList(issuance[1:]))
	for _, source := range []migrations.Source{
		sessionpg.CSRFMigrationSource{Schema: "organization_sessions", Version: 396},
		sessionpg.SSOOIDCSigninMigrationSource{Schema: "organization_sessions", Version: 397, ValidationVersion: 398, PreviousConstraint: "session_issuances_purpose_check"},
		sessionpg.SSOOAuth2SigninMigrationSource{Schema: "organization_sessions", Version: 399, ValidationVersion: 400},
		sessionpg.SSOSAMLSigninMigrationSource{Schema: "organization_sessions", Version: 401, ValidationVersion: 402},
		sessionpg.SSOSAMLIDPSigninMigrationSource{Schema: "organization_sessions", Version: 403, ValidationVersion: 404},
		ssopg.SAMLReplayMigrationSource{Version: 405},
		ssopg.SAMLIDPReplayMigrationSource{Version: 406, ValidationVersion: 407},
	} {
		installSAMLIDPStorage(t, f, source)
	}
	link := kernel.AccountLinkPreparationMigrationSource{Base: f.history, Version: 408}
	rpErasure := kernel.OAuthRPPreparationErasureMigrationSource{Base: link, Version: 409}
	linkErasure := kernel.AccountLinkPreparationErasureMigrationSource{Base: rpErasure, Version: 410}
	linkValidation := kernel.AccountLinkPreparationErasureValidationMigrationSource{Base: linkErasure, Version: 411}
	unlink := kernel.AccountUnlinkPreparationMigrationSource{Base: linkValidation, Version: 412}
	unlinkValidation := kernel.AccountUnlinkPreparationValidationMigrationSource{Base: unlink, Version: 413}
	providerRefresh := kernel.OAuthProviderRefreshErasureMigrationSource{Base: unlinkValidation, Version: 414}
	startErasure := kernel.SSOOIDCPreparationErasureMigrationSource{Base: providerRefresh, Version: 415}
	oidcErasure := kernel.SSOOIDCCallbackPreparationErasureMigrationSource{Base: startErasure, Version: 416}
	oauthErasure := kernel.SSOOAuth2CallbackPreparationErasureMigrationSource{Base: oidcErasure, Version: 417}
	refreshErasure := kernel.SSOEnterpriseGrantRefreshPreparationErasureMigrationSource{Base: oauthErasure, Version: 418}
	samlErasure := kernel.SSOSAMLCallbackPreparationErasureMigrationSource{Base: refreshErasure, Version: 419}
	samlStartErasure := kernel.SSOSAMLStartPreparationErasureMigrationSource{Base: samlErasure, Version: 420}
	erasure, err := (kernel.SSOSAMLIDPConfirmationPreparationErasureMigrationSource{Base: samlStartErasure, Version: 421}).Load(f.ctx)
	if err != nil || len(erasure) != len(f.history)+14 {
		t.Fatal("load the owning prepared-confirmation erasure history", err)
	}
	installSAMLIDPStorage(t, f, migrationList(erasure[len(f.history):]))

	verifications := 0
	admission, err := ssopg.NewProviderSAMLIDPAdmissionService(x.router, ssopg.ProviderSAMLIDPAdmissionConfig{
		TenantID: tenant, Profiles: []ssopg.StaticSAMLIDPAdmissionProfile{{Provider: x.profile, MaximumAge: time.Minute}},
		Verify: func(ctx context.Context, input ssopg.SAMLIDPResponseVerificationInput) (ssopg.SAMLVerifiedResponse, error) {
			verifications++
			x.assertVerifierInput(t, ctx, input, time.Minute)
			evidence := nativeSAMLIDPEvidence(input.Now)
			if verifications == 3 {
				evidence.ResponseID += "-late-authority"
				evidence.AssertionID += "-late-authority"
			}
			return evidence, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	admission, err = admission.WithLinkedRecipientPolicy("users")
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0xa4}, 32)
	signer, err := capability.NewHMACSHA256Signer("idp-confirmation-fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := capability.NewHMACSHA256Verifier(key)
	if err != nil {
		t.Fatal(err)
	}
	const issuerName = "https://identity.example.test"
	keys, err := capability.NewKeySet([]capability.Key{{Issuer: issuerName, ID: "idp-confirmation-fixture", Verifier: verifier}})
	if err != nil {
		t.Fatal(err)
	}
	arrival, err := ssopg.NewProviderSAMLIDPArrivalService(admission, ssopg.ProviderSAMLIDPArrivalConfig{
		ActorID: "native-saml-arrival", PolicyID: "saml-idp-policy", PolicyVersion: 1, GlobalAuthorityID: "organization-tests",
		Coordinator: kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: 30 * time.Second,
			CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {0xc1}},
			QueryPolicy: &kernel.CommandQueryPolicy{Authorization: idpFixtureQueryPolicy{}, Clock: clock.System{}, PolicyVersion: 1}},
		Capability: capabilitypg.IssuerConfig{
			Crypto: capability.ServiceConfig{Issuer: issuerName, Signer: signer, Resolver: keys,
				Clock: func() time.Time { return time.Now().UTC() }, Limits: capability.DefaultLimits()},
			Audience: "identity", CurrentReplayKeyVersion: 1, RetainedReplayKeys: map[uint32][32]byte{1: {0xc2}}, PreparationTimeout: time.Second,
		},
		KeyReference: x.enable.config.KeyReference, CurrentConfirmationKey: 1,
		ConfirmationKeys: map[uint32][32]byte{1: {0xc3}}, AuditRetentionPolicyVersion: 1,
	})
	if err != nil {
		t.Fatal("compose the native unsolicited arrival", err)
	}
	lookup, err := session.NewDigestKey(1, bytes.Repeat([]byte{0xd1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	csrfKey, err := session.NewCSRFKey(1, bytes.Repeat([]byte{0xd2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	cookiePolicy, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_session", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	rememberPolicy, err := session.NewRememberPolicy(session.RememberPolicySpec{Choice: session.BrowserSession, AbsoluteTTL: time.Hour,
		IdleTTL: 30 * time.Minute, RefreshAfter: 5 * time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	service, err := ssopg.NewProviderSAMLIDPConfirmationService(arrival, ssopg.ProviderSAMLIDPConfirmationConfig{
		Audience: "native-saml-idp-app", Session: sessionpg.Config{Schema: "organization_sessions", MaximumDuration: time.Second},
		Issuer:  session.IssuerConfig{Clock: clock.System{}, MaximumDuration: 3 * time.Second, LookupKey: lookup, TokenSize: 32, Cookie: cookiePolicy},
		CSRFKey: csrfKey, Remember: rememberPolicy,
	})
	if err != nil {
		t.Fatal("compose public native confirmation", err)
	}
	// No SP operation may supply correlation or browser state for this journey.
	if _, err := f.pool.Raw().Exec(f.ctx, `ALTER TABLE sso_providers.login_transactions RENAME TO fixture_unavailable_sp_logins`); err != nil {
		t.Fatal(err)
	}
	var existingSessions int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM organization_sessions.sessions`).Scan(&existingSessions); err != nil {
		t.Fatal(err)
	}
	pending, err := arrival.Prepare(f.ctx, x.request())
	if err != nil || pending.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("prepare original unsolicited confirmation", err)
	}
	browser, form, expiry, ok := pending.TakeConfirmation()
	if !ok || browser.Token() == form.Token() || !time.Now().Before(expiry) {
		t.Fatal("arrival did not disclose independent fresh browser and form custody")
	}
	request := ssopg.SAMLIDPConfirmationRequest{TenantID: tenant, ProviderID: x.profile.ProviderID, PendingID: pending.CommandID,
		Origin: x.profile.TrustedOrigin, Browser: browser, Form: form}
	assertNativeIDPArrivalCounts(t, f, 1, existingSessions)
	var originalEnvelope, originalBrowser, originalForm []byte
	var originalKey int64
	var originalIssued, originalExpiry time.Time
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT binding_envelope,confirmation_key_version,browser_digest,form_digest,issued_at,expires_at
FROM sso_providers.saml_idp_confirmations WHERE tenant_id=$1`, tenant).
		Scan(&originalEnvelope, &originalKey, &originalBrowser, &originalForm, &originalIssued, &originalExpiry); err != nil || len(originalEnvelope) == 0 ||
		len(originalBrowser) != 32 || len(originalForm) != 32 || bytes.Equal(originalBrowser, originalForm) || !originalExpiry.Truncate(time.Second).Equal(expiry) {
		t.Fatal("read original encrypted confirmation custody", err)
	}
	rateCustody := func() string {
		t.Helper()
		var custody string
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT json_build_array(
 (SELECT json_agg(ROW(xmin::text,p)) FROM sso_providers.saml_idp_confirmations p WHERE tenant_id=$1),
 (SELECT json_agg(ROW(xmin::text,c)) FROM identity.commands c WHERE tenant_id=$1),
 (SELECT json_agg(ROW(xmin::text,g)) FROM public.capability_identity_one_use g WHERE tenant_id=$1),
 (SELECT count(*) FROM organization_sessions.sessions),
 (SELECT count(*) FROM organization_sessions.session_issuances),
 (SELECT count(*) FROM sso_providers.saml_replay_members))::text`, tenant).Scan(&custody); err != nil {
			t.Fatal("observe native pending, command, grant, replay and session custody", err)
		}
		return custody
	}
	wantRate := ssopg.ProviderLoginCallbackRateContext{ProviderID: request.ProviderID,
		TransactionID: string(pending.CommandID), Lifetime: originalExpiry.Sub(originalIssued)}
	beforeRate := rateCustody()
	for i := 0; i < 3; i++ {
		gotRate, err := service.ConfirmationRateSource(f.ctx, request)
		if err != nil || gotRate != wantRate || gotRate.FlowID != "" || gotRate.Lifetime <= 0 {
			t.Fatal("rate attribution did not expose only canonical pending identity and immutable initial lifetime", err)
		}
	}
	for name, alter := range map[string]func(*ssopg.SAMLIDPConfirmationRequest){
		"wrong tenant":    func(r *ssopg.SAMLIDPConfirmationRequest) { r.TenantID = "foreign-tenant" },
		"wrong provider":  func(r *ssopg.SAMLIDPConfirmationRequest) { r.ProviderID = "foreign-provider" },
		"wrong origin":    func(r *ssopg.SAMLIDPConfirmationRequest) { r.Origin = "https://foreign.example.test" },
		"missing pending": func(r *ssopg.SAMLIDPConfirmationRequest) { r.PendingID = "" },
		"wrong pending": func(r *ssopg.SAMLIDPConfirmationRequest) {
			r.PendingID = identity.CommandID(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xef}, 16)))
		},
		"wrong browser": func(r *ssopg.SAMLIDPConfirmationRequest) {
			r.Browser = authentication.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xee}, 32)))
		},
		"wrong form": func(r *ssopg.SAMLIDPConfirmationRequest) {
			r.Form = authentication.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xee}, 32)))
		},
		"swapped browser pair": func(r *ssopg.SAMLIDPConfirmationRequest) { r.Browser, r.Form = r.Form, r.Browser },
	} {
		t.Run("rate source/"+name, func(t *testing.T) {
			wrong := request
			alter(&wrong)
			if gotRate, err := service.ConfirmationRateSource(f.ctx, wrong); !errors.Is(err, sso.ErrForbidden) || gotRate != (ssopg.ProviderLoginCallbackRateContext{}) {
				t.Fatal("unmatched pending confirmation disclosed rate correlation", err)
			}
		})
	}
	cancelled, cancelRate := context.WithCancel(f.ctx)
	cancelRate()
	if gotRate, err := service.ConfirmationRateSource(cancelled, request); !errors.Is(err, context.Canceled) || gotRate != (ssopg.ProviderLoginCallbackRateContext{}) {
		t.Fatal("cancelled pending attribution disclosed correlation or ignored cancellation", err)
	}
	if gotRate, err := service.ConfirmationRateSource(nil, request); !errors.Is(err, sso.ErrInvalidInput) || gotRate != (ssopg.ProviderLoginCallbackRateContext{}) {
		t.Fatal("nil context disclosed pending correlation", err)
	}
	var absentService *ssopg.ProviderSAMLIDPConfirmationService
	if gotRate, err := absentService.ConfirmationRateSource(f.ctx, request); !errors.Is(err, sso.ErrInvalidInput) || gotRate != (ssopg.ProviderLoginCallbackRateContext{}) {
		t.Fatal("missing confirmation composition disclosed pending correlation", err)
	}
	if verifications != 1 || rateCustody() != beforeRate {
		t.Fatal("rate attribution verified SAML, renewed pending cutoff or changed native custody")
	}
	for _, mode := range []string{"wrong origin", "wrong form"} {
		wrong := request
		if mode == "wrong origin" {
			wrong.Origin = "https://foreign.example.test"
		} else {
			wrong.Form = authentication.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xee}, 32)))
		}
		denied, err := service.Confirm(f.ctx, wrong)
		assertNativeSAMLCallbackWithholdsIssuance(t, denied)
		if err == nil || denied.Completion.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("substituted browser confirmation was accepted", mode)
		}
		assertNativeIDPArrivalCounts(t, f, 1, existingSessions)
		var unchanged bool
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT completed_at IS NULL AND binding_envelope=$2 AND confirmation_key_version=$3
 AND browser_digest=$4 AND form_digest=$5 AND expires_at=$6 FROM sso_providers.saml_idp_confirmations WHERE tenant_id=$1`,
			tenant, originalEnvelope, originalKey, originalBrowser, originalForm, originalExpiry).Scan(&unchanged); err != nil || !unchanged {
			t.Fatal("rejected browser confirmation changed original custody", mode, err)
		}
	}
	got, err := service.Confirm(f.ctx, request)
	if err != nil || got.Completion.Outcome != identity.CommitOutcomeCommitted ||
		got.Issuance.CommitOutcome != identity.CommitOutcomeCommitted || got.Issuance.Replayed || verifications != 1 {
		t.Fatal("public native confirmation did not commit the original linked session", err)
	}
	spec, err := got.Issuance.Session.Bindings()
	if err != nil || spec.TenantID != tenant || spec.UserID != "owner" || spec.Audience != "native-saml-idp-app" ||
		spec.Authentication.Proof.Method != "sso-saml" || spec.Authentication.CredentialID != "idp-credential" ||
		got.Completion.Binding.RecordID != string(pending.CommandID) || got.Completion.Binding.CommandID == pending.CommandID {
		t.Fatal("confirmation substituted the linked identity or original arrival", err)
	}
	remember, err := spec.Remember.Bindings()
	if err != nil || remember.Choice != session.BrowserSession {
		t.Fatal("confirmation lost the configured browser-session policy", err)
	}
	cookie := got.Issuance.Cookie
	if cookie.Name != "__Host-identity_session" || cookie.Value != "" || !cookie.Secure || !cookie.HttpOnly ||
		cookie.Path != "/" || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatal("confirmation did not issue normal host-only session transport")
	}
	bearer, tokenErr := got.Issuance.Token.Reveal()
	csrf, csrfErr := got.CSRF.Reveal()
	if tokenErr != nil || csrfErr != nil || bearer == "" || csrf == "" || got.Issuance.Session.CSRFState().Check(
		session.CSRFBinding{TenantID: tenant, SessionID: spec.SessionID, SessionVersion: spec.Version}, got.CSRF, csrfKey) != nil {
		t.Fatal("confirmation withheld a standard bearer or matching session-bound CSRF")
	}
	if _, err := got.Issuance.Token.Reveal(); err == nil {
		t.Fatal("confirmation bearer was disclosed twice")
	}
	completion, err := base64.RawURLEncoding.Strict().DecodeString(string(got.Completion.Binding.CommandID))
	if err != nil {
		t.Fatal(err)
	}
	assertCommitted := func() {
		t.Helper()
		var terminal, grant, journal bool
		var sessions, issuances, members, responses, assertions, spStarts, spLogins int
		var persisted []byte
		err := f.pool.Raw().QueryRow(f.ctx, `SELECT
 p.user_id='owner' AND p.completion_command_id=$2 AND p.completed_at IS NOT NULL AND p.expires_at=$3
 AND p.binding_envelope IS NULL AND p.confirmation_key_version IS NULL AND p.browser_digest IS NULL AND p.form_digest IS NULL,
 (SELECT count(*)=1 AND bool_and(state='finalized' AND uses=1 AND command_id=$4)
  FROM public.capability_identity_one_use WHERE tenant_id=p.tenant_id AND origin_command_id=$5 AND purpose='identity.sso.saml-idp-init'),
 j.state='committed' AND j.preparation_ciphertext IS NULL AND j.preparation_ciphertext_generation IS NULL,
 (SELECT count(*) FROM organization_sessions.sessions),
 (SELECT count(*) FROM organization_sessions.session_issuances WHERE tenant_id=p.tenant_id AND command_id=$2 AND purpose='identity.sso.saml-idp-init'),
 (SELECT count(*) FROM sso_providers.saml_replay_members WHERE tenant_id=p.tenant_id AND callback_command_id=$2),
 (SELECT count(*) FROM sso_providers.saml_replay_members WHERE tenant_id=p.tenant_id AND callback_command_id=$2 AND member_kind=1 AND member_digest=$6 AND issuer_digest=$8 AND provider_id=$9 AND organization_id=$10 AND callback_purpose='identity.sso.saml-idp-init'),
 (SELECT count(*) FROM sso_providers.saml_replay_members WHERE tenant_id=p.tenant_id AND callback_command_id=$2 AND member_kind=2 AND member_digest=$7 AND issuer_digest=$8 AND provider_id=$9 AND organization_id=$10 AND callback_purpose='identity.sso.saml-idp-init'),
 (SELECT count(*) FROM identity.commands WHERE purpose='identity.sso.saml-start'),
 (SELECT count(*) FROM sso_providers.fixture_unavailable_sp_logins),
 convert_to(s.record::text,'UTF8')
FROM sso_providers.saml_idp_confirmations p
JOIN identity.commands j ON j.tenant_id=p.tenant_id AND j.command_id=p.completion_command_id AND j.purpose='identity.sso.saml-idp-init'
JOIN organization_sessions.sessions s ON s.tenant_id=p.tenant_id AND s.session_id=$11 AND s.user_id=p.user_id AND s.state='active'
WHERE p.tenant_id=$1 AND p.confirmation_id=decode(translate($5,'-_','+/')||'==','base64')`, tenant, completion, originalExpiry,
			string(got.Completion.Binding.CommandID), string(pending.CommandID), nativeSAMLCallbackDigest("_native-idp-response"),
			nativeSAMLCallbackDigest("_native-idp-assertion"), nativeSAMLCallbackDigest(x.installed.EntityID),
			string(x.profile.ProviderID), string(x.profile.OrganizationID), spec.SessionID).Scan(
			&terminal, &grant, &journal, &sessions, &issuances, &members, &responses, &assertions, &spStarts, &spLogins, &persisted)
		if err != nil || !terminal || !grant || !journal || sessions != existingSessions+1 || issuances != 1 ||
			members != 2 || responses != 1 || assertions != 1 || spStarts != 0 || spLogins != 0 {
			t.Fatal("confirmation did not conserve its original grant, erase custody and commit exactly one replay pair and session without SP state",
				terminal, grant, journal, sessions, issuances, members, responses, assertions, spStarts, spLogins, err)
		}
		var durable struct {
			CSRF   session.CSRFStateSpec
			Lookup session.TokenDigest
		}
		if err := json.Unmarshal(persisted, &durable); err != nil {
			t.Fatal(err)
		}
		parsed, parseErr := session.ParseToken(bearer)
		digest, digestErr := parsed.Digest(lookup, string(tenant))
		state, stateErr := session.NewCSRFState(durable.CSRF)
		if parseErr != nil || digestErr != nil || stateErr != nil || digest != spec.Lookup || durable.Lookup != digest || state.Check(
			session.CSRFBinding{TenantID: tenant, SessionID: spec.SessionID, SessionVersion: spec.Version}, got.CSRF, csrfKey) != nil ||
			bytes.Contains(persisted, []byte(bearer)) || bytes.Contains(persisted, []byte(csrf)) {
			t.Fatal("durable session does not retain only the matching bearer and CSRF digests")
		}
	}
	assertCommitted()
	afterRate := rateCustody()
	if gotRate, err := service.ConfirmationRateSource(f.ctx, request); !errors.Is(err, sso.ErrForbidden) || gotRate != (ssopg.ProviderLoginCallbackRateContext{}) {
		t.Fatal("terminal confirmation disclosed new pending rate correlation", err)
	}
	if verifications != 1 || rateCustody() != afterRate {
		t.Fatal("terminal attribution repeated SAML verification or changed native custody")
	}
	b := got.Completion.Binding
	query := identity.RecoveryQuery{TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind,
		OperationID: b.OperationID, CommandID: b.CommandID, RecordID: b.RecordID}
	decision := authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Tenant: authorization.TenantID(b.TenantID),
		Subject: authorization.Subject{Kind: b.ActorKind, ID: authorization.SubjectID(b.ActorID)}, Action: authorization.Action(b.OperationID),
		Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}}}
	receipt, err := service.RecoverConfirmation(f.ctx, query, decision)
	if err != nil || receipt.Binding != b || receipt.Outcome != identity.CommitOutcomeCommitted || receipt.Feature == nil ||
		got.Completion.Feature == nil || *receipt.Feature != *got.Completion.Feature || verifications != 1 {
		t.Fatal("receipt recovery did not observe exactly the original historical confirmation", err)
	}
	query.UserID = "foreign-user"
	if receipt, err := service.RecoverConfirmation(f.ctx, query, decision); err == nil || receipt.Binding.CommandID != "" {
		t.Fatal("foreign receipt recovery disclosed confirmation history", err)
	}
	_, restoreErr := f.pool.Raw().Exec(f.ctx, `UPDATE sso_providers.saml_idp_confirmations
SET completed_at=NULL,completion_command_id=NULL,binding_envelope=$3,confirmation_key_version=$4,browser_digest=$5,form_digest=$6
WHERE tenant_id=$1 AND confirmation_id=decode(translate($2,'-_','+/')||'==','base64')`,
		tenant, string(pending.CommandID), originalEnvelope, originalKey, originalBrowser, originalForm)
	assertSAMLIDPStorageSQLState(t, "23514", restoreErr)
	repeated, _ := service.Confirm(f.ctx, request)
	assertNativeSAMLCallbackWithholdsIssuance(t, repeated)
	assertCommitted()

	// A fresh browser pair for the same signed response cannot bypass durable
	// response/assertion replay by selecting a different pending arrival.
	duplicate, err := arrival.Prepare(f.ctx, x.request())
	if err != nil || duplicate.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("prepare independently authenticated duplicate response", err)
	}
	duplicateBrowser, duplicateForm, _, ok := duplicate.TakeConfirmation()
	if !ok {
		t.Fatal("duplicate arrival did not obtain its independent pending pair")
	}
	duplicateRequest := request
	duplicateRequest.PendingID, duplicateRequest.Browser, duplicateRequest.Form = duplicate.CommandID, duplicateBrowser, duplicateForm
	denied, err := service.Confirm(f.ctx, duplicateRequest)
	assertNativeSAMLCallbackWithholdsIssuance(t, denied)
	if err == nil || denied.Completion.Outcome == identity.CommitOutcomeCommitted || verifications != 2 {
		t.Fatal("a new pending pair bypassed the original SAML replay set", err)
	}
	assertUnsettled := func(arrival identity.CommandID) {
		t.Helper()
		var intact, unused bool
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT p.completed_at IS NULL AND p.binding_envelope IS NOT NULL AND p.completion_command_id IS NULL,
 (SELECT count(*)=1 AND bool_and(state='released' AND uses=0) FROM public.capability_identity_one_use WHERE tenant_id=p.tenant_id AND origin_command_id=$2 AND purpose='identity.sso.saml-idp-init')
 FROM sso_providers.saml_idp_confirmations p WHERE p.tenant_id=$1 AND p.confirmation_id=decode(translate($2,'-_','+/')||'==','base64')`,
			tenant, string(arrival)).Scan(&intact, &unused); err != nil || !intact || !unused {
			t.Fatal("failed settlement did not preserve pending custody and terminally release its unused grant", intact, unused, err)
		}
	}
	assertUnsettled(duplicate.CommandID)
	assertCommitted()

	// A changed credential after issuance reaches SQL must roll back the
	// provisional session, replay pair, grant and pending custody together.
	late, err := arrival.Prepare(f.ctx, x.request())
	if err != nil || late.Outcome != identity.CommitOutcomeCommitted || verifications != 3 {
		t.Fatal("prepare a fresh pending confirmation for the final authority check", err)
	}
	lateBrowser, lateForm, _, ok := late.TakeConfirmation()
	if !ok {
		t.Fatal("fresh pending confirmation did not disclose its original pair")
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `CREATE SEQUENCE organization_sessions.fixture_idp_late_authority;
CREATE FUNCTION organization_sessions.fixture_idp_late_authority() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 PERFORM nextval('organization_sessions.fixture_idp_late_authority');
 UPDATE identity.credential_references SET enabled=false WHERE tenant_id=NEW.tenant_id AND user_id='owner' AND credential_id='idp-credential';
 RETURN NEW;
END $$;
CREATE TRIGGER fixture_idp_late_authority AFTER INSERT ON organization_sessions.session_issuances FOR EACH ROW
WHEN (NEW.purpose='identity.sso.saml-idp-init') EXECUTE FUNCTION organization_sessions.fixture_idp_late_authority()`); err != nil {
		t.Fatal("install the isolated final authority fixture", err)
	}
	lateRequest := request
	lateRequest.PendingID, lateRequest.Browser, lateRequest.Form = late.CommandID, lateBrowser, lateForm
	denied, err = service.Confirm(f.ctx, lateRequest)
	assertNativeSAMLCallbackWithholdsIssuance(t, denied)
	if err == nil || denied.Completion.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("a changed linked credential committed after provisional session write", err)
	}
	var reached, active bool
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT is_called FROM organization_sessions.fixture_idp_late_authority),
 (SELECT enabled FROM identity.credential_references WHERE tenant_id=$1 AND user_id='owner' AND credential_id='idp-credential')`, tenant).
		Scan(&reached, &active); err != nil || !reached || !active {
		t.Fatal("the exact final authority fixture was not exercised and rolled back", err)
	}
	assertUnsettled(late.CommandID)
	assertCommitted()
}
