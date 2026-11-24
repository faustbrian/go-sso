//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/faustbrian/go-sso/saml"
)

// Core §§3.7.1, 3.7.3.1; Profiles §§4.4.3.4, 4.4.4.1; Bindings
// §§3.5.4, 3.5.5.2: only an installed IdP's authenticated original request
// selects retained local sessions, and replay cannot issue another response.
func TestNativeSAMLIDPLogoutSignedRequestRevokesRetainedSessionOnce(t *testing.T) {
	spKey, spCertificate := nativeSAMLLogoutTestCertificate(t)
	private, err := x509.MarshalPKCS8PrivateKey(spKey)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	bundle, err := saml.EncodeSPSigningCredential(t.Context(), private, spCertificate, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(bundle)
	idpKey, idpCertificate := nativeSAMLLogoutTestCertificate(t)
	x := newNativeSAMLCallbackFixtureWithStart(t, newSAMLStartFixtureWithBundle(t, bundle, idpCertificate))
	f, loginConfig := x.start.start.enable.f, x.start.start.config
	ctx := f.ctx
	installSAMLIDPStorage(t, f, ssopg.SAMLLogoutSubjectMigrationSource{Version: 432})
	installSAMLIDPStorage(t, f, sessionpg.SSOSAMLIDPLogoutMigrationSource{Schema: loginConfig.Session.Schema, Version: 433})
	custody, err := ssopg.NewSAMLLogoutSubjectCustody(ssopg.SAMLLogoutSubjectCustodyConfig{
		KeyReference: loginConfig.KeyReference, CurrentMatchKey: 1, MatchKeys: map[uint32][32]byte{1: {0xa2}},
	})
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_session", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	const index = "native-idp-logout-original-index"
	const subjectFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	responseID, assertionID, sessionIndex := nativeSAMLCallbackResponseID, nativeSAMLCallbackAssertionID, index
	completionConfig := ssopg.ProviderSAMLLoginCompletionConfig{
		Audience: "native-saml-app", PolicyNamespace: "users", CSRFKey: x.csrf,
		Issuer: session.IssuerConfig{Clock: clock.System{}, MaximumDuration: 3 * time.Second, LookupKey: x.lookup, TokenSize: 32, Cookie: cookie},
	}
	verify := func(_ context.Context, in ssopg.SAMLResponseVerificationInput) (ssopg.SAMLVerifiedLoginResponse, error) {
		// This prerequisite assertion port is controlled; the logout request below
		// must pass the installed provider's real XML signature verifier.
		until := in.Now.Add(time.Minute)
		return ssopg.SAMLVerifiedLoginResponse{
			Evidence: ssopg.SAMLVerifiedResponse{ResponseID: responseID, AssertionID: assertionID,
				ProviderSubject: nativeSAMLCallbackSubject, SubjectFormat: subjectFormat, SessionIndex: sessionIndex, AssertionExpiresAt: until, ValidUntil: until},
			LogoutSubject: ssopg.SAMLLogoutSubject{ProviderSubject: nativeSAMLCallbackSubject, SubjectFormat: subjectFormat, SessionIndex: sessionIndex,
				NameQualifier: in.IdentityProviderEntityID, SPNameQualifier: in.SPEntityID},
		}, nil
	}
	completion, err := ssopg.NewProviderSAMLLoginCompletionServiceWithLogoutSubject(x.start.start.service, completionConfig, verify)
	if err != nil {
		t.Fatal(err)
	}
	completion, err = completion.WithLogoutSubjectCustody(custody)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := completion.SigninCallback(ctx, x.request)
	if err != nil || issued.Issuance.CommitOutcome != identity.CommitOutcomeCommitted {
		t.Fatal("issue a real local session with its original signed logout subject", err)
	}
	record, err := issued.Issuance.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	bearer, err := issued.Issuance.Token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	organizations, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	selection := sessionpg.SSOSAMLSessionAdmission{Profile: sessionpg.IdentifierAdmissionConfig{GlobalAuthorityID: loginConfig.GlobalAuthorityID,
		PolicyNamespace: "users", Audience: record.Audience, AuthenticationMethod: "sso-saml", CredentialKind: identity.CredentialProvider, CredentialOwner: "sso"}, Authority: organizations}
	reader, err := sessionpg.NewSelectedSessionServiceWithSSOSAML(f.pool, sessionpg.SelectedSessionServiceConfig{
		Repository: loginConfig.Session, Validation: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: record.Audience,
			LookupKeys: []session.DigestKey{x.lookup}, Clock: clock.System{}, MaximumDuration: time.Second, ClockUncertainty: time.Millisecond},
	}, selection, nil)
	if err != nil {
		t.Fatal(err)
	}
	get := nativeProviderLogoutGetRequest(t, record.TenantID, bearer)
	if got, err := reader.Get(ctx, get); err != nil || !got.Authenticated {
		t.Fatal("original native cookie must authenticate before the signed IdP request", err)
	}
	authorizer := &nativeSAMLIDPLogoutJourneyPolicy{tenant: record.TenantID, user: record.UserID}
	policy := kernel.CommandQueryPolicy{Authorization: authorizer, Clock: clock.System{}, PolicyVersion: 1}
	loginConfig.Coordinator.QueryPolicy, loginConfig.Coordinator.AdmissionPolicy = &policy, &policy
	loginConfig.RequestKeys, err = kernel.NewRequestKeyConfig("native-sso-login", [32]byte{0xaa}, policy)
	if err != nil {
		t.Fatal(err)
	}
	login, err := ssopg.NewProviderLoginServiceWithSAML(x.start.router, loginConfig, x.start.profiles, x.start.sign)
	if err != nil {
		t.Fatal(err)
	}
	profile := x.start.profiles[0]
	// The independent receiver uses the protocol's canonical, queryless
	// inbound verifier route; the signer separately tests fixed query support.
	const responseEndpoint = "https://identity-provider.example.test/slo/response"
	service, err := ssopg.NewProviderSAMLIDPLogoutService(login, ssopg.ProviderSAMLIDPLogoutConfig{
		Custody: custody, Providers: []ssopg.ProviderSAMLIDPLogoutProfile{{Provider: profile,
			IdentityProviderEntityID: nativeSAMLCallbackIssuer, ResponseEndpoint: responseEndpoint}},
	})
	if err != nil {
		t.Fatal("compose installed-provider IdP request processing", err)
	}
	spEntity := profile.TrustedOrigin + "/saml2/" + string(profile.ProviderID) + "/metadata"
	destination := profile.TrustedOrigin + "/saml2/" + string(profile.ProviderID) + "/slo"
	issuedAt := time.Now().UTC().Truncate(time.Second)
	wire := func(id, subject, sessionIndex string, key *rsa.PrivateKey, at time.Time) ssopg.ProviderSAMLIDPLogoutRequest {
		return ssopg.ProviderSAMLIDPLogoutRequest{ProviderID: profile.ProviderID, SAMLRequest: []string{
			nativeSAMLIDPLogoutRequestWire(t, key, nativeSAMLCallbackIssuer, spEntity, destination, id, subject, sessionIndex, at),
		}}
	}
	request := wire("_native-idp-logout-request", nativeSAMLCallbackSubject, index, idpKey, issuedAt)
	wrongKey, _ := nativeSAMLLogoutTestCertificate(t)
	decoded, err := base64.StdEncoding.DecodeString(request.SAMLRequest[0])
	if err != nil {
		t.Fatal(err)
	}
	tampered := base64.StdEncoding.EncodeToString([]byte(strings.Replace(string(decoded), nativeSAMLCallbackSubject, "substituted-subject", 1)))
	before := nativeSAMLIDPLogoutSnapshot(t, f, record.SessionID)
	for name, invalid := range map[string]ssopg.ProviderSAMLIDPLogoutRequest{
		"different signed subject": wire("_other-subject", "other-member", index, idpKey, issuedAt),
		"different signed index":   wire("_other-index", nativeSAMLCallbackSubject, "unrelated-index", idpKey, issuedAt),
		"uninstalled signing key":  wire("_wrong-key", nativeSAMLCallbackSubject, index, wrongKey, issuedAt),
		"tampered signed subject":  {ProviderID: profile.ProviderID, SAMLRequest: []string{tampered}},
		"duplicate form members":   {ProviderID: profile.ProviderID, SAMLRequest: []string{request.SAMLRequest[0], request.SAMLRequest[0]}},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := service.HandleRequest(ctx, invalid)
			if len(got.LocalRevocations) != 0 || got.Completion.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("unmatched or unauthenticated request fabricated local revocation authority", err)
			}
			if name == "uninstalled signing key" || name == "tampered signed subject" || name == "duplicate form members" {
				if _, exposed := got.Response(); exposed || !errors.Is(err, sso.ErrInvalidInput) {
					t.Fatal("invalid signature or form shape disclosed a signed protocol response", err)
				}
			}
			if after := nativeSAMLIDPLogoutSnapshot(t, f, record.SessionID); after != before {
				t.Fatal("rejected request changed the session or durable logout effects")
			}
		})
	}
	var originalExpiry time.Time
	if err := f.pool.Raw().QueryRow(ctx, `SELECT expires_at FROM sso_providers.saml_logout_subjects WHERE tenant_id=$1 AND session_id=$2`, record.TenantID, record.SessionID).Scan(&originalExpiry); err != nil {
		t.Fatal("retain exact fixture correlation before the in-Work recheck probe", err)
	}
	hookCalls := 0
	authorizer.beforeUserAuthorization = func(ctx context.Context) error {
		hookCalls++
		tag, err := f.pool.Raw().Exec(ctx, `UPDATE sso_providers.saml_logout_subjects SET expires_at=$3 WHERE tenant_id=$1 AND session_id=$2`,
			record.TenantID, record.SessionID, originalExpiry.Add(-time.Microsecond))
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return sso.ErrUnavailable
		}
		return nil
	}
	staleRequest := wire("_native-idp-logout-stale-correlation", nativeSAMLCallbackSubject, index, idpKey, issuedAt)
	stale, staleErr := service.HandleRequest(ctx, staleRequest)
	if tag, err := f.pool.Raw().Exec(ctx, `UPDATE sso_providers.saml_logout_subjects SET expires_at=$3 WHERE tenant_id=$1 AND session_id=$2`,
		record.TenantID, record.SessionID, originalExpiry); err != nil || tag.RowsAffected() != 1 {
		t.Fatal("restore exact original fixture correlation after the bounded recheck probe", err)
	}
	if _, exposed := stale.Response(); hookCalls != 1 || staleErr == nil || exposed || stale.Completion.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("changed retained correlation committed or disclosed a response after target preparation", staleErr)
	}
	for _, revocation := range stale.LocalRevocations {
		if revocation.Committed {
			t.Fatal("rolled-back target recheck reported a committed local revocation")
		}
	}
	afterStale := nativeSAMLIDPLogoutSnapshot(t, f, record.SessionID)
	if afterStale.state != before.state || afterStale.version != before.version || afterStale.revocations != before.revocations || afterStale.events != before.events {
		t.Fatal("changed retained correlation did not roll back the native session and lifecycle effects")
	}
	if observed, err := reader.Get(ctx, get); err != nil || !observed.Authenticated {
		t.Fatal("rolled-back correlation recheck invalidated the original cookie", err)
	}
	before = afterStale

	operationStarted := time.Now()
	got, err := service.HandleRequest(ctx, request)
	t.Logf("signed IdP logout HandleRequest elapsed: %s", time.Since(operationStarted))
	if err != nil || got.Completion.Outcome != identity.CommitOutcomeCommitted || len(got.LocalRevocations) != 1 {
		t.Fatal("signed installed-provider request did not commit its real retained session", err)
	}
	local := got.LocalRevocations[0]
	if local.Validate() != nil || local.SessionID != record.SessionID || local.Version != record.Version+1 || !local.Committed || local.ReconciliationRequired {
		t.Fatal("local result lost the exact committed session and revocation version")
	}
	if observed, err := reader.Get(ctx, get); err != nil || observed.Authenticated {
		t.Fatal("original native cookie still authenticates after IdP logout", err)
	}
	fields, exposed := got.Response()
	if !exposed || fields.Destination != responseEndpoint || fields.SAMLResponse == "" {
		t.Fatal("committed request did not return a POST response to the configured IdP endpoint")
	}
	// LogoutResponse carries no audience; the reverse verifier still requires
	// a valid HTTPS entity for its local receiver configuration.
	responseVerifier, err := saml.NewLogoutPOSTProfile(saml.LogoutPOSTConfig{SPEntityID: "https://identity-provider.example.test/metadata",
		IdentityProviderEntityID: spEntity, SingleLogoutURL: responseEndpoint, SigningCertificates: [][]byte{spCertificate}, MaximumAge: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := responseVerifier.Validate(ctx, saml.LogoutPOSTInput{SAMLResponse: []string{fields.SAMLResponse}, Now: time.Now().UTC()})
	if err != nil {
		t.Fatal("response was not signed by the installed SP credential for the exact IdP destination", err)
	}
	response, err := verified.Response()
	if err != nil || response.InResponseTo != "_native-idp-logout-request" || response.Status != (saml.LogoutPOSTStatus{Code: saml.LogoutStatusSuccess}) {
		t.Fatal("signed response did not acknowledge the exact original request", err)
	}
	committed := nativeSAMLIDPLogoutSnapshot(t, f, record.SessionID)
	if committed.state != "revoked" || committed.version != record.Version || committed.revocations != before.revocations+1 ||
		committed.commands != before.commands+1 || committed.audits != before.audits+1 || committed.events != before.events+1 {
		t.Fatal("logout did not retain one native session transition, command, audit and lifecycle effect")
	}
	replay, err := service.HandleRequest(ctx, request)
	if _, exposed := replay.Response(); err != nil || exposed || !reflect.DeepEqual(replay.LocalRevocations, got.LocalRevocations) ||
		!reflect.DeepEqual(replay.Completion, got.Completion) {
		t.Fatal("exact replay regenerated a response or changed the committed local projection", err)
	}
	if after := nativeSAMLIDPLogoutSnapshot(t, f, record.SessionID); after != committed {
		t.Fatal("same-key retry changed the session or created another audit/outbox effect")
	}
	changed := wire("_native-idp-logout-request", nativeSAMLCallbackSubject, index, idpKey, issuedAt.Add(-time.Second))
	conflict, err := service.HandleRequest(ctx, changed)
	if _, exposed := conflict.Response(); err == nil || exposed {
		t.Fatal("different signed bytes reused the original message ID", err)
	}
	if after := nativeSAMLIDPLogoutSnapshot(t, f, record.SessionID); after != committed {
		t.Fatal("changed-message replay changed the original committed session or effects")
	}

	t.Run("maximum native target set", func(t *testing.T) {
		const targetCount = 128
		const denseIndex = "native-idp-logout-dense-index"
		sessionIndex = denseIndex
		targets := make(map[string]uint64, targetCount)
		var denseLogin *ssopg.ProviderLoginService
		var denseCompletion *ssopg.ProviderSAMLLoginCompletionService
		for n := range targetCount {
			// The canonical authentication policy caps a tenant at ten attempts.
			// Separate fixture deployments keep each eight-login batch within that
			// limit while retaining real counters, audit, issuance and custody.
			if n%8 == 0 {
				denseConfig := x.start.start.config
				denseConfig.Risk = nativeSAMLIDPLogoutDenseAdmission(t, x.start.start.enable, fmt.Sprintf("native-saml-dense-%d", n/8))
				denseLogin, err = ssopg.NewProviderLoginServiceWithSAML(x.start.router, denseConfig, x.start.profiles, x.start.sign)
				if err != nil {
					t.Fatal("compose bounded real dense-fixture sign-in deployment", err)
				}
				denseCompletion, err = ssopg.NewProviderSAMLLoginCompletionServiceWithLogoutSubject(denseLogin, completionConfig, verify)
				if err != nil {
					t.Fatal(err)
				}
				denseCompletion, err = denseCompletion.WithLogoutSubjectCustody(custody)
				if err != nil {
					t.Fatal(err)
				}
			}
			correlation := fmt.Sprintf("native-saml-dense-browser-%d", n)
			prepared, err := x.start.start.flowIssuer.Prepare(session.PreAuthPrepareInput{CommandID: commandID(t), TenantID: record.TenantID,
				CorrelationID: correlation, Remember: x.start.start.originalFlow.Intent.Remember})
			if err != nil {
				t.Fatal("prepare a fresh native browser for the dense target set", err)
			}
			flowIssued, err := x.start.start.flowIssuer.Issue(ctx, prepared)
			if err != nil || flowIssued.CommitOutcome != identity.CommitOutcomeCommitted || flowIssued.Replayed {
				t.Fatal("issue a fresh native browser before measured logout", err)
			}
			flow, err := flowIssued.Flow.Bindings()
			if err != nil {
				t.Fatal(err)
			}
			flowCookie, err := flowIssued.Token.Reveal()
			if err != nil {
				t.Fatal(err)
			}
			browser := x.start.start.browser
			browser.FlowID, browser.FlowCookie = flow.Binding.ID, authentication.NewBearerCredential(flowCookie)
			started, err := denseLogin.SigninStartSAML(ctx, x.start.request, browser)
			if err != nil || started.Completion.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("commit the dense fixture's original native SAML start", err)
			}
			responseID, assertionID = fmt.Sprintf("_dense-response-%d", n), fmt.Sprintf("_dense-assertion-%d", n)
			callback := x.request
			callback.Browser, callback.RelayState = browser, started.RedirectURI.Query().Get("RelayState")
			signedIn, err := denseCompletion.SigninCallback(ctx, callback)
			if err != nil || signedIn.Issuance.CommitOutcome != identity.CommitOutcomeCommitted {
				t.Fatal("issue and correlate each real native session before measured logout", err)
			}
			binding, err := signedIn.Issuance.Session.Bindings()
			if err != nil {
				t.Fatal(err)
			}
			if _, duplicate := targets[binding.SessionID]; duplicate {
				t.Fatal("dense fixture reused a session rather than issuing a new one")
			}
			targets[binding.SessionID] = binding.Version
		}
		denseBefore := nativeSAMLIDPLogoutSnapshot(t, f, record.SessionID)
		denseRequest := wire("_native-idp-logout-maximum-targets", nativeSAMLCallbackSubject, denseIndex, idpKey, time.Now().UTC().Truncate(time.Second))
		acquisitionsBefore := f.pool.Raw().Stat().AcquireCount()
		startedAt := time.Now()
		dense, err := service.HandleRequest(ctx, denseRequest)
		elapsed := time.Since(startedAt)
		acquisitions := f.pool.Raw().Stat().AcquireCount() - acquisitionsBefore
		t.Logf("signed IdP logout HandleRequest targets=%d elapsed=%s pool_acquisitions=%d; preparation performs one indexed session read per target", targetCount, elapsed, acquisitions)
		if err != nil || dense.Completion.Outcome != identity.CommitOutcomeCommitted || len(dense.LocalRevocations) != targetCount {
			t.Fatal("maximum native target set did not commit every retained session", err)
		}
		for _, local := range dense.LocalRevocations {
			version, selected := targets[local.SessionID]
			if !selected || local.Validate() != nil || local.Version != version+1 || !local.Committed || local.ReconciliationRequired {
				t.Fatal("maximum native target set omitted, duplicated or misprojected a real session")
			}
			delete(targets, local.SessionID)
		}
		if len(targets) != 0 {
			t.Fatal("maximum native logout did not acknowledge its complete original target set")
		}
		denseFields, exposed := dense.Response()
		if !exposed || denseFields.Destination != responseEndpoint {
			t.Fatal("maximum native logout did not return its configured POST response")
		}
		verified, err := responseVerifier.Validate(ctx, saml.LogoutPOSTInput{SAMLResponse: []string{denseFields.SAMLResponse}, Now: time.Now().UTC()})
		if err != nil {
			t.Fatal("maximum native logout did not sign its response with the installed SP credential", err)
		}
		response, err := verified.Response()
		if err != nil || response.InResponseTo != "_native-idp-logout-maximum-targets" || response.Status != (saml.LogoutPOSTStatus{Code: saml.LogoutStatusSuccess}) {
			t.Fatal("maximum native logout signed the wrong original request or status", err)
		}
		denseAfter := nativeSAMLIDPLogoutSnapshot(t, f, record.SessionID)
		if denseAfter.state != denseBefore.state || denseAfter.version != denseBefore.version || denseAfter.revocations != denseBefore.revocations+1 ||
			denseAfter.commands != denseBefore.commands+1 || denseAfter.audits != denseBefore.audits+1 || denseAfter.events != denseBefore.events+1 {
			t.Fatal("maximum target set repeated the original revocation or did not retain exactly one command, audit and lifecycle effect")
		}
		var selectedSessions, revokedSessions int
		if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*),count(*) FILTER (WHERE s.state='revoked')
 FROM organization_sessions.sessions s JOIN sso_providers.saml_logout_subjects c
 ON (s.tenant_id,s.session_id)=(c.tenant_id,c.session_id)
 WHERE c.tenant_id=$1 AND c.provider_id=$2 AND c.session_id<>$3`, record.TenantID, profile.ProviderID, record.SessionID).Scan(&selectedSessions, &revokedSessions); err != nil || selectedSessions != targetCount || revokedSessions != targetCount {
			t.Fatal("maximum native logout left a real retained target active", err)
		}
	})
}

func nativeSAMLIDPLogoutDenseAdmission(t *testing.T, x providerEnableFixture, namespace string) risk.AuthenticationAdmissionCustodyConfig {
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
		t.Fatal(err)
	}
	counterKey, err := risk.NewCounterDigestKey(1, bytes.Repeat([]byte{0xb1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	counters, err := riskpg.NewDurableCounterStore(riskpg.DurableCounterConfig{Pool: x.f.pool, Schema: providerLoginRiskSchema, Namespace: namespace,
		Policy: policy, Keys: []risk.CounterDigestKey{counterKey}, ReplayKey: bytes.Repeat([]byte{0xb2}, 32),
		Tenants: []string{string(x.proof.TenantID)}, MaximumRecords: 64, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	wall := func() time.Time { return time.Now().UTC() }
	coordinator, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: policy, Store: counters, Clock: wall, Keys: []risk.CounterDigestKey{counterKey}, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	audits, err := auditpg.New(x.f.pool.Raw(), auditpg.Config{})
	if err != nil {
		t.Fatal(err)
	}
	evaluator, err := risk.NewEvaluator(risk.EvaluatorConfig{Policy: policy, Clock: wall, Timeout: 2 * time.Second, Counters: &coordinator,
		Sources: []risk.Source{{Name: "status", Version: "native-login-status-v1", Timeout: time.Second, Read: func(ctx context.Context, c risk.Context) (risk.Signal, error) {
			if err := ctx.Err(); err != nil {
				return risk.Signal{}, err
			}
			return risk.Signal{Tenant: c.Tenant, Operation: c.Operation, Attempt: c.Attempt, Name: "status", State: risk.SignalClean, Trust: risk.ServerVerified, ObservedAt: c.Now, ExpiresAt: c.Now.Add(20 * time.Second)}, nil
		}}},
		DecisionAudit: &risk.DecisionAuditConfig{PolicyID: string(commandID(t)), Timeout: time.Second, Delivery: audit.RecorderConfig{Sink: audits, Mode: audit.DeliveryFailClosed},
			OnLoss: func(context.Context, risk.DecisionDelivery) error {
				return errors.New("dense native login audit unavailable")
			}},
	})
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := risk.NewEvidenceKey(1, bytes.Repeat([]byte{0xb3}, 32), bytes.Repeat([]byte{0xb4}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return risk.AuthenticationAdmissionCustodyConfig{Evaluation: evaluator, ConfigurationID: "native-sso-login-risk-v1", Keys: []risk.EvidenceKey{evidence}}
}

type nativeSAMLIDPLogoutJourneyPolicy struct {
	tenant                  identity.TenantID
	user                    identity.UserID
	beforeUserAuthorization func(context.Context) error
}

func (p *nativeSAMLIDPLogoutJourneyPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	r := c.Request
	ownsUser := r.Resource.Type == "identity.user" && r.Resource.ID == authorization.ResourceID(p.user)
	resolvesKey := r.Resource.Type == "identity.request-admission" && r.Resource.ID == "identity.sso.saml-slo"
	if c.PolicyRevision == 1 && r.Tenant == authorization.TenantID(p.tenant) && r.Subject.Kind == authorization.SubjectServiceAccount &&
		r.Subject.ID == "native-sso-login" && r.Action == "identity.sso.saml-slo" && (ownsUser || resolvesKey) {
		if ownsUser && p.beforeUserAuthorization != nil {
			hook := p.beforeUserAuthorization
			p.beforeUserAuthorization = nil
			if err := hook(ctx); err != nil {
				return authorization.Decision{}, err
			}
		}
		return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
	}
	return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, nil
}

type nativeSAMLIDPLogoutState struct {
	state                                 string
	version                               uint64
	revocations, commands, audits, events int
}

func nativeSAMLIDPLogoutSnapshot(t *testing.T, f *orgFixture, sessionID string) nativeSAMLIDPLogoutState {
	t.Helper()
	var state nativeSAMLIDPLogoutState
	err := f.pool.Raw().QueryRow(f.ctx, `SELECT state,version,
 (SELECT count(*) FROM organization_sessions.saml_idp_logout_revocations),
 (SELECT count(*) FROM identity.commands WHERE purpose='identity.sso.saml-slo'),
 (SELECT count(*) FROM audit.records),
 (SELECT count(*) FROM public.outbox_messages)
 FROM organization_sessions.sessions WHERE session_id=$1`, sessionID).Scan(
		&state.state, &state.version, &state.revocations, &state.commands, &state.audits, &state.events)
	if err != nil {
		t.Fatal("observe native session and committed logout effect counts", err)
	}
	return state
}

// These canonical bytes are assembled independently of the production XML
// parser and signer, following XML Signature 1.1 §§3.1–3.2 and the selected
// exclusive-canonicalization, enveloped-signature and RSA-PSS SHA-256 profile.
func nativeSAMLIDPLogoutRequestWire(t *testing.T, signer *rsa.PrivateKey, issuer, spEntity, destination, id, subject, index string, issued time.Time) string {
	t.Helper()
	attribute := strings.NewReplacer("&", "&amp;", "<", "&lt;", `"`, "&quot;", "\t", "&#x9;", "\n", "&#xA;", "\r", "&#xD;")
	text := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\r", "&#xD;")
	open := `<p:LogoutRequest xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" Destination="` + attribute.Replace(destination) +
		`" ID="` + attribute.Replace(id) + `" IssueInstant="` + issued.UTC().Format(time.RFC3339Nano) +
		`" NotOnOrAfter="` + issued.Add(2*time.Minute).UTC().Format(time.RFC3339Nano) + `" Version="2.0">`
	issuerXML := `<a:Issuer xmlns:a="urn:oasis:names:tc:SAML:2.0:assertion">` + text.Replace(issuer) + `</a:Issuer>`
	subjectXML := `<a:NameID xmlns:a="urn:oasis:names:tc:SAML:2.0:assertion" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" NameQualifier="` +
		attribute.Replace(issuer) + `" SPNameQualifier="` + attribute.Replace(spEntity) + `">` + text.Replace(subject) + `</a:NameID>`
	indexXML := ""
	if index != "" {
		indexXML = `<p:SessionIndex>` + text.Replace(index) + `</p:SessionIndex>`
	}
	const closeXML = `</p:LogoutRequest>`
	targetDigest := sha256.Sum256([]byte(open + issuerXML + subjectXML + indexXML + closeXML))
	const signatureNamespace = `xmlns:ds="http://www.w3.org/2000/09/xmldsig#"`
	signedInfo := `<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod>` +
		`<ds:SignatureMethod Algorithm="` + saml.SignatureAlgorithmRSAPSSSHA256 + `"></ds:SignatureMethod>` +
		`<ds:Reference URI="#` + attribute.Replace(id) + `"><ds:Transforms>` +
		`<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform>` +
		`<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms>` +
		`<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod>` +
		`<ds:DigestValue>` + base64.StdEncoding.EncodeToString(targetDigest[:]) + `</ds:DigestValue></ds:Reference>`
	digest := sha256.Sum256([]byte(`<ds:SignedInfo ` + signatureNamespace + `>` + signedInfo + `</ds:SignedInfo>`))
	signature, err := rsa.SignPSS(rand.Reader, signer, crypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: sha256.Size})
	if err != nil {
		t.Fatal("sign independent fixture LogoutRequest", err)
	}
	signatureXML := `<ds:Signature ` + signatureNamespace + `><ds:SignedInfo>` + signedInfo + `</ds:SignedInfo><ds:SignatureValue>` +
		base64.StdEncoding.EncodeToString(signature) + `</ds:SignatureValue></ds:Signature>`
	return base64.StdEncoding.EncodeToString([]byte(open + issuerXML + signatureXML + subjectXML + indexXML + closeXML))
}
