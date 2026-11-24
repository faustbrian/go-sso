//go:build integration

package postgres_test

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/faustbrian/go-sso/saml"
)

func TestNativeSAMLLogoutRelayStateReservesOneOriginalWire(t *testing.T) {
	t.Run("acknowledged", func(t *testing.T) { assertNativeSAMLLogoutRelayState(t, false, nil) })
	t.Run("outbound failure preserves local result", func(t *testing.T) { assertNativeSAMLLogoutRelayState(t, true, nil) })
}

func TestNativeSAMLLogoutRelayStateRejectsStateFreeSettlement(t *testing.T) {
	assertNativeSAMLLogoutRelayState(t, false, func(ctx context.Context, service *ssopg.ProviderSAMLLogoutRedirectService, profile ssopg.StaticSAMLLoginProfile, idpKey *rsa.PrivateKey, start ssopg.ProviderSAMLLogoutRedirectResult, handle string) {
		status := saml.LogoutPOSTStatus{Code: saml.LogoutStatusSuccess}
		response := nativeSAMLLogoutResponseInput(t, profile, idpKey, status,
			"_saml-relay-required", "_"+string(start.Completion.Binding.CommandID), time.Now())
		result, err := service.SettleResponse(ctx, response)
		if _, continuation := result.FinalRedirect(); !errors.Is(err, sso.ErrInvalidInput) || continuation || result.Status != (saml.LogoutPOSTStatus{}) {
			t.Fatal("state-free settlement admitted a signed response for an original RelayState request", err)
		}
		for _, values := range [][]string{nil, {handle, handle}, {strings.Repeat("A", len(handle))}} {
			result, err := service.SettleResponseWithRelayState(ctx, response, values)
			if _, continuation := result.FinalRedirect(); !errors.Is(err, sso.ErrInvalidInput) || continuation || result.Status != (saml.LogoutPOSTStatus{}) {
				t.Fatal("wrong or ambiguous handle admitted original response", err)
			}
		}
		result, err = service.SettleResponseWithRelayState(ctx, response, []string{handle})
		continuation, exposed := result.FinalRedirect()
		if err != nil || !exposed || continuation.String() != nativeLogoutFinalRedirect || result.Outcome != ssopg.SAMLLogoutResponseSettled || result.Status != status || result.LocalRevocation != start.LocalRevocation {
			t.Fatal("signed response and exact state did not settle with its original continuation", result.Outcome, err)
		}
		replayed, err := service.SettleResponseWithRelayState(ctx, response, []string{handle})
		if _, continuation := replayed.FinalRedirect(); err != nil || continuation || replayed.Outcome != ssopg.SAMLLogoutResponseReplayed || replayed.LocalRevocation != start.LocalRevocation || replayed.Status != status {
			t.Fatal("exact replay did not recover the original receipt without its continuation", replayed.Outcome, err)
		}
		changed := nativeSAMLLogoutResponseInput(t, profile, idpKey, status, "_saml-relay-different-response", "_"+string(start.Completion.Binding.CommandID), time.Now())
		conflict, err := service.SettleResponseWithRelayState(ctx, changed, []string{handle})
		if _, continuation := conflict.FinalRedirect(); !errors.Is(err, sso.ErrConflict) || continuation || conflict.Status != (saml.LogoutPOSTStatus{}) {
			t.Fatal("another signed response acquired the consumed original state", conflict.Outcome, err)
		}
	})
}

func TestNativeSAMLLogoutRelayStateSettlesPartialWithoutContinuation(t *testing.T) {
	assertNativeSAMLLogoutRelayState(t, false, func(ctx context.Context, service *ssopg.ProviderSAMLLogoutRedirectService, profile ssopg.StaticSAMLLoginProfile, idpKey *rsa.PrivateKey, start ssopg.ProviderSAMLLogoutRedirectResult, handle string) {
		status := saml.LogoutPOSTStatus{Code: saml.LogoutStatusSuccess, Subcode: saml.LogoutStatusPartialLogout}
		response := nativeSAMLLogoutResponseInput(t, profile, idpKey, status, "_saml-relay-partial", "_"+string(start.Completion.Binding.CommandID), time.Now())
		result, err := service.SettleResponseWithRelayState(ctx, response, []string{handle})
		if _, continuation := result.FinalRedirect(); err != nil || continuation || result.Outcome != ssopg.SAMLLogoutResponseProviderFailure || result.Status != status || result.LocalRevocation != start.LocalRevocation {
			t.Fatal("signed partial response must settle without a continuation", result.Outcome, err)
		}
	})
}

type nativeSAMLLogoutRelayResponseCheck func(context.Context, *ssopg.ProviderSAMLLogoutRedirectService, ssopg.StaticSAMLLoginProfile, *rsa.PrivateKey, ssopg.ProviderSAMLLogoutRedirectResult, string)

func assertNativeSAMLLogoutRelayState(t *testing.T, failReservation bool, checkResponse nativeSAMLLogoutRelayResponseCheck) {
	t.Helper()
	key, bundle := nativeSAMLLogoutSigningBundle(t)
	defer clear(bundle)
	var idpKey *rsa.PrivateKey
	var certificates [][]byte
	if checkResponse != nil {
		var cert []byte
		idpKey, cert = nativeSAMLLogoutTestCertificate(t)
		certificates = [][]byte{cert}
	}
	x := newNativeSAMLCallbackFixtureWithStart(t, newSAMLStartFixtureWithBundle(t, bundle, certificates...))
	f, loginConfig := x.start.start.enable.f, x.start.start.config
	ctx := f.ctx
	revocation, err := (sessionpg.RevokeOneMigrationSource{Base: sessionpg.RevocationMigrationSource{
		Base: sessionpg.MigrationSource{Schema: loginConfig.Session.Schema, Version: 20}, Version: 370,
	}, Version: 432}).Load(ctx)
	if err != nil || len(revocation) != 3 {
		t.Fatal("load exact native revocation history", err)
	}
	installSAMLIDPStorage(t, f, migrationList(revocation[2:]))
	installSAMLIDPStorage(t, f, sessionpg.SSOSAMLLogoutStartMigrationSource{Schema: loginConfig.Session.Schema,
		Version: 433, ValidationVersion: 434, PreviousConstraint: "session_revocations_purpose_check"})
	installSAMLIDPStorage(t, f, ssopg.SAMLLogoutSubjectMigrationSource{Version: 435})
	installSAMLIDPStorage(t, f, ssopg.SAMLLogoutRequestMigrationSource{Version: 436})
	priorErasure := kernel.SSOSAMLIDPConfirmationPreparationErasureMigrationSource{Base: f.history, Version: 437}
	erasure, err := (kernel.SSOSAMLLogoutRelayIssuePreparationErasureMigrationSource{Base: priorErasure, Version: 438}).Load(ctx)
	if err != nil || len(erasure) < 2 {
		t.Fatal("load forward-only logout relay erasure", err)
	}
	installSAMLIDPStorage(t, f, migrationList(erasure[len(erasure)-2:]))
	if checkResponse != nil {
		installSAMLIDPStorage(t, f, ssopg.SAMLLogoutResponseMigrationSource{Version: 439})
	}
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
	const index = "native-original-saml-logout-index"
	completion, err := ssopg.NewProviderSAMLLoginCompletionServiceWithLogoutSubject(x.start.start.service, ssopg.ProviderSAMLLoginCompletionConfig{
		Audience: "native-saml-app", PolicyNamespace: "users", CSRFKey: x.csrf,
		Issuer: session.IssuerConfig{Clock: clock.System{}, MaximumDuration: 3 * time.Second, LookupKey: x.lookup, TokenSize: 32, Cookie: cookie},
	}, func(_ context.Context, in ssopg.SAMLResponseVerificationInput) (ssopg.SAMLVerifiedLoginResponse, error) {
		const format = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
		until := in.Now.Add(time.Minute)
		return ssopg.SAMLVerifiedLoginResponse{
			Evidence: ssopg.SAMLVerifiedResponse{ResponseID: nativeSAMLCallbackResponseID, AssertionID: nativeSAMLCallbackAssertionID,
				ProviderSubject: nativeSAMLCallbackSubject, SubjectFormat: format, SessionIndex: index, AssertionExpiresAt: until, ValidUntil: until},
			LogoutSubject: ssopg.SAMLLogoutSubject{ProviderSubject: nativeSAMLCallbackSubject, SubjectFormat: format, SessionIndex: index,
				NameQualifier: in.IdentityProviderEntityID, SPNameQualifier: in.SPEntityID},
		}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	completion, err = completion.WithLogoutSubjectCustody(custody)
	if err != nil {
		t.Fatal(err)
	}
	loginResult, err := completion.SigninCallback(ctx, x.request)
	if err != nil || loginResult.Issuance.CommitOutcome != identity.CommitOutcomeCommitted {
		t.Fatal("issue genuine native SAML session and retained signed-subject projection", err)
	}
	record, err := loginResult.Issuance.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	bearer, err := loginResult.Issuance.Token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	organizations, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	selection := sessionpg.SSOSAMLSessionAdmission{Profile: sessionpg.IdentifierAdmissionConfig{GlobalAuthorityID: loginConfig.GlobalAuthorityID,
		PolicyNamespace: "users", Audience: record.Audience, AuthenticationMethod: "sso-saml", CredentialKind: identity.CredentialProvider, CredentialOwner: "sso"},
		Authority: organizations}
	validation := session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: record.Audience, LookupKeys: []session.DigestKey{x.lookup},
		Clock: clock.System{}, MaximumDuration: time.Second, ClockUncertainty: time.Millisecond}
	reader, err := sessionpg.NewSelectedSessionServiceWithSSOSAML(f.pool, sessionpg.SelectedSessionServiceConfig{
		Repository: loginConfig.Session, Validation: validation}, selection, nil)
	if err != nil {
		t.Fatal(err)
	}
	policy := kernel.CommandQueryPolicy{Authorization: nativeSAMLLogoutRelayPolicy{local: nativeSAMLLogoutStartPolicy{tenant: record.TenantID, user: record.UserID}, serviceActor: loginConfig.ActorID},
		Clock: clock.System{}, PolicyVersion: 1}
	loginConfig.Coordinator.QueryPolicy, loginConfig.Coordinator.AdmissionPolicy = &policy, &policy
	loginConfig.RequestKeys, err = kernel.NewRequestKeyConfig("native-sso-login", [32]byte{0xaa}, policy)
	if err != nil {
		t.Fatal(err)
	}
	login, err := ssopg.NewProviderLoginServiceWithSAML(x.start.router, loginConfig, x.start.profiles, x.start.sign)
	if err != nil {
		t.Fatal(err)
	}
	logoutConfig := ssopg.ProviderSAMLLogoutConfig{Session: validation, Admission: selection,
		CSRFKeys: []session.CSRFKey{x.csrf}, FinalRedirectAllowlist: []string{nativeLogoutFinalRedirect}}
	localKeys, err := kernel.NewRequestKeyConfig("native-saml-logout-local", [32]byte{0xd2}, policy)
	if err != nil {
		t.Fatal(err)
	}
	local, err := ssopg.NewProviderSAMLLogoutServiceWithRequestKeys(login, logoutConfig, localKeys)
	if err != nil {
		t.Fatal(err)
	}
	const endpoint = "https://identity-provider.example.test/slo?x=retained"
	profile := x.start.profiles[0]
	profiles := []ssopg.ProviderSAMLLogoutRedirectProfile{
		{Provider: profile, IdentityProviderEntityID: nativeSAMLCallbackIssuer, Endpoint: endpoint},
	}
	service, err := local.WithProviderRedirect(custody, profiles)
	if err != nil {
		t.Fatal("select installed provider's exact SLO endpoint", err)
	}
	for _, shared := range []kernel.RequestKeyConfig{loginConfig.RequestKeys, localKeys} {
		if answered, err := service.WithRelayState(shared); !errors.Is(err, sso.ErrInvalidInput) || answered != nil {
			t.Fatal("relay selection accepted a sign-in or local logout namespace", err)
		}
	}
	relayKeys, err := kernel.NewRequestKeyConfig("native-saml-logout-relay", [32]byte{0xc1}, policy)
	if err != nil {
		t.Fatal(err)
	}
	service, err = service.WithRelayState(relayKeys)
	if err != nil {
		t.Fatal("explicitly select one-use native RelayState custody", err)
	}
	requestKey, err := identity.NewIdempotencyKey([]byte("native-saml-remote-outbound-logout"))
	if err != nil {
		t.Fatal(err)
	}
	request := ssopg.ProviderLogoutStartRequest{ProviderID: string(profile.ProviderID), IdempotencyKey: requestKey, FinalRedirect: nativeLogoutFinalRedirect}
	browser := ssopg.ProviderLogoutBrowser{Session: authentication.NewBearerCredential(bearer), CSRF: loginResult.CSRF, Origin: loginConfig.Origin}
	if failReservation {
		if _, err := f.pool.Raw().Exec(ctx, `ALTER TABLE sso_providers.saml_logout_requests ADD CONSTRAINT fixture_reject_relay CHECK(false) NOT VALID`); err != nil {
			t.Fatal(err)
		}
		failed, err := service.Start(ctx, request, browser)
		if _, exposed := failed.ProviderRedirect(); exposed || !errors.Is(err, sso.ErrUnavailable) || !failed.LocalOnly || !failed.LocalRevocation.Committed || failed.LocalRevocation.SessionID != record.SessionID || failed.LocalRevocation.Version != record.Version+1 {
			t.Fatal("remote reservation failure erased exact local revocation or disclosed unreserved wire", err)
		}
		var requests, grants int
		if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM sso_providers.saml_logout_requests),(SELECT count(*) FROM public.capability_identity_one_use WHERE purpose='identity.sso.saml-logout-relay-settle')`).Scan(&requests, &grants); err != nil || requests != 0 || grants != 0 {
			t.Fatal("failed sole Work left a request or one-use capability", err)
		}
		if current, err := reader.Get(ctx, nativeProviderLogoutGetRequest(t, record.TenantID, bearer)); err != nil || current.Authenticated {
			t.Fatal("remote failure restored original local cookie", err)
		}
		return
	}
	got, err := service.Start(ctx, request, browser)
	redirect, ok := got.ProviderRedirect()
	if err != nil || !ok || !got.LocalRevocation.Committed {
		t.Fatal("acknowledged exact local logout did not reserve provider wire", err)
	}
	handle := redirect.Query().Get("RelayState")
	if len(handle) == 0 || len(handle) > 80 {
		t.Fatal("selected outbound logout did not carry one bounded opaque RelayState")
	}
	signed, _, found := strings.Cut(strings.TrimPrefix(redirect.RawQuery, "x=retained&"), "&Signature=")
	signature, decodeErr := base64.StdEncoding.DecodeString(redirect.Query().Get("Signature"))
	digest := sha256.Sum256([]byte(signed))
	if !found || decodeErr != nil || !strings.Contains(signed, "&RelayState="+handle+"&SigAlg=") ||
		rsa.VerifyPSS(key, crypto.SHA256, digest[:], signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) != nil {
		t.Fatal("opaque RelayState was not bound in the exact original signed Redirect")
	}
	localBytes, err := base64.RawURLEncoding.Strict().DecodeString(string(got.Completion.Binding.CommandID))
	if err != nil {
		t.Fatal(err)
	}
	var grants int
	var exact bool
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*),bool_and(g.max_uses=1 AND g.uses=0 AND g.state='issued'
 AND g.origin_command_id<>$3 AND g.signed_issued_at=r.issued_at AND g.signed_not_before=r.issued_at
 AND g.expires_at=r.expires_at AND r.expires_at<=r.issued_at+interval '5 minutes'
 AND date_trunc('second',r.issued_at)=r.issued_at AND date_trunc('second',r.expires_at)=r.expires_at)
 FROM public.capability_identity_one_use g JOIN sso_providers.saml_logout_requests r ON r.tenant_id::text=g.tenant_id
 WHERE g.tenant_id=$1 AND r.start_command_id=$2 AND g.purpose='identity.sso.saml-logout-relay-settle'`, string(record.TenantID), localBytes, string(got.Completion.Binding.CommandID)).Scan(&grants, &exact); err != nil || grants != 1 || !exact {
		t.Fatal("reserved wire and sole original-window one-use capability were not durable together", err)
	}
	retry, err := service.Start(ctx, request, browser)
	original, ok := retry.ProviderRedirect()
	if err != nil || !ok || original.String() != redirect.String() || retry.LocalRevocation != got.LocalRevocation {
		t.Fatal("exact authorized retry did not return original reserved wire", err)
	}
	if current, err := reader.Get(ctx, nativeProviderLogoutGetRequest(t, record.TenantID, bearer)); err != nil || current.Authenticated {
		t.Fatal("outbound reservation did not preserve exact local revocation", err)
	}
	if checkResponse != nil {
		checkResponse(ctx, service, profile, idpKey, got, handle)
		var grantRows, responseRows int
		if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM public.capability_identity_one_use WHERE tenant_id=$1 AND purpose='identity.sso.saml-logout-relay-settle' AND state='finalized' AND uses=1),
(SELECT count(*) FROM sso_providers.saml_logout_responses WHERE tenant_id=$1::identity.directory_id AND request_id=$2)`, string(record.TenantID), "_"+string(got.Completion.Binding.CommandID)).Scan(&grantRows, &responseRows); err != nil || grantRows != 1 || responseRows != 1 {
			t.Fatal("settlement did not commit one capability consumption and one response", grantRows, responseRows, err)
		}
	}
	if _, err := f.pool.Raw().Exec(ctx, `UPDATE sso_providers.providers SET enabled=false,enablement_proof=NULL,enablement_credential_generation=NULL WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`, record.TenantID, profile.OrganizationID, profile.ProviderID); err != nil {
		t.Fatal(err)
	}
	denied, err := service.Start(ctx, request, browser)
	if _, exposed := denied.ProviderRedirect(); exposed || err == nil || denied.LocalRevocation != got.LocalRevocation {
		t.Fatal("changed current route disclosed original wire or erased local acknowledgement", err)
	}
}

type nativeSAMLLogoutRelayPolicy struct {
	local        nativeSAMLLogoutStartPolicy
	serviceActor identity.ActorID
}

func (p nativeSAMLLogoutRelayPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	op := kernel.SSOSAMLLogoutRelayIssueOperation().OperationID
	r := c.Request
	ownsResource := r.Resource.Type == "identity.user" && r.Resource.ID == authorization.ResourceID(p.local.user)
	mayResolve := r.Resource.Type == "identity.request-admission" && r.Resource.ID == authorization.ResourceID(op)
	if c.PolicyRevision == 1 && r.Tenant == authorization.TenantID(p.local.tenant) && r.Subject.Kind == authorization.SubjectServiceAccount && r.Subject.ID == authorization.SubjectID(p.serviceActor) && r.Action == authorization.Action(kernel.SSOSAMLLogoutRelaySettlementOperation().OperationID) && ownsResource {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
	}
	if c.PolicyRevision == 1 && r.Tenant == authorization.TenantID(p.local.tenant) && r.Subject.Kind == authorization.SubjectUser && r.Subject.ID == authorization.SubjectID(p.local.user) && r.Action == authorization.Action(op) && (ownsResource || mayResolve) {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
	}
	return p.local.Decide(ctx, c)
}
