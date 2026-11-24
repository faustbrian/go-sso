//go:build integration

package postgres_test

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
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

// Core §§3.2.1, 3.7.1; Profiles §4.4.4.1; Bindings §§3.4.3, 3.4.4.1:
// the exact session participant's request is signed before disclosure and
// retained once for response correlation. Failure cannot undo local logout.
func TestNativeSAMLLogoutPreservesOneSignedProviderRequest(t *testing.T) {
	t.Run("normal", func(t *testing.T) { assertNativeSAMLLogoutProviderRequest(t, false) })
	t.Run("first reservation unavailable", func(t *testing.T) { assertNativeSAMLLogoutProviderRequest(t, true) })
}

func assertNativeSAMLLogoutProviderRequest(t *testing.T, failReservation bool) {
	t.Helper()
	key, bundle := nativeSAMLLogoutSigningBundle(t)
	defer clear(bundle)
	x := newNativeSAMLCallbackFixtureWithStart(t, newSAMLStartFixtureWithBundle(t, bundle))
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
	policy := kernel.CommandQueryPolicy{Authorization: nativeSAMLLogoutStartPolicy{tenant: record.TenantID, user: record.UserID},
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
	local, err := ssopg.NewProviderSAMLLogoutService(login, ssopg.ProviderSAMLLogoutConfig{Session: validation, Admission: selection,
		CSRFKeys: []session.CSRFKey{x.csrf}, FinalRedirectAllowlist: []string{nativeLogoutFinalRedirect}})
	if err != nil {
		t.Fatal(err)
	}
	const endpoint = "https://identity-provider.example.test/slo?x=retained"
	profile := x.start.profiles[0]
	service, err := local.WithProviderRedirect(custody, []ssopg.ProviderSAMLLogoutRedirectProfile{
		{Provider: profile, IdentityProviderEntityID: nativeSAMLCallbackIssuer, Endpoint: endpoint},
	})
	if err != nil {
		t.Fatal("select installed provider's exact SLO endpoint", err)
	}
	requestKey, err := identity.NewIdempotencyKey([]byte("native-saml-remote-outbound-logout"))
	if err != nil {
		t.Fatal(err)
	}
	request := ssopg.ProviderLogoutStartRequest{ProviderID: string(profile.ProviderID), IdempotencyKey: requestKey, FinalRedirect: nativeLogoutFinalRedirect}
	browser := ssopg.ProviderLogoutBrowser{Session: authentication.NewBearerCredential(bearer), CSRF: loginResult.CSRF, Origin: loginConfig.Origin}
	if failReservation {
		if _, err := f.pool.Raw().Exec(ctx, `ALTER TABLE sso_providers.saml_logout_requests ADD CONSTRAINT fixture_reject_slo CHECK (false) NOT VALID`); err != nil {
			t.Fatal("configure isolated outbound reservation failure", err)
		}
		unavailable, err := service.Start(ctx, request, browser)
		if _, ok := unavailable.ProviderRedirect(); ok || !errors.Is(err, sso.ErrUnavailable) || !unavailable.LocalOnly ||
			!unavailable.LocalRevocation.Committed || unavailable.LocalRevocation.SessionID != record.SessionID {
			t.Fatal("outbound insert failure erased local logout or disclosed an unreserved redirect", err)
		}
		if current, err := reader.Get(ctx, nativeProviderLogoutGetRequest(t, record.TenantID, bearer)); err != nil || current.Authenticated {
			t.Fatal("outbound insert failure restored the original cookie", err)
		}
		if _, err := f.pool.Raw().Exec(ctx, `ALTER TABLE sso_providers.saml_logout_requests DROP CONSTRAINT fixture_reject_slo`); err != nil {
			t.Fatal("restore isolated outbound reservation", err)
		}
	}
	got, err := service.Start(ctx, request, browser)
	redirect, ok := got.ProviderRedirect()
	if err != nil || !ok || got.LocalOnly || !got.LocalRevocation.Committed || got.LocalRevocation.SessionID != record.SessionID ||
		got.LocalRevocation.Version != record.Version+1 {
		t.Fatal("authorized local logout did not disclose a reserved remote redirect", err)
	}
	wireID := "_" + string(got.Completion.Binding.CommandID)
	assertNativeSAMLLogoutWire(t, redirect, key, wireID, endpoint, index)
	if strings.Contains(fmt.Sprintf("%#v", got), redirect.Query().Get("SAMLRequest")) {
		t.Fatal("ordinary result formatting disclosed the signed provider request")
	}
	if current, err := reader.Get(ctx, nativeProviderLogoutGetRequest(t, record.TenantID, bearer)); err != nil || current.Authenticated {
		t.Fatal("front-channel request preceded authoritative local revocation", err)
	}
	var rows int
	var sealed []byte
	var bounded bool
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) OVER (), r.request_envelope, r.expires_at <= c.created_at + interval '5 minutes'
 FROM sso_providers.saml_logout_requests r JOIN identity.commands c
 ON (r.tenant_id,r.start_command_id,r.start_purpose)=(c.tenant_id,c.command_id,c.purpose)
 WHERE r.tenant_id=$1 AND r.request_id=$2 AND r.provider_id=$3`, record.TenantID, wireID, profile.ProviderID).Scan(&rows, &sealed, &bounded); err != nil ||
		rows != 1 || !bounded || len(sealed) == 0 || bytes.Contains(sealed, []byte(nativeSAMLCallbackSubject)) || bytes.Contains(sealed, []byte(redirect.String())) {
		t.Fatal("one encrypted, original-window correlation must exist before redirect disclosure", err)
	}
	repeat, err := service.Start(ctx, request, browser)
	original, ok := repeat.ProviderRedirect()
	if err != nil || !ok || original.String() != redirect.String() || repeat.LocalRevocation != got.LocalRevocation {
		t.Fatal("exact retry regenerated or lost the original wire and revocation", err)
	}
	if _, err := f.pool.Raw().Exec(ctx, `UPDATE sso_providers.providers SET enabled=false,enablement_proof=NULL,enablement_credential_generation=NULL
 WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`, record.TenantID, profile.OrganizationID, profile.ProviderID); err != nil {
		t.Fatal("disable selected installed provider", err)
	}
	disabled, err := service.Start(ctx, request, browser)
	if _, ok := disabled.ProviderRedirect(); ok || err != nil && !errors.Is(err, sso.ErrUnavailable) ||
		disabled.LocalRevocation != got.LocalRevocation || !disabled.LocalOnly {
		t.Fatal("provider disable must suppress redirect without erasing committed local outcome", err)
	}
}

func nativeSAMLLogoutSigningBundle(t *testing.T) (*rsa.PublicKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(der)
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := saml.EncodeSPSigningCredential(t.Context(), der, cert, now)
	if err != nil {
		t.Fatal(err)
	}
	return &key.PublicKey, bundle
}

func assertNativeSAMLLogoutWire(t *testing.T, got url.URL, key *rsa.PublicKey, id, endpoint, index string) {
	t.Helper()
	approved, err := url.Parse(endpoint)
	if err != nil || got.Scheme != approved.Scheme || got.Host != approved.Host || got.Path != approved.Path ||
		!strings.HasPrefix(got.RawQuery, approved.RawQuery+"&SAMLRequest=") {
		t.Fatal("redirect did not use the approved exact provider endpoint")
	}
	input, _, ok := strings.Cut(strings.TrimPrefix(got.RawQuery, approved.RawQuery+"&"), "&Signature=")
	signature, err := base64.StdEncoding.DecodeString(got.Query().Get("Signature"))
	digest := sha256.Sum256([]byte(input))
	if !ok || err != nil || got.Query().Get("SigAlg") != saml.SignatureAlgorithmRSAPSSSHA256 || got.Query().Has("RelayState") ||
		rsa.VerifyPSS(key, crypto.SHA256, digest[:], signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) != nil {
		t.Fatal("wire is not exact RSA-PSS signed Redirect without RelayState")
	}
	request, err := base64.StdEncoding.DecodeString(got.Query().Get("SAMLRequest"))
	if err != nil {
		t.Fatal(err)
	}
	r := flate.NewReader(bytes.NewReader(request))
	defer r.Close()
	document, err := io.ReadAll(io.LimitReader(r, 1<<16))
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		XMLName     xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol LogoutRequest"`
		ID          string   `xml:"ID,attr"`
		Destination string   `xml:"Destination,attr"`
		NameID      string   `xml:"NameID"`
		Index       string   `xml:"SessionIndex"`
	}
	if err := xml.Unmarshal(document, &decoded); err != nil || decoded.ID != id || decoded.Destination != endpoint ||
		decoded.NameID != nativeSAMLCallbackSubject || decoded.Index != index {
		t.Fatal("signed LogoutRequest did not preserve the original login's subject and session index", err)
	}
}
