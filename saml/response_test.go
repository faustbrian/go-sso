package saml

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

const (
	fixtureSP  = "https://login.example/saml2/metadata"
	fixtureIdP = "urn:example:approved-idp"
	fixtureACS = "https://login.example/saml2/test/acs"
	fixtureID  = "_approved_request"
)

// OASIS Core §§2.4.1.2, 2.5.1.2 and 3.2.2; Profiles §4.1.4.3. Both nodes
// are separately signed using literal exclusive-canonical fixture bytes.
func TestPOSTResponseValidatesTheOriginalRequestAndReturnsReplayPair(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certTime := time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: certTime.Add(-time.Hour), NotAfter: certTime.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	config := POSTResponseConfig{SPEntityID: fixtureSP, IdentityProviderEntityID: fixtureIdP, AssertionConsumerURL: fixtureACS, SigningCertificates: [][]byte{cert}}
	profile, err := NewPOSTResponseProfile(config)
	if err != nil {
		t.Fatal(err)
	}
	issued := time.Date(2026, 11, 23, 4, 0, 0, 0, time.UTC)
	input := POSTResponseInput{
		SAMLResponse: base64.StdEncoding.EncodeToString([]byte(signedResponseFixture(t, key, fixtureID, fixtureIdP, fixtureSP, fixtureACS, "_assertion", true))),
		RequestID:    fixtureID, IssuedAt: issued, Now: issued.Add(time.Minute), ExpiresAt: issued.Add(5 * time.Minute),
	}
	verified, err := profile.Validate(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := verified.Evidence()
	if err != nil || evidence.ProviderSubject != "member-042" || evidence.ResponseID != "_response" || evidence.AssertionID != "_assertion" ||
		evidence.SubjectFormat != "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" || evidence.SessionIndex != "member-session" ||
		!evidence.ValidUntil.Equal(issued.Add(3*time.Minute)) || !evidence.AssertionExpiresAt.Equal(issued.Add(4*time.Minute)) {
		t.Fatal("did not return the exact signed subject, replay pair and expiry", err)
	}
	for _, tc := range []struct {
		name   string
		change func(*POSTResponseInput)
		want   error
	}{
		{"different reserved request", func(in *POSTResponseInput) { in.RequestID = "_other_request" }, ErrInvalidInput},
		{"expired original request", func(in *POSTResponseInput) { in.ExpiresAt = in.Now }, ErrInvalidInput},
		{"exclusive confirmation expiry", func(in *POSTResponseInput) { in.Now = issued.Add(3 * time.Minute) }, ErrInvalidInput},
		{"bad form encoding", func(in *POSTResponseInput) { in.SAMLResponse = "not base64" }, ErrInvalidInput},
		{"signed wrong audience", func(in *POSTResponseInput) {
			in.SAMLResponse = base64.StdEncoding.EncodeToString([]byte(signedResponseFixture(t, key, fixtureID, fixtureIdP, "https://other.example/sp", fixtureACS, "_assertion", true)))
		}, ErrInvalidInput},
		{"signed wrong recipient", func(in *POSTResponseInput) {
			in.SAMLResponse = base64.StdEncoding.EncodeToString([]byte(signedResponseFixture(t, key, fixtureID, fixtureIdP, fixtureSP, "https://other.example/acs", "_assertion", true)))
		}, ErrInvalidInput},
		{"signed wrong issuer", func(in *POSTResponseInput) {
			in.SAMLResponse = base64.StdEncoding.EncodeToString([]byte(signedResponseFixture(t, key, fixtureID, "urn:example:different-idp", fixtureSP, fixtureACS, "_assertion", true)))
		}, ErrInvalidInput},
		{"repeated ID", func(in *POSTResponseInput) {
			in.SAMLResponse = base64.StdEncoding.EncodeToString([]byte(signedResponseFixture(t, key, fixtureID, fixtureIdP, fixtureSP, fixtureACS, "_response", true)))
		}, ErrInvalidInput},
		{"unsigned assertion", func(in *POSTResponseInput) {
			in.SAMLResponse = base64.StdEncoding.EncodeToString([]byte(signedResponseFixture(t, key, fixtureID, fixtureIdP, fixtureSP, fixtureACS, "_assertion", false)))
		}, ErrInvalidSignature},
		{"additional assertion outside selected response shape", func(in *POSTResponseInput) {
			const extra = `<a:AttributeStatement><a:Attribute Name="extra"><a:AttributeValue><a:Assertion ID="_additional"></a:Assertion></a:AttributeValue></a:Attribute></a:AttributeStatement>`
			in.SAMLResponse = base64.StdEncoding.EncodeToString([]byte(signedResponseFixture(t, key, fixtureID, fixtureIdP, fixtureSP, fixtureACS, "_assertion", true, extra)))
		}, ErrInvalidInput},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := input
			tc.change(&candidate)
			result, err := profile.Validate(t.Context(), candidate)
			if !errors.Is(err, tc.want) {
				t.Fatalf("wanted %v, got %v", tc.want, err)
			}
			if _, err := result.Evidence(); err == nil {
				t.Fatal("denial returned usable SAML evidence")
			}
		})
	}
	encoded := input.SAMLResponse
	input.SAMLResponse = encoded[:72] + "\r\n" + encoded[72:]
	if _, err := profile.Validate(t.Context(), input); err != nil {
		t.Fatal("HTTP-POST line-wrapped Base64 rejected", err)
	}

	t.Run("evidence cannot outlast the matched certificate", func(t *testing.T) {
		cutoff := issued.Add(2 * time.Minute)
		ending := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: certTime.Add(-time.Hour), NotAfter: cutoff, KeyUsage: x509.KeyUsageDigitalSignature}
		endingCert, err := x509.CreateCertificate(rand.Reader, ending, ending, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		cfg := config
		cfg.SigningCertificates = [][]byte{endingCert}
		expiring, err := NewPOSTResponseProfile(cfg)
		if err != nil {
			t.Fatal(err)
		}
		result, err := expiring.Validate(t.Context(), input)
		if err != nil {
			t.Fatal(err)
		}
		evidence, err := result.Evidence()
		if err != nil || !evidence.ValidUntil.Equal(cutoff) {
			t.Fatal("evidence outlasted the matched certificate", err)
		}
		late := input
		late.Now = cutoff
		if _, err := expiring.Validate(t.Context(), late); !errors.Is(err, ErrInvalidSignature) {
			t.Fatal("accepted the certificate at its exclusive cutoff", err)
		}
	})
}

func signedResponseFixture(t *testing.T, key *ecdsa.PrivateKey, request, idp, audience, acs, assertionID string, includeAssertionSignature bool, extra ...string) string {
	t.Helper()
	const algorithm = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
	const attributeValues = `<a:Subject><a:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">member-042</a:NameID><a:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><a:SubjectConfirmationData InResponseTo="REQUEST" NotOnOrAfter="2026-11-23T04:03:00Z" Recipient="ACS"></a:SubjectConfirmationData></a:SubjectConfirmation></a:Subject><a:Conditions NotBefore="2026-11-23T04:00:00Z" NotOnOrAfter="2026-11-23T04:04:00Z"><a:AudienceRestriction><a:Audience>AUDIENCE</a:Audience></a:AudienceRestriction></a:Conditions><a:AuthnStatement AuthnInstant="2026-11-23T03:59:00Z" SessionIndex="member-session"><a:AuthnContext><a:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</a:AuthnContextClassRef></a:AuthnContext></a:AuthnStatement>`
	const authStatus = `<p:Status><p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"></p:StatusCode></p:Status>`
	replace := strings.NewReplacer("REQUEST", request, "ACS", acs, "AUDIENCE", audience)
	assertionIssuer := `<a:Issuer>` + idp + `</a:Issuer>`
	assertionOpen := `<a:Assertion xmlns:a="urn:oasis:names:tc:SAML:2.0:assertion" ID="` + assertionID + `" IssueInstant="2026-11-23T04:00:30Z" Version="2.0">`
	assertionContent := replace.Replace(attributeValues) + strings.Join(extra, "") + `</a:Assertion>`
	assertionSignature := ""
	if includeAssertionSignature {
		assertionSignature = fixtureSignature(t, assertionID, algorithm, key, assertionOpen+assertionIssuer+assertionContent)
	}
	assertion := assertionOpen + assertionIssuer + assertionSignature + assertionContent
	responseOpen := replace.Replace(`<p:Response xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" Destination="ACS" ID="_response" InResponseTo="REQUEST" IssueInstant="2026-11-23T04:00:30Z" Version="2.0">`)
	responseIssuer := `<a:Issuer xmlns:a="urn:oasis:names:tc:SAML:2.0:assertion">` + idp + `</a:Issuer>`
	responseContent := authStatus + assertion + `</p:Response>`
	return responseOpen + responseIssuer + fixtureSignature(t, "_response", algorithm, key, responseOpen+responseIssuer+responseContent) + responseContent
}
