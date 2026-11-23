package saml

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"
)

const fixtureIDPInitiatedURL = "https://login.example/saml2/test/idp-init"

// Profiles §4.1.5 and Core §§2.4.1.2, 2.5.1.2, 3.2.2: unsolicited
// evidence comes from the signed pair without inventing request correlation.
func TestIDPInitiatedPOSTResponseReturnsOnlySignedEvidence(t *testing.T) {
	key, certificate := idpResponseSigningFixture(t)
	config := idpResponseConfigFixture(certificate)
	profile, err := NewIDPInitiatedPOSTResponseProfile(config)
	if err != nil {
		t.Fatal(err)
	}
	fixture := newIDPResponseFixture()
	input := IDPInitiatedPOSTResponseInput{SAMLResponse: signedIDPResponseFixture(t, key, fixture), Now: fixture.responseIssuedAt.Add(30 * time.Second)}
	result, err := profile.Validate(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := result.Evidence()
	if err != nil || evidence.ResponseID != "_response" || evidence.AssertionID != "_assertion" ||
		evidence.ProviderSubject != "member-042" || evidence.SubjectFormat != "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" ||
		evidence.SessionIndex != "member-session" || !evidence.AssertionExpiresAt.Equal(fixture.conditionsExpiresAt) ||
		!evidence.ValidUntil.Equal(fixture.responseIssuedAt.Add(config.MaximumAge)) {
		t.Fatal("did not return the exact signed subject, replay pair and age-limited expiry", err)
	}

	var zeroProfile IDPInitiatedPOSTResponseProfile
	denied, err := zeroProfile.Validate(t.Context(), input)
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatal("zero profile accepted an unsolicited response", err)
	}
	if _, err := denied.Evidence(); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("zero profile returned usable evidence", err)
	}
	var zeroEvidence VerifiedIDPInitiatedPOSTResponse
	if _, err := zeroEvidence.Evidence(); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("zero result returned usable evidence", err)
	}
}

// Profiles §4.1.5 requires absence, not an empty or ignored correlation value.
func TestIDPInitiatedPOSTResponseRejectsSignedCorrelationAndSubstitution(t *testing.T) {
	key, certificate := idpResponseSigningFixture(t)
	profile, err := NewIDPInitiatedPOSTResponseProfile(idpResponseConfigFixture(certificate))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*idpResponseFixture)
	}{
		{"Response InResponseTo", func(f *idpResponseFixture) { f.responseCorrelation = ` InResponseTo="_request"` }},
		{"empty Response InResponseTo", func(f *idpResponseFixture) { f.responseCorrelation = ` InResponseTo=""` }},
		{"confirmation InResponseTo", func(f *idpResponseFixture) { f.confirmationCorrelation = ` InResponseTo="_request"` }},
		{"empty confirmation InResponseTo", func(f *idpResponseFixture) { f.confirmationCorrelation = ` InResponseTo=""` }},
		{"qualified Response InResponseTo", func(f *idpResponseFixture) { f.qualifiedResponseCorrelation = ` q:InResponseTo=""` }},
		{"qualified confirmation InResponseTo", func(f *idpResponseFixture) { f.qualifiedConfirmationCorrelation = ` q:InResponseTo=""` }},
		{"SP destination and recipient", func(f *idpResponseFixture) { f.destination, f.recipient = fixtureACS, fixtureACS }},
		{"SP destination only", func(f *idpResponseFixture) { f.destination = fixtureACS }},
		{"SP recipient only", func(f *idpResponseFixture) { f.recipient = fixtureACS }},
		{"other provider route", func(f *idpResponseFixture) {
			f.destination, f.recipient = "https://login.example/saml2/other/idp-init", "https://login.example/saml2/other/idp-init"
		}},
		{"trailing slash", func(f *idpResponseFixture) { f.destination += "/"; f.recipient += "/" }},
		{"other audience", func(f *idpResponseFixture) { f.audience = "https://other.example/sp" }},
		{"other Response issuer", func(f *idpResponseFixture) { f.responseIssuer = "urn:example:other-idp" }},
		{"other Assertion issuer", func(f *idpResponseFixture) { f.assertionIssuer = "urn:example:other-idp" }},
		{"duplicate replay ID", func(f *idpResponseFixture) { f.assertionID = f.responseID }},
		{"missing Response ID", func(f *idpResponseFixture) { f.responseID = "" }},
		{"missing Assertion ID", func(f *idpResponseFixture) { f.assertionID = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newIDPResponseFixture()
			tc.change(&fixture)
			input := IDPInitiatedPOSTResponseInput{SAMLResponse: signedIDPResponseFixture(t, key, fixture), Now: fixture.responseIssuedAt.Add(30 * time.Second)}
			result, err := profile.Validate(t.Context(), input)
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatal("accepted signed correlation or substituted binding", err)
			}
			if _, err := result.Evidence(); err == nil {
				t.Fatal("denial returned usable evidence")
			}
		})
	}
}

func TestIDPInitiatedPOSTResponseCapsAgeAtEarliestSignedIssueTimeWithoutSkew(t *testing.T) {
	key, certificate := idpResponseSigningFixture(t)
	config := idpResponseConfigFixture(certificate)
	config.MaximumAge = time.Minute
	config.ClockSkew = 5 * time.Minute
	profile, err := NewIDPInitiatedPOSTResponseProfile(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, earlierNode := range []string{"Response", "Assertion"} {
		t.Run(earlierNode, func(t *testing.T) {
			fixture := newIDPResponseFixture()
			earliestIssue := fixture.responseIssuedAt.Add(-10 * time.Second)
			if earlierNode == "Response" {
				fixture.responseIssuedAt = earliestIssue
			} else {
				fixture.assertionIssuedAt = earliestIssue
			}
			cutoff := earliestIssue.Add(config.MaximumAge)
			input := IDPInitiatedPOSTResponseInput{SAMLResponse: signedIDPResponseFixture(t, key, fixture), Now: cutoff.Add(-time.Nanosecond)}
			result, err := profile.Validate(t.Context(), input)
			if err != nil {
				t.Fatal("rejected response immediately before its signed age cutoff", err)
			}
			evidence, err := result.Evidence()
			if err != nil || !evidence.ValidUntil.Equal(cutoff) {
				t.Fatal("signed age cutoff was not the earliest issue time plus maximum age", err)
			}
			for _, now := range []time.Time{cutoff, cutoff.Add(time.Nanosecond), cutoff.Add(config.ClockSkew)} {
				input.Now = now
				denied, err := profile.Validate(t.Context(), input)
				if !errors.Is(err, ErrInvalidInput) {
					t.Fatal("clock skew extended the exclusive signed age cutoff", err)
				}
				if _, err := denied.Evidence(); err == nil {
					t.Fatal("expired response returned usable evidence")
				}
			}
		})
	}

	t.Run("one-second configured age", func(t *testing.T) {
		config.MaximumAge = time.Second
		short, err := NewIDPInitiatedPOSTResponseProfile(config)
		if err != nil {
			t.Fatal(err)
		}
		fixture := newIDPResponseFixture()
		input := IDPInitiatedPOSTResponseInput{SAMLResponse: signedIDPResponseFixture(t, key, fixture), Now: fixture.responseIssuedAt.Add(time.Second - time.Nanosecond)}
		if _, err := short.Validate(t.Context(), input); err != nil {
			t.Fatal("rejected response before one-second age limit", err)
		}
		input.Now = fixture.responseIssuedAt.Add(time.Second)
		if _, err := short.Validate(t.Context(), input); !errors.Is(err, ErrInvalidInput) {
			t.Fatal("accepted response at one-second age limit", err)
		}
	})
}

func TestIDPInitiatedPOSTResponseRequiresBothTrustedSignatures(t *testing.T) {
	key, certificate := idpResponseSigningFixture(t)
	otherKey, _ := idpResponseSigningFixture(t)
	profile, err := NewIDPInitiatedPOSTResponseProfile(idpResponseConfigFixture(certificate))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*idpResponseFixture)
	}{
		{"unsigned Response", func(f *idpResponseFixture) { f.omitResponseSignature = true }},
		{"unsigned Assertion", func(f *idpResponseFixture) { f.omitAssertionSignature = true }},
		{"neither signed", func(f *idpResponseFixture) { f.omitResponseSignature, f.omitAssertionSignature = true, true }},
		{"untrusted Response signer", func(f *idpResponseFixture) { f.responseSigner = otherKey }},
		{"untrusted Assertion signer", func(f *idpResponseFixture) { f.assertionSigner = otherKey }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newIDPResponseFixture()
			tc.change(&fixture)
			input := IDPInitiatedPOSTResponseInput{SAMLResponse: signedIDPResponseFixture(t, key, fixture), Now: fixture.responseIssuedAt.Add(30 * time.Second)}
			result, err := profile.Validate(t.Context(), input)
			if !errors.Is(err, ErrInvalidSignature) {
				t.Fatal("accepted missing or untrusted signature", err)
			}
			if _, err := result.Evidence(); err == nil {
				t.Fatal("signature denial returned usable evidence")
			}
		})
	}
}

func TestPOSTResponseKeepsSPCorrelationSeparateFromIDPInitiatedEvidence(t *testing.T) {
	key, certificate := idpResponseSigningFixture(t)
	profile, err := NewPOSTResponseProfile(POSTResponseConfig{
		SPEntityID: fixtureSP, IdentityProviderEntityID: fixtureIdP, AssertionConsumerURL: fixtureACS, SigningCertificates: [][]byte{certificate},
	})
	if err != nil {
		t.Fatal(err)
	}
	issued := time.Date(2026, 11, 23, 4, 0, 0, 0, time.UTC)
	input := POSTResponseInput{
		SAMLResponse: base64.StdEncoding.EncodeToString([]byte(signedResponseFixture(t, key, fixtureID, fixtureIdP, fixtureSP, fixtureACS, "_assertion", true))),
		RequestID:    fixtureID, IssuedAt: issued, Now: issued.Add(time.Minute), ExpiresAt: issued.Add(5 * time.Minute),
	}
	if _, err := profile.Validate(t.Context(), input); err != nil {
		t.Fatal("existing correlated SP fixture no longer validates", err)
	}
	fixture := newIDPResponseFixture()
	fixture.destination, fixture.recipient = fixtureACS, fixtureACS
	input.SAMLResponse = signedIDPResponseFixture(t, key, fixture)
	denied, err := profile.Validate(t.Context(), input)
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatal("SP profile accepted unsolicited XML at its own ACS", err)
	}
	if _, err := denied.Evidence(); err == nil {
		t.Fatal("SP denial returned usable evidence")
	}
}

func idpResponseConfigFixture(certificate []byte) IDPInitiatedPOSTResponseConfig {
	return IDPInitiatedPOSTResponseConfig{
		SPEntityID: fixtureSP, IdentityProviderEntityID: fixtureIdP,
		ExternalOrigin: "https://login.example", ProviderID: "test", SigningCertificates: [][]byte{certificate}, MaximumAge: 2 * time.Minute,
	}
}

func idpResponseSigningFixture(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issued := time.Date(2026, 11, 23, 4, 0, 0, 0, time.UTC)
	template := &x509.Certificate{SerialNumber: big.NewInt(27), NotBefore: issued.Add(-time.Hour), NotAfter: issued.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return key, certificate
}

type idpResponseFixture struct {
	responseID, assertionID                                        string
	responseIssuer, assertionIssuer                                string
	destination, recipient, audience                               string
	responseCorrelation, confirmationCorrelation                   string
	qualifiedResponseCorrelation, qualifiedConfirmationCorrelation string
	responseIssuedAt, assertionIssuedAt                            time.Time
	conditionsExpiresAt                                            time.Time
	omitResponseSignature, omitAssertionSignature                  bool
	responseSigner, assertionSigner                                *ecdsa.PrivateKey
}

func newIDPResponseFixture() idpResponseFixture {
	issued := time.Date(2026, 11, 23, 4, 0, 30, 0, time.UTC)
	return idpResponseFixture{
		responseID: "_response", assertionID: "_assertion", responseIssuer: fixtureIdP, assertionIssuer: fixtureIdP,
		destination: fixtureIDPInitiatedURL, recipient: fixtureIDPInitiatedURL, audience: fixtureSP,
		responseIssuedAt: issued, assertionIssuedAt: issued, conditionsExpiresAt: issued.Add(210 * time.Second),
	}
}

// Canonical targets are fixed literal XML, independently of the validator's
// tree/serializer, following the existing signedResponseFixture convention.
func signedIDPResponseFixture(t *testing.T, key *ecdsa.PrivateKey, f idpResponseFixture) string {
	t.Helper()
	const algorithm = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
	const aliasNamespace = ` xmlns:q="urn:example:correlation"`
	responseNamespace, confirmationNamespace := "", ""
	if f.qualifiedResponseCorrelation != "" {
		responseNamespace = aliasNamespace
	}
	if f.qualifiedConfirmationCorrelation != "" {
		confirmationNamespace = aliasNamespace
	}
	assertionOpen := fmt.Sprintf(`<a:Assertion xmlns:a="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" IssueInstant="%s" Version="2.0">`, f.assertionID, f.assertionIssuedAt.Format(time.RFC3339Nano))
	assertionIssuer := `<a:Issuer>` + f.assertionIssuer + `</a:Issuer>`
	assertionContent := fmt.Sprintf(`<a:Subject><a:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">member-042</a:NameID><a:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><a:SubjectConfirmationData%s%s NotOnOrAfter="2026-11-23T04:03:00Z" Recipient="%s"%s></a:SubjectConfirmationData></a:SubjectConfirmation></a:Subject><a:Conditions NotBefore="2026-11-23T04:00:00Z" NotOnOrAfter="%s"><a:AudienceRestriction><a:Audience>%s</a:Audience></a:AudienceRestriction></a:Conditions><a:AuthnStatement AuthnInstant="2026-11-23T03:59:00Z" SessionIndex="member-session"><a:AuthnContext><a:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</a:AuthnContextClassRef></a:AuthnContext></a:AuthnStatement></a:Assertion>`, confirmationNamespace, f.confirmationCorrelation, f.recipient, f.qualifiedConfirmationCorrelation, f.conditionsExpiresAt.Format(time.RFC3339Nano), f.audience)
	assertionSigner := key
	if f.assertionSigner != nil {
		assertionSigner = f.assertionSigner
	}
	assertionSignature := ""
	if !f.omitAssertionSignature {
		assertionSignature = fixtureSignature(t, f.assertionID, algorithm, assertionSigner, assertionOpen+assertionIssuer+assertionContent)
	}
	assertion := assertionOpen + assertionIssuer + assertionSignature + assertionContent
	responseOpen := fmt.Sprintf(`<p:Response xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol"%s Destination="%s" ID="%s"%s IssueInstant="%s" Version="2.0"%s>`, responseNamespace, f.destination, f.responseID, f.responseCorrelation, f.responseIssuedAt.Format(time.RFC3339Nano), f.qualifiedResponseCorrelation)
	responseIssuer := `<a:Issuer xmlns:a="urn:oasis:names:tc:SAML:2.0:assertion">` + f.responseIssuer + `</a:Issuer>`
	responseContent := `<p:Status><p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"></p:StatusCode></p:Status>` + assertion + `</p:Response>`
	responseSigner := key
	if f.responseSigner != nil {
		responseSigner = f.responseSigner
	}
	responseSignature := ""
	if !f.omitResponseSignature {
		responseSignature = fixtureSignature(t, f.responseID, algorithm, responseSigner, responseOpen+responseIssuer+responseContent)
	}
	return base64.StdEncoding.EncodeToString([]byte(responseOpen + responseIssuer + responseSignature + responseContent))
}
