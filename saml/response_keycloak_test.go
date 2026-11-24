package saml

import (
	"bytes"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"testing"
	"time"
)

// The synthetic Response and Assertion were independently signed by the
// unmodified Keycloak 26.4.7 XMLSignatureUtil and SAML2Signature classes.
// Release archive: https://github.com/keycloak/keycloak/releases/tag/26.4.7
// SHA-256: aca60ab72ae4d67adc6b8fe7fca5e08d16a6bb5e4a4f2ebb54050e3f5503fd2b.
// OASIS Core §3.2.2 and Profiles §4.1.4.3: the exact correlated POST carries
// a distinct Response/Assertion replay pair; RFC 6931 §2.3.10 selects the
// fixed RSA-PSS signature method. This is not an IdP server journey.
func TestPOSTResponseAcceptsIndependentKeycloakRSAPSSSignatures(t *testing.T) {
	certificatePEM, err := os.ReadFile("testdata/keycloak-rsa-pss/idp-public-certificate.txt")
	if err != nil {
		t.Fatal("read independent public signing certificate:", err)
	}
	certificate, rest := pem.Decode(certificatePEM)
	if certificate == nil || certificate.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatal("expected exactly one public signing certificate")
	}
	wire, err := os.ReadFile("testdata/keycloak-rsa-pss/response.xml")
	if err != nil {
		t.Fatal("read independently signed Response:", err)
	}
	profile, err := NewPOSTResponseProfile(POSTResponseConfig{
		SPEntityID:               "https://sp.example.test/saml2/interop/metadata",
		IdentityProviderEntityID: "https://idp.example.test/realms/interop",
		AssertionConsumerURL:     "https://sp.example.test/saml2/interop/acs",
		SigningCertificates:      [][]byte{certificate.Bytes},
	})
	if err != nil {
		t.Fatal("configure the independent IdP public trust:", err)
	}
	issued := time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)
	input := POSTResponseInput{
		SAMLResponse: base64.StdEncoding.EncodeToString(bytes.TrimSpace(wire)),
		RequestID:    "_golib_interop_request",
		IssuedAt:     issued,
		ExpiresAt:    issued.Add(5 * time.Minute),
		Now:          issued.Add(time.Minute),
	}
	verified, err := profile.Validate(t.Context(), input)
	if err != nil {
		t.Fatal("rejecting the independently signed fixed-profile POST:", err)
	}
	evidence, err := verified.Evidence()
	if err != nil || evidence.ResponseID != "_keycloak_response" || evidence.AssertionID != "_keycloak_assertion" ||
		evidence.ProviderSubject != "interop-member" || evidence.SessionIndex != "interop-session" ||
		!evidence.ValidUntil.Equal(issued.Add(3*time.Minute)) || !evidence.AssertionExpiresAt.Equal(issued.Add(4*time.Minute)) {
		t.Fatal("lost the exact signed identity, replay pair or expiry")
	}

	altered := bytes.Replace(wire, []byte("interop-member"), []byte("other--member"), 1)
	if bytes.Equal(wire, altered) {
		t.Fatal("the negative control did not reach signed content")
	}
	input.SAMLResponse = base64.StdEncoding.EncodeToString(bytes.TrimSpace(altered))
	denied, err := profile.Validate(t.Context(), input)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatal("altered independent assertion did not fail signature verification:", err)
	}
	if _, err := denied.Evidence(); err == nil {
		t.Fatal("altered independent assertion returned trusted evidence")
	}
}
