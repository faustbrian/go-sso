package saml_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-sso/saml"
)

func TestValidateRegistrationAcceptsExactSelectedIdPFields(t *testing.T) {
	key := metadataRSAKey(t, 2048)
	certificates := make([][]byte, 5)
	for i := range certificates {
		certificates[i] = metadataCertificate(t, key, &key.PublicKey, int64(i+1))
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecCertificate := metadataCertificate(t, key, &ecKey.PublicKey, 10)
	for _, tc := range []struct {
		name, entity, endpoint string
		certificates           [][]byte
	}{
		{"URN identity", "urn:example:exact-idp", "https://idp.example/sso", certificates[:1]},
		{"exact URI and fixed query", "HTTPS://idp.example/Entity%2fexact?realm=one", "https://idp.example/sso?realm=one&service=saml", certificates},
		{"P-256 response signing key", "urn:example:p256", "https://idp.example/sso", [][]byte{ecCertificate}},
		{"maximum DER bytes", "urn:example:bounded", "https://idp.example/sso", [][]byte{metadataSizedCertificate(t, key, 64*1024)}},
		{"maximum identity and endpoint bytes", "urn:" + strings.Repeat("a", 1024-4), "https://idp.example/" + strings.Repeat("a", 2048-len("https://idp.example/")), certificates[:1]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := make([][]byte, len(tc.certificates))
			for i, der := range tc.certificates {
				before[i] = bytes.Clone(der)
			}
			if err := saml.ValidateRegistration(t.Context(), tc.entity, tc.endpoint, tc.certificates); err != nil {
				t.Fatal("valid selected IdP configuration rejected", err)
			}
			for i, der := range tc.certificates {
				if !bytes.Equal(der, before[i]) {
					t.Fatal("validation modified borrowed certificate bytes")
				}
			}
		})
	}
}

func TestValidateRegistrationRejectsInvalidIdentityAndRedirect(t *testing.T) {
	key := metadataRSAKey(t, 2048)
	certificates := [][]byte{metadataCertificate(t, key, &key.PublicKey, 1)}
	for _, entity := range []string{
		"", "relative-idp", "urn:", "https://", "https://user:password@idp.example/entity",
		"urn:example:idp#fragment", "urn:example:space here", "urn:example:%zz", "urn:example:\\idp",
		"urn:example:\nsecret", "urn:example:é", "urn:" + strings.Repeat("a", 1024-3),
	} {
		t.Run("entity "+entity, func(t *testing.T) {
			if err := saml.ValidateRegistration(t.Context(), entity, "https://idp.example/sso", certificates); err != saml.ErrInvalidInput {
				t.Fatal("invalid identity did not return the redacted input error", err)
			}
		})
	}
	for _, endpoint := range []string{
		"", "http://idp.example/sso", "https://", "https://user:password@idp.example/sso",
		"https://idp.example/sso#fragment", "https://idp.example/a/../sso", "https://idp.example/%0a",
		"https://idp.example/%zz", "https://idp.example/sso?realm=%zz", "https://idp.example/sso?realm=one;two",
		"https://idp.example/" + strings.Repeat("a", 2049-len("https://idp.example/")),
	} {
		t.Run("endpoint "+endpoint, func(t *testing.T) {
			if err := saml.ValidateRegistration(t.Context(), "urn:example:idp", endpoint, certificates); err != saml.ErrInvalidInput {
				t.Fatal("invalid redirect did not return the redacted input error", err)
			}
		})
	}
	for _, field := range []string{"SAMLRequest", "SAMLResponse", "RelayState", "SigAlg", "Signature", "sAmLrEqUeSt", "%53AMLRequest"} {
		t.Run("reserved query "+field, func(t *testing.T) {
			endpoint := "https://idp.example/sso?realm=one&" + field + "=private-value"
			if err := saml.ValidateRegistration(t.Context(), "urn:example:idp", endpoint, certificates); err != saml.ErrInvalidInput {
				t.Fatal("reserved binding query did not return the redacted input error", err)
			}
		})
	}
}

func TestValidateRegistrationRejectsInvalidPinnedSigningCertificates(t *testing.T) {
	key := metadataRSAKey(t, 2048)
	certificate := metadataCertificate(t, key, &key.PublicKey, 1)
	weakKey := metadataRSAKey(t, 1024)
	ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tooMany := make([][]byte, 6)
	for i := range tooMany {
		tooMany[i] = metadataCertificate(t, key, &key.PublicKey, int64(i+10))
	}
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name         string
		certificates [][]byte
	}{
		{"absent", nil},
		{"too many distinct certificates", tooMany},
		{"empty DER", [][]byte{nil}},
		{"invalid DER", [][]byte{[]byte("private-certificate-marker")}},
		{"trailing DER", [][]byte{append(bytes.Clone(certificate), 0)}},
		{"oversized valid DER", [][]byte{metadataSizedCertificate(t, key, 64*1024+1)}},
		{"duplicate DER", [][]byte{certificate, bytes.Clone(certificate)}},
		{"nonadjacent duplicate DER", [][]byte{certificate, tooMany[0], bytes.Clone(certificate)}},
		{"undersized RSA", [][]byte{metadataCertificate(t, weakKey, &weakKey.PublicKey, 2)}},
		{"unsupported P-384", [][]byte{metadataCertificate(t, key, &ecKey.PublicKey, 3)}},
		{"non-signing key usage", [][]byte{registrationCertificate(t, key, start, start.Add(time.Hour), x509.KeyUsageKeyEncipherment)}},
		{"empty lifetime", [][]byte{registrationCertificate(t, key, start, start, x509.KeyUsageDigitalSignature)}},
		{"reversed lifetime", [][]byte{registrationCertificate(t, key, start, start.Add(-time.Hour), x509.KeyUsageDigitalSignature)}},
		{"invalid rollover", [][]byte{certificate, []byte("private-rollover-marker")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := saml.ValidateRegistration(t.Context(), "urn:example:idp", "https://idp.example/sso", tc.certificates); err != saml.ErrInvalidInput {
				t.Fatal("invalid certificate set did not return the redacted input error", err)
			}
		})
	}
}

func TestValidateRegistrationDoesNotClaimWallClockCertificateValidity(t *testing.T) {
	key := metadataRSAKey(t, 2048)
	for _, year := range []int{2000, 2100} {
		start := time.Date(year, 1, 1, 0, 0, 0, 0, time.UTC)
		for _, usage := range []x509.KeyUsage{0, x509.KeyUsageDigitalSignature} {
			certificate := registrationCertificate(t, key, start, start.Add(time.Hour), usage)
			if err := saml.ValidateRegistration(t.Context(), "urn:example:idp", "https://idp.example/sso", [][]byte{certificate}); err != nil {
				t.Fatal("static registration incorrectly checked the current time or required an optional key usage extension", err)
			}
		}
	}
}

func TestValidateRegistrationRejectsNilAndCanceledContext(t *testing.T) {
	key := metadataRSAKey(t, 2048)
	certificates := [][]byte{metadataCertificate(t, key, &key.PublicKey, 1)}
	if err := saml.ValidateRegistration(nil, "urn:example:idp", "https://idp.example/sso", certificates); err != saml.ErrInvalidInput {
		t.Fatal("nil context did not return the redacted input error", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := saml.ValidateRegistration(ctx, "urn:example:idp", "https://idp.example/sso", certificates); !errors.Is(err, context.Canceled) || err.Error() != context.Canceled.Error() {
		t.Fatal("canceled validation did not return cancellation without configuration data", err)
	}
}

func registrationCertificate(t *testing.T, signer *rsa.PrivateKey, start, end time.Time, usage x509.KeyUsage) []byte {
	t.Helper()
	template := &x509.Certificate{SerialNumber: big.NewInt(100), NotBefore: start, NotAfter: end, KeyUsage: usage}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &signer.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
