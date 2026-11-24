package saml

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"math/big"
	"testing"
	"time"
)

// OASIS Profiles §4.1.4.3 authenticates the correlated signed pair using the
// configured IdP trust. These locally signed fixtures cover trust rollover,
// not an independent IdP server journey or replay reservation.
func TestPOSTResponseSigningCertificateRollover(t *testing.T) {
	issued := time.Date(2026, 11, 23, 4, 0, 0, 0, time.UTC)
	oldCutoff := issued.Add(2 * time.Minute)
	newStart := issued.Add(time.Minute)
	oldKey, oldCertificate := rolloverSigningCertificate(t, 1, issued.Add(-time.Hour), oldCutoff)
	newKey, newCertificate := rolloverSigningCertificate(t, 2, newStart, issued.Add(time.Hour))
	const skew = 30 * time.Second
	config := POSTResponseConfig{
		SPEntityID: fixtureSP, IdentityProviderEntityID: fixtureIdP, AssertionConsumerURL: fixtureACS,
		SigningCertificates: [][]byte{oldCertificate, newCertificate}, ClockSkew: skew,
	}
	overlap, err := NewPOSTResponseProfile(config)
	if err != nil {
		t.Fatal("configure overlapping signing pins:", err)
	}
	config.SigningCertificates = [][]byte{newCertificate}
	replaced, err := NewPOSTResponseProfile(config)
	if err != nil {
		t.Fatal("configure replacement signing pin:", err)
	}

	oldInput := POSTResponseInput{
		SAMLResponse: base64.StdEncoding.EncodeToString([]byte(signedResponseFixture(t, oldKey, fixtureID,
			fixtureIdP, fixtureSP, fixtureACS, "_old_assertion", true))),
		RequestID: fixtureID, IssuedAt: issued, ExpiresAt: issued.Add(5 * time.Minute), Now: issued.Add(90 * time.Second),
	}
	newInput := oldInput
	newInput.SAMLResponse = base64.StdEncoding.EncodeToString([]byte(signedResponseFixture(t, newKey, fixtureID,
		fixtureIdP, fixtureSP, fixtureACS, "_new_assertion", true)))

	for _, tc := range []struct {
		name        string
		profile     POSTResponseProfile
		input       POSTResponseInput
		assertionID string
		validUntil  time.Time
		want        error
	}{
		{"overlap accepts old signer", overlap, oldInput, "_old_assertion", oldCutoff, nil},
		{"overlap accepts new signer", overlap, newInput, "_new_assertion", issued.Add(3*time.Minute + skew), nil},
		{"replacement accepts new signer", replaced, newInput, "_new_assertion", issued.Add(3*time.Minute + skew), nil},
		{"replacement denies still valid retired signer", replaced, oldInput, "", time.Time{}, ErrInvalidSignature},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := tc.profile.Validate(t.Context(), tc.input)
			if !errors.Is(err, tc.want) {
				t.Fatalf("wanted %v, got %v", tc.want, err)
			}
			if tc.want != nil {
				if _, err := result.Evidence(); !errors.Is(err, ErrInvalidInput) {
					t.Fatal("denied signer returned usable evidence:", err)
				}
				return
			}
			evidence, err := result.Evidence()
			want := POSTResponseEvidence{
				ResponseID: "_response", AssertionID: tc.assertionID, ProviderSubject: "member-042",
				SubjectFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", SessionIndex: "member-session",
				AssertionExpiresAt: issued.Add(4 * time.Minute), ValidUntil: tc.validUntil,
			}
			if err != nil || evidence != want {
				t.Fatal("rollover changed the exact signed profile or matched-certificate cutoff:", err)
			}
		})
	}

	// Certificate validity is not extended by the configured assertion skew.
	for _, tc := range []struct {
		name  string
		now   time.Time
		input POSTResponseInput
		want  error
	}{
		{"new pin before NotBefore", newStart.Add(-time.Nanosecond), newInput, ErrInvalidSignature},
		{"old pin before new NotBefore", newStart.Add(-time.Nanosecond), oldInput, nil},
		{"new pin at NotBefore", newStart, newInput, nil},
		{"old pin just before NotAfter", oldCutoff.Add(-time.Nanosecond), oldInput, nil},
		{"retained old pin at NotAfter", oldCutoff, oldInput, ErrInvalidSignature},
		{"retained old pin after NotAfter", oldCutoff.Add(time.Nanosecond), oldInput, ErrInvalidSignature},
		{"new pin remains valid at old NotAfter", oldCutoff, newInput, nil},
		{"new pin remains valid after old NotAfter", oldCutoff.Add(time.Nanosecond), newInput, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := tc.input
			input.Now = tc.now
			result, err := overlap.Validate(t.Context(), input)
			if !errors.Is(err, tc.want) {
				t.Fatalf("wanted %v, got %v", tc.want, err)
			}
			evidence, evidenceErr := result.Evidence()
			if tc.want != nil {
				if !errors.Is(evidenceErr, ErrInvalidInput) {
					t.Fatal("inactive retained pin returned usable evidence:", evidenceErr)
				}
				return
			}
			if evidenceErr != nil || evidence.ProviderSubject != "member-042" || !input.Now.Before(evidence.ValidUntil) {
				t.Fatal("active signing pin lost valid correlated evidence:", evidenceErr)
			}
		})
	}
}

func rolloverSigningCertificate(t *testing.T, serial int64, notBefore, notAfter time.Time) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("generate rollover fixture key:", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal("create rollover fixture certificate:", err)
	}
	return key, certificate
}
