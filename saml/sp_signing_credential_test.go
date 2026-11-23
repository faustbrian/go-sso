package saml_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/faustbrian/go-sso/saml"
)

func TestSPSigningCredentialRoundTrip(t *testing.T) {
	key := spCredentialRSAKey(t, 2048)
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	expires := now.Add(24 * time.Hour)
	privateDER := spCredentialPKCS8(t, key)
	certificate := spCredentialCertificate(t, key, &key.PublicKey, now, expires, x509.KeyUsageDigitalSignature)
	privateBefore := bytes.Clone(privateDER)
	certificateBefore := bytes.Clone(certificate)

	bundle, err := saml.EncodeSPSigningCredential(t.Context(), privateDER, certificate, now)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(bundle)
	wantBundle := spCredentialBundle(privateDER, certificate)
	defer clear(wantBundle)
	if !bytes.Equal(bundle, wantBundle) || len(bundle) > 28*1024 {
		t.Fatal("credential did not use the bounded version-one encoding")
	}
	if !bytes.Equal(privateDER, privateBefore) || !bytes.Equal(certificate, certificateBefore) {
		t.Fatal("encoding changed caller-owned input")
	}
	validUntil, err := saml.ValidateSPSigningCredential(t.Context(), bundle, now)
	if err != nil || !validUntil.Equal(expires) {
		t.Fatalf("validation did not return the original exclusive certificate expiry: %v", err)
	}
	second, err := saml.EncodeSPSigningCredential(t.Context(), privateDER, certificate, now)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(second)
	if !bytes.Equal(bundle, second) {
		t.Fatal("credential encoding was not deterministic")
	}
	clear(privateDER)
	clear(certificate)
	if _, err := saml.ValidateSPSigningCredential(t.Context(), bundle, now); err != nil {
		t.Fatal("encoded credential retained aliases of the inputs")
	}
}

func TestSPSigningCredentialRejectsUnusableKeysAndCertificates(t *testing.T) {
	key := spCredentialRSAKey(t, 2048)
	other := spCredentialRSAKey(t, 2048)
	weak := spCredentialRSAKey(t, 1024)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	expires := now.Add(time.Hour)
	privateDER := spCredentialPKCS8(t, key)
	certificate := spCredentialCertificate(t, key, &key.PublicKey, now.Add(-time.Hour), expires, x509.KeyUsageDigitalSignature)
	invalidExponent := new(big.Int).Add(key.D, big.NewInt(2))
	oversizedModulus := new(big.Int).Lsh(big.NewInt(1), 4096)
	withAttribute, err := asn1.Marshal(struct {
		Version    int
		Algorithm  pkix.AlgorithmIdentifier
		PrivateKey []byte
		Attributes asn1.RawValue `asn1:"optional,tag:0"`
	}{
		Algorithm:  pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}, Parameters: asn1.RawValue{Tag: 5}},
		PrivateKey: x509.MarshalPKCS1PrivateKey(key),
		Attributes: asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: []byte{}},
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name        string
		privateDER  []byte
		certificate []byte
	}{
		{name: "missing key", certificate: certificate},
		{name: "missing certificate", privateDER: privateDER},
		{name: "mismatched key", privateDER: spCredentialPKCS8(t, other), certificate: certificate},
		{name: "wrong certificate key algorithm", privateDER: privateDER, certificate: spCredentialCertificate(t, key, &ecKey.PublicKey, now, expires, x509.KeyUsageDigitalSignature)},
		{name: "wrong private key algorithm", privateDER: spCredentialPKCS8(t, ecKey), certificate: spCredentialCertificate(t, ecKey, &ecKey.PublicKey, now, expires, x509.KeyUsageDigitalSignature)},
		{name: "undersized RSA", privateDER: spCredentialPKCS8(t, weak), certificate: spCredentialCertificate(t, key, &weak.PublicKey, now, expires, x509.KeyUsageDigitalSignature)},
		{name: "oversized RSA", privateDER: spCredentialRSAWithParameters(t, key, oversizedModulus, key.D), certificate: certificate},
		{name: "invalid RSA private exponent", privateDER: spCredentialRSAWithParameters(t, key, key.N, invalidExponent), certificate: certificate},
		{name: "encryption only", privateDER: privateDER, certificate: spCredentialCertificate(t, key, &key.PublicKey, now, expires, x509.KeyUsageKeyEncipherment)},
		{name: "unspecified signing usage", privateDER: privateDER, certificate: spCredentialCertificate(t, key, &key.PublicKey, now, expires, 0)},
		{name: "PKCS1 instead of PKCS8", privateDER: x509.MarshalPKCS1PrivateKey(key), certificate: certificate},
		{name: "PEM instead of DER", privateDER: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), certificate: certificate},
		{name: "PKCS8 attributes are not canonical", privateDER: withAttribute, certificate: certificate},
		{name: "trailing private key", privateDER: append(bytes.Clone(privateDER), 0), certificate: certificate},
		{name: "trailing certificate", privateDER: privateDER, certificate: append(bytes.Clone(certificate), 0)},
		{name: "certificate chain", privateDER: privateDER, certificate: append(bytes.Clone(certificate), certificate...)},
		{name: "oversized private key input", privateDER: make([]byte, 8*1024+1), certificate: certificate},
		{name: "oversized certificate input", privateDER: privateDER, certificate: make([]byte, 20*1024+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bundle, err := saml.EncodeSPSigningCredential(t.Context(), tc.privateDER, tc.certificate, now)
			if err != saml.ErrInvalidInput || bundle != nil {
				t.Fatal("encoding did not reject invalid material with a redacted error")
			}
			encoded := spCredentialBundle(tc.privateDER, tc.certificate)
			defer clear(encoded)
			validUntil, err := saml.ValidateSPSigningCredential(t.Context(), encoded, now)
			if err != saml.ErrInvalidInput || !validUntil.IsZero() {
				t.Fatal("validation accepted invalid material or exposed an expiry/error payload")
			}
		})
	}
}

func TestSPSigningCredentialRejectsMultiPrimeRSA(t *testing.T) {
	// Generate a valid key from the unsupported profile rather than relying on
	// whether the standard library rejects malformed RSA arithmetic.
	key, err := rsa.GenerateMultiPrimeKey(rand.Reader, 3, 2048)
	if err != nil {
		t.Fatal("could not generate an ephemeral multiprime test key")
	}
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	privateDER := spCredentialPKCS8(t, key)
	defer clear(privateDER)
	certificate := spCredentialCertificate(t, key, &key.PublicKey, now, now.Add(time.Hour), x509.KeyUsageDigitalSignature)
	bundle, err := saml.EncodeSPSigningCredential(t.Context(), privateDER, certificate, now)
	defer clear(bundle)
	if err != saml.ErrInvalidInput || bundle != nil {
		t.Error("encoding accepted a key outside the selected two-prime profile")
	}
	wire := spCredentialBundle(privateDER, certificate)
	defer clear(wire)
	if expiry, err := saml.ValidateSPSigningCredential(t.Context(), wire, now); err != saml.ErrInvalidInput || !expiry.IsZero() {
		t.Error("validation accepted a key outside the selected two-prime profile")
	}
}

func FuzzSPSigningCredentialBundle(f *testing.F) {
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	expires := now.Add(time.Hour)
	key := spCredentialRSAKey(f, 2048)
	privateDER := spCredentialPKCS8(f, key)
	defer clear(privateDER)
	cert := spCredentialCertificate(f, key, &key.PublicKey, now, expires, x509.KeyUsageDigitalSignature)
	bundle := spCredentialBundle(privateDER, cert)
	defer clear(bundle)
	f.Add(bundle)
	f.Add(bytes.Clone(bundle[:len(bundle)-1]))
	f.Add(spCredentialBundle([]byte{0x30, 0}, []byte{0x30, 0}))
	f.Fuzz(func(t *testing.T, bundle []byte) {
		until, err := saml.ValidateSPSigningCredential(t.Context(), bundle, now)
		if err != nil {
			if err != saml.ErrInvalidInput || !until.IsZero() {
				t.Fatal("invalid input returned an unredacted error or expiry")
			}
		} else if !now.Before(until) {
			t.Fatal("accepted signing material without a future expiry")
		}
	})
}

func TestSPSigningCredentialUsesHalfOpenCertificateValidity(t *testing.T) {
	key := spCredentialRSAKey(t, 2048)
	starts := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	expires := starts.Add(time.Hour)
	privateDER := spCredentialPKCS8(t, key)
	certificate := spCredentialCertificate(t, key, &key.PublicKey, starts, expires, x509.KeyUsageDigitalSignature)
	encoded := spCredentialBundle(privateDER, certificate)
	defer clear(encoded)
	for _, tc := range []struct {
		name string
		now  time.Time
		ok   bool
	}{
		{name: "before activation", now: starts.Add(-time.Nanosecond)},
		{name: "inclusive activation", now: starts, ok: true},
		{name: "last nanosecond", now: expires.Add(-time.Nanosecond), ok: true},
		{name: "exclusive expiry", now: expires},
		{name: "after expiry", now: expires.Add(time.Nanosecond)},
		{name: "zero clock"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bundle, encodeErr := saml.EncodeSPSigningCredential(t.Context(), privateDER, certificate, tc.now)
			defer clear(bundle)
			validUntil, validateErr := saml.ValidateSPSigningCredential(t.Context(), encoded, tc.now)
			if tc.ok {
				if encodeErr != nil || validateErr != nil || !validUntil.Equal(expires) {
					t.Fatal("rejected an active credential or changed its original expiry")
				}
			} else if encodeErr != saml.ErrInvalidInput || validateErr != saml.ErrInvalidInput || bundle != nil || !validUntil.IsZero() {
				t.Fatal("accepted a credential outside its half-open validity window")
			}
		})
	}
	for _, cutoff := range []time.Time{starts, starts.Add(-time.Second)} {
		invalid := spCredentialCertificate(t, key, &key.PublicKey, starts, cutoff, x509.KeyUsageDigitalSignature)
		if result, err := saml.EncodeSPSigningCredential(t.Context(), privateDER, invalid, starts); err != saml.ErrInvalidInput || result != nil {
			t.Fatal("accepted an empty or inverted certificate lifetime")
		}
	}
}

func TestSPSigningCredentialRejectsMalformedBundles(t *testing.T) {
	key := spCredentialRSAKey(t, 2048)
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	certificate := spCredentialCertificate(t, key, &key.PublicKey, now, now.Add(time.Hour), x509.KeyUsageDigitalSignature)
	valid := spCredentialBundle(spCredentialPKCS8(t, key), certificate)
	defer clear(valid)
	wrongVersion := bytes.Clone(valid)
	wrongVersion[7] = 2
	wrongMagic := bytes.Clone(valid)
	wrongMagic[0] = 'X'
	overflow := bytes.Clone(valid)
	binary.BigEndian.PutUint32(overflow[8:12], ^uint32(0))
	zeroKey := bytes.Clone(valid)
	binary.BigEndian.PutUint32(zeroKey[8:12], 0)
	for _, bundle := range [][]byte{nil, {}, valid[:7], valid[:15], valid[:len(valid)-1], append(bytes.Clone(valid), 0), wrongVersion, wrongMagic, overflow, zeroKey, make([]byte, 28*1024+1)} {
		validUntil, err := saml.ValidateSPSigningCredential(t.Context(), bundle, now)
		if err != saml.ErrInvalidInput || !validUntil.IsZero() {
			t.Fatal("accepted a malformed bundle or disclosed non-redacted failure data")
		}
	}
}

func TestSPSigningCredentialHonorsCancellation(t *testing.T) {
	key := spCredentialRSAKey(t, 2048)
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	privateDER := spCredentialPKCS8(t, key)
	certificate := spCredentialCertificate(t, key, &key.PublicKey, now, now.Add(time.Hour), x509.KeyUsageDigitalSignature)
	bundle := spCredentialBundle(privateDER, certificate)
	defer clear(bundle)
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	expired, stop := context.WithDeadline(t.Context(), time.Unix(1, 0))
	defer stop()
	for _, tc := range []struct {
		ctx  context.Context
		want error
	}{
		{ctx: canceled, want: context.Canceled},
		{ctx: expired, want: context.DeadlineExceeded},
		{want: saml.ErrInvalidInput},
	} {
		encoded, err := saml.EncodeSPSigningCredential(tc.ctx, privateDER, certificate, now)
		if !errors.Is(err, tc.want) || encoded != nil {
			t.Fatal("encoding did not preserve cancellation or reject nil context")
		}
		validUntil, err := saml.ValidateSPSigningCredential(tc.ctx, bundle, now)
		if !errors.Is(err, tc.want) || !validUntil.IsZero() {
			t.Fatal("validation did not preserve cancellation or reject nil context")
		}
	}
}

func spCredentialRSAKey(t testing.TB, bits int) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal("could not generate ephemeral RSA test key")
	}
	return key
}

func spCredentialPKCS8(t testing.TB, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal("could not marshal ephemeral test key")
	}
	return der
}

func spCredentialRSAWithParameters(t *testing.T, key *rsa.PrivateKey, modulus, privateExponent *big.Int) []byte {
	t.Helper()
	// The native PKCS#8 marshaler correctly refuses invalid RSA arithmetic.
	// Encode ASN.1 directly to exercise rejection at the public input boundary.
	privateDER, err := asn1.Marshal(struct {
		Version               int
		N                     *big.Int
		E                     int
		D, P, Q, Dp, Dq, Qinv *big.Int
	}{
		N: modulus, E: key.E, D: privateExponent, P: key.Primes[0], Q: key.Primes[1],
		Dp: key.Precomputed.Dp, Dq: key.Precomputed.Dq, Qinv: key.Precomputed.Qinv,
	})
	if err != nil {
		t.Fatal("could not encode ephemeral RSA test parameters")
	}
	der, err := asn1.Marshal(struct {
		Version    int
		Algorithm  pkix.AlgorithmIdentifier
		PrivateKey []byte
	}{
		Algorithm:  pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}, Parameters: asn1.NullRawValue},
		PrivateKey: privateDER,
	})
	clear(privateDER)
	if err != nil {
		t.Fatal("could not encode ephemeral PKCS8 test parameters")
	}
	return der
}

func spCredentialCertificate(t testing.TB, signer crypto.Signer, public any, starts, expires time.Time, usage x509.KeyUsage) []byte {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ephemeral-sp.example"},
		NotBefore: starts, NotAfter: expires, KeyUsage: usage,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, signer)
	if err != nil {
		t.Fatal("could not create ephemeral test certificate")
	}
	return der
}

func spCredentialBundle(privateDER, certificate []byte) []byte {
	// Independent version-one fixture: 8-byte tag, lengths, exact DER values.
	bundle := make([]byte, 16+len(privateDER)+len(certificate))
	copy(bundle, "SAMLSPC\x01")
	binary.BigEndian.PutUint32(bundle[8:12], uint32(len(privateDER)))
	binary.BigEndian.PutUint32(bundle[12:16], uint32(len(certificate)))
	copy(bundle[16:], privateDER)
	copy(bundle[16+len(privateDER):], certificate)
	return bundle
}
