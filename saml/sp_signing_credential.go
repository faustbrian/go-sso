package saml

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"math/bits"
	"time"
)

const (
	spSigningCredentialTag         = "SAMLSPC\x01"
	spSigningCredentialHeaderBytes = 16
	// The selected native secret envelope allows 32 KiB serialized values.
	// Leave room for its authenticated encryption and serialization overhead.
	maximumSPSigningCredentialBytes = 28 * 1024
	maximumSPPrivateKeyBytes        = 8 * 1024
	maximumSPCertificateBytes       = 20 * 1024
)

// EncodeSPSigningCredential validates and copies an RSA signing key and its
// matching certificate into a deterministic version-one plaintext bundle.
// The key must be canonical unencrypted PKCS#8 DER, with a valid 2048..4096-bit
// two-prime RSA private key. The certificate must be one DER certificate with explicit
// digital-signature key usage and must be active at now: NotBefore <= now <
// NotAfter. No chain validation, provider authorization or trust is implied.
//
// The encoding is the 8 bytes "SAMLSPC\x01", two big-endian uint32 lengths
// (key, certificate), then those exact DER values without padding or trailers.
// Key, certificate and aggregate limits are 8 KiB, 20 KiB and 28 KiB respectively.
// These bytes are not encrypted and must only be used as transient input to a
// secret envelope. The caller owns the returned buffer and must clear it after
// sealing; it must never be logged or implicitly serialized.
//
// Inputs are borrowed synchronously without modification or retention and must
// not be mutated concurrently. There is no I/O or clock lookup. A nil context,
// zero now or unsupported input returns ErrInvalidInput without input details.
// Cancellation is checked between bounded parsing steps and before disclosure;
// standard-library parsing cannot be interrupted midway. It returns ctx.Err().
func EncodeSPSigningCredential(ctx context.Context, privateKeyPKCS8, certificateDER []byte, now time.Time) ([]byte, error) {
	if _, _, err := parseSPSigningCredential(ctx, privateKeyPKCS8, certificateDER, now); err != nil {
		return nil, err
	}
	bundle := make([]byte, spSigningCredentialHeaderBytes+len(privateKeyPKCS8)+len(certificateDER))
	copy(bundle, spSigningCredentialTag)
	binary.BigEndian.PutUint32(bundle[8:12], uint32(len(privateKeyPKCS8)))
	binary.BigEndian.PutUint32(bundle[12:16], uint32(len(certificateDER)))
	copy(bundle[spSigningCredentialHeaderBytes:], privateKeyPKCS8)
	copy(bundle[spSigningCredentialHeaderBytes+len(privateKeyPKCS8):], certificateDER)
	if err := ctx.Err(); err != nil {
		clear(bundle)
		return nil, err
	}
	return bundle, nil
}

// ValidateSPSigningCredential validates exactly the plaintext version-one
// encoding described by EncodeSPSigningCredential, including its RSA key,
// certificate match, explicit signing usage and half-open validity window.
// It returns the certificate's original NotAfter, the exclusive expiry, not
// a newly selected or extended lifetime. Failures return a zero time.
//
// The bundle is borrowed synchronously without modification or retention.
// It is secret plaintext: the caller must clear its buffer after use and must
// not log it or mutate it concurrently. No I/O, provider admission or trust-chain
// validation occurs. Nil contexts and malformed, noncanonical, oversized or
// inactive inputs return ErrInvalidInput; cancellation returns ctx.Err().
func ValidateSPSigningCredential(ctx context.Context, bundle []byte, now time.Time) (time.Time, error) {
	if ctx == nil {
		return time.Time{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	if len(bundle) < spSigningCredentialHeaderBytes || len(bundle) > maximumSPSigningCredentialBytes ||
		string(bundle[:len(spSigningCredentialTag)]) != spSigningCredentialTag {
		return time.Time{}, ErrInvalidInput
	}
	keyBytes := binary.BigEndian.Uint32(bundle[8:12])
	certificateBytes := binary.BigEndian.Uint32(bundle[12:16])
	if keyBytes == 0 || keyBytes > maximumSPPrivateKeyBytes || certificateBytes == 0 || certificateBytes > maximumSPCertificateBytes {
		return time.Time{}, ErrInvalidInput
	}
	// Lengths are bounded before conversion and addition, including on 32-bit Go.
	certificateOffset := spSigningCredentialHeaderBytes + int(keyBytes)
	if certificateOffset+int(certificateBytes) != len(bundle) {
		return time.Time{}, ErrInvalidInput
	}
	_, certificate, err := parseSPSigningCredential(ctx, bundle[spSigningCredentialHeaderBytes:certificateOffset], bundle[certificateOffset:], now)
	if err != nil {
		return time.Time{}, err
	}
	return certificate.NotAfter, nil
}

func parseSPSigningCredential(ctx context.Context, privateDER, certificateDER []byte, now time.Time) (*rsa.PrivateKey, *x509.Certificate, error) {
	if ctx == nil {
		return nil, nil, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if now.IsZero() || len(privateDER) == 0 || len(privateDER) > maximumSPPrivateKeyBytes ||
		len(certificateDER) == 0 || len(certificateDER) > maximumSPCertificateBytes ||
		spSigningCredentialHeaderBytes+len(privateDER)+len(certificateDER) > maximumSPSigningCredentialBytes ||
		!boundedSPRSAPrivateKey(privateDER) {
		return nil, nil, ErrInvalidInput
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(privateDER)
	if canceled := ctx.Err(); canceled != nil {
		return nil, nil, canceled
	}
	if err != nil {
		return nil, nil, ErrInvalidInput
	}
	key, ok := parsedKey.(*rsa.PrivateKey)
	if !ok || key == nil || key.N == nil || len(key.Primes) != 2 || key.N.BitLen() < 2048 || key.N.BitLen() > 4096 ||
		key.E < 3 || key.E%2 == 0 || key.Validate() != nil {
		return nil, nil, ErrInvalidInput
	}
	canonicalKey, err := x509.MarshalPKCS8PrivateKey(key)
	canonical := err == nil && bytes.Equal(canonicalKey, privateDER)
	clear(canonicalKey)
	if !canonical {
		return nil, nil, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if canceled := ctx.Err(); canceled != nil {
		return nil, nil, canceled
	}
	if err != nil || certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 ||
		!certificate.NotBefore.Before(certificate.NotAfter) || now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
		return nil, nil, ErrInvalidInput
	}
	public, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok || public == nil || !key.PublicKey.Equal(public) {
		return nil, nil, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	return key, certificate, nil
}

// ParsePKCS8PrivateKey can precompute with individual RSA operands before
// rejecting an inconsistent key. Admit only the bounded two-prime PKCS#1
// shape (RFC 8017, Appendix A.1.2) before calling it; x509 and rsa still own
// arithmetic validation. The two-prime profile uses Go's CRT validation.
func boundedSPRSAPrivateKey(der []byte) bool {
	var envelope struct {
		Version    int
		Algorithm  pkix.AlgorithmIdentifier
		PrivateKey []byte
	}
	rest, err := asn1.Unmarshal(der, &envelope)
	if err != nil || len(rest) != 0 || envelope.Version != 0 ||
		!envelope.Algorithm.Algorithm.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}) {
		return false
	}
	var sequence asn1.RawValue
	rest, err = asn1.Unmarshal(envelope.PrivateKey, &sequence)
	if err != nil || len(rest) != 0 || sequence.Class != 0 || sequence.Tag != asn1.TagSequence || !sequence.IsCompound {
		return false
	}
	var version int
	remaining, err := asn1.Unmarshal(sequence.Bytes, &version)
	if err != nil || version != 0 {
		return false
	}
	modulus, remaining := positiveSPDERInteger(remaining)
	if len(modulus) == 0 || len(modulus) > 512 || modulus[len(modulus)-1]&1 == 0 {
		return false
	}
	if len(modulus)*8-8+bits.Len8(modulus[0]) < 2048 {
		return false
	}
	exponent, remaining := positiveSPDERInteger(remaining)
	if len(exponent) == 0 || len(exponent) > 4 || len(exponent) == 4 && exponent[0]&0x80 != 0 ||
		exponent[len(exponent)-1]&1 == 0 || len(exponent) == 1 && exponent[0] < 3 {
		return false
	}
	// d, p, q, dP, dQ and qInv are positive integers smaller than n. Bound
	// all six before handing any part of the private key to RSA precompute.
	for range 6 {
		var operand []byte
		operand, remaining = positiveSPDERInteger(remaining)
		if len(operand) == 0 || len(operand) > len(modulus) ||
			len(operand) == len(modulus) && bytes.Compare(operand, modulus) >= 0 {
			return false
		}
	}
	return len(remaining) == 0
}

// positiveSPDERInteger returns the canonical, unsigned magnitude as an alias
// of the DER bytes. A nil magnitude means malformed or not positive.
func positiveSPDERInteger(der []byte) (magnitude, remaining []byte) {
	var integer asn1.RawValue
	rest, err := asn1.Unmarshal(der, &integer)
	if err != nil || integer.Class != 0 || integer.Tag != asn1.TagInteger ||
		integer.IsCompound || len(integer.Bytes) == 0 || integer.Bytes[0]&0x80 != 0 {
		return nil, nil
	}
	value := integer.Bytes
	if value[0] == 0 {
		if len(value) == 1 || value[1]&0x80 == 0 {
			return nil, nil
		}
		value = value[1:]
	}
	return value, rest
}
