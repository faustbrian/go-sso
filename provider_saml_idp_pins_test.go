package sso_test

import (
	"bytes"
	"errors"
	"math"
	"testing"

	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
)

func TestSAMLIDPSigningCertificatesCanonicalOrderedDetachedBundle(t *testing.T) {
	certificates := [][]byte{{0x30, 0x01}, {0x30, 0x02, 0x03}}
	want := []byte{1, 2, 0, 0, 0, 2, 0x30, 0x01, 0, 0, 0, 3, 0x30, 0x02, 0x03}
	bundle, err := sso.EncodeSAMLIDPSigningCertificates(certificates)
	if err != nil || !bytes.Equal(bundle, want) {
		t.Fatal("ordered certificate bytes did not use the canonical versioned frame", err)
	}
	certificates[0][0] = 0xff
	if !bytes.Equal(bundle, want) {
		t.Fatal("encoding retained caller-owned certificate bytes")
	}
	decoded, err := sso.DecodeSAMLIDPSigningCertificates(bundle)
	if err != nil || len(decoded) != 2 || !bytes.Equal(decoded[0], []byte{0x30, 0x01}) || !bytes.Equal(decoded[1], []byte{0x30, 0x02, 0x03}) {
		t.Fatal("decoding changed ordered certificate bytes", err)
	}
	decoded[0][0] = 0xee
	if !bytes.Equal(bundle, want) || decoded[1][0] != 0x30 {
		t.Fatal("decoding aliased its input or another certificate")
	}
	bundle[7] = 0xdd
	if decoded[0][1] != 0x01 {
		t.Fatal("decoded certificate retained the input frame")
	}

	// DER/type validity belongs to the native validator, not this framing codec.
	structuralOnly, err := sso.EncodeSAMLIDPSigningCertificates([][]byte{{0x01}})
	if err != nil {
		t.Fatal("structural encoder attempted certificate validation", err)
	}
	if _, err := sso.DecodeSAMLIDPSigningCertificates(structuralOnly); err != nil {
		t.Fatal("structural decoder attempted certificate validation", err)
	}
}

func TestSAMLIDPSigningCertificatesCountAndTotalSizeBoundaries(t *testing.T) {
	for _, certificates := range [][][]byte{
		{{1}},
		{{1}, {2}, {3}, {4}, {5}},
		{bytes.Repeat([]byte{0x30}, 24*1024-6)},
	} {
		bundle, err := sso.EncodeSAMLIDPSigningCertificates(certificates)
		if err != nil || len(bundle) > 24*1024 {
			t.Fatal("valid bounded certificate set was rejected", err)
		}
		decoded, err := sso.DecodeSAMLIDPSigningCertificates(bundle)
		if err != nil || len(decoded) != len(certificates) {
			t.Fatal("bounded certificate count did not round trip", err)
		}
		for index := range certificates {
			if !bytes.Equal(decoded[index], certificates[index]) {
				t.Fatal("bounded certificate bytes changed")
			}
		}
	}
	for name, certificates := range map[string][][]byte{
		"nil":            nil,
		"empty":          {},
		"empty-entry":    {{1}, {}},
		"nil-entry":      {{1}, nil},
		"duplicate":      {{1}, {2}, {1}},
		"too-many":       {{1}, {2}, {3}, {4}, {5}, {6}},
		"one-byte-over":  {bytes.Repeat([]byte{0x30}, 24*1024-5)},
		"aggregate-over": {bytes.Repeat([]byte{1}, 12*1024), bytes.Repeat([]byte{2}, 12*1024)},
	} {
		t.Run(name, func(t *testing.T) {
			bundle, err := sso.EncodeSAMLIDPSigningCertificates(certificates)
			if bundle != nil || !errors.Is(err, sso.ErrInvalidInput) || err.Error() != sso.ErrInvalidInput.Error() {
				t.Fatal("invalid certificate set returned data or a non-redacted error")
			}
		})
	}
}

func TestSAMLIDPSigningCertificatesRejectsMalformedFramesWithoutPartialOutput(t *testing.T) {
	valid := []byte{1, 1, 0, 0, 0, 1, 0x30}
	for end := 0; end < len(valid); end++ {
		decoded, err := sso.DecodeSAMLIDPSigningCertificates(valid[:end])
		if decoded != nil || !errors.Is(err, sso.ErrInvalidInput) {
			t.Fatal("truncated certificate frame returned data or success")
		}
	}
	for name, bundle := range map[string][]byte{
		"unknown-version": {2, 1, 0, 0, 0, 1, 0x30},
		"zero-count":      {1, 0},
		"oversized-count": {1, 6},
		"zero-length":     {1, 1, 0, 0, 0, 0},
		"overflow-length": {1, 1, 0xff, 0xff, 0xff, 0xff},
		"duplicate":       {1, 2, 0, 0, 0, 1, 0x30, 0, 0, 0, 1, 0x30},
		"partial-output":  {1, 2, 0, 0, 0, 1, 0x30, 0, 0, 0, 2, 0x31},
		"trailing":        append(bytes.Clone(valid), 0),
		"oversized":       append([]byte{1, 1, 0, 0, 0, 1, 0x30}, make([]byte, 24*1024)...),
	} {
		t.Run(name, func(t *testing.T) {
			decoded, err := sso.DecodeSAMLIDPSigningCertificates(bundle)
			if decoded != nil || !errors.Is(err, sso.ErrInvalidInput) || err.Error() != sso.ErrInvalidInput.Error() {
				t.Fatal("malformed frame returned partial data or a non-redacted error")
			}
		})
	}
}

func TestSAMLIDPSigningCertificatesContextBindsPurposeAndProviderSuccessor(t *testing.T) {
	binding := credentialReferenceContext()
	binding.Protocol = "saml"
	binding.Purpose = sso.SAMLIDPSigningCertificatesPurpose
	binding.ProviderVersion, binding.Generation = 7, 8
	aad, err := binding.EncryptionContext()
	if err != nil {
		t.Fatal("IdP pin-set successor context rejected", err)
	}
	want, err := envelope.NewContext(map[string]string{
		"owner": "sso/provider-credentials", "tenant": binding.TenantID,
		"organization": binding.OrganizationID, "provider": binding.ProviderID,
		"protocol": "saml", "purpose": "idp-signing-certificates",
		"generation": "8", "provider-version": "7", "audience": binding.Audience,
		"key-id":     binding.EnvelopeKeyID,
		"issued-at":  binding.IssuedAt.Format("2006-01-02T15:04:05.999999999Z07:00"),
		"expires-at": binding.ExpiresAt.Format("2006-01-02T15:04:05.999999999Z07:00"),
	})
	if err != nil || !bytes.Equal(aad.AdditionalData(), want.AdditionalData()) {
		t.Fatal("IdP ingress changed the existing exact credential AAD frame", err)
	}
	service := newCredentialEnvelopeService(t)
	wire := credentialEnvelope(t, service, binding)
	reference, err := sso.NewEncryptedCredentialReference(t.Context(), service, wire, binding)
	if err != nil || reference.Context() != binding {
		t.Fatal("IdP pin-set ingress failed exact-context authentication", err)
	}
	for _, purpose := range []string{sso.SAMLSigningCredentialPurpose, "client-secret", "idp-signing-certificates "} {
		changed := binding
		changed.Purpose = purpose
		if _, err := sso.NewEncryptedCredentialReference(t.Context(), service, wire, changed); err == nil {
			t.Fatal("IdP ciphertext authenticated under another purpose")
		}
	}
	for _, protocol := range []string{"oidc", "oauth2", "SAML", ""} {
		changed := binding
		changed.Protocol = protocol
		if _, err := changed.EncryptionContext(); !errors.Is(err, sso.ErrInvalidInput) {
			t.Fatal("IdP pin-set purpose escaped its exact SAML protocol")
		}
	}
	changed := binding
	changed.ProviderVersion, changed.Generation = 8, 9
	if _, err := sso.NewEncryptedCredentialReference(t.Context(), service, wire, changed); !errors.Is(err, sso.ErrForbidden) {
		t.Fatal("IdP ciphertext authenticated a different valid provider successor", err)
	}
}

func TestSAMLIDPSigningCertificatesContextRejectsMismatchedAndOverflowGeneration(t *testing.T) {
	for _, versions := range [][2]uint64{{0, 1}, {1, 0}, {7, 7}, {7, 9}, {math.MaxUint64, 0}, {math.MaxUint64, 1}, {math.MaxUint64, math.MaxUint64}} {
		binding := credentialReferenceContext()
		binding.Protocol, binding.Purpose = "saml", sso.SAMLIDPSigningCertificatesPurpose
		binding.ProviderVersion, binding.Generation = versions[0], versions[1]
		if _, err := binding.EncryptionContext(); !errors.Is(err, sso.ErrInvalidInput) {
			t.Fatal("IdP generation was not the non-overflowing provider successor")
		}
	}
	binding := credentialReferenceContext()
	binding.Protocol, binding.Purpose = "saml", sso.SAMLIDPSigningCertificatesPurpose
	binding.ProviderVersion, binding.Generation = math.MaxUint64-1, math.MaxUint64
	if _, err := binding.EncryptionContext(); err != nil {
		t.Fatal("last non-overflowing IdP successor rejected", err)
	}
	for _, protocolPurpose := range [][2]string{{"saml", sso.SAMLSigningCredentialPurpose}, {"oidc", "client-secret"}, {"oauth2", "client-secret"}} {
		binding.Protocol, binding.Purpose = protocolPurpose[0], protocolPurpose[1]
		binding.ProviderVersion, binding.Generation = 7, 2
		if _, err := binding.EncryptionContext(); err != nil {
			t.Fatal("existing credential generation acquired the IdP provider-successor rule", err)
		}
	}
}

func FuzzSAMLIDPSigningCertificatesDecode(f *testing.F) {
	for _, seed := range [][]byte{
		nil,
		{1, 1, 0, 0, 0, 1, 0x30},
		{1, 2, 0, 0, 0, 1, 0x30, 0, 0, 0, 1, 0x31},
		{1, 1, 0xff, 0xff, 0xff, 0xff},
		{1, 2, 0, 0, 0, 1, 0x30, 0, 0, 0, 1, 0x30},
		{1, 6},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, bundle []byte) {
		decoded, err := sso.DecodeSAMLIDPSigningCertificates(bundle)
		if err != nil {
			if decoded != nil || !errors.Is(err, sso.ErrInvalidInput) || err.Error() != sso.ErrInvalidInput.Error() {
				t.Fatal("malformed frame leaked partial output or error details")
			}
			return
		}
		if len(bundle) > 24*1024 || len(decoded) == 0 || len(decoded) > 5 {
			t.Fatal("decoder accepted an unbounded frame")
		}
		canonical, err := sso.EncodeSAMLIDPSigningCertificates(decoded)
		if err != nil || !bytes.Equal(canonical, bundle) {
			t.Fatal("decoder accepted a noncanonical frame", err)
		}
		for index, certificate := range decoded {
			if len(certificate) == 0 {
				t.Fatal("decoder accepted invalid certificate lengths")
			}
			for _, previous := range decoded[:index] {
				if bytes.Equal(certificate, previous) {
					t.Fatal("decoder accepted duplicate certificate bytes")
				}
			}
		}
		decoded[0][0] ^= 1
		if !bytes.Equal(canonical, bundle) {
			t.Fatal("decoded certificate aliases the input frame")
		}
	})
}
