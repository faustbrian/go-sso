package sso

import (
	"bytes"
	"encoding/binary"
)

// Leave room for envelope framing and bound native certificate work. The
// separate 32768-byte limit still applies to the complete sealed reference.
const maxSAMLIDPSigningCertificatesBundleSize = 24 * 1024

// EncodeSAMLIDPSigningCertificates encodes an ordered set of one through five
// nonempty, distinct certificate byte slices into a fresh bundle of at most
// 24 KiB. The canonical frame is version byte 1, a one-byte count, then each
// certificate's uint32 big-endian length and unchanged bytes. The input is
// borrowed only until return and is not modified or retained. This function
// validates framing only; DER, certificate type, validity, and trust must be
// validated by the native SAML owner. Invalid input returns nil and
// ErrInvalidInput without including certificate bytes in the error.
func EncodeSAMLIDPSigningCertificates(certificates [][]byte) ([]byte, error) {
	if len(certificates) == 0 || len(certificates) > 5 {
		return nil, ErrInvalidInput
	}

	size := 2
	for index, certificate := range certificates {
		if len(certificate) == 0 || len(certificate) > maxSAMLIDPSigningCertificatesBundleSize-size-4 {
			return nil, ErrInvalidInput
		}
		for _, previous := range certificates[:index] {
			if bytes.Equal(certificate, previous) {
				return nil, ErrInvalidInput
			}
		}
		size += 4 + len(certificate)
	}

	bundle := make([]byte, size)
	bundle[0], bundle[1] = 1, byte(len(certificates))
	offset := 2
	for _, certificate := range certificates {
		binary.BigEndian.PutUint32(bundle[offset:offset+4], uint32(len(certificate)))
		offset += 4
		copy(bundle[offset:], certificate)
		offset += len(certificate)
	}
	return bundle, nil
}

// DecodeSAMLIDPSigningCertificates decodes the canonical version-1 frame
// described by EncodeSAMLIDPSigningCertificates. It accepts at most 24 KiB and
// one through five nonempty, distinct certificate byte slices in their original
// order. Every returned slice is detached from the input and every other slice.
// The input is borrowed only until return and is not modified or retained.
// Validation is structural only; DER, certificate type, validity, and trust
// remain the native SAML owner's responsibility. Malformed, oversized,
// duplicate, or trailing data returns nil and ErrInvalidInput without partial
// output or certificate bytes in the error.
func DecodeSAMLIDPSigningCertificates(bundle []byte) ([][]byte, error) {
	if len(bundle) < 7 || len(bundle) > maxSAMLIDPSigningCertificatesBundleSize || bundle[0] != 1 || bundle[1] == 0 || bundle[1] > 5 {
		return nil, ErrInvalidInput
	}

	certificates := make([][]byte, int(bundle[1]))
	offset := 2
	for index := range certificates {
		if len(bundle)-offset < 4 {
			return nil, ErrInvalidInput
		}
		length := binary.BigEndian.Uint32(bundle[offset : offset+4])
		offset += 4
		if length == 0 || length > uint32(len(bundle)-offset) {
			return nil, ErrInvalidInput
		}
		certificate := bundle[offset : offset+int(length)]
		for _, previous := range certificates[:index] {
			if bytes.Equal(certificate, previous) {
				return nil, ErrInvalidInput
			}
		}
		certificates[index] = certificate
		offset += int(length)
	}
	if offset != len(bundle) {
		return nil, ErrInvalidInput
	}
	for index, certificate := range certificates {
		certificates[index] = bytes.Clone(certificate)
	}
	return certificates, nil
}
