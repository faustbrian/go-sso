package saml

import (
	"bytes"
	"context"
	"time"
)

// SPSigningCertificate returns an owned, detached copy of the exact public
// certificate DER in the plaintext bundle described by EncodeSPSigningCredential.
// It applies ValidateSPSigningCredential's matching RSA key, explicit signing
// usage and active half-open validity policy, and returns the certificate's
// original NotAfter as an exclusive cutoff. Every failure returns nil bytes and
// a zero time. No private key is returned and no provider admission, trust-chain
// validation, credential rotation or metadata publication occurs.
//
// The secret bundle is borrowed synchronously without modification or retention;
// the caller must clear it after use and must not log or mutate it concurrently.
// Clearing the bundle does not erase Go-managed parsed key objects. There is no
// I/O, clock lookup or stored state. Nil contexts and invalid input return
// ErrInvalidInput; cancellation returns ctx.Err(). Cancellation is checked
// between bounded parsing steps and after copying before disclosure, but
// standard-library parsing cannot be interrupted midway.
func SPSigningCertificate(ctx context.Context, bundle []byte, now time.Time) ([]byte, time.Time, error) {
	_, certificate, err := parseSPSigningCredentialBundle(ctx, bundle, now)
	if err != nil {
		return nil, time.Time{}, err
	}
	publicDER := bytes.Clone(certificate.Raw)
	if err := ctx.Err(); err != nil {
		clear(publicDER)
		return nil, time.Time{}, err
	}
	return publicDER, certificate.NotAfter, nil
}
