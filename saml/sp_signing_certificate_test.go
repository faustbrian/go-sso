package saml_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/faustbrian/go-sso/saml"
)

func TestSPSigningCertificateReturnsExactDetachedPublicCertificate(t *testing.T) {
	key := spCredentialRSAKey(t, 2048)
	privateDER := spCredentialPKCS8(t, key)
	defer clear(privateDER)
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	expires := now.Add(time.Hour)
	certificate := spCredentialCertificate(t, key, &key.PublicKey, now, expires, x509.KeyUsageDigitalSignature)
	bundle := spCredentialBundle(privateDER, certificate)
	defer clear(bundle)
	before := bytes.Clone(bundle)
	defer clear(before)

	publicDER, cutoff, err := saml.SPSigningCertificate(t.Context(), bundle, now)
	if err != nil || !cutoff.Equal(expires) || !bytes.Equal(publicDER, certificate) {
		t.Fatal("projection did not return the exact public certificate and original exclusive expiry")
	}
	if !bytes.Equal(bundle, before) {
		t.Fatal("projection changed caller-owned credential storage")
	}
	secondDER, secondCutoff, err := saml.SPSigningCertificate(t.Context(), bundle, now)
	if err != nil || !secondCutoff.Equal(expires) {
		t.Fatal("repeated projection changed the certificate expiry")
	}
	clear(publicDER)
	if !bytes.Equal(bundle, before) || !bytes.Equal(secondDER, certificate) {
		t.Fatal("public certificate result aliases the bundle or another result")
	}
	clear(bundle)
	clear(privateDER)
	if !bytes.Equal(secondDER, certificate) {
		t.Fatal("clearing the secret credential changed the detached public certificate")
	}
}

func TestSPSigningCertificateUsesHalfOpenValidity(t *testing.T) {
	key := spCredentialRSAKey(t, 2048)
	privateDER := spCredentialPKCS8(t, key)
	defer clear(privateDER)
	starts := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	expires := starts.Add(time.Hour)
	certificate := spCredentialCertificate(t, key, &key.PublicKey, starts, expires, x509.KeyUsageDigitalSignature)
	bundle := spCredentialBundle(privateDER, certificate)
	defer clear(bundle)
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
			publicDER, cutoff, err := saml.SPSigningCertificate(t.Context(), bundle, tc.now)
			if tc.ok {
				if err != nil || !cutoff.Equal(expires) || !bytes.Equal(publicDER, certificate) {
					t.Fatal("active credential projection changed the certificate or original expiry")
				}
			} else if err != saml.ErrInvalidInput || publicDER != nil || !cutoff.IsZero() {
				t.Fatal("inactive credential disclosed a certificate or expiry")
			}
		})
	}
}

func TestSPSigningCertificateRejectsInvalidOrCanceledInputWithoutDisclosure(t *testing.T) {
	key := spCredentialRSAKey(t, 2048)
	other := spCredentialRSAKey(t, 2048)
	privateDER := spCredentialPKCS8(t, key)
	defer clear(privateDER)
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	expires := now.Add(time.Hour)
	certificate := spCredentialCertificate(t, key, &key.PublicKey, now, expires, x509.KeyUsageDigitalSignature)
	bundle := spCredentialBundle(privateDER, certificate)
	defer clear(bundle)
	mismatched := spCredentialBundle(privateDER, spCredentialCertificate(t, other, &other.PublicKey, now, expires, x509.KeyUsageDigitalSignature))
	defer clear(mismatched)
	wrongUsage := spCredentialBundle(privateDER, spCredentialCertificate(t, key, &key.PublicKey, now, expires, x509.KeyUsageKeyEncipherment))
	defer clear(wrongUsage)
	wrongVersion := bytes.Clone(bundle)
	defer clear(wrongVersion)
	wrongVersion[7] = 2
	trailing := append(bytes.Clone(bundle), 0)
	defer clear(trailing)
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	deadline, stop := context.WithDeadline(t.Context(), time.Unix(1, 0))
	defer stop()
	for _, tc := range []struct {
		name   string
		ctx    context.Context
		bundle []byte
		want   error
	}{
		{name: "nil context", bundle: bundle, want: saml.ErrInvalidInput},
		{name: "canceled", ctx: canceled, bundle: bundle, want: context.Canceled},
		{name: "deadline exceeded", ctx: deadline, bundle: bundle, want: context.DeadlineExceeded},
		{name: "missing bundle", ctx: t.Context(), want: saml.ErrInvalidInput},
		{name: "short header", ctx: t.Context(), bundle: bundle[:15], want: saml.ErrInvalidInput},
		{name: "truncated certificate", ctx: t.Context(), bundle: bundle[:len(bundle)-1], want: saml.ErrInvalidInput},
		{name: "trailing byte", ctx: t.Context(), bundle: trailing, want: saml.ErrInvalidInput},
		{name: "wrong version", ctx: t.Context(), bundle: wrongVersion, want: saml.ErrInvalidInput},
		{name: "oversized bundle", ctx: t.Context(), bundle: make([]byte, 28*1024+1), want: saml.ErrInvalidInput},
		{name: "mismatched key", ctx: t.Context(), bundle: mismatched, want: saml.ErrInvalidInput},
		{name: "encryption only", ctx: t.Context(), bundle: wrongUsage, want: saml.ErrInvalidInput},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := bytes.Clone(tc.bundle)
			defer clear(before)
			publicDER, cutoff, err := saml.SPSigningCertificate(tc.ctx, tc.bundle, now)
			if err != tc.want || publicDER != nil || !cutoff.IsZero() {
				t.Fatal("invalid or canceled credential disclosed a certificate, expiry or unredacted error")
			}
			if !bytes.Equal(tc.bundle, before) {
				t.Fatal("failed projection changed caller-owned credential storage")
			}
		})
	}
}
