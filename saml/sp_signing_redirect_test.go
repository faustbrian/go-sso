package saml_test

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/xml"
	"io"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-sso/saml"
)

func TestAuthnRedirectWithSPSigningCredentialPreservesSignedRequestAndExpiry(t *testing.T) {
	key := spCredentialRSAKey(t, 2048)
	privateDER := spCredentialPKCS8(t, key)
	defer clear(privateDER)
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	expires := now.Add(time.Hour)
	certificate := spCredentialCertificate(t, key, &key.PublicKey, now.Add(-time.Hour), expires, x509.KeyUsageDigitalSignature)
	bundle, err := saml.EncodeSPSigningCredential(t.Context(), privateDER, certificate, now)
	if err != nil {
		t.Fatal("could not encode ephemeral signing credential")
	}
	defer clear(bundle)
	before := bytes.Clone(bundle)
	defer clear(before)
	config := saml.AuthnRedirectConfig{
		SPEntityID:           "HTTPS://identity.example/saml2/service%2fID?profile=exact",
		AssertionConsumerURL: "https://identity.example/saml2/test/acs",
		IdentityProviderURL:  "https://idp.example/sso%2Fprimary?connection=partners%2Fwest",
	}
	profile, err := saml.NewAuthnRedirectProfile(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, relay := range []string{"", strings.Repeat("A", 80)} {
		request := saml.AuthnRequest{ID: "_original_request-7241", IssuedAt: now.Add(-time.Minute), RelayState: relay}
		result, validUntil, err := profile.RedirectWithSPSigningCredential(t.Context(), request, bundle, now)
		if err != nil || !validUntil.Equal(expires) {
			t.Fatal("signing failed or changed the original exclusive certificate expiry")
		}
		if !bytes.Equal(bundle, before) {
			t.Fatal("signing changed caller-owned credential storage")
		}
		redirect, err := result.URL()
		if err != nil {
			t.Fatal("signing returned an unusable redirect")
		}
		const fixedQuery = "connection=partners%2Fwest&"
		if redirect.Scheme != "https" || redirect.Host != "idp.example" || redirect.EscapedPath() != "/sso%2Fprimary" || !strings.HasPrefix(redirect.RawQuery, fixedQuery) {
			t.Fatal("signing changed the registered provider endpoint")
		}
		signed, encodedSignature, ok := strings.Cut(strings.TrimPrefix(redirect.RawQuery, fixedQuery), "&Signature=")
		if !ok || strings.Contains(encodedSignature, "&") {
			t.Fatal("signature was not the last binding field")
		}
		encodedRequest, signedTail, ok := strings.Cut(strings.TrimPrefix(signed, "SAMLRequest="), "&")
		wantTail := "SigAlg=" + url.QueryEscape("http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1")
		if relay != "" {
			wantTail = "RelayState=" + relay + "&" + wantTail
		}
		if !ok || !strings.HasPrefix(signed, "SAMLRequest=") || signedTail != wantTail {
			t.Fatal("signing did not use the exact selected Redirect binding sequence")
		}
		digest := sha256.Sum256([]byte(signed))
		signature := decodeRedirectField(t, encodedSignature)
		if err := rsa.VerifyPSS(&key.PublicKey, crypto.SHA256, digest[:], signature, &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: sha256.Size}); err != nil {
			t.Fatal("exact Redirect query signature did not verify with the installed certificate key")
		}
		reader := flate.NewReader(bytes.NewReader(decodeRedirectField(t, encodedRequest)))
		var document struct {
			XMLName     xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol AuthnRequest"`
			ID          string   `xml:"ID,attr"`
			Version     string   `xml:"Version,attr"`
			IssueTime   string   `xml:"IssueInstant,attr"`
			Destination string   `xml:"Destination,attr"`
			Consumer    string   `xml:"AssertionConsumerServiceURL,attr"`
			Binding     string   `xml:"ProtocolBinding,attr"`
			Issuer      string   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
		}
		decodeErr := xml.NewDecoder(io.LimitReader(reader, 4096)).Decode(&document)
		closeErr := reader.Close()
		if decodeErr != nil || closeErr != nil {
			t.Fatal("could not decode the signed authentication request")
		}
		if document.ID != request.ID || document.Version != "2.0" || document.IssueTime != "2026-11-23T11:59:00Z" ||
			document.Destination != config.IdentityProviderURL || document.Consumer != config.AssertionConsumerURL ||
			document.Binding != "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" || document.Issuer != config.SPEntityID {
			t.Fatal("signing replaced original request values or the selected SAML profile")
		}
	}
}

func TestAuthnRedirectWithSPSigningCredentialUsesHalfOpenCertificateLifetime(t *testing.T) {
	key := spCredentialRSAKey(t, 2048)
	privateDER := spCredentialPKCS8(t, key)
	defer clear(privateDER)
	starts := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	expires := starts.Add(time.Hour)
	certificate := spCredentialCertificate(t, key, &key.PublicKey, starts, expires, x509.KeyUsageDigitalSignature)
	bundle, err := saml.EncodeSPSigningCredential(t.Context(), privateDER, certificate, starts)
	if err != nil {
		t.Fatal("could not encode ephemeral signing credential")
	}
	defer clear(bundle)
	profile := spSigningRedirectProfile(t)
	request := saml.AuthnRequest{ID: "_original", IssuedAt: starts}
	for _, tc := range []struct {
		name string
		now  time.Time
		ok   bool
	}{
		{name: "before activation", now: starts.Add(-time.Nanosecond)},
		{name: "inclusive activation", now: starts, ok: true},
		{name: "last nanosecond", now: expires.Add(-time.Nanosecond), ok: true},
		{name: "exclusive expiry", now: expires},
		{name: "already expired", now: expires.Add(time.Hour)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, validUntil, err := profile.RedirectWithSPSigningCredential(t.Context(), request, bundle, tc.now)
			if tc.ok {
				if err != nil || !validUntil.Equal(expires) {
					t.Fatal("rejected an active credential or extended its original expiry")
				}
				if _, err := result.URL(); err != nil {
					t.Fatal("active credential did not produce a usable redirect")
				}
			} else if err != saml.ErrInvalidInput || result != (saml.AuthnRedirect{}) || !validUntil.IsZero() {
				t.Fatal("inactive credential returned a redirect, expiry or non-redacted error")
			}
		})
	}
}

func TestAuthnRedirectWithSPSigningCredentialRejectsInvalidOrCanceledInputWithoutDisclosure(t *testing.T) {
	key := spCredentialRSAKey(t, 2048)
	other := spCredentialRSAKey(t, 2048)
	privateDER := spCredentialPKCS8(t, key)
	defer clear(privateDER)
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	certificate := spCredentialCertificate(t, key, &key.PublicKey, now, now.Add(time.Hour), x509.KeyUsageDigitalSignature)
	bundle := spCredentialBundle(privateDER, certificate)
	defer clear(bundle)
	mismatched := spCredentialBundle(privateDER, spCredentialCertificate(t, other, &other.PublicKey, now, now.Add(time.Hour), x509.KeyUsageDigitalSignature))
	defer clear(mismatched)
	wrongUsage := spCredentialBundle(privateDER, spCredentialCertificate(t, key, &key.PublicKey, now, now.Add(time.Hour), x509.KeyUsageKeyEncipherment))
	defer clear(wrongUsage)
	profile := spSigningRedirectProfile(t)
	request := saml.AuthnRequest{ID: "_original", IssuedAt: now}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	expired, stop := context.WithDeadline(t.Context(), time.Unix(1, 0))
	defer stop()
	for _, tc := range []struct {
		name    string
		ctx     context.Context
		profile saml.AuthnRedirectProfile
		request saml.AuthnRequest
		bundle  []byte
		now     time.Time
		want    error
	}{
		{name: "nil context", profile: profile, request: request, bundle: bundle, now: now, want: saml.ErrInvalidInput},
		{name: "canceled", ctx: canceled, profile: profile, request: request, bundle: bundle, now: now, want: context.Canceled},
		{name: "deadline exceeded", ctx: expired, profile: profile, request: request, bundle: bundle, now: now, want: context.DeadlineExceeded},
		{name: "zero profile", ctx: t.Context(), request: request, bundle: bundle, now: now, want: saml.ErrInvalidInput},
		{name: "zero request", ctx: t.Context(), profile: profile, bundle: bundle, now: now, want: saml.ErrInvalidInput},
		{name: "zero clock", ctx: t.Context(), profile: profile, request: request, bundle: bundle, want: saml.ErrInvalidInput},
		{name: "missing bundle", ctx: t.Context(), profile: profile, request: request, now: now, want: saml.ErrInvalidInput},
		{name: "truncated bundle", ctx: t.Context(), profile: profile, request: request, bundle: bundle[:len(bundle)-1], now: now, want: saml.ErrInvalidInput},
		{name: "mismatched certificate", ctx: t.Context(), profile: profile, request: request, bundle: mismatched, now: now, want: saml.ErrInvalidInput},
		{name: "encryption only", ctx: t.Context(), profile: profile, request: request, bundle: wrongUsage, now: now, want: saml.ErrInvalidInput},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := bytes.Clone(tc.bundle)
			defer clear(before)
			result, validUntil, err := tc.profile.RedirectWithSPSigningCredential(tc.ctx, tc.request, tc.bundle, tc.now)
			if err != tc.want || result != (saml.AuthnRedirect{}) || !validUntil.IsZero() {
				t.Fatal("invalid or canceled input returned a redirect, expiry or non-redacted error")
			}
			if !bytes.Equal(tc.bundle, before) {
				t.Fatal("failure changed caller-owned credential storage")
			}
		})
	}
}

func spSigningRedirectProfile(t *testing.T) saml.AuthnRedirectProfile {
	t.Helper()
	profile, err := saml.NewAuthnRedirectProfile(saml.AuthnRedirectConfig{
		SPEntityID: "https://identity.example/saml2/service", AssertionConsumerURL: "https://identity.example/saml2/test/acs",
		IdentityProviderURL: "https://idp.example/sso",
	})
	if err != nil {
		t.Fatal(err)
	}
	return profile
}
