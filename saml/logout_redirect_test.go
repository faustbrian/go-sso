package saml_test

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-sso/saml"
)

// Core §§3.2.1, 3.7.1; Profiles §4.4.4.1; Bindings §§3.4.3,
// 3.4.4.1; RFC 6931 §2.3.10. This is only a signed wire message, not a
// statement that either the local or remote session was revoked.
func TestLogoutRedirectPreservesOriginalCorrelatedRequest(t *testing.T) {
	key := spCredentialRSAKey(t, 2048)
	config := logoutRedirectConfig()
	profile, err := saml.NewLogoutRedirectProfile(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, format, relay string }{
		{name: "persistent without relay", format: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"},
		{name: "email with relay at wire limit", format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", relay: strings.Repeat("A", 80)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := logoutRedirectRequest()
			request.NameID.SubjectFormat, request.RelayState = tc.format, tc.relay
			result, err := profile.Redirect(t.Context(), request, key)
			if err != nil {
				t.Fatal(err)
			}
			assertLogoutRedirectWire(t, result, config, request, &key.PublicKey)
		})
	}
	request := logoutRedirectRequest()
	request.NameID.NameQualifier, request.NameID.SPNameQualifier = "", ""
	request.NameID.Value = strings.Repeat("N", 512)
	request.SessionIndex = strings.Repeat("S", 2048)
	result, err := profile.Redirect(t.Context(), request, key)
	if err != nil {
		t.Fatal("rejected supported boundary sizes or absent optional qualifiers")
	}
	assertLogoutRedirectWire(t, result, config, request, &key.PublicKey)
}

func TestLogoutRedirectRejectsInvalidConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*saml.LogoutRedirectConfig)
	}{
		{name: "absent SP", edit: func(c *saml.LogoutRedirectConfig) { c.SPEntityID = "" }},
		{name: "absent IdP", edit: func(c *saml.LogoutRedirectConfig) { c.IdentityProviderEntityID = "" }},
		{name: "non-HTTPS IdP entity", edit: func(c *saml.LogoutRedirectConfig) { c.IdentityProviderEntityID = "http://idp.example/entity" }},
		{name: "oversized entity", edit: func(c *saml.LogoutRedirectConfig) { c.IdentityProviderEntityID += strings.Repeat("I", 1024) }},
		{name: "insecure endpoint", edit: func(c *saml.LogoutRedirectConfig) { c.IdentityProviderURL = "http://idp.example/logout" }},
		{name: "endpoint userinfo", edit: func(c *saml.LogoutRedirectConfig) { c.IdentityProviderURL = "https://user@idp.example/logout" }},
		{name: "endpoint fragment", edit: func(c *saml.LogoutRedirectConfig) { c.IdentityProviderURL += "#fragment" }},
		{name: "oversized endpoint", edit: func(c *saml.LogoutRedirectConfig) { c.IdentityProviderURL += strings.Repeat("Q", 2048) }},
		{name: "malformed query", edit: func(c *saml.LogoutRedirectConfig) { c.IdentityProviderURL = "https://idp.example/logout?fixed=%ZZ" }},
		{name: "request collision", edit: func(c *saml.LogoutRedirectConfig) { c.IdentityProviderURL += "&SAMLRequest=fixed" }},
		{name: "response collision", edit: func(c *saml.LogoutRedirectConfig) { c.IdentityProviderURL += "&SAMLResponse=fixed" }},
		{name: "relay collision", edit: func(c *saml.LogoutRedirectConfig) { c.IdentityProviderURL += "&RelayState=fixed" }},
		{name: "encoded algorithm collision", edit: func(c *saml.LogoutRedirectConfig) { c.IdentityProviderURL += "&%53igAlg=fixed" }},
		{name: "signature collision", edit: func(c *saml.LogoutRedirectConfig) { c.IdentityProviderURL += "&signature=fixed" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := logoutRedirectConfig()
			tc.edit(&config)
			profile, err := saml.NewLogoutRedirectProfile(config)
			if !errors.Is(err, saml.ErrInvalidInput) {
				t.Fatal("accepted an invalid registered configuration")
			}
			if result, err := profile.Redirect(t.Context(), logoutRedirectRequest(), nil); err == nil {
				t.Fatal("invalid profile rendered a redirect", result)
			}
		})
	}
}

// Core §§2.2.2, 2.2.3, 3.7.1 and Profiles §4.4.4.1: this outbound
// session-participant request must carry its authenticated SessionIndex.
// That requirement does not select policy for inbound IdP LogoutRequests.
func TestLogoutRedirectRejectsInvalidCorrelatedRequest(t *testing.T) {
	key := spCredentialRSAKey(t, 2048)
	profile := newLogoutRedirectProfile(t)
	for _, tc := range []struct {
		name string
		edit func(*saml.LogoutRequest)
	}{
		{name: "absent ID", edit: func(r *saml.LogoutRequest) { r.ID = "" }},
		{name: "invalid ID", edit: func(r *saml.LogoutRequest) { r.ID = "1invalid" }},
		{name: "oversized ID", edit: func(r *saml.LogoutRequest) { r.ID = strings.Repeat("I", 2049) }},
		{name: "zero issue time", edit: func(r *saml.LogoutRequest) { r.IssuedAt = time.Time{} }},
		{name: "unrepresentable issue time", edit: func(r *saml.LogoutRequest) { r.IssuedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) }},
		{name: "absent NameID", edit: func(r *saml.LogoutRequest) { r.NameID.Value = "" }},
		{name: "whitespace NameID", edit: func(r *saml.LogoutRequest) { r.NameID.Value = "  " }},
		{name: "oversized NameID", edit: func(r *saml.LogoutRequest) { r.NameID.Value = strings.Repeat("N", 513) }},
		{name: "invalid UTF-8 NameID", edit: func(r *saml.LogoutRequest) { r.NameID.Value = "bad\xff" }},
		{name: "control NameID", edit: func(r *saml.LogoutRequest) { r.NameID.Value = "bad\nsubject" }},
		{name: "invalid XML NameID", edit: func(r *saml.LogoutRequest) { r.NameID.Value = "bad\ufffe" }},
		{name: "absent format", edit: func(r *saml.LogoutRequest) { r.NameID.SubjectFormat = "" }},
		{name: "unsupported format", edit: func(r *saml.LogoutRequest) {
			r.NameID.SubjectFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
		}},
		{name: "wrong IdP qualifier", edit: func(r *saml.LogoutRequest) { r.NameID.NameQualifier = "https://other.example/entity" }},
		{name: "normalized IdP qualifier", edit: func(r *saml.LogoutRequest) { r.NameID.NameQualifier = strings.ToLower(r.NameID.NameQualifier) }},
		{name: "wrong SP qualifier", edit: func(r *saml.LogoutRequest) { r.NameID.SPNameQualifier = "https://other.example/entity" }},
		{name: "absent SessionIndex", edit: func(r *saml.LogoutRequest) { r.SessionIndex = "" }},
		{name: "oversized SessionIndex", edit: func(r *saml.LogoutRequest) { r.SessionIndex = strings.Repeat("S", 2049) }},
		{name: "control SessionIndex", edit: func(r *saml.LogoutRequest) { r.SessionIndex = "bad\tsession" }},
		{name: "invalid UTF-8 SessionIndex", edit: func(r *saml.LogoutRequest) { r.SessionIndex = "bad\xff" }},
		{name: "invalid XML SessionIndex", edit: func(r *saml.LogoutRequest) { r.SessionIndex = "bad\uffff" }},
		{name: "oversized relay", edit: func(r *saml.LogoutRequest) { r.RelayState = strings.Repeat("A", 81) }},
		{name: "raw state relay", edit: func(r *saml.LogoutRequest) { r.RelayState = "return=https://application.example" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := logoutRedirectRequest()
			tc.edit(&request)
			result, err := profile.Redirect(t.Context(), request, key)
			assertDeniedLogoutRedirect(t, result, err, saml.ErrInvalidInput)
		})
	}
}

func TestLogoutRedirectChecksSigningAndCancellationBeforeDisclosure(t *testing.T) {
	key := spCredentialRSAKey(t, 2048)
	profile := newLogoutRedirectProfile(t)
	request := logoutRedirectRequest()
	var zeroProfile saml.LogoutRedirectProfile
	result, err := zeroProfile.Redirect(t.Context(), request, key)
	assertDeniedLogoutRedirect(t, result, err, saml.ErrInvalidInput)
	result, err = profile.Redirect(nil, request, key)
	assertDeniedLogoutRedirect(t, result, err, saml.ErrInvalidInput)
	result, err = profile.Redirect(t.Context(), request, nil)
	assertDeniedLogoutRedirect(t, result, err, saml.ErrInvalidInput)
	var nilKey *rsa.PrivateKey
	result, err = profile.Redirect(t.Context(), request, nilKey)
	assertDeniedLogoutRedirect(t, result, err, saml.ErrInvalidInput)
	result, err = profile.Redirect(t.Context(), request, incompatiblePSSSigner{key})
	assertDeniedLogoutRedirect(t, result, err, saml.ErrSigning)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	result, err = profile.Redirect(ctx, request, key)
	assertDeniedLogoutRedirect(t, result, err, context.Canceled)
	ctx, cancel = context.WithCancel(t.Context())
	defer cancel()
	result, err = profile.Redirect(ctx, request, logoutCancelSigner{key, cancel})
	assertDeniedLogoutRedirect(t, result, err, context.Canceled)
}

func TestLogoutRedirectWithSPSigningCredentialPreservesRequestAndCutoff(t *testing.T) {
	key := spCredentialRSAKey(t, 2048)
	privateDER := spCredentialPKCS8(t, key)
	defer clear(privateDER)
	now := logoutRedirectRequest().IssuedAt.Truncate(time.Second)
	expires := now.Add(time.Hour)
	certificate := spCredentialCertificate(t, key, &key.PublicKey, now, expires, x509.KeyUsageDigitalSignature)
	bundle, err := saml.EncodeSPSigningCredential(t.Context(), privateDER, certificate, now)
	if err != nil {
		t.Fatal("could not encode ephemeral signing credential")
	}
	defer clear(bundle)
	before := bytes.Clone(bundle)
	defer clear(before)
	profile := newLogoutRedirectProfile(t)
	for _, relay := range []string{"", strings.Repeat("A", 80)} {
		request := logoutRedirectRequest()
		request.RelayState = relay
		result, cutoff, err := profile.RedirectWithSPSigningCredential(t.Context(), request, bundle, now)
		if err != nil || !cutoff.Equal(expires) || !bytes.Equal(bundle, before) {
			t.Fatal("native credential signing changed original cutoff or caller storage")
		}
		assertLogoutRedirectWire(t, result, logoutRedirectConfig(), request, &key.PublicKey)
	}
	for _, tc := range []struct {
		name   string
		bundle []byte
		now    time.Time
	}{
		{name: "malformed credential", bundle: []byte("not a credential"), now: now},
		{name: "before activation", bundle: bundle, now: now.Add(-time.Nanosecond)},
		{name: "exclusive expiry", bundle: bundle, now: expires},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, cutoff, err := profile.RedirectWithSPSigningCredential(t.Context(), logoutRedirectRequest(), tc.bundle, tc.now)
			assertDeniedLogoutRedirect(t, result, err, saml.ErrInvalidInput)
			if !cutoff.IsZero() {
				t.Fatal("failure disclosed a certificate cutoff")
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	result, cutoff, err := profile.RedirectWithSPSigningCredential(ctx, logoutRedirectRequest(), bundle, now)
	assertDeniedLogoutRedirect(t, result, err, context.Canceled)
	if !cutoff.IsZero() {
		t.Fatal("cancellation disclosed a certificate cutoff")
	}
}

func TestLogoutRedirectRedactsImplicitSerialization(t *testing.T) {
	key := spCredentialRSAKey(t, 2048)
	request := logoutRedirectRequest()
	result, err := newLogoutRedirectProfile(t).Redirect(t.Context(), request, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []interface {
		MarshalJSON() ([]byte, error)
		MarshalText() ([]byte, error)
		LogValue() slog.Value
	}{request, request.NameID, result} {
		formatted := fmt.Sprintf("%+v %#v", value, value)
		if !strings.Contains(formatted, "redacted") || strings.Contains(formatted, request.NameID.Value) || strings.Contains(formatted, "SAMLRequest=") {
			t.Fatal("implicit formatting disclosed logout data")
		}
		if data, err := json.Marshal(value); err == nil || len(data) != 0 {
			t.Fatal("implicit JSON serialization did not fail closed")
		}
		if data, err := value.MarshalText(); !errors.Is(err, saml.ErrSensitiveSerialization) || data != nil {
			t.Fatal("implicit text serialization did not fail closed")
		}
		if strings.Contains(value.LogValue().String(), request.NameID.Value) || !strings.Contains(value.LogValue().String(), "redacted") {
			t.Fatal("structured logging disclosed logout data")
		}
	}
}

// Core §§2.2.2, 2.2.3, 3.7.1: malformed text must be rejected, never
// normalized into a different signed subject/session. Accepted Unicode must
// survive independent wire decoding byte-for-byte.
func FuzzLogoutRedirectPreservesCorrelatedText(f *testing.F) {
	key := spCredentialRSAKey(f, 2048)
	config := logoutRedirectConfig()
	profile, err := saml.NewLogoutRedirectProfile(config)
	if err != nil {
		f.Fatal(err)
	}
	f.Add("member-042", "session-042", "opaque-handle")
	f.Add("member<&\"é", "session<&\"é", "")
	f.Add("bad\ufffe", "session", "")
	f.Add("member", "bad\xff", "")
	f.Add(strings.Repeat("N", 513), "session", "")
	f.Fuzz(func(t *testing.T, subject, session, relay string) {
		request := logoutRedirectRequest()
		request.NameID.Value, request.SessionIndex, request.RelayState = subject, session, relay
		result, err := profile.Redirect(t.Context(), request, key)
		if err != nil {
			assertDeniedLogoutRedirect(t, result, err, saml.ErrInvalidInput)
			return
		}
		assertLogoutRedirectWire(t, result, config, request, &key.PublicKey)
	})
}

func logoutRedirectConfig() saml.LogoutRedirectConfig {
	return saml.LogoutRedirectConfig{
		SPEntityID:               "HTTPS://identity.example/saml2/service%2fID?profile=exact",
		IdentityProviderEntityID: "HTTPS://idp.example/entity%2fID?profile=exact",
		IdentityProviderURL:      "https://idp.example/logout%2Fprimary?connection=partners%2Fwest&fixed=a+b&fixed=a%20b",
	}
}

func logoutRedirectRequest() saml.LogoutRequest {
	config := logoutRedirectConfig()
	return saml.LogoutRequest{
		ID: "_original_logout-7241", IssuedAt: time.Date(2026, 11, 23, 12, 0, 0, 123, time.FixedZone("source", 7200)),
		NameID:       saml.LogoutNameID{Value: "member<&\"é@example.com", SubjectFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", NameQualifier: config.IdentityProviderEntityID, SPNameQualifier: config.SPEntityID},
		SessionIndex: "session<&\"é-participant", RelayState: "opaque_transaction-7241",
	}
}

func newLogoutRedirectProfile(t *testing.T) saml.LogoutRedirectProfile {
	t.Helper()
	profile, err := saml.NewLogoutRedirectProfile(logoutRedirectConfig())
	if err != nil {
		t.Fatal(err)
	}
	return profile
}

func assertDeniedLogoutRedirect(t *testing.T, result saml.LogoutRedirect, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatal("logout did not return the expected redacted error")
	}
	if _, err := result.URL(); !errors.Is(err, saml.ErrInvalidInput) {
		t.Fatal("failure disclosed a usable logout URL")
	}
}

func assertLogoutRedirectWire(t *testing.T, result saml.LogoutRedirect, config saml.LogoutRedirectConfig, request saml.LogoutRequest, key *rsa.PublicKey) {
	t.Helper()
	destination, err := result.URL()
	if err != nil {
		t.Fatal("logout result did not contain a URL")
	}
	endpoint, err := url.Parse(config.IdentityProviderURL)
	if err != nil {
		t.Fatal(err)
	}
	fixedQuery := endpoint.RawQuery + "&"
	if destination.Scheme != endpoint.Scheme || destination.Host != endpoint.Host || destination.EscapedPath() != endpoint.EscapedPath() || !strings.HasPrefix(destination.RawQuery, fixedQuery) {
		t.Fatal("logout changed the exact registered endpoint")
	}
	signed, encodedSignature, ok := strings.Cut(strings.TrimPrefix(destination.RawQuery, fixedQuery), "&Signature=")
	if !ok || strings.Contains(encodedSignature, "&") {
		t.Fatal("signature was not the final query field")
	}
	encodedRequest, tail, ok := strings.Cut(strings.TrimPrefix(signed, "SAMLRequest="), "&")
	wantTail := "SigAlg=" + url.QueryEscape("http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1")
	if request.RelayState != "" {
		wantTail = "RelayState=" + url.QueryEscape(request.RelayState) + "&" + wantTail
	}
	if !ok || !strings.HasPrefix(signed, "SAMLRequest=") || tail != wantTail {
		t.Fatal("logout did not sign the exact selected raw query sequence")
	}
	digest := sha256.Sum256([]byte(signed))
	if rsa.VerifyPSS(key, crypto.SHA256, digest[:], decodeRedirectField(t, encodedSignature), &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: sha256.Size}) != nil {
		t.Fatal("exact transmitted logout query did not verify with fixed RSA-PSS parameters")
	}
	reader := flate.NewReader(bytes.NewReader(decodeRedirectField(t, encodedRequest)))
	// Bound the independent decoder above the worst-case escaped XML size
	// admitted by the individual input limits; this is not a new wire policy.
	const decodeLimit = 64 * 1024
	documentBytes, readErr := io.ReadAll(io.LimitReader(reader, decodeLimit+1))
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || len(documentBytes) > decodeLimit {
		t.Fatal("logout was not bounded raw DEFLATE")
	}
	var document struct {
		XMLName     xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol LogoutRequest"`
		ID          string   `xml:"ID,attr"`
		Version     string   `xml:"Version,attr"`
		Issued      string   `xml:"IssueInstant,attr"`
		Destination string   `xml:"Destination,attr"`
		Issuer      string   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
		NameID      struct {
			Value           string `xml:",chardata"`
			Format          string `xml:"Format,attr"`
			NameQualifier   string `xml:"NameQualifier,attr"`
			SPNameQualifier string `xml:"SPNameQualifier,attr"`
		} `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
		SessionIndex []string `xml:"urn:oasis:names:tc:SAML:2.0:protocol SessionIndex"`
	}
	if xml.Unmarshal(documentBytes, &document) != nil || document.ID != request.ID || document.Version != "2.0" || document.Issued != request.IssuedAt.UTC().Format(time.RFC3339Nano) || document.Destination != config.IdentityProviderURL || document.Issuer != config.SPEntityID || document.NameID.Value != request.NameID.Value || document.NameID.Format != request.NameID.SubjectFormat || document.NameID.NameQualifier != request.NameID.NameQualifier || document.NameID.SPNameQualifier != request.NameID.SPNameQualifier || len(document.SessionIndex) != 1 || document.SessionIndex[0] != request.SessionIndex {
		t.Fatal("logout did not preserve the original correlated XML fields")
	}
	decoder := xml.NewDecoder(bytes.NewReader(documentBytes))
	var elements []string
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal("logout XML was malformed")
		}
		if start, ok := token.(xml.StartElement); ok {
			elements = append(elements, start.Name.Local)
			allowed := map[string]bool{}
			switch start.Name.Local {
			case "LogoutRequest":
				allowed = map[string]bool{"ID": true, "Version": true, "IssueInstant": true, "Destination": true}
			case "NameID":
				allowed = map[string]bool{"Format": true}
				if request.NameID.NameQualifier != "" {
					allowed["NameQualifier"] = true
				}
				if request.NameID.SPNameQualifier != "" {
					allowed["SPNameQualifier"] = true
				}
			}
			for _, attr := range start.Attr {
				if attr.Name.Local == "xmlns" || attr.Name.Space == "xmlns" {
					continue
				}
				if attr.Name.Space != "" || !allowed[attr.Name.Local] {
					t.Fatal("logout contained an unselected XML attribute")
				}
			}
		}
	}
	if strings.Join(elements, ",") != "LogoutRequest,Issuer,NameID,SessionIndex" {
		t.Fatal("logout contained an unselected message field or binding")
	}
}

type logoutCancelSigner struct {
	*rsa.PrivateKey
	cancel context.CancelFunc
}

func (s logoutCancelSigner) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	signature, err := s.PrivateKey.Sign(random, digest, opts)
	s.cancel()
	return signature, err
}
