package saml_test

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"io"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-sso/saml"
)

// OASIS Bindings §§3.4.3, 3.4.4.1 and RFC 6931 §2.3.10.
func TestSignedAuthenticationRedirect(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	config := saml.AuthnRedirectConfig{
		SPEntityID:           "HTTPS://identity.example/saml2/service%2fID?profile=exact",
		AssertionConsumerURL: "https://identity.example/saml2/test/acs",
		IdentityProviderURL:  "https://idp.example/sso%2Fprimary?connection=partners%2Fwest",
	}
	profile, err := saml.NewAuthnRedirectProfile(config)
	if err != nil {
		t.Fatal(err)
	}
	issued := time.Date(2026, 11, 23, 4, 5, 7, 0, time.UTC)

	for _, tc := range []struct{ name, relay string }{
		{name: "absent"},
		{name: "present at the limit", relay: strings.Repeat("A", 80)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := saml.AuthnRequest{ID: "_issued_request-7241", IssuedAt: issued, RelayState: tc.relay}
			result, err := profile.Redirect(t.Context(), request, key)
			if err != nil {
				t.Fatal(err)
			}
			redirect, err := result.URL()
			if err != nil {
				t.Fatal(err)
			}
			const installedQuery = "connection=partners%2Fwest&"
			if redirect.Scheme != "https" || redirect.Host != "idp.example" || redirect.EscapedPath() != "/sso%2Fprimary" || !strings.HasPrefix(redirect.RawQuery, installedQuery) {
				t.Fatal("did not preserve the registered IdP endpoint and fixed query")
			}
			wireMessage := strings.TrimPrefix(redirect.RawQuery, installedQuery)
			signed, encodedSignature, ok := strings.Cut(wireMessage, "&Signature=")
			if !ok || strings.Contains(encodedSignature, "&") {
				t.Fatal("signature is missing or is not the last parameter")
			}
			encodedRequest, signedTail, ok := strings.Cut(strings.TrimPrefix(signed, "SAMLRequest="), "&")
			const sigAlg = "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1"
			wantTail := "SigAlg=" + url.QueryEscape(sigAlg)
			if tc.relay != "" {
				wantTail = "RelayState=" + tc.relay + "&" + wantTail
			}
			if !ok || !strings.HasPrefix(signed, "SAMLRequest=") || signedTail != wantTail {
				t.Fatal("signature input does not match the selected binding")
			}
			signature := decodeRedirectField(t, encodedSignature)
			digest := sha256.Sum256([]byte(signed))
			options := &rsa.PSSOptions{SaltLength: sha256.Size, Hash: crypto.SHA256}
			if err := rsa.VerifyPSS(&key.PublicKey, crypto.SHA256, digest[:], signature, options); err != nil {
				t.Fatal("exact encoded query signature did not verify with fixed PSS parameters")
			}
			reader := flate.NewReader(bytes.NewReader(decodeRedirectField(t, encodedRequest)))
			defer reader.Close()
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
			if err := xml.NewDecoder(io.LimitReader(reader, 4096)).Decode(&document); err != nil {
				t.Fatal(err)
			}
			if document.ID != request.ID || document.Version != "2.0" || document.IssueTime != "2026-11-23T04:05:07Z" ||
				document.Destination != config.IdentityProviderURL || document.Consumer != config.AssertionConsumerURL ||
				document.Binding != "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" || document.Issuer != config.SPEntityID {
				t.Fatalf("unexpected AuthnRequest: %+v", document)
			}
		})
	}
}

func TestAuthnRedirectRejectsInvalidConfiguration(t *testing.T) {
	for _, destination := range []string{
		"http://idp.example/sso", "https://user@idp.example/sso", "https://idp.example/sso#extra",
		"https://idp.example/sso?SAMLRequest=fixed", "https://idp.example/sso?%53igAlg=fixed",
	} {
		if _, err := saml.NewAuthnRedirectProfile(saml.AuthnRedirectConfig{
			SPEntityID: "https://identity.example/saml2/service", AssertionConsumerURL: "https://identity.example/saml2/test/acs", IdentityProviderURL: destination,
		}); err == nil {
			t.Errorf("accepted unsupported provider URL %q", destination)
		}
	}
}

func TestAuthnRedirectRejectsInvalidOriginalRequest(t *testing.T) {
	profile, err := saml.NewAuthnRedirectProfile(saml.AuthnRedirectConfig{
		SPEntityID: "https://identity.example/saml2/service", AssertionConsumerURL: "https://identity.example/saml2/test/acs",
		IdentityProviderURL: "https://idp.example/sso",
	})
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	issued := time.Date(2026, 11, 23, 4, 5, 7, 0, time.UTC)
	for _, request := range []saml.AuthnRequest{
		{ID: "_valid", IssuedAt: issued, RelayState: strings.Repeat("A", 81)},
		{ID: "_valid", IssuedAt: issued, RelayState: "application=state"},
		{ID: "1invalid-xml-id", IssuedAt: issued},
		{ID: "_valid"},
	} {
		result, err := profile.Redirect(t.Context(), request, key)
		if err == nil {
			t.Fatal("issued a redirect without a valid original request")
		}
		if _, err := result.URL(); err == nil {
			t.Fatal("denial returned a usable redirect")
		}
	}
}

func TestAuthnRedirectRejectsAnIncompatibleSigner(t *testing.T) {
	profile, err := saml.NewAuthnRedirectProfile(saml.AuthnRedirectConfig{
		SPEntityID: "https://identity.example/saml2/service", AssertionConsumerURL: "https://identity.example/saml2/test/acs",
		IdentityProviderURL: "https://idp.example/sso",
	})
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	request := saml.AuthnRequest{ID: "_issued", IssuedAt: time.Date(2026, 11, 23, 4, 5, 7, 0, time.UTC)}
	result, err := profile.Redirect(t.Context(), request, incompatiblePSSSigner{key})
	if !errors.Is(err, saml.ErrSigning) {
		t.Fatalf("invalid signer result: %v", err)
	}
	if _, err := result.URL(); err == nil {
		t.Fatal("disclosed a redirect without a compliant signature")
	}
}

type incompatiblePSSSigner struct{ *rsa.PrivateKey }

func (s incompatiblePSSSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// A compatibility layer configured for a different profile must not be
	// able to make the adapter accept its parameters as the fixed baseline.
	pss := opts.(*rsa.PSSOptions)
	pss.SaltLength = 20
	return s.PrivateKey.Sign(r, digest, pss)
}

func decodeRedirectField(t *testing.T, encoded string) []byte {
	t.Helper()
	value, err := url.QueryUnescape(encoded)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
