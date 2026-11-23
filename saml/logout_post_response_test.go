package saml_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-sso/saml"
)

const (
	postResponseProtocol  = "urn:oasis:names:tc:SAML:2.0:protocol"
	postResponseAssertion = "urn:oasis:names:tc:SAML:2.0:assertion"
	postResponseSignature = "http://www.w3.org/2000/09/xmldsig#"
	postResponseExclusive = "http://www.w3.org/2001/10/xml-exc-c14n#"
	postResponseSHA256    = "http://www.w3.org/2001/04/xmlenc#sha256"
	postResponseEnveloped = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
)

// Core §§3.2.2, 3.2.2.2, 3.7.2, 3.7.3.2; Bindings §§3.5.4,
// 3.5.5.2; Profiles §§4.4.3.4, 4.4.4.2: emit one signed status response,
// not an assertion that local or remote revocation happened.
func TestLogoutPOSTResponseSignsExactOriginalStatusAndDestination(t *testing.T) {
	key := spCredentialRSAKey(t, 2048)
	config := postResponseConfig()
	profile := newPostResponseProfile(t, config)
	for _, code := range []saml.LogoutStatusCode{saml.LogoutStatusSuccess, saml.LogoutStatusRequester, saml.LogoutStatusResponder, saml.LogoutStatusVersionMismatch} {
		for _, subcode := range []saml.LogoutStatusCode{"", saml.LogoutStatusPartialLogout, saml.LogoutStatusUnknownPrincipal, saml.LogoutStatusRequestDenied, saml.LogoutStatusUnsupportedBinding} {
			if code == saml.LogoutStatusSuccess && subcode != "" && subcode != saml.LogoutStatusPartialLogout {
				continue
			}
			response := postResponseInput()
			response.Status = saml.LogoutPOSTStatus{Code: code, Subcode: subcode}
			result, err := profile.Sign(t.Context(), response, key)
			if err != nil {
				t.Fatal("selected signed response rejected", err)
			}
			assertPostResponseWire(t, result, config, response, &key.PublicKey)
		}
	}
	response := postResponseInput()
	response.ID, response.InResponseTo = strings.Repeat("I", 2048), strings.Repeat("R", 2048)
	result, err := profile.Sign(t.Context(), response, key)
	if err != nil {
		t.Fatal("bounded canonical IDs rejected", err)
	}
	assertPostResponseWire(t, result, config, response, &key.PublicKey)
}

func TestLogoutPOSTResponseRejectsInvalidConfigurationAndCorrelation(t *testing.T) {
	key := spCredentialRSAKey(t, 2048)
	for _, edit := range []func(*saml.LogoutPOSTResponseConfig){
		func(c *saml.LogoutPOSTResponseConfig) { c.SPEntityID = "" },
		func(c *saml.LogoutPOSTResponseConfig) { c.IdentityProviderURL = "http://idp.example/logout" },
		func(c *saml.LogoutPOSTResponseConfig) { c.IdentityProviderURL = "https://user@idp.example/logout" },
		func(c *saml.LogoutPOSTResponseConfig) { c.IdentityProviderURL += "#fragment" },
		func(c *saml.LogoutPOSTResponseConfig) { c.IdentityProviderURL += "&SAMLResponse=fixed" },
		func(c *saml.LogoutPOSTResponseConfig) { c.IdentityProviderURL += "&RelayState=fixed" },
		func(c *saml.LogoutPOSTResponseConfig) { c.IdentityProviderURL += "&SigAlg=fixed" },
		func(c *saml.LogoutPOSTResponseConfig) { c.IdentityProviderURL += "&Signature=fixed" },
		func(c *saml.LogoutPOSTResponseConfig) { c.IdentityProviderURL += "&bad=%ZZ" },
		func(c *saml.LogoutPOSTResponseConfig) { c.IdentityProviderURL += strings.Repeat("x", 2048) },
	} {
		config := postResponseConfig()
		edit(&config)
		profile, err := saml.NewLogoutPOSTResponseProfile(config)
		if !errors.Is(err, saml.ErrInvalidInput) {
			t.Fatal("invalid installed endpoint accepted")
		}
		result, err := profile.Sign(t.Context(), postResponseInput(), key)
		assertPostResponseDenied(t, result, err, saml.ErrInvalidInput)
	}
	profile := newPostResponseProfile(t, postResponseConfig())
	for _, edit := range []func(*saml.LogoutResponse){
		func(r *saml.LogoutResponse) { r.ID = "" }, func(r *saml.LogoutResponse) { r.ID = "bad id" },
		func(r *saml.LogoutResponse) { r.ID = strings.Repeat("x", 2049) },
		func(r *saml.LogoutResponse) { r.InResponseTo = "" }, func(r *saml.LogoutResponse) { r.InResponseTo = "1bad" },
		func(r *saml.LogoutResponse) { r.InResponseTo = strings.Repeat("x", 2049) },
		func(r *saml.LogoutResponse) { r.IssuedAt = time.Time{} },
		func(r *saml.LogoutResponse) { r.IssuedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) },
		func(r *saml.LogoutResponse) { r.Status.Code = "" },
		func(r *saml.LogoutResponse) { r.Status.Code = "urn:unselected" },
		func(r *saml.LogoutResponse) { r.Status.Subcode = "urn:unselected" },
		func(r *saml.LogoutResponse) { r.Status.Subcode = saml.LogoutStatusUnknownPrincipal },
	} {
		response := postResponseInput()
		edit(&response)
		result, err := profile.Sign(t.Context(), response, key)
		assertPostResponseDenied(t, result, err, saml.ErrInvalidInput)
	}
}

func TestLogoutPOSTResponseRejectsInvalidUTF8WithoutRewritingIDs(t *testing.T) {
	profile := newPostResponseProfile(t, postResponseConfig())
	key := spCredentialRSAKey(t, 2048)
	for _, tc := range []struct {
		name string
		set  func(*saml.LogoutResponse)
	}{
		{"ID", func(r *saml.LogoutResponse) { r.ID = "_\xff" }},
		{"InResponseTo", func(r *saml.LogoutResponse) { r.InResponseTo = "_\xff" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := postResponseInput()
			tc.set(&response)
			result, err := profile.Sign(t.Context(), response, key)
			assertPostResponseDenied(t, result, err, saml.ErrInvalidInput)
		})
	}
}

// XML Signature 1.1 §§3.1, 4.4.3, 6.4, 6.6.4; RFC 6931 §2.3.10:
// a borrowed signer cannot change the fixed PSS salt or mutable digest/options.
func TestLogoutPOSTResponseRejectsNoncompliantSignerAndCancellation(t *testing.T) {
	profile := newPostResponseProfile(t, postResponseConfig())
	key := spCredentialRSAKey(t, 2048)
	response := postResponseInput()
	var nilKey *rsa.PrivateKey
	for _, signer := range []crypto.Signer{nil, nilKey} {
		result, err := profile.Sign(t.Context(), response, signer)
		assertPostResponseDenied(t, result, err, saml.ErrInvalidInput)
	}
	result, err := profile.Sign(t.Context(), response, incompatiblePSSSigner{key})
	assertPostResponseDenied(t, result, err, saml.ErrSigning)
	result, err = profile.Sign(nil, response, key)
	assertPostResponseDenied(t, result, err, saml.ErrInvalidInput)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	result, err = profile.Sign(ctx, response, key)
	assertPostResponseDenied(t, result, err, context.Canceled)
	ctx, cancel = context.WithCancel(t.Context())
	defer cancel()
	result, err = profile.Sign(ctx, response, logoutCancelSigner{key, cancel})
	assertPostResponseDenied(t, result, err, context.Canceled)
	result, err = profile.Sign(t.Context(), response, postResponseMutatingSigner{key})
	assertPostResponseDenied(t, result, err, saml.ErrSigning)
	result, err = profile.Sign(t.Context(), response, postResponseFailingSigner{key})
	assertPostResponseDenied(t, result, err, saml.ErrSigning)
}

func TestLogoutPOSTResponseNativeCredentialPreservesOriginalCutoff(t *testing.T) {
	key := spCredentialRSAKey(t, 2048)
	private := spCredentialPKCS8(t, key)
	defer clear(private)
	now := postResponseInput().IssuedAt.Truncate(time.Second)
	expires := now.Add(time.Hour)
	certificate := spCredentialCertificate(t, key, &key.PublicKey, now, expires, x509.KeyUsageDigitalSignature)
	bundle, err := saml.EncodeSPSigningCredential(t.Context(), private, certificate, now)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(bundle)
	before := bytes.Clone(bundle)
	defer clear(before)
	config := postResponseConfig()
	profile := newPostResponseProfile(t, config)
	response := postResponseInput()
	response.Status = saml.LogoutPOSTStatus{Code: saml.LogoutStatusSuccess, Subcode: saml.LogoutStatusPartialLogout}
	for _, at := range []time.Time{now, expires.Add(-time.Nanosecond)} {
		result, cutoff, err := profile.SignWithSPSigningCredential(t.Context(), response, bundle, at)
		if err != nil || !cutoff.Equal(expires) || !bytes.Equal(bundle, before) {
			t.Fatal("original certificate lifetime/storage changed")
		}
		assertPostResponseWire(t, result, config, response, &key.PublicKey)
	}
	for _, at := range []time.Time{now.Add(-time.Nanosecond), expires} {
		result, cutoff, err := profile.SignWithSPSigningCredential(t.Context(), response, bundle, at)
		assertPostResponseDenied(t, result, err, saml.ErrInvalidInput)
		if !cutoff.IsZero() {
			t.Fatal("inactive certificate disclosed a cutoff")
		}
	}
	result, cutoff, err := profile.SignWithSPSigningCredential(t.Context(), response, []byte("invalid-private-bundle"), now)
	assertPostResponseDenied(t, result, err, saml.ErrInvalidInput)
	if !cutoff.IsZero() {
		t.Fatal("invalid credential disclosed cutoff")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	result, cutoff, err = profile.SignWithSPSigningCredential(ctx, response, bundle, now)
	assertPostResponseDenied(t, result, err, context.Canceled)
	if !cutoff.IsZero() {
		t.Fatal("cancellation disclosed cutoff")
	}
}

// Bindings §3.5.3: the transport owns RelayState independently. This value
// contains only the exact destination and SAMLResponse, with explicit release.
func TestLogoutPOSTResponseRedactsExplicitWireFields(t *testing.T) {
	key := spCredentialRSAKey(t, 2048)
	response := postResponseInput()
	result, err := newPostResponseProfile(t, postResponseConfig()).Sign(t.Context(), response, key)
	if err != nil {
		t.Fatal(err)
	}
	fields, err := result.Fields()
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []interface {
		MarshalJSON() ([]byte, error)
		MarshalText() ([]byte, error)
		LogValue() slog.Value
	}{response, result, fields} {
		if text := fmt.Sprintf("%+v %#v", value, value); !strings.Contains(text, "redacted") || strings.Contains(text, response.ID) || strings.Contains(text, fields.SAMLResponse) {
			t.Fatal("implicit response formatting escaped")
		}
		if data, err := json.Marshal(value); !errors.Is(err, saml.ErrSensitiveSerialization) || len(data) != 0 {
			t.Fatal("implicit JSON escaped")
		}
		if data, err := value.MarshalText(); !errors.Is(err, saml.ErrSensitiveSerialization) || data != nil {
			t.Fatal("implicit text escaped")
		}
		if text := value.LogValue().String(); !strings.Contains(text, "redacted") || strings.Contains(text, response.ID) {
			t.Fatal("structured logging escaped")
		}
	}
	if _, err := (saml.SignedLogoutPOSTResponse{}).Fields(); !errors.Is(err, saml.ErrInvalidInput) {
		t.Fatal("zero wire result disclosed")
	}
}

// This oracle builds canonical root/SignedInfo bytes independently, parses XML
// with encoding/xml and verifies fixed PSS through crypto/rsa. It does not call
// the production XML verifier or canonicalizer to establish the signature.
func assertPostResponseWire(t *testing.T, result saml.SignedLogoutPOSTResponse, config saml.LogoutPOSTResponseConfig, response saml.LogoutResponse, key *rsa.PublicKey) {
	t.Helper()
	fields, err := result.Fields()
	if err != nil {
		t.Fatal(err)
	}
	if fields.Destination != config.IdentityProviderURL {
		t.Fatal("registered response endpoint changed")
	}
	wire, err := base64.StdEncoding.Strict().DecodeString(fields.SAMLResponse)
	if err != nil {
		t.Fatal("response is not plain Base64 XML")
	}
	var document struct {
		XMLName      xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol LogoutResponse"`
		ID           string   `xml:"ID,attr"`
		InResponseTo string   `xml:"InResponseTo,attr"`
		IssueInstant string   `xml:"IssueInstant,attr"`
		Destination  string   `xml:"Destination,attr"`
		Version      string   `xml:"Version,attr"`
		Issuer       string   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
		Signature    struct {
			SignedInfo struct {
				Canonicalization struct {
					Algorithm string `xml:"Algorithm,attr"`
				} `xml:"CanonicalizationMethod"`
				Method struct {
					Algorithm string `xml:"Algorithm,attr"`
				} `xml:"SignatureMethod"`
				Reference struct {
					URI        string `xml:"URI,attr"`
					Transforms []struct {
						Algorithm string `xml:"Algorithm,attr"`
					} `xml:"Transforms>Transform"`
					DigestMethod struct {
						Algorithm string `xml:"Algorithm,attr"`
					} `xml:"DigestMethod"`
					Digest string `xml:"DigestValue"`
				} `xml:"Reference"`
			} `xml:"SignedInfo"`
			Value string `xml:"SignatureValue"`
		} `xml:"http://www.w3.org/2000/09/xmldsig# Signature"`
		Status struct {
			Code struct {
				Value   string `xml:"Value,attr"`
				Subcode *struct {
					Value string `xml:"Value,attr"`
				} `xml:"StatusCode"`
			} `xml:"StatusCode"`
		} `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
		Extra []struct{ XMLName xml.Name } `xml:",any"`
	}
	if err := xml.Unmarshal(wire, &document); err != nil {
		t.Fatal("XML oracle rejected response", err)
	}
	if document.ID != response.ID || document.InResponseTo != response.InResponseTo || document.Version != "2.0" || document.IssueInstant != response.IssuedAt.UTC().Format(time.RFC3339Nano) || document.Destination != config.IdentityProviderURL || document.Issuer != config.SPEntityID || len(document.Extra) != 0 {
		t.Fatal("signed response identity/correlation shape changed")
	}
	if document.Status.Code.Value != string(response.Status.Code) || (document.Status.Code.Subcode != nil) != (response.Status.Subcode != "") {
		t.Fatal("signed status changed")
	}
	if document.Status.Code.Subcode != nil && document.Status.Code.Subcode.Value != string(response.Status.Subcode) {
		t.Fatal("signed subordinate status changed")
	}
	info := document.Signature.SignedInfo
	reference := info.Reference
	if info.Canonicalization.Algorithm != postResponseExclusive || info.Method.Algorithm != saml.SignatureAlgorithmRSAPSSSHA256 || reference.URI != "#"+response.ID || reference.DigestMethod.Algorithm != postResponseSHA256 || len(reference.Transforms) != 2 || reference.Transforms[0].Algorithm != postResponseEnveloped || reference.Transforms[1].Algorithm != postResponseExclusive {
		t.Fatal("XML signature profile changed")
	}
	status := `<Status><StatusCode Value="` + string(response.Status.Code) + `">`
	if response.Status.Subcode != "" {
		status += `<StatusCode Value="` + string(response.Status.Subcode) + `"></StatusCode>`
	}
	status += `</StatusCode></Status>`
	canonicalRoot := `<LogoutResponse xmlns="` + postResponseProtocol + `" Destination="` + postResponseEscape(config.IdentityProviderURL) + `" ID="` + response.ID + `" InResponseTo="` + response.InResponseTo + `" IssueInstant="` + response.IssuedAt.UTC().Format(time.RFC3339Nano) + `" Version="2.0"><Issuer xmlns="` + postResponseAssertion + `">` + postResponseEscape(config.SPEntityID) + `</Issuer>` + status + `</LogoutResponse>`
	digest := sha256.Sum256([]byte(canonicalRoot))
	if reference.Digest != base64.StdEncoding.EncodeToString(digest[:]) {
		t.Fatal("root digest does not authenticate independently expected response")
	}
	canonicalInfo := `<SignedInfo xmlns="` + postResponseSignature + `"><CanonicalizationMethod Algorithm="` + postResponseExclusive + `"></CanonicalizationMethod><SignatureMethod Algorithm="` + saml.SignatureAlgorithmRSAPSSSHA256 + `"></SignatureMethod><Reference URI="#` + response.ID + `"><Transforms><Transform Algorithm="` + postResponseEnveloped + `"></Transform><Transform Algorithm="` + postResponseExclusive + `"></Transform></Transforms><DigestMethod Algorithm="` + postResponseSHA256 + `"></DigestMethod><DigestValue>` + reference.Digest + `</DigestValue></Reference></SignedInfo>`
	signedDigest := sha256.Sum256([]byte(canonicalInfo))
	signature, err := base64.StdEncoding.Strict().DecodeString(document.Signature.Value)
	if err != nil || rsa.VerifyPSS(key, crypto.SHA256, signedDigest[:], signature, &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: sha256.Size}) != nil {
		t.Fatal("independent fixed-profile signature verification failed")
	}
}

func postResponseEscape(value string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", `"`, "&quot;").Replace(value)
}
func postResponseConfig() saml.LogoutPOSTResponseConfig {
	return saml.LogoutPOSTResponseConfig{SPEntityID: "HTTPS://identity.example/saml2/service%2fID?profile=exact", IdentityProviderURL: "https://idp.example/logout%2Fresponse?connection=partners%2Fwest&tenant=one"}
}
func postResponseInput() saml.LogoutResponse {
	return saml.LogoutResponse{ID: "_private_response", InResponseTo: "_original_request", IssuedAt: time.Date(2026, 11, 23, 12, 0, 0, 123, time.FixedZone("offset", 2*60*60)), Status: saml.LogoutPOSTStatus{Code: saml.LogoutStatusSuccess}}
}
func newPostResponseProfile(t *testing.T, config saml.LogoutPOSTResponseConfig) saml.LogoutPOSTResponseProfile {
	t.Helper()
	profile, err := saml.NewLogoutPOSTResponseProfile(config)
	if err != nil {
		t.Fatal(err)
	}
	return profile
}
func assertPostResponseDenied(t *testing.T, result saml.SignedLogoutPOSTResponse, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatal("wrong redacted signing error", err)
	}
	if _, err := result.Fields(); !errors.Is(err, saml.ErrInvalidInput) {
		t.Fatal("failed signing disclosed wire output")
	}
}

type postResponseMutatingSigner struct{ *rsa.PrivateKey }

func (s postResponseMutatingSigner) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	digest[0] ^= 1
	return s.PrivateKey.Sign(random, digest, opts)
}

type postResponseFailingSigner struct{ *rsa.PrivateKey }

func (s postResponseFailingSigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("private-signing-backend-error")
}
