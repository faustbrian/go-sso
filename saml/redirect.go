package saml

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	// SignatureAlgorithmRSAPSSSHA256 is the fixed SHA-256/MGF1-SHA-256 RSA-PSS
	// identifier from RFC 6931 §2.3.10, with a 32-byte salt.
	SignatureAlgorithmRSAPSSSHA256 = "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1"
	httpPostBinding                = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	maximumEndpointBytes           = 2048 // Reference saml.id_uri_bytes.
	maximumEntityIDBytes           = 1024 // Reference saml.sp_entity_id.
	maximumRelayStateBytes         = 80   // OASIS Bindings §3.4.3.
	maximumRedirectBytes           = 8192 // Parent sso.ProtocolStartResult bound.
)

var (
	// ErrInvalidInput reports an invalid or unsupported SAML input without wire data.
	ErrInvalidInput = errors.New("saml: invalid input")
	// ErrSigning reports that the selected signer did not produce a valid signature.
	ErrSigning = errors.New("saml: signing failed")
	// ErrSensitiveSerialization reports an unsafe implicit projection.
	ErrSensitiveSerialization = errors.New("saml: sensitive serialization refused")
)

// AuthnRedirectConfig is the exact, already-approved service-provider login
// configuration. Its consumer URL is the registered HTTP-POST ACS, not an
// application landing URL. IdentityProviderURL is the registered Redirect
// endpoint and may carry non-SAML fixed query parameters.
type AuthnRedirectConfig struct {
	SPEntityID           string
	AssertionConsumerURL string
	IdentityProviderURL  string
}

// AuthnRedirectProfile is immutable. It performs no key, provider, or login
// admission and holds no replay state. Its zero value cannot render a redirect.
type AuthnRedirectProfile struct {
	config   AuthnRedirectConfig
	endpoint url.URL
}

// NewAuthnRedirectProfile validates static URL shape. It never contacts the
// provider or changes configured URL bytes. Provider registration must already
// have approved the entity, endpoints and active signing credential.
func NewAuthnRedirectProfile(config AuthnRedirectConfig) (AuthnRedirectProfile, error) {
	if !samlSPEntityID(config.SPEntityID) {
		return AuthnRedirectProfile{}, ErrInvalidInput
	}
	if !samlAssertionConsumerURL(config.AssertionConsumerURL) {
		return AuthnRedirectProfile{}, ErrInvalidInput
	}
	endpoint, ok := samlHTTPSURL(config.IdentityProviderURL, maximumEndpointBytes, true)
	if !ok || !validFixedRedirectQuery(endpoint.RawQuery) {
		return AuthnRedirectProfile{}, ErrInvalidInput
	}
	return AuthnRedirectProfile{config: config, endpoint: endpoint}, nil
}

// AuthnRequest carries the original request ID and issue time already selected
// by the trusted transaction owner. RelayState is absent when empty. When used,
// it must be an already issued opaque URL-safe handle, not application data.
// This value creates neither a transaction nor a capability.
type AuthnRequest struct {
	ID         string
	IssuedAt   time.Time
	RelayState string
}

// AuthnRedirect holds the URL to disclose only to the admitted browser.
// The explicit URL accessor is required; implicit formatting redacts it.
type AuthnRedirect struct{ destination url.URL }

// URL returns a copy of the final wire URL. It does not assert that the
// underlying transaction is still usable. A zero result is invalid.
func (r AuthnRedirect) URL() (url.URL, error) {
	if r.destination.Host == "" {
		return url.URL{}, ErrInvalidInput
	}
	return r.destination, nil
}

// Redirect encodes the exact SAML 2.0 AuthnRequest and signs the raw binding
// fields with the supplied installed RSA signer. The signer is borrowed
// synchronously; it must have bounded latency and must not be changed during
// the call. Cancellation is checked before signing and before disclosure.
// The caller owns transaction expiry and retention of the original request.
func (p AuthnRedirectProfile) Redirect(ctx context.Context, request AuthnRequest, signer crypto.Signer) (AuthnRedirect, error) {
	if ctx == nil || p.endpoint.Host == "" || !request.valid() || signer == nil {
		return AuthnRedirect{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return AuthnRedirect{}, err
	}
	key, ok := redirectSigningKey(signer)
	if !ok {
		return AuthnRedirect{}, ErrInvalidInput
	}

	encoded, err := p.encodeAuthnRequest(request)
	if err != nil {
		return AuthnRedirect{}, err
	}
	destination, err := signRedirectRequest(ctx, p.endpoint, encoded, request.RelayState, signer, key)
	if err != nil {
		return AuthnRedirect{}, err
	}
	return AuthnRedirect{destination: destination}, nil
}

func redirectSigningKey(signer crypto.Signer) (*rsa.PublicKey, bool) {
	if signer == nil {
		return nil, false
	}
	if local, ok := signer.(*rsa.PrivateKey); ok && local == nil {
		return nil, false
	}
	key, ok := signer.Public().(*rsa.PublicKey)
	if !ok || key == nil || key.N == nil || key.N.Sign() != 1 || key.N.BitLen() < 2048 ||
		key.Size() > maximumRedirectBytes || key.E < 3 || key.E%2 == 0 {
		return nil, false
	}
	return key, true
}

// signRedirectRequest owns only the closed outbound SAMLRequest binding. It
// accepts already bounded, encoded XML and an already validated RSA public key.
func signRedirectRequest(ctx context.Context, endpoint url.URL, encoded, relayState string, signer crypto.Signer, key *rsa.PublicKey) (url.URL, error) {
	// The configured fixed query is not signature input. Bindings §3.4.4.1
	// orders the percent-encoded protocol fields and omits absent RelayState.
	signed := "SAMLRequest=" + url.QueryEscape(encoded)
	if relayState != "" {
		signed += "&RelayState=" + url.QueryEscape(relayState)
	}
	signed += "&SigAlg=" + url.QueryEscape(SignatureAlgorithmRSAPSSSHA256)

	if err := ctx.Err(); err != nil {
		return url.URL{}, err
	}
	digest := sha256.Sum256([]byte(signed))
	signerDigest := digest
	signingOptions := &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: sha256.Size}
	signature, err := signer.Sign(rand.Reader, signerDigest[:], signingOptions)
	if canceled := ctx.Err(); canceled != nil {
		return url.URL{}, canceled
	}
	// Verify against the profile, not the mutable arguments borrowed by the
	// signer. A signer backend cannot select a digest or salt policy for us.
	verificationOptions := &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: sha256.Size}
	if err != nil || len(signature) != key.Size() || rsa.VerifyPSS(key, crypto.SHA256, digest[:], signature, verificationOptions) != nil {
		return url.URL{}, ErrSigning
	}
	result := endpoint
	if result.RawQuery != "" {
		result.RawQuery += "&"
	}
	result.RawQuery += signed + "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(signature))
	if len(result.String()) > maximumRedirectBytes {
		return url.URL{}, ErrInvalidInput
	}
	return result, nil
}

type requestXML struct {
	XMLName     xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol AuthnRequest"`
	ID          string   `xml:"ID,attr"`
	Version     string   `xml:"Version,attr"`
	IssueTime   string   `xml:"IssueInstant,attr"`
	Destination string   `xml:"Destination,attr"`
	Consumer    string   `xml:"AssertionConsumerServiceURL,attr"`
	Binding     string   `xml:"ProtocolBinding,attr"`
	Issuer      string   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
}

func (p AuthnRedirectProfile) encodeAuthnRequest(request AuthnRequest) (string, error) {
	document, err := xml.Marshal(requestXML{
		ID: request.ID, Version: "2.0", IssueTime: request.IssuedAt.UTC().Format(time.RFC3339Nano),
		Destination: p.config.IdentityProviderURL, Consumer: p.config.AssertionConsumerURL,
		Binding: httpPostBinding, Issuer: p.config.SPEntityID,
	})
	if err != nil {
		return "", ErrInvalidInput
	}
	return deflateRedirectRequest(document)
}

func deflateRedirectRequest(document []byte) (string, error) {
	var compressed bytes.Buffer
	writer, err := flate.NewWriter(&compressed, flate.DefaultCompression)
	if err != nil {
		return "", ErrInvalidInput
	}
	_, writeErr := writer.Write(document)
	closeErr := writer.Close()
	if writeErr != nil || closeErr != nil {
		return "", ErrInvalidInput
	}
	return base64.StdEncoding.EncodeToString(compressed.Bytes()), nil
}

func (r AuthnRequest) valid() bool {
	if len(r.ID) == 0 || len(r.ID) > maximumEndpointBytes || r.IssuedAt.IsZero() ||
		r.IssuedAt.UTC().Year() < 1 || r.IssuedAt.UTC().Year() > 9999 || len(r.RelayState) > maximumRelayStateBytes {
		return false
	}
	for index := range len(r.ID) {
		char := r.ID[index]
		if asciiLetter(char) || char == '_' || index > 0 && (asciiDigit(char) || char == '-' || char == '.') {
			continue
		}
		return false // A generated SAML ID uses the ASCII subset of XML NCName.
	}
	for index := range len(r.RelayState) {
		char := r.RelayState[index]
		if !asciiLetter(char) && !asciiDigit(char) && char != '-' && char != '_' {
			return false
		}
	}
	return true
}

func asciiLetter(char byte) bool { return char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' }
func asciiDigit(char byte) bool  { return char >= '0' && char <= '9' }

func samlSPEntityID(raw string) bool {
	if len(raw) > maximumEntityIDBytes {
		return false
	}
	scheme, suffix, found := strings.Cut(raw, ":")
	if !found || !strings.EqualFold(scheme, "https") {
		return false
	}
	// The entity identifier is compared as configured, not navigated. Only
	// the validation copy folds the URI scheme for Go's URL parser.
	_, ok := samlHTTPSURL("https:"+suffix, maximumEntityIDBytes, true)
	return ok
}

func samlAssertionConsumerURL(raw string) bool {
	consumer, ok := samlHTTPSURL(raw, maximumEndpointBytes, false)
	// The ACS comes from the canonical installed route, not arbitrary metadata.
	return ok && consumer.Path != "" && consumer.Path != "/" && !strings.Contains(consumer.EscapedPath(), "%")
}

func samlHTTPSURL(raw string, maximum int, allowQuery bool) (url.URL, bool) {
	if len(raw) == 0 || len(raw) > maximum || strings.ContainsAny(raw, "\\#") {
		return url.URL{}, false
	}
	for index := range len(raw) {
		if raw[index] < '!' || raw[index] > '~' {
			return url.URL{}, false
		}
	}
	if _, err := url.PathUnescape(raw); err != nil {
		return url.URL{}, false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil ||
		parsed.Opaque != "" || (!allowQuery && (parsed.RawQuery != "" || parsed.ForceQuery)) ||
		parsed.String() != raw || !utf8.ValidString(parsed.Path) || strings.ContainsRune(parsed.Path, '\\') ||
		strings.ContainsFunc(parsed.Path, unicode.IsControl) {
		return url.URL{}, false
	}
	for part := range strings.SplitSeq(parsed.Path, "/") {
		if part == "." || part == ".." {
			return url.URL{}, false
		}
	}
	return *parsed, true
}

func validFixedRedirectQuery(query string) bool {
	values, err := url.ParseQuery(query)
	if err != nil {
		return false
	}
	for name := range values {
		switch strings.ToLower(name) {
		case "samlrequest", "samlresponse", "relaystate", "sigalg", "signature":
			return false // The adapter alone owns the signed binding fields.
		}
	}
	return true
}

func (AuthnRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("saml.AuthnRequest(redacted)"))
}
func (AuthnRequest) LogValue() slog.Value         { return slog.StringValue("saml.AuthnRequest(redacted)") }
func (AuthnRequest) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (AuthnRequest) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

func (AuthnRedirect) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("saml.AuthnRedirect(redacted)"))
}
func (AuthnRedirect) LogValue() slog.Value         { return slog.StringValue("saml.AuthnRedirect(redacted)") }
func (AuthnRedirect) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (AuthnRedirect) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
