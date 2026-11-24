package saml

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/faustbrian/go-sso"
	"github.com/knroy/go-xml/v2/xdm"
)

const (
	samlProtocolNS         = "urn:oasis:names:tc:SAML:2.0:protocol"
	samlAssertionNS        = "urn:oasis:names:tc:SAML:2.0:assertion"
	maximumPOSTBase64Bytes = 4 << 20 // Reference saml.base64_bytes, before decoding.
	maximumSAMLClockSkew   = 5 * time.Minute
	samlStatusSuccess      = "urn:oasis:names:tc:SAML:2.0:status:Success"
	samlBearerConfirmation = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
	samlPersistentNameID   = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	samlEmailNameID        = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
)

// POSTResponseConfig selects the exact, already approved active IdP signing
// certificate set and public SP identity. The owner must pin the same metadata
// version at start and callback admission. Fields are borrowed during
// construction; no metadata, URL, embedded certificate or network is fetched.
// ClockSkew explicitly selects 0..5 minutes for IdP timestamps, never for the
// original local callback expiry.
type POSTResponseConfig struct {
	SPEntityID               string
	IdentityProviderEntityID string
	AssertionConsumerURL     string
	SigningCertificates      [][]byte
	ClockSkew                time.Duration
}

type pinnedSAMLCertificate struct {
	key                 crypto.PublicKey
	notBefore, notAfter time.Time
}

// POSTResponseProfile validates signed XML for a configured SP-initiated POST.
// It owns only static verification inputs and is safe for concurrent use.
// It cannot select a provider, reserve replay IDs or issue a login. Zero denies.
type POSTResponseProfile struct {
	sp, idp, acs string
	signing      []pinnedSAMLCertificate
	skew         time.Duration
	mapping      *postAssertionMapping
}

// NewPOSTResponseProfile validates exact identities and copies the approved
// RSA-PSS/P-256 signing keys, never using an input document to enlarge trust.
func NewPOSTResponseProfile(config POSTResponseConfig) (POSTResponseProfile, error) {
	if !samlSPEntityID(config.SPEntityID) || !samlIdPEntityID(config.IdentityProviderEntityID) ||
		!samlAssertionConsumerURL(config.AssertionConsumerURL) || config.ClockSkew < 0 || config.ClockSkew > maximumSAMLClockSkew {
		return POSTResponseProfile{}, ErrInvalidInput
	}
	keys, err := parsePinnedSigningCertificates(config.SigningCertificates)
	if err != nil {
		return POSTResponseProfile{}, err
	}
	return POSTResponseProfile{sp: config.SPEntityID, idp: config.IdentityProviderEntityID,
		acs: config.AssertionConsumerURL, signing: keys, skew: config.ClockSkew}, nil
}

func parsePinnedSigningCertificates(certificates [][]byte) ([]pinnedSAMLCertificate, error) {
	if len(certificates) == 0 || len(certificates) > maximumPinnedSigningKeys {
		return nil, ErrInvalidInput
	}
	keys := make([]pinnedSAMLCertificate, 0, len(certificates))
	seen := make(map[string]struct{}, len(certificates))
	for _, der := range certificates {
		if len(der) == 0 || len(der) > maximumCertificateBytes {
			return nil, ErrInvalidInput
		}
		identity := string(der)
		if _, exists := seen[identity]; exists {
			return nil, ErrInvalidInput
		}
		seen[identity] = struct{}{}
		certificate, err := x509.ParseCertificate(der)
		if err != nil || !usableSAMLSigningCertificate(certificate) {
			return nil, ErrInvalidInput
		}
		keys = append(keys, pinnedSAMLCertificate{certificate.PublicKey, certificate.NotBefore, certificate.NotAfter})
	}
	return keys, nil
}

func usableSAMLSigningCertificate(cert *x509.Certificate) bool {
	if !cert.NotBefore.Before(cert.NotAfter) || cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return false
	}
	return samlSignatureKeyBytes(SignatureAlgorithmRSAPSSSHA256, cert.PublicKey) > 0 ||
		samlSignatureKeyBytes(xmlSignatureECDSAP256, cert.PublicKey) > 0
}

// POSTResponseInput contains the single decoded form member SAMLResponse (whose
// value is still Base64). RequestID, IssuedAt and ExpiresAt must be taken from
// the admitted original transaction, with Now supplied by its trusted clock;
// the caller must enforce the form, browser correlation, route and RelayState.
type POSTResponseInput struct {
	SAMLResponse string
	RequestID    string
	IssuedAt     time.Time
	ExpiresAt    time.Time
	Now          time.Time
}

// POSTResponseEvidence contains the exact signed subject and replay set. The
// two IDs must be reserved atomically before any authority is issued. A NameID
// in emailAddress format is still only a provider subject, not a verified
// email claim. Attribute and role mapping are not inferred by this profile.
// AssertionExpiresAt is the raw assertion cutoff for retained replay evidence;
// ValidUntil is the earliest allowed local acceptance window, conditions,
// subject confirmation, remote session and matched signing certificate cutoff.
type POSTResponseEvidence struct {
	ResponseID, AssertionID        string
	ProviderSubject, SubjectFormat string
	SessionIndex                   string
	AssertionExpiresAt, ValidUntil time.Time
}

// VerifiedPOSTResponse is detached evidence, not a replay reservation,
// application principal, session, or permission to issue one.
type VerifiedPOSTResponse struct{ verified verifiedPOSTResponseData }

type verifiedPOSTResponseData struct {
	evidence                       POSTResponseEvidence
	nameQualifier, spNameQualifier string
	assertion                      *sso.ProtocolAssertion
}

// Evidence explicitly returns the detached identity fields and replay set.
// A zero or denied result returns no evidence.
func (v VerifiedPOSTResponse) Evidence() (POSTResponseEvidence, error) {
	if v.verified.evidence.AssertionID == "" {
		return POSTResponseEvidence{}, ErrInvalidInput
	}
	return v.verified.evidence, nil
}

// Validate authenticates the exact Response and its one Assertion from the
// same bounded XML tree. It checks the configured issuer, expected recipient
// and audience, original request, time windows and the supported NameID form.
// Unsolicited, encrypted, non-bearer, and failure response profiles are denied.
func (p POSTResponseProfile) Validate(ctx context.Context, input POSTResponseInput) (VerifiedPOSTResponse, error) {
	if ctx == nil || len(p.signing) == 0 || !validSAMLID(input.RequestID) || !validSAMLTime(input.IssuedAt) ||
		!validSAMLTime(input.Now) || !validSAMLTime(input.ExpiresAt) || input.Now.Before(input.IssuedAt) || !input.Now.Before(input.ExpiresAt) {
		return VerifiedPOSTResponse{}, ErrInvalidInput
	}
	evidence, err := p.validatePOSTResponse(ctx, input.SAMLResponse, postResponseBinding{
		requestID: input.RequestID, issuedAt: input.IssuedAt, expiresAt: input.ExpiresAt, now: input.Now,
	})
	return VerifiedPOSTResponse{verified: evidence}, err
}

// postResponseBinding keeps protocol timing and request-mode selection private.
// The unsolicited entry point supplies its nonzero age, never a request ID.
type postResponseBinding struct {
	requestID                string
	issuedAt, expiresAt, now time.Time
	maximumUnsolicitedAge    time.Duration
}

func (p POSTResponseProfile) validatePOSTResponse(ctx context.Context, encoded string, binding postResponseBinding) (verifiedPOSTResponseData, error) {
	if err := ctx.Err(); err != nil {
		return verifiedPOSTResponseData{}, err
	}
	document, err := decodePOSTResponse(encoded)
	if err != nil {
		return verifiedPOSTResponseData{}, err
	}
	response, err := parseSAMLDocument(ctx, document)
	if err != nil {
		return verifiedPOSTResponseData{}, err
	}
	if !samlElement(response, samlProtocolNS, "Response") || !uniqueSAMLDocumentIDs(response) || !p.matchIssuer(response) {
		return verifiedPOSTResponseData{}, ErrInvalidInput
	}
	keys, expiries := p.activeSigningKeys(binding.now)
	responseSigner, err := verifySAMLSignature(ctx, response, keys)
	if err != nil {
		return verifiedPOSTResponseData{}, err
	}
	assertion := p.responseAssertion(response, binding)
	if assertion == nil || !p.matchIssuer(assertion) {
		return verifiedPOSTResponseData{}, ErrInvalidInput
	}
	responseCutoff, ok := p.issueCutoff(response, binding)
	if !ok {
		return verifiedPOSTResponseData{}, ErrInvalidInput
	}
	binding.expiresAt = responseCutoff
	assertionSigner, err := verifySAMLSignature(ctx, assertion, keys)
	if err != nil {
		return verifiedPOSTResponseData{}, err
	}
	evidence, ok := p.bindAssertion(assertion, binding)
	if !ok {
		return verifiedPOSTResponseData{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return verifiedPOSTResponseData{}, err
	}
	evidence.evidence.ResponseID = samlAttr(response, "ID")
	evidence.evidence.ValidUntil = earlierSAMLTime(evidence.evidence.ValidUntil, expiries[responseSigner])
	evidence.evidence.ValidUntil = earlierSAMLTime(evidence.evidence.ValidUntil, expiries[assertionSigner])
	return evidence, nil
}

func (p POSTResponseProfile) activeSigningKeys(now time.Time) ([]crypto.PublicKey, []time.Time) {
	keys := make([]crypto.PublicKey, 0, len(p.signing))
	expiries := make([]time.Time, 0, len(p.signing))
	for _, cert := range p.signing {
		if !now.Before(cert.notBefore) && now.Before(cert.notAfter) {
			keys = append(keys, cert.key)
			expiries = append(expiries, cert.notAfter)
		}
	}
	return keys, expiries
}

func decodePOSTResponse(encoded string) ([]byte, error) {
	if len(encoded) == 0 || len(encoded) > maximumPOSTBase64Bytes {
		return nil, ErrInvalidInput
	}
	decoder := base64.NewDecoder(base64.StdEncoding.Strict(), strings.NewReader(encoded))
	decoded, err := io.ReadAll(io.LimitReader(decoder, maximumSAMLXMLBytes+1))
	if err != nil || len(decoded) == 0 || len(decoded) > maximumSAMLXMLBytes {
		return nil, ErrInvalidInput
	}
	return decoded, nil
}

func validSAMLID(value string) bool {
	return len(value) <= maximumEndpointBytes && xdm.IsNCName(value)
}

func validSAMLTime(t time.Time) bool {
	return !t.IsZero() && t.UTC().Year() >= 1 && t.UTC().Year() <= 9999
}

func samlIdPEntityID(raw string) bool {
	if len(raw) == 0 || len(raw) > maximumEntityIDBytes {
		return false
	}
	for _, ch := range raw {
		if ch <= ' ' || ch >= 127 || strings.ContainsRune("\"<>\\^`{|}#", ch) {
			return false
		}
	}
	if _, err := url.PathUnescape(raw); err != nil {
		return false
	}
	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() || parsed.User != nil || (parsed.Host == "" && parsed.Path == "" && parsed.Opaque == "") {
		return false
	}
	scheme, rest, _ := strings.Cut(raw, ":")
	parsed.Scheme = scheme
	return parsed.String() == raw && (!strings.HasPrefix(rest, "//") || parsed.Hostname() != "")
}

func uniqueSAMLDocumentIDs(root *xdm.Node) bool {
	ids := make(map[string]struct{})
	var signatureCount, assertionCount int
	visit := func(node *xdm.Node) bool {
		if samlElement(node, samlAssertionNS, "Assertion") {
			// There is one assertion for the entire selected response profile,
			// including signed content we do not interpret (e.g. attributes).
			assertionCount++
			if assertionCount > 1 {
				return false
			}
		}
		if samlElement(node, xmlSignatureNamespace, "Signature") {
			signatureCount++
			if signatureCount > 4 { // Reference saml.signatures_max.
				return false
			}
		}
		for i := range node.NumAttrs() {
			attr := node.AttrAt(i)
			name := attr.Name()
			if name.Local != "ID" && name.Local != "Id" && !(name.URI == xdm.NSXML && name.Local == "id") {
				continue
			}
			id := attr.Value()
			if _, found := ids[id]; found || !validSAMLID(id) {
				return false
			}
			ids[id] = struct{}{}
		}
		return true
	}
	if !visit(root) {
		return false
	}
	for node := range root.Descendants() {
		if node.Kind() == xdm.KindElement && !visit(node) {
			return false
		}
	}
	return true
}

func (p POSTResponseProfile) matchIssuer(parent *xdm.Node) bool {
	issuer := samlSingleChild(parent, samlAssertionNS, "Issuer")
	value, ok := samlSimpleText(issuer, maximumEndpointBytes)
	return ok && value == p.idp && (issuer.NumAttrs() == 0 ||
		issuer.NumAttrs() == 1 && samlAttr(issuer, "Format") == "urn:oasis:names:tc:SAML:2.0:nameid-format:entity")
}

func samlAttr(n *xdm.Node, name string) string {
	if attr := n.Attr("", name); attr != nil {
		return attr.Value()
	}
	return ""
}

func samlSimpleText(n *xdm.Node, limit int) (string, bool) {
	if n == nil {
		return "", false
	}
	child := n.FirstChild()
	if child == nil || child.Kind() != xdm.KindText || child.NextSibling() != nil {
		return "", false
	}
	value := child.Value()
	if len(value) == 0 || len(value) > limit || !utf8.ValidString(value) || strings.ContainsFunc(value, unicode.IsControl) {
		return "", false
	}
	return value, true
}

func (POSTResponseInput) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "saml.POSTResponseInput(redacted)")
}
func (POSTResponseInput) LogValue() slog.Value {
	return slog.StringValue("saml.POSTResponseInput(redacted)")
}
func (POSTResponseInput) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (POSTResponseInput) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

func (POSTResponseEvidence) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "saml.POSTResponseEvidence(redacted)")
}
func (POSTResponseEvidence) LogValue() slog.Value {
	return slog.StringValue("saml.POSTResponseEvidence(redacted)")
}
func (POSTResponseEvidence) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (POSTResponseEvidence) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

func (VerifiedPOSTResponse) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "saml.VerifiedPOSTResponse(redacted)")
}
func (VerifiedPOSTResponse) LogValue() slog.Value {
	return slog.StringValue("saml.VerifiedPOSTResponse(redacted)")
}
func (VerifiedPOSTResponse) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (VerifiedPOSTResponse) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
