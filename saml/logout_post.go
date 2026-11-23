package saml

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/knroy/go-xml/v2/xdm"
)

// LogoutPOSTConfig selects an already-approved IdP signing certificate set,
// exact SP/IdP entities and registered HTTPS SP SingleLogoutURL. Construction
// copies certificate material; no metadata, URL or embedded key is fetched.
// MaximumAge explicitly selects a hard acceptance window of (0, 5 minutes]
// from signed IssueInstant. ClockSkew selects 0..5 minutes for future issue
// timestamps only; it never extends age, signed expiry or certificate expiry.
type LogoutPOSTConfig struct {
	SPEntityID               string
	IdentityProviderEntityID string
	SingleLogoutURL          string
	SigningCertificates      [][]byte
	ClockSkew                time.Duration
	MaximumAge               time.Duration
}

// LogoutPOSTProfile authenticates inbound IdP-to-SP POST logout XML. It owns
// immutable verification inputs and is safe for concurrent use. Zero denies.
// It neither selects local sessions nor reserves replay IDs, correlates stored
// requests, revokes sessions, or establishes remote revocation.
type LogoutPOSTProfile struct {
	verifier   POSTResponseProfile
	maximumAge time.Duration
}

// NewLogoutPOSTProfile installs exact static verification inputs. The caller
// must have approved the provider, certificate version and registered route.
// Malformed/unsupported configuration returns the redacted ErrInvalidInput.
func NewLogoutPOSTProfile(config LogoutPOSTConfig) (LogoutPOSTProfile, error) {
	if config.MaximumAge <= 0 || config.MaximumAge > 5*time.Minute {
		return LogoutPOSTProfile{}, ErrInvalidInput
	}
	verifier, err := NewPOSTResponseProfile(POSTResponseConfig{
		SPEntityID: config.SPEntityID, IdentityProviderEntityID: config.IdentityProviderEntityID,
		AssertionConsumerURL: config.SingleLogoutURL, SigningCertificates: config.SigningCertificates,
		ClockSkew: config.ClockSkew,
	})
	if err != nil {
		return LogoutPOSTProfile{}, err
	}
	return LogoutPOSTProfile{verifier: verifier, maximumAge: config.MaximumAge}, nil
}

// LogoutPOSTInput contains the decoded form values, still Base64-encoded.
// Exactly one field must be present with exactly one nonempty value; slices
// preserve duplicates so they cannot silently disappear. Values are borrowed
// synchronously and must not change during Validate. Now is a trusted clock.
// The caller owns HTTP POST/route/form admission and separately bounded
// RelayState, which has no input or authority at this XML-only boundary.
type LogoutPOSTInput struct {
	SAMLRequest, SAMLResponse []string
	Now                       time.Time
}

// LogoutPOSTKind discriminates authenticated logout wire messages. Empty is
// the invalid/zero result, never an implicit request or response.
type LogoutPOSTKind string

const (
	LogoutPOSTRequest  LogoutPOSTKind = "request"
	LogoutPOSTResponse LogoutPOSTKind = "response"
)

// LogoutReason is a selected signed Core §3.7.3 reason; empty means absent.
type LogoutReason string

const (
	LogoutReasonUser  LogoutReason = "urn:oasis:names:tc:SAML:2.0:logout:user"
	LogoutReasonAdmin LogoutReason = "urn:oasis:names:tc:SAML:2.0:logout:admin"
)

// LogoutStatusCode is an exact selected Core §3.2.2.2 status URI, not free
// text. The four top-level codes and four SLO-relevant subordinate codes below
// form this closed profile; unknown or more deeply nested codes are denied.
type LogoutStatusCode string

const (
	LogoutStatusSuccess            LogoutStatusCode = "urn:oasis:names:tc:SAML:2.0:status:Success"
	LogoutStatusRequester          LogoutStatusCode = "urn:oasis:names:tc:SAML:2.0:status:Requester"
	LogoutStatusResponder          LogoutStatusCode = "urn:oasis:names:tc:SAML:2.0:status:Responder"
	LogoutStatusVersionMismatch    LogoutStatusCode = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch"
	LogoutStatusPartialLogout      LogoutStatusCode = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout"
	LogoutStatusUnknownPrincipal   LogoutStatusCode = "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal"
	LogoutStatusRequestDenied      LogoutStatusCode = "urn:oasis:names:tc:SAML:2.0:status:RequestDenied"
	LogoutStatusUnsupportedBinding LogoutStatusCode = "urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding"
)

// LogoutPOSTStatus is only the signed IdP status. Subcode is absent when empty.
// Optional bounded plain StatusMessage text is validated and discarded, never
// exposed here. No value proves local or remote sessions were actually revoked.
type LogoutPOSTStatus struct{ Code, Subcode LogoutStatusCode }

// LogoutPOSTRequestEvidence is detached authenticated request context, never
// local-session authority. Qualifiers and SessionIndex preserve exact absence;
// nothing is normalized or inferred. The caller must strongly match the NameID
// and optional index against authoritative stored login context and reserve ID
// once before acting. Empty SessionIndex is the selected IdP authority's request
// for all applicable sessions, not permission to skip authoritative matching.
// NotOnOrAfter is zero if absent; ValidUntil is the earliest hard message-age,
// signed expiry and matched signing-certificate cutoff.
type LogoutPOSTRequestEvidence struct {
	ID                             string
	IssuedAt, ValidUntil           time.Time
	ProviderSubject, SubjectFormat string
	NameQualifier, SPNameQualifier string
	SessionIndex                   string
	NotOnOrAfter                   time.Time
	Reason                         LogoutReason
}

// LogoutPOSTResponseEvidence contains signed status/correlation only. The
// caller must atomically match and consume InResponseTo against one outstanding
// original request and recover every subject/session/provider target from that
// stored request. No response field supplies those targets. ValidUntil is the
// earliest hard message-age and signing-certificate cutoff; ID needs replay
// handling even for signed failure statuses, which are returned without error.
type LogoutPOSTResponseEvidence struct {
	ID, InResponseTo     string
	IssuedAt, ValidUntil time.Time
	Status               LogoutPOSTStatus
}

// VerifiedLogoutPOST is detached, discriminated signed wire evidence. Guarded
// projections cannot expose a response as subject-bearing request authority.
// Zero values and every failed validation disclose no evidence.
type VerifiedLogoutPOST struct {
	kind     LogoutPOSTKind
	request  LogoutPOSTRequestEvidence
	response LogoutPOSTResponseEvidence
}

// Kind returns the authenticated message kind, or empty for a denied/zero value.
func (v VerifiedLogoutPOST) Kind() LogoutPOSTKind { return v.kind }

// Request explicitly discloses request evidence, denying responses and zero.
func (v VerifiedLogoutPOST) Request() (LogoutPOSTRequestEvidence, error) {
	if v.kind != LogoutPOSTRequest {
		return LogoutPOSTRequestEvidence{}, ErrInvalidInput
	}
	return v.request, nil
}

// Response explicitly discloses response evidence, denying requests and zero.
func (v VerifiedLogoutPOST) Response() (LogoutPOSTResponseEvidence, error) {
	if v.kind != LogoutPOSTResponse {
		return LogoutPOSTResponseEvidence{}, ErrInvalidInput
	}
	return v.response, nil
}

// Validate bounds and parses XML once, discriminates the exact signed root,
// rejects duplicate IDs, then authenticates that node against installed active
// leaves before interpreting a subject. It requires exact issuer/destination,
// selected shape and timestamps. Malformed input returns ErrInvalidInput;
// signature/key/leaf failures return ErrInvalidSignature. Cancellation returns
// ctx.Err(). Parsing/canonicalization/crypto are bounded but not interruptible
// internally. Every error returns a zero result without local-session evidence.
func (p LogoutPOSTProfile) Validate(ctx context.Context, input LogoutPOSTInput) (VerifiedLogoutPOST, error) {
	if ctx == nil || len(p.verifier.signing) == 0 || !validSAMLTime(input.Now) {
		return VerifiedLogoutPOST{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return VerifiedLogoutPOST{}, err
	}
	var encoded, rootName string
	switch {
	case len(input.SAMLRequest) == 1 && len(input.SAMLResponse) == 0:
		encoded, rootName = input.SAMLRequest[0], "LogoutRequest"
	case len(input.SAMLResponse) == 1 && len(input.SAMLRequest) == 0:
		encoded, rootName = input.SAMLResponse[0], "LogoutResponse"
	default:
		return VerifiedLogoutPOST{}, ErrInvalidInput
	}
	document, err := decodePOSTResponse(encoded)
	if err != nil {
		return VerifiedLogoutPOST{}, err
	}
	root, err := parseSAMLDocument(ctx, document)
	if err != nil {
		return VerifiedLogoutPOST{}, err
	}
	if !samlElement(root, samlProtocolNS, rootName) || !uniqueSAMLDocumentIDs(root) || !p.verifier.matchIssuer(root) {
		return VerifiedLogoutPOST{}, ErrInvalidInput
	}
	keys, expiries := p.verifier.activeSigningKeys(input.Now)
	signer, err := verifySAMLSignature(ctx, root, keys)
	if err != nil {
		return VerifiedLogoutPOST{}, err
	}
	issued, cutoff, ok := p.bindLogoutEnvelope(root, input.Now, expiries[signer])
	if !ok {
		return VerifiedLogoutPOST{}, ErrInvalidInput
	}
	var result VerifiedLogoutPOST
	if rootName == "LogoutRequest" {
		request, ok := p.bindLogoutRequest(root, issued, cutoff, input.Now)
		if !ok {
			return VerifiedLogoutPOST{}, ErrInvalidInput
		}
		result = VerifiedLogoutPOST{kind: LogoutPOSTRequest, request: request}
	} else {
		response, ok := bindLogoutResponse(root, issued, cutoff)
		if !ok {
			return VerifiedLogoutPOST{}, ErrInvalidInput
		}
		result = VerifiedLogoutPOST{kind: LogoutPOSTResponse, response: response}
	}
	if err := ctx.Err(); err != nil {
		return VerifiedLogoutPOST{}, err
	}
	return result, nil
}

func (p LogoutPOSTProfile) bindLogoutEnvelope(root *xdm.Node, now, certificateExpiry time.Time) (time.Time, time.Time, bool) {
	issued, ok := parseSAMLTime(samlAttr(root, "IssueInstant"))
	if !ok || !validSAMLID(samlAttr(root, "ID")) || samlAttr(root, "Version") != "2.0" ||
		samlAttr(root, "Destination") != p.verifier.acs || issued.After(now.Add(p.verifier.skew)) {
		return time.Time{}, time.Time{}, false
	}
	cutoff := earlierSAMLTime(issued.Add(p.maximumAge), certificateExpiry)
	return issued, cutoff, now.Before(cutoff)
}

func (p LogoutPOSTProfile) bindLogoutRequest(root *xdm.Node, issued, cutoff, now time.Time) (LogoutPOSTRequestEvidence, bool) {
	request := LogoutPOSTRequestEvidence{ID: samlAttr(root, "ID"), IssuedAt: issued, ValidUntil: cutoff}
	for index := range root.NumAttrs() {
		attr := root.AttrAt(index)
		if attr.Name().URI != "" {
			return LogoutPOSTRequestEvidence{}, false
		}
		switch attr.Name().Local {
		case "ID", "Version", "IssueInstant", "Destination":
		case "NotOnOrAfter":
			expiry, ok := parseSAMLTime(attr.Value())
			if !ok || !expiry.After(issued) {
				return LogoutPOSTRequestEvidence{}, false
			}
			request.NotOnOrAfter = expiry
			request.ValidUntil = earlierSAMLTime(request.ValidUntil, expiry)
		case "Reason":
			request.Reason = LogoutReason(attr.Value())
			if request.Reason != LogoutReasonUser && request.Reason != LogoutReasonAdmin {
				return LogoutPOSTRequestEvidence{}, false
			}
		default:
			return LogoutPOSTRequestEvidence{}, false
		}
	}
	if !now.Before(request.ValidUntil) {
		return LogoutPOSTRequestEvidence{}, false
	}
	parts, ok := samlElementChildren(root, 4)
	if !ok || len(parts) < 3 || !samlElement(parts[0], samlAssertionNS, "Issuer") ||
		!samlElement(parts[1], xmlSignatureNamespace, "Signature") || !samlElement(parts[2], samlAssertionNS, "NameID") {
		return LogoutPOSTRequestEvidence{}, false
	}
	name := parts[2]
	request.SubjectFormat = samlAttr(name, "Format")
	if request.SubjectFormat != samlPersistentNameID && request.SubjectFormat != samlEmailNameID {
		return LogoutPOSTRequestEvidence{}, false
	}
	for index := range name.NumAttrs() {
		attr := name.AttrAt(index)
		if attr.Name().URI != "" {
			return LogoutPOSTRequestEvidence{}, false
		}
		switch attr.Name().Local {
		case "Format":
		case "NameQualifier":
			if attr.Value() != p.verifier.idp {
				return LogoutPOSTRequestEvidence{}, false
			}
			request.NameQualifier = attr.Value()
		case "SPNameQualifier":
			if attr.Value() != p.verifier.sp {
				return LogoutPOSTRequestEvidence{}, false
			}
			request.SPNameQualifier = attr.Value()
		default:
			return LogoutPOSTRequestEvidence{}, false
		}
	}
	request.ProviderSubject, ok = samlSimpleText(name, 512)
	if !ok || strings.TrimSpace(request.ProviderSubject) == "" {
		return LogoutPOSTRequestEvidence{}, false
	}
	if len(parts) == 4 {
		session := parts[3]
		if !samlElement(session, samlProtocolNS, "SessionIndex") || session.NumAttrs() != 0 {
			return LogoutPOSTRequestEvidence{}, false
		}
		request.SessionIndex, ok = samlSimpleText(session, maximumEndpointBytes)
		if !ok {
			return LogoutPOSTRequestEvidence{}, false
		}
	}
	return request, true
}

func bindLogoutResponse(root *xdm.Node, issued, cutoff time.Time) (LogoutPOSTResponseEvidence, bool) {
	correlation := samlAttr(root, "InResponseTo")
	if root.NumAttrs() != 5 || !validSAMLID(correlation) {
		return LogoutPOSTResponseEvidence{}, false
	}
	parts, ok := samlElementChildren(root, 3)
	if !ok || len(parts) != 3 || !samlElement(parts[0], samlAssertionNS, "Issuer") ||
		!samlElement(parts[1], xmlSignatureNamespace, "Signature") || !samlElement(parts[2], samlProtocolNS, "Status") {
		return LogoutPOSTResponseEvidence{}, false
	}
	status, ok := bindLogoutStatus(parts[2])
	if !ok {
		return LogoutPOSTResponseEvidence{}, false
	}
	return LogoutPOSTResponseEvidence{ID: samlAttr(root, "ID"), InResponseTo: correlation, IssuedAt: issued, ValidUntil: cutoff, Status: status}, true
}

func bindLogoutStatus(node *xdm.Node) (LogoutPOSTStatus, bool) {
	parts, ok := samlElementChildren(node, 2)
	if !ok || node.NumAttrs() != 0 || len(parts) < 1 || !samlElement(parts[0], samlProtocolNS, "StatusCode") {
		return LogoutPOSTStatus{}, false
	}
	if len(parts) == 2 && !boundedLogoutStatusMessage(parts[1]) {
		return LogoutPOSTStatus{}, false
	}
	code := parts[0]
	status := LogoutPOSTStatus{Code: LogoutStatusCode(samlAttr(code, "Value"))}
	if code.NumAttrs() != 1 {
		return LogoutPOSTStatus{}, false
	}
	switch status.Code {
	case LogoutStatusSuccess, LogoutStatusRequester, LogoutStatusResponder, LogoutStatusVersionMismatch:
	default:
		return LogoutPOSTStatus{}, false
	}
	children, ok := samlElementChildren(code, 1)
	if !ok {
		return LogoutPOSTStatus{}, false
	}
	if len(children) == 0 {
		return status, true
	}
	child := children[0]
	if !samlElement(child, samlProtocolNS, "StatusCode") || child.NumAttrs() != 1 {
		return LogoutPOSTStatus{}, false
	}
	if _, empty := samlElementChildren(child, 0); !empty {
		return LogoutPOSTStatus{}, false
	}
	status.Subcode = LogoutStatusCode(samlAttr(child, "Value"))
	// Core §3.7.3.2 uses Success/PartialLogout when the session authority
	// could not propagate logout to all participants. Preserve that status;
	// it is not evidence that every remote or local session was revoked.
	if status.Code == LogoutStatusSuccess && status.Subcode != LogoutStatusPartialLogout {
		return LogoutPOSTStatus{}, false
	}
	switch status.Subcode {
	case LogoutStatusPartialLogout, LogoutStatusUnknownPrincipal, LogoutStatusRequestDenied, LogoutStatusUnsupportedBinding:
		return status, true
	default:
		return LogoutPOSTStatus{}, false
	}
}

func boundedLogoutStatusMessage(node *xdm.Node) bool {
	if !samlElement(node, samlProtocolNS, "StatusMessage") || node.NumAttrs() != 0 {
		return false
	}
	// Core §3.2.2.1 permits operator diagnostics, not additional authority.
	// Scan plain text under the existing small protocol-text bound without
	// concatenating or retaining it. Empty and XML-whitespace text are valid.
	remaining := maximumEndpointBytes
	for child := range node.Children() {
		if child.Kind() != xdm.KindText {
			return false
		}
		remaining -= len(child.Value())
		if remaining < 0 {
			return false
		}
	}
	return true
}

func (LogoutPOSTInput) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "saml.LogoutPOSTInput(redacted)")
}
func (LogoutPOSTInput) LogValue() slog.Value {
	return slog.StringValue("saml.LogoutPOSTInput(redacted)")
}
func (LogoutPOSTInput) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (LogoutPOSTInput) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

func (VerifiedLogoutPOST) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "saml.VerifiedLogoutPOST(redacted)")
}
func (VerifiedLogoutPOST) LogValue() slog.Value {
	return slog.StringValue("saml.VerifiedLogoutPOST(redacted)")
}
func (VerifiedLogoutPOST) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (VerifiedLogoutPOST) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

func (LogoutPOSTRequestEvidence) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "saml.LogoutPOSTRequestEvidence(redacted)")
}
func (LogoutPOSTRequestEvidence) LogValue() slog.Value {
	return slog.StringValue("saml.LogoutPOSTRequestEvidence(redacted)")
}
func (LogoutPOSTRequestEvidence) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (LogoutPOSTRequestEvidence) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

func (LogoutPOSTResponseEvidence) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "saml.LogoutPOSTResponseEvidence(redacted)")
}
func (LogoutPOSTResponseEvidence) LogValue() slog.Value {
	return slog.StringValue("saml.LogoutPOSTResponseEvidence(redacted)")
}
func (LogoutPOSTResponseEvidence) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (LogoutPOSTResponseEvidence) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
