package saml

import (
	"context"
	"crypto"
	"encoding/xml"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// LogoutRedirectConfig contains the exact, already-approved entity identifiers
// and IdP HTTP-Redirect logout endpoint. IdentityProviderURL may carry fixed
// non-SAML query parameters. It is not the SP's inbound HTTP-POST SLO route.
type LogoutRedirectConfig struct {
	SPEntityID               string
	IdentityProviderEntityID string
	IdentityProviderURL      string
}

// LogoutRedirectProfile is an immutable outbound SP session-participant wire
// profile. It performs no provider admission, correlation, replay, local-session
// revocation or remote logout. Its zero value cannot render a redirect.
type LogoutRedirectProfile struct {
	config   LogoutRedirectConfig
	endpoint url.URL
}

// NewLogoutRedirectProfile validates the static shape of the approved entity
// identifiers and endpoint without changing their bytes or contacting the IdP.
// Provider registration must already have approved them and the active signer.
// Unsupported or malformed input returns the redacted ErrInvalidInput.
func NewLogoutRedirectProfile(config LogoutRedirectConfig) (LogoutRedirectProfile, error) {
	if !samlSPEntityID(config.SPEntityID) || !samlSPEntityID(config.IdentityProviderEntityID) {
		return LogoutRedirectProfile{}, ErrInvalidInput
	}
	endpoint, ok := samlHTTPSURL(config.IdentityProviderURL, maximumEndpointBytes, true)
	if !ok || !validFixedRedirectQuery(endpoint.RawQuery) {
		return LogoutRedirectProfile{}, ErrInvalidInput
	}
	return LogoutRedirectProfile{config: config, endpoint: endpoint}, nil
}

// LogoutNameID preserves the signed, verified NameID and its optional qualifiers
// from authenticated local correlation. Value is nonempty UTF-8, at most 512
// bytes, without controls, invalid XML characters or all-whitespace content,
// matching the supported login subject boundary. SubjectFormat is the supported
// persistent or email NameID URI. Nonempty qualifiers must match the exact IdP/SP
// identifiers respectively. Nothing is normalized, inferred or made authoritative
// by this value. Implicit formatting and serialization redact or refuse it.
type LogoutNameID struct {
	Value           string
	SubjectFormat   string
	NameQualifier   string
	SPNameQualifier string
}

// LogoutRequest carries the original ID, issue time, verified NameID and exactly
// one SessionIndex already selected by the authenticated local correlation owner.
// SessionIndex is nonempty XML-compatible UTF-8 without controls, at most 2048 bytes.
// The ID uses the ASCII NCName subset, at most 2048 bytes; IssuedAt must be a
// nonzero representable XML time. The caller owns clock, expiry and replay policy.
//
// RelayState is absent when empty; otherwise it is an already-issued opaque
// ASCII URL-safe handle of at most 80 bytes, never raw application state. This
// value creates no transaction, capability, session or revocation authority.
type LogoutRequest struct {
	ID           string
	IssuedAt     time.Time
	NameID       LogoutNameID
	SessionIndex string
	RelayState   string
}

// LogoutRedirect contains only the signed browser wire URL. It establishes
// neither local nor remote logout success. Use URL explicitly to disclose it;
// implicit formatting and serialization redact or refuse the sensitive URL.
type LogoutRedirect struct{ destination url.URL }

// URL returns a copy of the signed wire URL. It says nothing about whether the
// stored correlation is still usable. A zero result returns ErrInvalidInput.
func (r LogoutRedirect) URL() (url.URL, error) {
	if r.destination.Host == "" {
		return url.URL{}, ErrInvalidInput
	}
	return r.destination, nil
}

// Redirect encodes only the selected SAML 2.0 SP-to-IdP LogoutRequest and signs
// the exact HTTP-Redirect binding fields using the fixed RSA-PSS/SHA-256 profile.
// The signer is borrowed synchronously; it must have bounded latency and must
// not be changed during the call. No I/O, clock lookup or stored mutation occurs.
//
// A nil context, invalid request/profile or unsupported signing key returns
// ErrInvalidInput. A failed or noncompliant signature returns ErrSigning.
// Cancellation is checked before signing and before disclosure and returns
// ctx.Err(); standard-library XML encoding and signing are not interruptible.
// Every failure returns a zero redirect. Concurrent calls are safe when the
// borrowed signer supports them; the caller owns correlation and logout policy.
func (p LogoutRedirectProfile) Redirect(ctx context.Context, request LogoutRequest, signer crypto.Signer) (LogoutRedirect, error) {
	if ctx == nil || p.endpoint.Host == "" || !p.validRequest(request) || signer == nil {
		return LogoutRedirect{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return LogoutRedirect{}, err
	}
	key, ok := redirectSigningKey(signer)
	if !ok {
		return LogoutRedirect{}, ErrInvalidInput
	}
	encoded, err := p.encodeLogoutRequest(request)
	if err != nil {
		return LogoutRedirect{}, err
	}
	destination, err := signRedirectRequest(ctx, p.endpoint, encoded, request.RelayState, signer, key)
	if err != nil {
		return LogoutRedirect{}, err
	}
	return LogoutRedirect{destination: destination}, nil
}

func (p LogoutRedirectProfile) validRequest(request LogoutRequest) bool {
	// Reuse the unchanged ID/time/opaque-RelayState policy of the selected
	// outbound AuthnRequest binding, not a generic XML message profile.
	if !(AuthnRequest{ID: request.ID, IssuedAt: request.IssuedAt, RelayState: request.RelayState}).valid() {
		return false
	}
	name := request.NameID
	if !validLogoutText(name.Value, 512) || strings.TrimSpace(name.Value) == "" ||
		(name.SubjectFormat != samlPersistentNameID && name.SubjectFormat != samlEmailNameID) ||
		(name.NameQualifier != "" && name.NameQualifier != p.config.IdentityProviderEntityID) ||
		(name.SPNameQualifier != "" && name.SPNameQualifier != p.config.SPEntityID) {
		return false
	}
	// Profiles §4.4.4.1 requires SessionIndex for the initiating session
	// participant. This bounded profile targets one correlated SP session;
	// it does not impose that requirement on inbound IdP LogoutRequests.
	return validLogoutText(request.SessionIndex, maximumEndpointBytes)
}

func validLogoutText(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	// encoding/xml replaces XML 1.0-invalid code points. Reject them before
	// encoding so a verified NameID or SessionIndex can never change on wire.
	return !strings.ContainsFunc(value, func(character rune) bool {
		return unicode.IsControl(character) || character == '\uFFFE' || character == '\uFFFF'
	})
}

type logoutRequestXML struct {
	XMLName      xml.Name        `xml:"urn:oasis:names:tc:SAML:2.0:protocol LogoutRequest"`
	ID           string          `xml:"ID,attr"`
	Version      string          `xml:"Version,attr"`
	IssueTime    string          `xml:"IssueInstant,attr"`
	Destination  string          `xml:"Destination,attr"`
	Issuer       string          `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	NameID       logoutNameIDXML `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
	SessionIndex string          `xml:"urn:oasis:names:tc:SAML:2.0:protocol SessionIndex"`
}

type logoutNameIDXML struct {
	Value           string `xml:",chardata"`
	Format          string `xml:"Format,attr"`
	NameQualifier   string `xml:"NameQualifier,attr,omitempty"`
	SPNameQualifier string `xml:"SPNameQualifier,attr,omitempty"`
}

func (p LogoutRedirectProfile) encodeLogoutRequest(request LogoutRequest) (string, error) {
	document, err := xml.Marshal(logoutRequestXML{
		ID: request.ID, Version: "2.0", IssueTime: request.IssuedAt.UTC().Format(time.RFC3339Nano),
		Destination: p.config.IdentityProviderURL, Issuer: p.config.SPEntityID,
		NameID: logoutNameIDXML{Value: request.NameID.Value, Format: request.NameID.SubjectFormat,
			NameQualifier: request.NameID.NameQualifier, SPNameQualifier: request.NameID.SPNameQualifier},
		SessionIndex: request.SessionIndex,
	})
	if err != nil {
		return "", ErrInvalidInput
	}
	return deflateRedirectRequest(document)
}

func (LogoutNameID) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("saml.LogoutNameID(redacted)"))
}
func (LogoutNameID) LogValue() slog.Value         { return slog.StringValue("saml.LogoutNameID(redacted)") }
func (LogoutNameID) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (LogoutNameID) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

func (LogoutRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("saml.LogoutRequest(redacted)"))
}
func (LogoutRequest) LogValue() slog.Value         { return slog.StringValue("saml.LogoutRequest(redacted)") }
func (LogoutRequest) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (LogoutRequest) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

func (LogoutRedirect) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("saml.LogoutRedirect(redacted)"))
}
func (LogoutRedirect) LogValue() slog.Value         { return slog.StringValue("saml.LogoutRedirect(redacted)") }
func (LogoutRedirect) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (LogoutRedirect) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
