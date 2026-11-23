package saml

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"time"
	"unicode/utf8"

	"github.com/knroy/go-xml/v2/c14n"
)

// LogoutPOSTResponseConfig selects the installed SP entity and already-approved
// exact HTTPS IdP POST response endpoint. Fixed non-SAML query parameters are
// preserved; configuration never comes from the inbound request's Destination.
type LogoutPOSTResponseConfig struct {
	SPEntityID          string
	IdentityProviderURL string
}

// LogoutPOSTResponseProfile generates only signed SP-to-IdP POST LogoutResponse
// wire messages. It is immutable and safe for concurrent use; zero denies.
// It neither chooses status nor admits providers, correlates/replays requests,
// revokes sessions, builds HTML, or handles RelayState or browser transport.
type LogoutPOSTResponseProfile struct{ config LogoutPOSTResponseConfig }

// NewLogoutPOSTResponseProfile validates and retains exact approved public
// identities without fetching metadata or normalizing endpoint bytes.
func NewLogoutPOSTResponseProfile(config LogoutPOSTResponseConfig) (LogoutPOSTResponseProfile, error) {
	if !samlSPEntityID(config.SPEntityID) {
		return LogoutPOSTResponseProfile{}, ErrInvalidInput
	}
	endpoint, ok := samlHTTPSURL(config.IdentityProviderURL, maximumEndpointBytes, true)
	if !ok || !validFixedRedirectQuery(endpoint.RawQuery) {
		return LogoutPOSTResponseProfile{}, ErrInvalidInput
	}
	return LogoutPOSTResponseProfile{config: config}, nil
}

// LogoutResponse contains the original response ID, exact authenticated request
// ID, issue time and selected status from the native owner. IDs are nonempty
// NCNames of at most 2048 bytes; times must be nonzero representable XML UTC
// instants. Status follows the installed closed LogoutPOSTStatus selection,
// including Success/PartialLogout. It conveys no local/remote revocation proof.
type LogoutResponse struct {
	ID, InResponseTo string
	IssuedAt         time.Time
	Status           LogoutPOSTStatus
}

// LogoutPOSTResponseFields contains only the exact form destination and Base64
// SAMLResponse value. It contains no HTML, RelayState, subject or revocation
// flags. The transport separately owns route admission, correlation and the
// exact echo of optional bounded RelayState under Bindings §3.5.3.
type LogoutPOSTResponseFields struct{ Destination, SAMLResponse string }

// SignedLogoutPOSTResponse is immutable generated signed wire output. Explicit
// Fields access is required to release it; implicit serialization is refused.
// It does not establish that the original local logout committed or that the
// IdP received the response. The zero value discloses no fields.
type SignedLogoutPOSTResponse struct{ fields LogoutPOSTResponseFields }

// Fields returns a detached value copy of the exact destination and encoded
// SAMLResponse, or ErrInvalidInput for a zero/failed result.
func (r SignedLogoutPOSTResponse) Fields() (LogoutPOSTResponseFields, error) {
	if r.fields.SAMLResponse == "" {
		return LogoutPOSTResponseFields{}, ErrInvalidInput
	}
	return r.fields, nil
}

func validLogoutPOSTResponseID(value string) bool {
	// encoding/xml replaces invalid UTF-8 rather than returning an error.
	// Never sign an identifier different from the one supplied by the caller.
	return validSAMLID(value) && utf8.ValidString(value)
}

// Sign generates and signs only its own bounded LogoutResponse XML, never
// caller-supplied XML. It signs the exact document root with a same-document
// reference, enveloped-signature plus exclusive canonicalization without
// comments, SHA-256 and fixed RSA-PSS/SHA-256 (MGF1 SHA-256, 32-byte salt).
// The borrowed installed signer must have bounded synchronous latency and not
// be mutated concurrently; concurrent calls require a concurrency-safe signer.
// There is no I/O, clock lookup, stored mutation or certificate validation here.
//
// Nil context, invalid configuration/input or unsupported keys return the
// redacted ErrInvalidInput; failed/noncompliant signing returns ErrSigning.
// Cancellation is checked between bounded operations and before disclosure,
// returning ctx.Err(); standard-library crypto cannot be interrupted midway.
// Every failure returns a zero result with no usable wire fields.
func (p LogoutPOSTResponseProfile) Sign(ctx context.Context, response LogoutResponse, signer crypto.Signer) (SignedLogoutPOSTResponse, error) {
	if ctx == nil || p.config.SPEntityID == "" || !validLogoutPOSTResponseID(response.ID) ||
		!validLogoutPOSTResponseID(response.InResponseTo) || !validSAMLTime(response.IssuedAt) ||
		!validLogoutPOSTResponseStatus(response.Status) || signer == nil {
		return SignedLogoutPOSTResponse{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return SignedLogoutPOSTResponse{}, err
	}
	borrowedKey, ok := redirectSigningKey(signer)
	if !ok {
		return SignedLogoutPOSTResponse{}, ErrInvalidInput
	}
	// Verification must not borrow mutable public-key storage from Sign.
	key := &rsa.PublicKey{N: new(big.Int).Set(borrowedKey.N), E: borrowedKey.E}
	document := logoutPOSTResponseXML{
		ID: response.ID, InResponseTo: response.InResponseTo, Version: "2.0",
		IssueInstant: response.IssuedAt.UTC().Format(time.RFC3339Nano),
		Destination:  p.config.IdentityProviderURL, Issuer: p.config.SPEntityID,
		Status: logoutPOSTResponseStatusXML{Code: logoutPOSTResponseCodeXML{Value: string(response.Status.Code)}},
	}
	if response.Status.Subcode != "" {
		document.Status.Code.Subcode = &logoutPOSTResponseCodeXML{Value: string(response.Status.Subcode)}
	}
	unsignedXML, err := xml.Marshal(document)
	if err != nil {
		return SignedLogoutPOSTResponse{}, ErrInvalidInput
	}
	unsigned, err := parseSAMLDocument(ctx, unsignedXML)
	if err != nil {
		return SignedLogoutPOSTResponse{}, err
	}
	exclusive := c14n.Options{Algorithm: c14n.Exclusive10}
	rootDigest, err := c14n.Digest(sha256.New(), unsigned, exclusive)
	if err != nil {
		return SignedLogoutPOSTResponse{}, ErrSigning
	}
	info := logoutPOSTResponseSignedInfoXML{
		Canonicalization: logoutPOSTResponseMethodXML{Algorithm: string(c14n.Exclusive10)},
		Method:           logoutPOSTResponseMethodXML{Algorithm: SignatureAlgorithmRSAPSSSHA256},
		Reference: logoutPOSTResponseReferenceXML{
			URI: "#" + response.ID,
			Transforms: logoutPOSTResponseTransformsXML{Methods: []logoutPOSTResponseMethodXML{
				{Algorithm: xmlEnvelopedTransform}, {Algorithm: string(c14n.Exclusive10)},
			}},
			DigestMethod: logoutPOSTResponseMethodXML{Algorithm: xmlDigestSHA256},
			DigestValue:  base64.StdEncoding.EncodeToString(rootDigest),
		},
	}
	infoXML, err := xml.Marshal(info)
	if err != nil {
		return SignedLogoutPOSTResponse{}, ErrInvalidInput
	}
	infoNode, err := parseSAMLDocument(ctx, infoXML)
	if err != nil {
		return SignedLogoutPOSTResponse{}, err
	}
	digest, err := c14n.Digest(sha256.New(), infoNode, exclusive)
	if err != nil {
		return SignedLogoutPOSTResponse{}, ErrSigning
	}
	if err := ctx.Err(); err != nil {
		return SignedLogoutPOSTResponse{}, err
	}
	// Retain the actual digest and fixed verification policy independently of
	// the mutable digest/options passed to a borrowed signer implementation.
	signerDigest := append([]byte(nil), digest...)
	signature, err := signer.Sign(rand.Reader, signerDigest, &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: sha256.Size})
	if canceled := ctx.Err(); canceled != nil {
		return SignedLogoutPOSTResponse{}, canceled
	}
	if err != nil || len(signature) != key.Size() ||
		rsa.VerifyPSS(key, crypto.SHA256, digest, signature, &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: sha256.Size}) != nil {
		return SignedLogoutPOSTResponse{}, ErrSigning
	}
	document.Signature = &logoutPOSTResponseSignatureXML{SignedInfo: info, Value: base64.StdEncoding.EncodeToString(signature)}
	wire, err := xml.Marshal(document)
	if err != nil {
		return SignedLogoutPOSTResponse{}, ErrInvalidInput
	}
	// Verify exact generated-root coverage after namespace composition, before
	// disclosing any output. This parses only owned generated XML, never input.
	root, err := parseSAMLDocument(ctx, wire)
	if err != nil {
		return SignedLogoutPOSTResponse{}, err
	}
	if _, err := verifySAMLSignature(ctx, root, []crypto.PublicKey{key}); err != nil {
		if canceled := ctx.Err(); canceled != nil {
			return SignedLogoutPOSTResponse{}, canceled
		}
		return SignedLogoutPOSTResponse{}, ErrSigning
	}
	fields := LogoutPOSTResponseFields{Destination: p.config.IdentityProviderURL, SAMLResponse: base64.StdEncoding.EncodeToString(wire)}
	if err := ctx.Err(); err != nil {
		return SignedLogoutPOSTResponse{}, err
	}
	return SignedLogoutPOSTResponse{fields: fields}, nil
}

// SignWithSPSigningCredential applies ValidateSPSigningCredential's exact
// original plaintext bundle and half-open certificate lifetime policy, then
// Sign's fixed XML profile without exposing its parsed private key. It returns
// the original certificate NotAfter as an exclusive cutoff, never a renewed
// lifetime. Every failure returns a zero result and zero cutoff.
//
// The bundle is borrowed synchronously without modification or retention; the
// caller must clear its secret plaintext buffer after use and must not log or
// concurrently mutate it. Clearing it does not erase Go-managed parsed key
// objects. No provider admission, trust-chain validation, stored mutation or
// clock lookup occurs. Sign's errors/cancellation and concurrency rules apply.
func (p LogoutPOSTResponseProfile) SignWithSPSigningCredential(ctx context.Context, response LogoutResponse, bundle []byte, now time.Time) (SignedLogoutPOSTResponse, time.Time, error) {
	key, certificate, err := parseSPSigningCredentialBundle(ctx, bundle, now)
	if err != nil {
		return SignedLogoutPOSTResponse{}, time.Time{}, err
	}
	result, err := p.Sign(ctx, response, key)
	if err != nil {
		return SignedLogoutPOSTResponse{}, time.Time{}, err
	}
	if err := ctx.Err(); err != nil {
		return SignedLogoutPOSTResponse{}, time.Time{}, err
	}
	return result, certificate.NotAfter, nil
}

func validLogoutPOSTResponseStatus(status LogoutPOSTStatus) bool {
	switch status.Code {
	case LogoutStatusSuccess, LogoutStatusRequester, LogoutStatusResponder, LogoutStatusVersionMismatch:
	default:
		return false
	}
	if status.Subcode == "" {
		return true
	}
	if status.Code == LogoutStatusSuccess && status.Subcode != LogoutStatusPartialLogout {
		return false
	}
	switch status.Subcode {
	case LogoutStatusPartialLogout, LogoutStatusUnknownPrincipal, LogoutStatusRequestDenied, LogoutStatusUnsupportedBinding:
		return true
	default:
		return false
	}
}

type logoutPOSTResponseXML struct {
	XMLName      xml.Name                        `xml:"urn:oasis:names:tc:SAML:2.0:protocol LogoutResponse"`
	ID           string                          `xml:"ID,attr"`
	InResponseTo string                          `xml:"InResponseTo,attr"`
	Version      string                          `xml:"Version,attr"`
	IssueInstant string                          `xml:"IssueInstant,attr"`
	Destination  string                          `xml:"Destination,attr"`
	Issuer       string                          `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Signature    *logoutPOSTResponseSignatureXML `xml:"http://www.w3.org/2000/09/xmldsig# Signature,omitempty"`
	Status       logoutPOSTResponseStatusXML     `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
}
type logoutPOSTResponseStatusXML struct {
	Code logoutPOSTResponseCodeXML `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusCode"`
}
type logoutPOSTResponseCodeXML struct {
	Value   string                     `xml:"Value,attr"`
	Subcode *logoutPOSTResponseCodeXML `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusCode,omitempty"`
}
type logoutPOSTResponseSignatureXML struct {
	SignedInfo logoutPOSTResponseSignedInfoXML `xml:"http://www.w3.org/2000/09/xmldsig# SignedInfo"`
	Value      string                          `xml:"http://www.w3.org/2000/09/xmldsig# SignatureValue"`
}
type logoutPOSTResponseSignedInfoXML struct {
	XMLName          xml.Name                       `xml:"http://www.w3.org/2000/09/xmldsig# SignedInfo"`
	Canonicalization logoutPOSTResponseMethodXML    `xml:"http://www.w3.org/2000/09/xmldsig# CanonicalizationMethod"`
	Method           logoutPOSTResponseMethodXML    `xml:"http://www.w3.org/2000/09/xmldsig# SignatureMethod"`
	Reference        logoutPOSTResponseReferenceXML `xml:"http://www.w3.org/2000/09/xmldsig# Reference"`
}
type logoutPOSTResponseReferenceXML struct {
	URI          string                          `xml:"URI,attr"`
	Transforms   logoutPOSTResponseTransformsXML `xml:"http://www.w3.org/2000/09/xmldsig# Transforms"`
	DigestMethod logoutPOSTResponseMethodXML     `xml:"http://www.w3.org/2000/09/xmldsig# DigestMethod"`
	DigestValue  string                          `xml:"http://www.w3.org/2000/09/xmldsig# DigestValue"`
}
type logoutPOSTResponseTransformsXML struct {
	Methods []logoutPOSTResponseMethodXML `xml:"http://www.w3.org/2000/09/xmldsig# Transform"`
}
type logoutPOSTResponseMethodXML struct {
	Algorithm string `xml:"Algorithm,attr"`
}

func (LogoutResponse) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "saml.LogoutResponse(redacted)")
}
func (LogoutResponse) LogValue() slog.Value         { return slog.StringValue("saml.LogoutResponse(redacted)") }
func (LogoutResponse) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (LogoutResponse) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (LogoutPOSTResponseFields) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "saml.LogoutPOSTResponseFields(redacted)")
}
func (LogoutPOSTResponseFields) LogValue() slog.Value {
	return slog.StringValue("saml.LogoutPOSTResponseFields(redacted)")
}
func (LogoutPOSTResponseFields) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (LogoutPOSTResponseFields) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (SignedLogoutPOSTResponse) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "saml.SignedLogoutPOSTResponse(redacted)")
}
func (SignedLogoutPOSTResponse) LogValue() slog.Value {
	return slog.StringValue("saml.SignedLogoutPOSTResponse(redacted)")
}
func (SignedLogoutPOSTResponse) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (SignedLogoutPOSTResponse) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
