package sso

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

// These structural bounds match the native SAML redirect/POST profiles:
// saml.id_uri_bytes, saml.sp_entity_id, and saml.certificates_per_metadata_entity.
// Certificate byte bounds match saml.maximumCertificateBytes before DER parsing.
const (
	maximumSAMLRegistrationEntityBytes      = 1024
	maximumSAMLRegistrationEndpointBytes    = 2048
	maximumSAMLRegistrationCertificates     = 5
	maximumSAMLRegistrationCertificateBytes = 64 * 1024
)

// SAMLConfigurationSpec is explicit IdP configuration for the selected
// SP-initiated profile, not a metadata document or an SP route. EntityID is an
// exact HTTPS or URN identifier of at most 1024 bytes. RedirectEndpoint is an
// exact HTTPS endpoint of at most 2048 bytes; fixed non-SAML query fields are
// allowed. SigningCertificates contains 1..5 distinct pinned DER values, each
// 1..65536 bytes. Construction borrows this input only until return.
type SAMLConfigurationSpec struct {
	EntityID            string
	RedirectEndpoint    string
	SigningCertificates [][]byte
}

// SAMLConfiguration owns an immutable detached snapshot of bounded explicit
// IdP input. It performs no I/O and establishes no certificate, key, time,
// signature-profile, provider-readiness or domain trust. The native SAML
// constructor must validate the actual DER and protocol profile before use.
// Its zero value is invalid; copies are safe for concurrent reads.
type SAMLConfiguration struct {
	spec SAMLConfigurationSpec
}

// NewSAMLConfiguration checks input shape and bounds before copying certificate
// bytes. It preserves the entity and Redirect endpoint byte-for-byte, imports
// no metadata and performs no network or activation work. It exposes no
// private-key or signing-credential interface.
func NewSAMLConfiguration(spec SAMLConfigurationSpec) (SAMLConfiguration, error) {
	if !validSAMLRegistrationEntity(spec.EntityID) {
		return SAMLConfiguration{}, ErrInvalidInput
	}
	endpoint, ok := samlRegistrationHTTPSURL(spec.RedirectEndpoint, maximumSAMLRegistrationEndpointBytes)
	if !ok || !validSAMLRegistrationFixedQuery(endpoint.RawQuery) {
		return SAMLConfiguration{}, ErrInvalidInput
	}
	if len(spec.SigningCertificates) == 0 || len(spec.SigningCertificates) > maximumSAMLRegistrationCertificates {
		return SAMLConfiguration{}, ErrInvalidInput
	}
	for i, certificate := range spec.SigningCertificates {
		if len(certificate) == 0 || len(certificate) > maximumSAMLRegistrationCertificateBytes {
			return SAMLConfiguration{}, ErrInvalidInput
		}
		for _, previous := range spec.SigningCertificates[:i] {
			if bytes.Equal(previous, certificate) {
				return SAMLConfiguration{}, ErrInvalidInput
			}
		}
	}
	spec.SigningCertificates = cloneSAMLRegistrationCertificates(spec.SigningCertificates)
	return SAMLConfiguration{spec: spec}, nil
}

// Spec explicitly projects a detached copy for trusted configuration
// persistence or protocol composition. The caller owns every returned slice.
// A zero configuration returns ErrInvalidInput and a zero projection.
func (c SAMLConfiguration) Spec() (SAMLConfigurationSpec, error) {
	if c.spec.EntityID == "" {
		return SAMLConfigurationSpec{}, ErrInvalidInput
	}
	spec := c.spec
	spec.SigningCertificates = cloneSAMLRegistrationCertificates(spec.SigningCertificates)
	return spec, nil
}

func cloneSAMLRegistrationCertificates(certificates [][]byte) [][]byte {
	cloned := make([][]byte, len(certificates))
	for i, certificate := range certificates {
		cloned[i] = bytes.Clone(certificate)
	}
	return cloned
}

func validSAMLRegistrationEntity(raw string) bool {
	if len(raw) == 0 || len(raw) > maximumSAMLRegistrationEntityBytes {
		return false
	}
	for _, char := range raw {
		if char <= ' ' || char >= 127 || strings.ContainsRune("\"<>\\^`{|}#", char) {
			return false
		}
	}
	scheme, suffix, found := strings.Cut(raw, ":")
	if !found {
		return false
	}
	if strings.EqualFold(scheme, "https") {
		// Entity identity is exact, not navigated. Fold only the validation
		// copy, as the native SAML profile does for configured entity IDs.
		_, ok := samlRegistrationHTTPSURL("https:"+suffix, maximumSAMLRegistrationEntityBytes)
		return ok
	}
	if !strings.EqualFold(scheme, "urn") {
		return false
	}
	if _, err := url.PathUnescape(raw); err != nil {
		return false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.User != nil || parsed.Host != "" || parsed.Opaque == "" {
		return false
	}
	namespace, name, found := strings.Cut(parsed.Opaque, ":")
	if !found || namespace == "" || name == "" {
		return false
	}
	parsed.Scheme = scheme
	return parsed.String() == raw
}

func samlRegistrationHTTPSURL(raw string, maximum int) (url.URL, bool) {
	if len(raw) == 0 || len(raw) > maximum || strings.ContainsAny(raw, "\\#") {
		return url.URL{}, false
	}
	for i := range len(raw) {
		if raw[i] < '!' || raw[i] > '~' {
			return url.URL{}, false
		}
	}
	if _, err := url.PathUnescape(raw); err != nil {
		return url.URL{}, false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil ||
		parsed.Opaque != "" || parsed.String() != raw || !utf8.ValidString(parsed.Path) ||
		strings.ContainsRune(parsed.Path, '\\') || strings.ContainsFunc(parsed.Path, unicode.IsControl) {
		return url.URL{}, false
	}
	for part := range strings.SplitSeq(parsed.Path, "/") {
		if part == "." || part == ".." {
			return url.URL{}, false
		}
	}
	return *parsed, true
}

func validSAMLRegistrationFixedQuery(query string) bool {
	values, err := url.ParseQuery(query)
	if err != nil {
		return false
	}
	for name := range values {
		switch strings.ToLower(name) {
		case "samlrequest", "samlresponse", "relaystate", "sigalg", "signature":
			return false // Only the native adapter owns signed binding fields.
		}
	}
	return true
}

func (SAMLConfiguration) Format(state fmt.State, _ rune) {
	_, _ = fmt.Fprint(state, "sso.SAMLConfiguration(redacted)")
}

func (SAMLConfiguration) LogValue() slog.Value {
	return slog.StringValue("sso.SAMLConfiguration(redacted)")
}

func (SAMLConfiguration) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (SAMLConfiguration) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// ProviderRegisterSamlRequest is intent to register a disabled SP-initiated
// SAML provider with explicit IdP fields. Domains remain pending verification,
// never ownership proof. No SP/ACS URL, private-key or signing-credential
// interface, metadata import or activation flag is accepted. Domains are
// borrowed during use and must not be
// mutated; keep the original command, key and input unchanged across retries.
// Only the native owner may authorize and persist the operation.
type ProviderRegisterSamlRequest struct {
	CommandID      identity.CommandID
	OrganizationID string
	Configuration  SAMLConfiguration
	Domains        []string
	Mapping        AttributeMapping
	IdempotencyKey identity.IdempotencyKey
}

// Validate checks bounded structural intent without authenticating a caller,
// proving domains, validating DER or performing I/O. Native protocol validation
// remains mandatory before persistence or use.
func (r ProviderRegisterSamlRequest) Validate() error {
	if _, err := identity.ParseCommandID(string(r.CommandID)); err != nil {
		return ErrInvalidInput
	}
	if !providerClaimName(r.OrganizationID) || r.IdempotencyKey == (identity.IdempotencyKey{}) ||
		r.Configuration.spec.EntityID == "" || len(r.Domains) == 0 || len(r.Domains) > 128 {
		return ErrInvalidInput
	}
	if _, err := r.Mapping.Spec(); err != nil {
		return ErrInvalidInput
	}
	seen := make(map[string]struct{}, len(r.Domains))
	for _, domain := range r.Domains {
		if len(domain) == 0 || len(domain) > 253 {
			return ErrInvalidInput
		}
		canonical, err := organization.CanonicalDomain(domain)
		if _, duplicate := seen[domain]; err != nil || canonical != domain || duplicate {
			return ErrInvalidInput
		}
		seen[domain] = struct{}{}
	}
	return nil
}

func (ProviderRegisterSamlRequest) Format(state fmt.State, _ rune) {
	_, _ = fmt.Fprint(state, "sso.ProviderRegisterSamlRequest(redacted)")
}

func (ProviderRegisterSamlRequest) LogValue() slog.Value {
	return slog.StringValue("sso.ProviderRegisterSamlRequest(redacted)")
}

func (ProviderRegisterSamlRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (ProviderRegisterSamlRequest) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// ProviderRegisterSamlResult contains disabled-provider metadata and the
// original durable completion, never certificate or login authority. The count
// describes pending domain-verification requirements rather than proof truth.
type ProviderRegisterSamlResult struct {
	Provider                     Provider
	VerificationRequirementCount uint32
	Completion                   Completion
}
