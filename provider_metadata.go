package sso

import (
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"
)

// OIDCStaticMetadataSpec is explicit startup/provider-administration input for
// the authorization-code profile. It supplies locations only, not discovered
// provider identity, verified keys or permission to make a network request.
// Issuer is limited to 2048 bytes by the provider-registration contract;
// endpoints are limited to 4096 bytes by the selected configuration profile,
// independently of protocol limits. Issuer bytes are never normalized.
type OIDCStaticMetadataSpec struct {
	Issuer                string
	AuthorizationEndpoint string
	TokenEndpoint         string
	JWKSURI               string
}

// OIDCStaticMetadata is immutable validated static configuration. The zero
// value is invalid. Copies share no mutable state or runtime resource. It
// performs no discovery, endpoint fetching, authentication or key validation;
// a selected protocol adapter must enforce its own network and proof policy.
// Diagnostics and implicit encodings deliberately omit configuration values.
type OIDCStaticMetadata struct {
	spec  OIDCStaticMetadataSpec
	valid bool
}

// NewOIDCStaticMetadata validates complete explicit HTTPS locations without I/O.
// OIDC Discovery 1.0 section 3 requires an issuer without query/fragment and
// allows endpoint queries. RFC6749 sections 3.1 and 3.2 forbid fragments.
// Preserve accepted URL bytes for exact issuer comparison and configured query
// parameters; parsing does not establish endpoint ownership or reachability.
func NewOIDCStaticMetadata(spec OIDCStaticMetadataSpec) (OIDCStaticMetadata, error) {
	if len(spec.Issuer) > 2048 {
		return OIDCStaticMetadata{}, ErrInvalidInput
	}
	issuer, err := staticOIDCEndpoint(spec.Issuer)
	if err != nil || issuer.RawQuery != "" || issuer.ForceQuery {
		return OIDCStaticMetadata{}, ErrInvalidInput
	}
	for _, endpoint := range []string{spec.AuthorizationEndpoint, spec.TokenEndpoint, spec.JWKSURI} {
		if _, err := staticOIDCEndpoint(endpoint); err != nil {
			return OIDCStaticMetadata{}, ErrInvalidInput
		}
	}
	return OIDCStaticMetadata{spec: spec, valid: true}, nil
}

func staticOIDCEndpoint(raw string) (*url.URL, error) {
	if len(raw) == 0 || len(raw) > 4096 || !utf8.ValidString(raw) || strings.ContainsAny(raw, "\r\n\t #") {
		return nil, ErrInvalidInput
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.Opaque != "" {
		return nil, ErrInvalidInput
	}
	return parsed, nil
}

// Spec explicitly projects an owned, scalar-only configuration copy for trusted
// composition or encrypted persistence. It never grants provider readiness.
// A zero value returns ErrInvalidInput and a zero projection.
func (m OIDCStaticMetadata) Spec() (OIDCStaticMetadataSpec, error) {
	if !m.valid {
		return OIDCStaticMetadataSpec{}, ErrInvalidInput
	}
	return m.spec, nil
}

func (OIDCStaticMetadata) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("sso.OIDCStaticMetadata(redacted)"))
}

func (OIDCStaticMetadata) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

func (OIDCStaticMetadata) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
