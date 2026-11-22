package sso

import (
	"fmt"
	"log/slog"
	"unicode"
	"unicode/utf8"
)

// AttributePresence preserves a selected claim's absence, explicit null or
// supplied value. Its zero value is invalid; absence is an explicit observation.
type AttributePresence string

const (
	// AttributeAbsent records that the validated source did not contain a claim.
	AttributeAbsent AttributePresence = "absent"
	// AttributeNull records an explicit null in the validated source.
	AttributeNull AttributePresence = "null"
	// AttributeValue records an exact supported scalar, including false or empty.
	AttributeValue AttributePresence = "value"
)

// AttributeSource identifies the protocol evidence channel, not claim authority.
type AttributeSource string

const (
	// AttributeSourceOIDCIDToken identifies an already validated signed ID token.
	// Selecting it does not validate a signature, issuer, audience or claim.
	AttributeSourceOIDCIDToken AttributeSource = "oidc-id-token"
	// AttributeSourceOAuthIdentityEndpoint identifies evidence from a configured,
	// authenticated OAuth identity endpoint, never an access token alone. This
	// label does not authenticate the endpoint, subject or supplied claims.
	AttributeSourceOAuthIdentityEndpoint AttributeSource = "oauth-identity-endpoint"
)

// AttributeProvenance binds a claim observation to its exact configured provider,
// positive validation-profile version, verified HTTPS issuer and evidence source.
// It is descriptive data supplied by the protocol validator, never proof by
// itself. The issuer is bounded to 2048 bytes, as in OIDCStaticMetadataSpec.
type AttributeProvenance struct {
	ProviderID             ProviderID
	ProviderProfileVersion uint64
	Issuer                 string
	Source                 AttributeSource
}

func (p AttributeProvenance) validate() error {
	if !providerClaimName(string(p.ProviderID)) || p.ProviderProfileVersion == 0 || len(p.Issuer) > 2048 {
		return ErrInvalidInput
	}
	switch p.Source {
	case AttributeSourceOIDCIDToken, AttributeSourceOAuthIdentityEndpoint:
	default:
		return ErrInvalidInput
	}
	issuer, err := staticOIDCEndpoint(p.Issuer)
	if err != nil || issuer.RawQuery != "" || issuer.ForceQuery {
		return ErrInvalidInput
	}
	return nil
}

// VerifiedAttributeSpec describes a flat, case-exact claim and its evidence
// metadata. Names use AttributeMappingSpec's 1..128-byte printable ASCII grammar.
// Absent/null require both scalar pointers nil; value requires exactly one.
// The finite mapping profile supports strings and booleans, not JSON objects,
// arrays, numbers or implicit coercion. Strings are 0..512 valid UTF-8 bytes
// without controls, using ProtocolAssertion's subject bound for every mapped
// scalar. No name/value normalization is performed.
//
// Verified records the validator's evidence assessment. Authoritative records
// the selected mapping policy's source-of-truth assessment; neither implies the
// other, and neither flag grants identity or privilege. Constructors do not
// authenticate those assessments. Callers must not supply token or credential
// bytes; exchanged tokens belong exclusively to the enterprise-token boundary.
// Input pointers are borrowed only for the duration of construction.
type VerifiedAttributeSpec struct {
	Name          string
	Presence      AttributePresence
	StringValue   *string
	BooleanValue  *bool
	Verified      bool
	Authoritative bool
	Provenance    AttributeProvenance
}

func (s VerifiedAttributeSpec) validate() error {
	if !providerClaimName(s.Name) || s.Provenance.validate() != nil {
		return ErrInvalidInput
	}
	switch s.Presence {
	case AttributeAbsent, AttributeNull:
		if s.StringValue != nil || s.BooleanValue != nil {
			return ErrInvalidInput
		}
	case AttributeValue:
		if (s.StringValue == nil) == (s.BooleanValue == nil) {
			return ErrInvalidInput
		}
		if s.StringValue != nil && !protocolAssertionText(*s.StringValue, 0, 512) {
			return ErrInvalidInput
		}
	default:
		return ErrInvalidInput
	}
	return nil
}

func cloneVerifiedAttributeSpec(s VerifiedAttributeSpec) VerifiedAttributeSpec {
	if s.StringValue != nil {
		value := *s.StringValue
		s.StringValue = &value
	}
	if s.BooleanValue != nil {
		value := *s.BooleanValue
		s.BooleanValue = &value
	}
	return s
}

// VerifiedAttribute is an immutable detached claim observation. Zero is invalid.
// Concurrent reads of copies are supported. It owns no token, network or storage
// resources and performs no mapping, authorization or authentication.
type VerifiedAttribute struct {
	spec  VerifiedAttributeSpec
	valid bool
}

// NewVerifiedAttribute validates bounded shape and snapshots each scalar. It
// preserves presence and trust flags without inferring verification, ownership
// or authority. Only a trusted protocol validator and current mapping-policy
// owner can establish the supplied metadata's truth. Invalid shape returns only
// ErrInvalidInput and no usable observation, without echoing supplied data.
func NewVerifiedAttribute(spec VerifiedAttributeSpec) (VerifiedAttribute, error) {
	if err := spec.validate(); err != nil {
		return VerifiedAttribute{}, ErrInvalidInput
	}
	return VerifiedAttribute{spec: cloneVerifiedAttributeSpec(spec), valid: true}, nil
}

// Spec explicitly projects detached evidence for trusted SSO policy evaluation.
// Mutating the returned pointers does not change this observation. Zero returns
// ErrInvalidInput and no evidence; projection itself establishes no authority.
func (a VerifiedAttribute) Spec() (VerifiedAttributeSpec, error) {
	if !a.valid {
		return VerifiedAttributeSpec{}, ErrInvalidInput
	}
	return cloneVerifiedAttributeSpec(a.spec), nil
}

func protocolAssertionText(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func (AttributeProvenance) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("sso.AttributeProvenance(redacted)"))
}

func (AttributeProvenance) LogValue() slog.Value {
	return slog.StringValue("sso.AttributeProvenance(redacted)")
}

func (AttributeProvenance) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (AttributeProvenance) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

func (VerifiedAttributeSpec) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("sso.VerifiedAttributeSpec(redacted)"))
}

func (VerifiedAttributeSpec) LogValue() slog.Value {
	return slog.StringValue("sso.VerifiedAttributeSpec(redacted)")
}

func (VerifiedAttributeSpec) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (VerifiedAttributeSpec) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

func (VerifiedAttribute) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("sso.VerifiedAttribute(redacted)"))
}

func (VerifiedAttribute) LogValue() slog.Value {
	return slog.StringValue("sso.VerifiedAttribute(redacted)")
}

func (VerifiedAttribute) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (VerifiedAttribute) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
