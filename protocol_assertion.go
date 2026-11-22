package sso

import (
	"fmt"
	"log/slog"
	"slices"
	"unicode/utf8"

	organization "github.com/faustbrian/go-organization"
)

// ProtocolAssertion is detached protocol evidence for the exact selected SSO
// provider and organization. ProviderSubject is an unchanged stable subject of
// 1..512 UTF-8 bytes without controls. Both versions are positive. Up to 256
// distinct flat attributes preserve presence, provenance and trust assessments;
// nil means no attribute observations, not permission to retain earlier values.
//
// Protocol adapters own authentication of this evidence. Neither construction
// nor validation grants provider/organization, JIT, membership, role or session
// authority. SSO must apply current policy for every existing or new subject.
// The caller owns exported fields and slices; call Validate after mutation and
// before consumption. Attribute values themselves are immutable.
//
// TokenReference is optional, nonsecret token-custody correlation, not a token,
// recoverable storage, lookup permission or proof of vault custody. Its provider,
// organization and subject must match this assertion exactly. Native transaction
// admission must separately check tenant, original callback command and activated
// credential generation before any token linkage; they are not assertion fields.
// Raw token material must never enter this evidence or its mapped attributes.
type ProtocolAssertion struct {
	ProviderID             ProviderID
	OrganizationID         organization.ID
	ProviderSubject        string
	Attributes             []VerifiedAttribute
	ProviderProfileVersion uint64
	MappingVersion         uint64
	TokenReference         TokenVersion
}

// NewProtocolAssertion validates the complete bounded shape before cloning the
// attribute collection. It does not authenticate claims, check current provider
// or mapping authority, perform I/O or establish a login. Invalid input returns
// only the redacted ErrInvalidInput and no usable assertion.
func NewProtocolAssertion(input ProtocolAssertion) (ProtocolAssertion, error) {
	if err := input.Validate(); err != nil {
		return ProtocolAssertion{}, ErrInvalidInput
	}
	input.Attributes = slices.Clone(input.Attributes)
	return input, nil
}

// Validate checks shape and exact attribute provider/profile binding without
// normalization, mapping or authentication. Every observation must have the same
// issuer and source; no precedence is inferred between different authorities.
// Attribute names are case-exact; duplicate observations are invalid.
func (a ProtocolAssertion) Validate() error {
	if !providerClaimName(string(a.ProviderID)) || !protocolAssertionOrganizationID(a.OrganizationID) {
		return ErrInvalidInput
	}
	if !protocolAssertionText(a.ProviderSubject, 1, 512) {
		return ErrInvalidInput
	}
	if a.ProviderProfileVersion == 0 || a.MappingVersion == 0 || len(a.Attributes) > 256 {
		return ErrInvalidInput
	}
	if a.TokenReference != (TokenVersion{}) {
		token, err := a.TokenReference.Spec()
		if err != nil || token.ProviderID != a.ProviderID || token.OrganizationID != a.OrganizationID || token.ProviderSubject != a.ProviderSubject {
			return ErrInvalidInput
		}
	}
	seen := make(map[string]struct{}, len(a.Attributes))
	var provenance AttributeProvenance
	for index, attribute := range a.Attributes {
		if !attribute.valid {
			return ErrInvalidInput
		}
		spec := attribute.spec
		if spec.Provenance.ProviderID != a.ProviderID || spec.Provenance.ProviderProfileVersion != a.ProviderProfileVersion {
			return ErrInvalidInput
		}
		if index == 0 {
			provenance = spec.Provenance
		} else if spec.Provenance != provenance {
			return ErrInvalidInput
		}
		if _, duplicate := seen[spec.Name]; duplicate {
			return ErrInvalidInput
		}
		seen[spec.Name] = struct{}{}
	}
	return nil
}

// Match organization.ID's existing owner grammar rather than imposing the
// provider's narrower ASCII namespace or normalizing organization identifiers.
func protocolAssertionOrganizationID(value organization.ID) bool {
	raw := string(value)
	if len(raw) == 0 || len(raw) > 128 || !utf8.ValidString(raw) {
		return false
	}
	for _, r := range raw {
		if r <= ' ' || r == 127 {
			return false
		}
	}
	return true
}

func (ProtocolAssertion) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("sso.ProtocolAssertion(redacted)"))
}

func (ProtocolAssertion) LogValue() slog.Value {
	return slog.StringValue("sso.ProtocolAssertion(redacted)")
}

func (ProtocolAssertion) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (ProtocolAssertion) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
