package sso

import (
	"fmt"

	identity "github.com/faustbrian/go-identity"
)

// TypedProviderConfiguration is a closed, non-secret configuration profile.
// The selected profile contains only explicit static OIDC metadata. It cannot
// carry credentials, discovery requests, enablement or routing policy. The zero
// value is invalid; constructing it grants no provider or organization authority.
type TypedProviderConfiguration struct {
	metadata OIDCStaticMetadata
}

// NewStaticOIDCProviderConfiguration selects validated static metadata without
// network I/O. Updates preserve the existing issuer and pending domain identity.
func NewStaticOIDCProviderConfiguration(metadata OIDCStaticMetadata) (TypedProviderConfiguration, error) {
	if _, err := metadata.Spec(); err != nil {
		return TypedProviderConfiguration{}, ErrInvalidInput
	}
	return TypedProviderConfiguration{metadata: metadata}, nil
}

// StaticOIDC explicitly projects the selected metadata for trusted composition
// or encrypted persistence. A zero value returns ErrInvalidInput.
func (c TypedProviderConfiguration) StaticOIDC() (OIDCStaticMetadata, error) {
	if _, err := c.metadata.Spec(); err != nil {
		return OIDCStaticMetadata{}, ErrInvalidInput
	}
	return c.metadata, nil
}

func (TypedProviderConfiguration) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("sso.TypedProviderConfiguration(redacted)"))
}
func (TypedProviderConfiguration) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (TypedProviderConfiguration) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// ProviderUpdateRequest replaces selected non-secret static-OIDC endpoints and
// a complete mapping on a disabled provider. ExpectedVersion must match current
// state. Mapping.Version must be its immediate successor and SubjectClaim stays
// unchanged. The organization selector is bound separately to the service before
// invocation and checked against current native organization authority; ProviderID
// never establishes ownership. Preserve every field and the original key on retry.
type ProviderUpdateRequest struct {
	CommandID       identity.CommandID
	ProviderID      string
	ExpectedVersion uint64
	Configuration   TypedProviderConfiguration
	Mapping         AttributeMapping
	IdempotencyKey  identity.IdempotencyKey
}

// ProviderUpdateResult returns the original successor's detached safe metadata
// and native completion. Unknown completion never returns provider metadata.
type ProviderUpdateResult struct {
	Provider   Provider
	Completion Completion
}
