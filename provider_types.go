package sso

import (
	"fmt"
	"net/url"
	"unicode/utf8"

	identity "github.com/faustbrian/go-identity"
)

// ProviderID selects an enterprise provider, not its organization or a human.
// IDs are opaque and bounded to 128 bytes; possession grants no access.
type ProviderID string

// AttributeMappingSpec selects flat, case-exact assertion claim names. Version
// is positive. SubjectClaim is required; the other names may be omitted. Names
// are bounded to 128 printable ASCII bytes and are never interpreted as paths.
// This profile has no role, permission, tenant or organization mapping rule.
type AttributeMappingSpec struct {
	Version            uint64
	SubjectClaim       string
	EmailClaim         string
	VerifiedEmailClaim string
	DisplayNameClaim   string
}

// AttributeMapping is immutable representation policy, not a validated
// assertion, account link or permission. It applies no mapping and performs no
// I/O. A selected protocol/provisioning transition must separately validate the
// source assertion and its own stable-subject and verified-email requirements.
type AttributeMapping struct {
	spec  AttributeMappingSpec
	valid bool
}

// NewAttributeMapping snapshots a positive policy version and explicit flat
// claim names without discovery, interpretation or privilege assignment.
func NewAttributeMapping(spec AttributeMappingSpec) (AttributeMapping, error) {
	if spec.Version == 0 || !providerClaimName(spec.SubjectClaim) {
		return AttributeMapping{}, ErrInvalidInput
	}
	for _, claim := range []string{spec.EmailClaim, spec.VerifiedEmailClaim, spec.DisplayNameClaim} {
		if claim != "" && !providerClaimName(claim) {
			return AttributeMapping{}, ErrInvalidInput
		}
	}
	return AttributeMapping{spec: spec, valid: true}, nil
}

func providerClaimName(name string) bool {
	if len(name) == 0 || len(name) > 128 || !utf8.ValidString(name) {
		return false
	}
	for _, b := range []byte(name) {
		if b < '!' || b > '~' {
			return false
		}
	}
	return true
}

// Spec explicitly projects a scalar policy copy for trusted composition or
// encrypted persistence. A zero mapping returns ErrInvalidInput, not defaults.
func (m AttributeMapping) Spec() (AttributeMappingSpec, error) {
	if !m.valid {
		return AttributeMappingSpec{}, ErrInvalidInput
	}
	return m.spec, nil
}

func (AttributeMapping) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("sso.AttributeMapping(redacted)"))
}

func (AttributeMapping) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (AttributeMapping) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// Provider is detached nonsecret administration metadata, not current domain or
// login authority. Registered disabled providers have an empty VerifiedDomains
// slice; requested domains remain pending, never synthetic ownership evidence.
// Consumers own returned slices. Positive versions identify persisted policy
// snapshots; reads must still authenticate current organization authority.
type Provider struct {
	ID, OrganizationID, Protocol string
	Version                      uint64
	Enabled                      bool
	VerifiedDomains              []string
	MappingVersion               uint64
	EnforcementVersion           uint64
}

// Completion is the identity coordinator's actual durable command result. SSO
// creates no parallel outcome state machine. Unknown never permits a new write.
type Completion = identity.CommandResult

// ProviderRegisterOidcRequest borrows bounded caller input until return. The
// static-only profile rejects DiscoveryURL, requires an exact matching Issuer,
// 1..128 canonical distinct Domains and a validated Mapping. It accepts no credential
// material or enabled flag. Keep the original command/key/input across retries;
// a changed request under the same key conflicts. Neither input IDs nor mapping
// versions confer organization, provider or protocol authority.
type ProviderRegisterOidcRequest struct {
	CommandID      identity.CommandID
	OrganizationID string
	Issuer         string
	DiscoveryURL   url.URL
	StaticMetadata OIDCStaticMetadata
	Domains        []string
	Mapping        AttributeMapping
	IdempotencyKey identity.IdempotencyKey
}

// ProviderRegisterOidcResult contains no secret or sign-in permission. The
// verification count describes pending domain requirements, not proof truth.
type ProviderRegisterOidcResult struct {
	Provider                     Provider
	VerificationRequirementCount uint32
	Completion                   Completion
}

// ProviderGetRequest selects an exact organization/provider pair. Both are
// untrusted selectors until current authentication and read policy succeed.
type ProviderGetRequest struct {
	OrganizationID string
	ProviderID     ProviderID
}

// ProviderGetResult is detached metadata from one currently authorized read.
type ProviderGetResult struct{ Provider Provider }

// ProviderListRequest selects bounded ID-ordered organization metadata. An empty
// cursor starts the first page; a cursor never changes the organization scope.
type ProviderListRequest struct {
	OrganizationID string
	Cursor         ProviderID
	Limit          uint32
}

// ProviderListResult owns its provider and nested slices. NextCursor is opaque
// continuation data, not a reusable organization authorization snapshot.
type ProviderListResult struct {
	Providers  []Provider
	NextCursor ProviderID
}
