package sso

import (
	"fmt"
	"math"
	"time"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

// DomainProofCheckpoint selects an exact organization-owned proof for current
// native revalidation. ProofVersion must equal Key.ProofVersion. Zero is invalid;
// neither a caller-supplied key nor historical proof establishes current domain
// ownership. The native transition must consult organization.DomainProofReader.
type DomainProofCheckpoint struct {
	Key          organization.DomainProofKey
	ProofVersion uint64
}

func (DomainProofCheckpoint) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("sso.DomainProofCheckpoint(redacted)"))
}
func (DomainProofCheckpoint) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (DomainProofCheckpoint) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// CredentialCheckpointBinding is a detached, non-authoritative snapshot for the
// enablement-only static-OIDC client-secret checkpoint. IDs are exact 1..128
// printable ASCII bytes. ProviderVersion is the current optimistic version;
// Generation selects the active encrypted credential. Observation and exclusive
// expiry must be UTC microseconds, with a positive lifetime of at most 20 seconds.
// These fields select no other protocol, credential purpose or operation.
type CredentialCheckpointBinding struct {
	TenantID        identity.TenantID
	OrganizationID  organization.ID
	ProviderID      string
	ProviderVersion uint64
	Generation      uint64
	ObservedAt      time.Time
	ExpiresAt       time.Time
}

// CredentialCheckpoint is immutable, enablement-only static-OIDC client-secret
// metadata. It contains no secret and grants no authority. Zero is invalid; copies
// are safe for concurrent reads. Native admission must read the current encrypted
// credential under the exact owner/version/generation and original lifetime.
type CredentialCheckpoint struct {
	binding CredentialCheckpointBinding
	valid   bool
}

// NewCredentialCheckpoint snapshots validated shape only, without I/O, clock
// reads, authorization or renewal. Native admission, not caller construction,
// determines whether this exact checkpoint still describes a usable credential.
func NewCredentialCheckpoint(b CredentialCheckpointBinding) (CredentialCheckpoint, error) {
	for _, owner := range []string{string(b.TenantID), string(b.OrganizationID), b.ProviderID} {
		if !providerClaimName(owner) {
			return CredentialCheckpoint{}, ErrInvalidInput
		}
	}
	if b.ProviderVersion == 0 || b.ProviderVersion == math.MaxUint64 || b.Generation == 0 {
		return CredentialCheckpoint{}, ErrInvalidInput
	}
	if !credentialReferenceTime(b.ObservedAt) || !credentialReferenceTime(b.ExpiresAt) || !b.ExpiresAt.After(b.ObservedAt) {
		return CredentialCheckpoint{}, ErrInvalidInput
	}
	// The bounded enablement profile admits only the original short observation;
	// constructor retries and explicit projections must never extend that interval.
	if b.ExpiresAt.Sub(b.ObservedAt) > 20*time.Second {
		return CredentialCheckpoint{}, ErrInvalidInput
	}
	return CredentialCheckpoint{binding: b, valid: true}, nil
}

// Bindings explicitly returns a detached metadata copy for native composition.
// It does not check freshness, establish authority or renew the original lifetime.
// The zero checkpoint returns ErrInvalidInput and no binding.
func (c CredentialCheckpoint) Bindings() (CredentialCheckpointBinding, error) {
	if !c.valid {
		return CredentialCheckpointBinding{}, ErrInvalidInput
	}
	return c.binding, nil
}

func (CredentialCheckpoint) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("sso.CredentialCheckpoint(redacted)"))
}
func (CredentialCheckpoint) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (CredentialCheckpoint) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// ProviderEnableRequest selects one disabled static-OIDC provider and its exact
// domain/credential checkpoints. Native fresh org:sso-write authorization and
// current primary owner reads remain mandatory. Preserve all original fields and
// the key across retries; this keyed operation has no caller-selected command ID.
type ProviderEnableRequest struct {
	ProviderID            string
	ExpectedVersion       uint64
	DomainProofCheckpoint DomainProofCheckpoint
	CredentialCheckpoint  CredentialCheckpoint
	IdempotencyKey        identity.IdempotencyKey
}

// Validate checks bounded canonical shape and exact checkpoint agreement, not
// current readiness, authorization, revocation or expiry. A structurally valid
// historical checkpoint never substitutes for current native authority reads.
// Every shape failure returns only the redacted ErrInvalidInput category.
func (r ProviderEnableRequest) Validate() error {
	if !providerClaimName(r.ProviderID) || r.ExpectedVersion == 0 || r.ExpectedVersion == math.MaxUint64 {
		return ErrInvalidInput
	}
	if r.IdempotencyKey == (identity.IdempotencyKey{}) {
		return ErrInvalidInput
	}
	credential, err := r.CredentialCheckpoint.Bindings()
	if err != nil {
		return ErrInvalidInput
	}
	if credential.ProviderID != r.ProviderID || credential.ProviderVersion != r.ExpectedVersion {
		return ErrInvalidInput
	}

	checkpoint := r.DomainProofCheckpoint
	proof := checkpoint.Key
	if proof.TenantID != credential.TenantID || proof.OrganizationID != credential.OrganizationID || !providerClaimName(string(proof.ClaimID)) {
		return ErrInvalidInput
	}
	if proof.ClaimVersion == 0 || checkpoint.ProofVersion == 0 || checkpoint.ProofVersion != proof.ProofVersion || proof.Revoked {
		return ErrInvalidInput
	}
	domain, err := organization.CanonicalDomain(proof.Domain)
	if err != nil || domain != proof.Domain {
		return ErrInvalidInput
	}
	if proof.Method != organization.DomainDNS && proof.Method != organization.DomainHTTPS {
		return ErrInvalidInput
	}
	if !credentialReferenceTime(proof.ObservedAt) || !credentialReferenceTime(proof.ExpiresAt) || !proof.ExpiresAt.After(proof.ObservedAt) {
		return ErrInvalidInput
	}
	return nil
}

func (ProviderEnableRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("sso.ProviderEnableRequest(redacted)"))
}
func (ProviderEnableRequest) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (ProviderEnableRequest) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// ProviderEnableResult contains detached non-secret provider metadata and the
// sole native durable completion. Unknown returns no provider metadata and must
// be reconciled through the original operation, never by issuing another write.
type ProviderEnableResult struct {
	Provider   Provider
	Completion Completion
}
