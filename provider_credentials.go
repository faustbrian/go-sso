package sso

import (
	"context"
	"fmt"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

// CredentialReferenceContext is the complete immutable AAD for an OIDC
// client-secret ingress envelope. It selects neither current ownership nor
// permission. IDs and key identity are canonical 1..128 printable ASCII bytes.
// Times must be UTC microsecond values with a positive lifetime. Generation is
// the credential successor, while ProviderVersion is the current optimistic
// provider version; the native owner must verify both against current state.
type CredentialReferenceContext struct {
	TenantID, OrganizationID, ProviderID string
	Protocol, Purpose                    string
	Generation, ProviderVersion          uint64
	Audience, EnvelopeKeyID              string
	IssuedAt, ExpiresAt                  time.Time
}

// EncryptionContext returns the exact non-secret authenticated binding for
// trusted secret ingress. Only static OIDC client secrets for the separate
// credentials-rotate operation are selected. No implicit canonicalization,
// issuer lookup, key lookup or lifetime renewal is performed.
func (c CredentialReferenceContext) EncryptionContext() (envelope.Context, error) {
	for _, value := range []string{c.TenantID, c.OrganizationID, c.ProviderID, c.EnvelopeKeyID} {
		if !providerClaimName(value) {
			return envelope.Context{}, ErrInvalidInput
		}
	}
	if c.Protocol != "oidc" || c.Purpose != "client-secret" || c.Audience != "identity.sso.provider.credentials-rotate" || c.Generation == 0 || c.ProviderVersion == 0 || !credentialReferenceTime(c.IssuedAt) || !credentialReferenceTime(c.ExpiresAt) || !c.ExpiresAt.After(c.IssuedAt) {
		return envelope.Context{}, ErrInvalidInput
	}
	return envelope.NewContext(map[string]string{
		"owner": "sso/provider-credentials", "tenant": c.TenantID,
		"organization": c.OrganizationID, "provider": c.ProviderID,
		"protocol": c.Protocol, "purpose": c.Purpose,
		"generation":       strconv.FormatUint(c.Generation, 10),
		"provider-version": strconv.FormatUint(c.ProviderVersion, 10),
		"audience":         c.Audience, "key-id": c.EnvelopeKeyID,
		"issued-at":  c.IssuedAt.Format(time.RFC3339Nano),
		"expires-at": c.ExpiresAt.Format(time.RFC3339Nano),
	})
}

func credentialReferenceTime(at time.Time) bool {
	return !at.IsZero() && at.Year() > 0 && at.Year() < 10000 && at == at.UTC().Truncate(time.Microsecond)
}

// EncryptedCredentialReference contains only authenticated envelope ciphertext
// and its immutable binding. It exposes no plaintext or bearer authority.
// Safe for concurrent reads; zero is invalid. Native consumers must authenticate
// it again with their configured envelope service and immutable ingress policy,
// including the current owner, key, audience, generation, version and lifetime.
type EncryptedCredentialReference struct {
	sealed  envelope.Envelope
	binding CredentialReferenceContext
	valid   bool
}

// NewEncryptedCredentialReference authenticates at most 32768 envelope bytes
// under the supplied exact binding and immediately clears temporary plaintext.
// This convenience factory neither ingests raw secrets nor grants authorization.
// The supplied service is not evidence of the native consumer's key authority.
// It borrows wire until return and snapshots authenticated immutable state.
// Callers must supply a bounded context; no deadline or retry is added here.
func NewEncryptedCredentialReference(ctx context.Context, service *envelope.Service, wire []byte, binding CredentialReferenceContext) (EncryptedCredentialReference, error) {
	if ctx == nil || service == nil || len(wire) == 0 || len(wire) > 32768 {
		return EncryptedCredentialReference{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return EncryptedCredentialReference{}, err
	}
	aad, err := binding.EncryptionContext()
	if err != nil {
		return EncryptedCredentialReference{}, err
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return EncryptedCredentialReference{}, ErrInvalidInput
	}
	if sealed.KeyReference() != binding.EnvelopeKeyID {
		return EncryptedCredentialReference{}, ErrForbidden
	}
	plain, err := service.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	defer clear(plain)
	if ctx.Err() != nil {
		return EncryptedCredentialReference{}, ctx.Err()
	}
	if err != nil || len(plain) == 0 || len(plain) > 32768 {
		return EncryptedCredentialReference{}, ErrForbidden
	}
	return EncryptedCredentialReference{sealed: sealed, binding: binding, valid: true}, nil
}

// Context returns a detached non-authoritative binding, never the secret.
func (r EncryptedCredentialReference) Context() CredentialReferenceContext { return r.binding }

// EncryptedEnvelope explicitly projects immutable encrypted custody for trusted
// persistence or native reauthentication. Its binary representation is sensitive
// and must not be logged. The zero reference projects a zero envelope.
func (r EncryptedCredentialReference) EncryptedEnvelope() envelope.Envelope { return r.sealed }

// ValidateAt checks construction and the original half-open lifetime without
// renewing it. It proves no current permission, provider state or key authority.
func (r EncryptedCredentialReference) ValidateAt(at time.Time) error {
	if !r.valid || at.IsZero() {
		return ErrInvalidInput
	}
	if at.Before(r.binding.IssuedAt) || !at.Before(r.binding.ExpiresAt) {
		return ErrForbidden
	}
	return nil
}

func (EncryptedCredentialReference) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("sso.EncryptedCredentialReference(redacted)"))
}
func (EncryptedCredentialReference) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (EncryptedCredentialReference) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// CredentialOverlapPolicy is an explicit closed rotation profile. The selected
// profile permits no overlap and only a disabled static-OIDC provider. It grants
// no enablement, active-use, grace, drain or provider-network authority.
type CredentialOverlapPolicy struct{ noOverlap bool }

// NewNoCredentialOverlapPolicy selects immediate replacement with no retained
// usable predecessor. The zero policy is deliberately not a default selection.
func NewNoCredentialOverlapPolicy() CredentialOverlapPolicy {
	return CredentialOverlapPolicy{noOverlap: true}
}

// Validate rejects an unselected policy; it does not check provider readiness.
func (p CredentialOverlapPolicy) Validate() error {
	if !p.noOverlap {
		return ErrInvalidInput
	}
	return nil
}

func (CredentialOverlapPolicy) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("sso.CredentialOverlapPolicy(redacted)"))
}
func (CredentialOverlapPolicy) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (CredentialOverlapPolicy) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// ProviderCredentialsRotateRequest initializes or replaces one disabled static
// OIDC provider's encrypted client-secret generation. Fresh org:sso-credentials
// authorization and current provider ownership/version are mandatory at the
// native transition. Preserve the complete original command across retries;
// there is deliberately no external idempotency key or implicit overlap policy.
type ProviderCredentialsRotateRequest struct {
	CommandID           identity.CommandID
	ProviderID          string
	ExpectedVersion     uint64
	CredentialReference EncryptedCredentialReference
	OverlapPolicy       CredentialOverlapPolicy
}

func (ProviderCredentialsRotateRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("sso.ProviderCredentialsRotateRequest(redacted)"))
}
func (ProviderCredentialsRotateRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (ProviderCredentialsRotateRequest) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// ProviderCredentialsRotateResult is redacted successor metadata and the sole
// native completion. Active describes credential activation, never provider
// enablement. Unknown requires reconciliation and cannot claim Active=true.
type ProviderCredentialsRotateResult struct {
	ProviderID             string
	Version                uint64
	Active                 bool
	ReconciliationRequired bool
	Completion             Completion
}
