package sso

import (
	"fmt"
	"log/slog"

	identity "github.com/faustbrian/go-identity"
)

// RevokeEnterpriseToken is an immutable request correlating the exact original
// token-custody profile, command and generation with a stable client retry key.
// Zero is invalid; copies are comparable and safe for concurrent reads. It owns
// no credentials, provider endpoint, network or storage resources and establishes
// neither authorization nor proof of local removal or provider revocation.
type RevokeEnterpriseToken struct {
	grant TokenVersion
	key   identity.IdempotencyKey
}

// NewRevokeEnterpriseToken retains the exact nonzero grant and client key.
// It validates presence only; the consuming adapter must authorize the original
// grant and resolve current provider state. No lookup, digest or I/O occurs.
// Invalid input returns ErrInvalidInput and an unusable zero request without
// retaining or disclosing either supplied binding.
func NewRevokeEnterpriseToken(grant TokenVersion, key identity.IdempotencyKey) (RevokeEnterpriseToken, error) {
	if grant == (TokenVersion{}) || key == (identity.IdempotencyKey{}) {
		return RevokeEnterpriseToken{}, ErrInvalidInput
	}
	return RevokeEnterpriseToken{grant: grant, key: key}, nil
}

// Bindings explicitly projects immutable correlation for the consuming adapter.
// The values grant no authority or evidence of a completed revocation. Zero
// requests return ErrInvalidInput and neither binding; copies cannot mutate the
// request or reconstruct a different client key owner.
func (r RevokeEnterpriseToken) Bindings() (TokenVersion, identity.IdempotencyKey, error) {
	if r.grant == (TokenVersion{}) || r.key == (identity.IdempotencyKey{}) {
		return TokenVersion{}, identity.IdempotencyKey{}, ErrInvalidInput
	}
	return r.grant, r.key, nil
}

func (RevokeEnterpriseToken) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("sso.RevokeEnterpriseToken(redacted)"))
}

func (RevokeEnterpriseToken) LogValue() slog.Value {
	return slog.StringValue("sso.RevokeEnterpriseToken(redacted)")
}

func (RevokeEnterpriseToken) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (RevokeEnterpriseToken) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
