package sso

import (
	"fmt"
	"log/slog"

	identity "github.com/faustbrian/go-identity"
)

// RefreshEnterpriseToken is an immutable request correlating the exact original
// token-custody profile, command and generation with a stable client retry key.
// Zero is invalid; copies are comparable and safe for concurrent reads. It owns
// no credentials, provider endpoint, network or storage resources and establishes
// neither authorization nor proof of a completed provider refresh or rotation.
type RefreshEnterpriseToken struct {
	grant TokenVersion
	key   identity.IdempotencyKey
}

// NewRefreshEnterpriseToken retains the exact nonzero grant and client key.
// It validates presence only; the consuming adapter must authorize the original
// grant and resolve current provider state. No lookup, digest or I/O occurs.
// Invalid input returns ErrInvalidInput and an unusable zero request without
// retaining or disclosing either supplied binding.
func NewRefreshEnterpriseToken(grant TokenVersion, key identity.IdempotencyKey) (RefreshEnterpriseToken, error) {
	if grant == (TokenVersion{}) || key == (identity.IdempotencyKey{}) {
		return RefreshEnterpriseToken{}, ErrInvalidInput
	}
	return RefreshEnterpriseToken{grant: grant, key: key}, nil
}

// Bindings explicitly projects immutable correlation for the consuming adapter.
// The values grant no authority or evidence of a completed refresh. Zero
// requests return ErrInvalidInput and neither binding; copies cannot mutate the
// request or reconstruct a different client key owner.
func (r RefreshEnterpriseToken) Bindings() (TokenVersion, identity.IdempotencyKey, error) {
	if r.grant == (TokenVersion{}) || r.key == (identity.IdempotencyKey{}) {
		return TokenVersion{}, identity.IdempotencyKey{}, ErrInvalidInput
	}
	return r.grant, r.key, nil
}

func (RefreshEnterpriseToken) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("sso.RefreshEnterpriseToken(redacted)"))
}

func (RefreshEnterpriseToken) LogValue() slog.Value {
	return slog.StringValue("sso.RefreshEnterpriseToken(redacted)")
}

func (RefreshEnterpriseToken) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (RefreshEnterpriseToken) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
