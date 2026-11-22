package sso

import (
	"fmt"
	"math"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ActiveTransactionDispositionMode selects a closed native disablement policy,
// not an observation of transactions or evidence that cleanup has completed.
type ActiveTransactionDispositionMode string

const (
	// ActiveTransactionDrain selects native draining of existing transactions.
	ActiveTransactionDrain ActiveTransactionDispositionMode = "drain"
	// ActiveTransactionRevoke selects native revocation of existing transactions.
	ActiveTransactionRevoke ActiveTransactionDispositionMode = "revoke"
)

// ActiveTransactionDispositionBinding is a detached, non-authoritative selection
// for one provider and its current optimistic version. ProviderID is 1..128
// printable ASCII bytes; ProviderVersion must allow a successor. Mode selects
// only drain or revoke and conveys no transaction count or cleanup evidence.
type ActiveTransactionDispositionBinding struct {
	ProviderID      ProviderID
	ProviderVersion uint64
	Mode            ActiveTransactionDispositionMode
}

// ActiveTransactionDisposition is an immutable disablement-policy selector.
// Zero is invalid; copies are safe for concurrent reads. Only native current
// authority and transaction reads can establish whether the policy is applicable
// or complete; constructing a selector performs no I/O or authorization.
type ActiveTransactionDisposition struct {
	binding ActiveTransactionDispositionBinding
	valid   bool
}

// NewActiveTransactionDisposition binds a closed drain-or-revoke selection to
// the exact provider and current optimistic version without canonicalization.
// Zero and exhausted versions cannot select a provider successor. Every shape
// failure returns only ErrInvalidInput, with no supplied values in diagnostics.
func NewActiveTransactionDisposition(provider ProviderID, version uint64, mode ActiveTransactionDispositionMode) (ActiveTransactionDisposition, error) {
	if !providerClaimName(string(provider)) || version == 0 || version == math.MaxUint64 {
		return ActiveTransactionDisposition{}, ErrInvalidInput
	}
	if mode != ActiveTransactionDrain && mode != ActiveTransactionRevoke {
		return ActiveTransactionDisposition{}, ErrInvalidInput
	}
	return ActiveTransactionDisposition{
		binding: ActiveTransactionDispositionBinding{ProviderID: provider, ProviderVersion: version, Mode: mode},
		valid:   true,
	}, nil
}

// Bindings explicitly returns a detached policy selection for trusted native
// composition. It establishes no current owner, permission, transaction count,
// drain or revocation outcome. Zero returns ErrInvalidInput and no selection.
func (d ActiveTransactionDisposition) Bindings() (ActiveTransactionDispositionBinding, error) {
	if !d.valid {
		return ActiveTransactionDispositionBinding{}, ErrInvalidInput
	}
	return d.binding, nil
}

func (ActiveTransactionDisposition) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("sso.ActiveTransactionDisposition(redacted)"))
}
func (ActiveTransactionDisposition) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (ActiveTransactionDisposition) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// ProviderDisableRequest selects one provider's disablement policy. Native fresh
// org:sso-write authorization, exact current ownership/version and transaction
// reads remain mandatory. Preserve all original fields for canonical repeat
// handling; this operation has no external idempotency key or command ID.
type ProviderDisableRequest struct {
	ProviderID                   string
	ExpectedVersion              uint64
	Reason                       string
	ActiveTransactionDisposition ActiveTransactionDisposition
}

// Validate checks bounded shape and exact disposition agreement, not current
// authority, transaction state or completed cleanup. The lifecycle reason is
// 1..1024 valid UTF-8 bytes, nonblank and control-free; validation preserves it
// exactly. Every shape failure returns only the redacted ErrInvalidInput.
func (r ProviderDisableRequest) Validate() error {
	if !providerClaimName(r.ProviderID) || r.ExpectedVersion == 0 || r.ExpectedVersion == math.MaxUint64 {
		return ErrInvalidInput
	}
	if len(r.Reason) == 0 || len(r.Reason) > 1024 || !utf8.ValidString(r.Reason) || strings.TrimSpace(r.Reason) == "" {
		return ErrInvalidInput
	}
	for _, char := range r.Reason {
		if unicode.IsControl(char) {
			return ErrInvalidInput
		}
	}
	binding, err := r.ActiveTransactionDisposition.Bindings()
	if err != nil || string(binding.ProviderID) != r.ProviderID || binding.ProviderVersion != r.ExpectedVersion {
		return ErrInvalidInput
	}
	return nil
}

func (ProviderDisableRequest) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("sso.ProviderDisableRequest(redacted)"))
}
func (ProviderDisableRequest) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (ProviderDisableRequest) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// ProviderDisableResult reports the native lifecycle outcome and sole durable
// completion. A committed terminal result has exactly one of Deleted or Disabled
// true; unknown or reconciliation leaves both false. ActiveTransactionCount is
// native-reported and saturates at the one-million reporting bound; a selector
// cannot supply it or establish draining/revocation. These values add no callable
// disable operation and grant no current provider or sign-in authority.
type ProviderDisableResult struct {
	Deleted                bool
	Disabled               bool
	ActiveTransactionCount uint32
	Completion             Completion
}
