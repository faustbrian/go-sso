// Package oidc provides enterprise OpenID Connect relying-party protocol values.
package oidc

import (
	"fmt"
	"log/slog"
	"net/url"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-sso"
)

// Completion is the sole identity command receipt, not provider completion or
// current session authority. This package never manufactures a command outcome.
type Completion = identity.CommandResult

// OIDCLogoutOutcome is the closed, mutually exclusive provider disposition.
// It does not replace the independently retained local revocation receipt.
type OIDCLogoutOutcome uint8

const (
	// OIDCLogoutInvalid is the unusable zero outcome.
	OIDCLogoutInvalid OIDCLogoutOutcome = iota
	// OIDCLogoutRedirect supplies an exact, separately allowlisted protocol URL.
	OIDCLogoutRedirect
	// OIDCLogoutLocalOnly completed local revocation without provider completion.
	OIDCLogoutLocalOnly
	// OIDCLogoutProviderComplete reports a validated completed provider outcome.
	OIDCLogoutProviderComplete
	// OIDCLogoutProviderError preserves a failed provider outcome and local truth.
	OIDCLogoutProviderError
	// OIDCLogoutTimeout preserves a timed-out provider outcome and local truth.
	OIDCLogoutTimeout
	// OIDCLogoutUnknownReconciliation requires authoritative reconciliation.
	OIDCLogoutUnknownReconciliation
)

// LogoutStartResult is an immutable, opaque start-operation observation. Zero
// is invalid. Copies are safe for concurrent reads and own no runtime resources.
// Constructing one validates shape only; it neither revokes a session nor
// authenticates a receipt, provider, redirect allowlist or one-time state.
type LogoutStartResult struct{ result logoutResult }

// LogoutCompleteResult is an immutable, opaque completion-operation observation.
// Zero is invalid. Copies are safe for concurrent reads. Construction performs
// no callback validation, state consumption, revocation or reconciliation.
type LogoutCompleteResult struct{ result logoutResult }

type logoutResult struct {
	outcome    OIDCLogoutOutcome
	redirect   url.URL
	completion Completion
}

// NewLogoutStartResult snapshots a redirect, local-only or unknown-reconciliation
// observation and the exact start-operation receipt. The fixed start variants
// follow API_OPERATIONS.md's identity.sso.oidc-logout contract; provider-complete,
// provider-error and timeout belong only to completion. A redirect is at most
// 2048 bytes of exact HTTPS URL and is present only on its selected variant.
// Its query may contain secret state: this function never parses or copies it
// into a second field. Trusted composition separately owns allowlisting, state
// binding, the exact operation descriptor and the actual durable observation.
// Invalid input returns ErrInvalidInput without retaining supplied values.
func NewLogoutStartResult(outcome OIDCLogoutOutcome, redirect url.URL, completion Completion) (LogoutStartResult, error) {
	result := logoutResult{outcome: outcome, redirect: redirect, completion: completion}
	if result.validate("identity.sso.oidc-logout") != nil {
		return LogoutStartResult{}, sso.ErrInvalidInput
	}
	result.completion = copyLogoutCompletion(completion)
	return LogoutStartResult{result: result}, nil
}

// NewLogoutCompleteResult snapshots one closed completion disposition and the
// exact completion-operation receipt. The receipt's command comes from trusted
// sealed state, never from inbound provider parameters. Provider failure or
// timeout cannot undo committed local revocation. An unresolved local command
// permits only unknown-reconciliation, never a redirect or settled provider
// result. URL shape, ownership and invalid-input semantics match start.
func NewLogoutCompleteResult(outcome OIDCLogoutOutcome, redirect url.URL, completion Completion) (LogoutCompleteResult, error) {
	result := logoutResult{outcome: outcome, redirect: redirect, completion: completion}
	if result.validate("identity.sso.oidc-logout-complete") != nil {
		return LogoutCompleteResult{}, sso.ErrInvalidInput
	}
	result.completion = copyLogoutCompletion(completion)
	return LogoutCompleteResult{result: result}, nil
}

func (r logoutResult) validate(operation string) error {
	switch r.outcome {
	case OIDCLogoutRedirect, OIDCLogoutLocalOnly, OIDCLogoutUnknownReconciliation:
	case OIDCLogoutProviderComplete, OIDCLogoutProviderError, OIDCLogoutTimeout:
		if operation != "identity.sso.oidc-logout-complete" {
			return sso.ErrInvalidInput
		}
	default:
		return sso.ErrInvalidInput
	}

	if r.completion.Validate() != nil || r.completion.Binding.OperationID != operation || r.completion.Feature == nil || r.completion.Feature.Operation.Owner != "sso/oidc" || r.completion.Cascade != nil {
		return sso.ErrInvalidInput
	}
	// The goal's local-authority rule forbids interpreting an ambiguous command
	// as provider or local success. A committed command can still leave the
	// provider outcome unknown; its original receipt must remain unchanged.
	switch r.completion.Outcome {
	case identity.CommitOutcomeCommitted:
	case identity.CommitOutcomeUnknown, identity.CommitOutcomeInProgress:
		if r.outcome != OIDCLogoutUnknownReconciliation {
			return sso.ErrInvalidInput
		}
	default:
		return sso.ErrInvalidInput
	}

	if r.outcome == OIDCLogoutRedirect {
		if !validLogoutRedirect(r.redirect) {
			return sso.ErrInvalidInput
		}
	} else if r.redirect != (url.URL{}) {
		return sso.ErrInvalidInput
	}
	return nil
}

func validLogoutRedirect(redirect url.URL) bool {
	if redirect.Scheme != "https" || redirect.Opaque != "" || redirect.User != nil || redirect.OmitHost || redirect.Fragment != "" || redirect.RawFragment != "" {
		return false
	}
	for _, part := range []string{redirect.Host, redirect.Path, redirect.RawPath, redirect.RawQuery} {
		if len(part) > 2048 {
			return false
		}
	}
	if redirect.Hostname() == "" {
		return false
	}
	raw := redirect.String()
	if len(raw) > 2048 {
		return false
	}
	parsed, err := url.Parse(raw)
	return err == nil && *parsed == redirect
}

func copyLogoutCompletion(completion Completion) Completion {
	feature := *completion.Feature
	completion.Feature = &feature
	return completion
}

// Validate rejects zero or malformed values without performing I/O or granting
// authority. It does not revalidate the provider outcome or current session.
func (r LogoutStartResult) Validate() error { return r.result.validate("identity.sso.oidc-logout") }

// Validate rejects zero or malformed completion observations without I/O.
func (r LogoutCompleteResult) Validate() error {
	return r.result.validate("identity.sso.oidc-logout-complete")
}

// Outcome returns the selected disposition; zero results return OIDCLogoutInvalid.
func (r LogoutStartResult) Outcome() OIDCLogoutOutcome { return r.result.outcome }

// Outcome returns the selected disposition; zero results return OIDCLogoutInvalid.
func (r LogoutCompleteResult) Outcome() OIDCLogoutOutcome { return r.result.outcome }

// RedirectURI explicitly discloses a detached secret-bearing redirect only for
// the redirect variant. The Boolean reports presence, not revocation success.
func (r LogoutStartResult) RedirectURI() (url.URL, bool) {
	return r.result.redirect, r.result.outcome == OIDCLogoutRedirect
}

// RedirectURI explicitly discloses a detached URL only for the redirect variant.
func (r LogoutCompleteResult) RedirectURI() (url.URL, bool) {
	return r.result.redirect, r.result.outcome == OIDCLogoutRedirect
}

// Completion explicitly projects a detached copy of the original local receipt.
// It conveys no provider or current session authority. Zero returns no receipt.
func (r LogoutStartResult) Completion() (Completion, error) {
	if err := r.Validate(); err != nil {
		return Completion{}, err
	}
	return copyLogoutCompletion(r.result.completion), nil
}

// Completion explicitly projects a detached original receipt, never a fabricated
// provider-success receipt. Invalid results return only ErrInvalidInput.
func (r LogoutCompleteResult) Completion() (Completion, error) {
	if err := r.Validate(); err != nil {
		return Completion{}, err
	}
	return copyLogoutCompletion(r.result.completion), nil
}

func (LogoutStartResult) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("oidc.LogoutStartResult(redacted)"))
}

func (LogoutCompleteResult) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("oidc.LogoutCompleteResult(redacted)"))
}

func (LogoutStartResult) LogValue() slog.Value {
	return slog.StringValue("oidc.LogoutStartResult(redacted)")
}

func (LogoutCompleteResult) LogValue() slog.Value {
	return slog.StringValue("oidc.LogoutCompleteResult(redacted)")
}

func (LogoutStartResult) MarshalJSON() ([]byte, error) { return nil, sso.ErrSensitiveSerialization }
func (LogoutStartResult) MarshalText() ([]byte, error) { return nil, sso.ErrSensitiveSerialization }

func (LogoutCompleteResult) MarshalJSON() ([]byte, error) { return nil, sso.ErrSensitiveSerialization }
func (LogoutCompleteResult) MarshalText() ([]byte, error) { return nil, sso.ErrSensitiveSerialization }
