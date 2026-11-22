package sso

import (
	"fmt"
	"log/slog"
	"net/url"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	organization "github.com/faustbrian/go-organization"
)

// LoginIntent is an immutable, already resolved session-lifetime selection.
// Zero is invalid; copies are safe for concurrent reads. It grants no login,
// provider, organization or session authority and chooses no deployment default.
type LoginIntent struct {
	remember session.RememberPolicy
}

// NewLoginIntent retains an exact resolved remember policy without applying
// defaults, changing lifetimes, performing I/O or establishing authentication.
// A zero policy returns only ErrInvalidInput and no usable intent.
func NewLoginIntent(remember session.RememberPolicy) (LoginIntent, error) {
	if _, err := remember.Bindings(); err != nil {
		return LoginIntent{}, ErrInvalidInput
	}
	return LoginIntent{remember: remember}, nil
}

// RememberPolicy explicitly returns the immutable resolved policy copy for
// trusted continuation composition. It does not issue or renew a session.
// Zero intent returns only ErrInvalidInput and no policy.
func (i LoginIntent) RememberPolicy() (session.RememberPolicy, error) {
	if _, err := i.remember.Bindings(); err != nil {
		return session.RememberPolicy{}, ErrInvalidInput
	}
	return i.remember, nil
}

func (LoginIntent) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("sso.LoginIntent(redacted)"))
}

func (LoginIntent) LogValue() slog.Value { return slog.StringValue("sso.LoginIntent(redacted)") }

func (LoginIntent) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (LoginIntent) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// SigninStartRequest selects a provider or canonical DNS domain, or both, and
// exact HTTPS callbacks of at most 2048 serialized bytes. ProviderID, when set,
// is 1..128 printable ASCII bytes; Domain follows organization.CanonicalDomain
// without implicit normalization. Retain the original command, key, callbacks
// and intent across retries. Native composition separately owns current route,
// pre-authentication, origin, callback allowlist and provider admission; these
// fields and Validate never grant authority or perform a callable sign-in.
type SigninStartRequest struct {
	CommandID       identity.CommandID
	ProviderID      string
	Domain          string
	SuccessCallback url.URL
	ErrorCallback   url.URL
	LoginIntent     LoginIntent
	IdempotencyKey  identity.IdempotencyKey
}

// Validate checks bounded canonical shape without I/O or modification. At least
// one routing selector is required; a native profile may require both or resolve
// a separately configured default. HTTPS callbacks exclude userinfo, fragments,
// opaque forms and hidden URL state that cannot round-trip exactly. This is not
// an allowlist check. Invalid shape returns only the redacted ErrInvalidInput.
func (r SigninStartRequest) Validate() error {
	if _, err := identity.ParseCommandID(string(r.CommandID)); err != nil {
		return ErrInvalidInput
	}
	if r.IdempotencyKey == (identity.IdempotencyKey{}) {
		return ErrInvalidInput
	}
	if r.ProviderID == "" && r.Domain == "" {
		return ErrInvalidInput
	}
	if r.ProviderID != "" && !providerClaimName(r.ProviderID) {
		return ErrInvalidInput
	}
	if r.Domain != "" {
		domain, err := organization.CanonicalDomain(r.Domain)
		if err != nil || domain != r.Domain {
			return ErrInvalidInput
		}
	}
	if !signinStartCallback(r.SuccessCallback) || !signinStartCallback(r.ErrorCallback) {
		return ErrInvalidInput
	}
	if _, err := r.LoginIntent.RememberPolicy(); err != nil {
		return ErrInvalidInput
	}
	return nil
}

func signinStartCallback(callback url.URL) bool {
	return boundedSSOHTTPSURL(callback, 2048)
}

func boundedSSOHTTPSURL(callback url.URL, maximum int) bool {
	if callback.Scheme != "https" || callback.Opaque != "" || callback.User != nil || callback.OmitHost || callback.Fragment != "" || callback.RawFragment != "" {
		return false
	}
	// Bound caller-owned components before String or parsing can allocate.
	for _, component := range []string{callback.Host, callback.Path, callback.RawPath, callback.RawQuery} {
		if len(component) > maximum {
			return false
		}
	}
	if callback.Hostname() == "" {
		return false
	}
	raw := callback.String()
	if len(raw) == 0 || len(raw) > maximum {
		return false
	}
	parsed, err := url.Parse(raw)
	// A url.URL literal can carry ignored RawPath or OmitHost state. Reject it
	// instead of letting serialization silently alter the original callback.
	return err == nil && *parsed == callback
}

func (SigninStartRequest) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("sso.SigninStartRequest(redacted)"))
}

func (SigninStartRequest) LogValue() slog.Value {
	return slog.StringValue("sso.SigninStartRequest(redacted)")
}

func (SigninStartRequest) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (SigninStartRequest) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// SigninStartResult reports the exact native protocol redirect, transaction and
// provider selection with the sole durable Completion. These fields establish
// no login/session authority, current route or transaction lifetime; zero is not
// a successful result. Unknown completion must not be presented as a redirect
// grant or retried under a replacement command. This type performs no workflow.
type SigninStartResult struct {
	RedirectURI   url.URL
	TransactionID string
	ProviderID    string
	Protocol      string
	Completion    Completion
}

func (SigninStartResult) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("sso.SigninStartResult(redacted)"))
}

func (SigninStartResult) LogValue() slog.Value {
	return slog.StringValue("sso.SigninStartResult(redacted)")
}

func (SigninStartResult) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (SigninStartResult) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
