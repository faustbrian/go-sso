package oidc

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/faustbrian/go-sso"
)

const (
	rpLogoutStateSize    = 32
	rpLogoutStateEncoded = 43
	maximumRPLogoutQuery = 4096 // Three bounded form-escaped fields, including 1024 description bytes.
)

// RPLogoutProfileConfig explicitly selects a static provider supporting
// client_id logout with an already registered RP callback. CallbackURI is the
// protocol return route, not the final application redirect. The owner pins
// this configuration to the installed provider and original session. No
// discovery or ID-token hint is inferred from other provider features.
type RPLogoutProfileConfig struct {
	Issuer             string
	ClientID           string
	EndSessionEndpoint string
	CallbackURI        string
}

// RPLogoutProfile is immutable wire configuration. It does not establish
// provider authority, create state, revoke sessions or consume a return.
type RPLogoutProfile struct {
	config   RPLogoutProfileConfig
	endpoint url.URL
}

// NewRPLogoutProfile selects the bounded HTTPS client-ID profile without I/O.
// End-session and callback URLs do not accept a query, fragment, userinfo
// or ambiguous path. The provider registration must already permit this
// callback without an ID-token hint; provider confirmation may be required.
func NewRPLogoutProfile(config RPLogoutProfileConfig) (RPLogoutProfile, error) {
	endpoint, ok := rpLogoutURI(config.EndSessionEndpoint)
	callback, callbackOK := rpLogoutURI(config.CallbackURI)
	if _, issuerOK := rpLogoutURI(config.Issuer); !issuerOK || !ok || !callbackOK || callback.Path == "" ||
		!rpLogoutVisible(config.ClientID, 1024) {
		return RPLogoutProfile{}, sso.ErrInvalidInput
	}
	profile := RPLogoutProfile{config: config, endpoint: endpoint}
	// The state has a fixed escaped width; reject configurations that could
	// never fit the existing LogoutStartResult's complete redirect bound.
	if !validLogoutRedirect(profile.render(strings.Repeat("A", rpLogoutStateEncoded))) {
		return RPLogoutProfile{}, sso.ErrInvalidInput
	}
	return profile, nil
}

// Spec returns the original static facts for trusted scoped persistence. It
// adds no admission authority; zero returns an error.
func (p RPLogoutProfile) Spec() (RPLogoutProfileConfig, error) {
	if p.endpoint.Scheme == "" {
		return RPLogoutProfileConfig{}, sso.ErrInvalidInput
	}
	return p.config, nil
}

func rpLogoutURI(raw string) (url.URL, bool) {
	if len(raw) == 0 || len(raw) > 2048 || !utf8.ValidString(raw) || strings.ContainsAny(raw, "\\ \r\n\t#") {
		return url.URL{}, false
	}
	u, err := url.Parse(raw)
	if err != nil || u.String() != raw || !validLogoutRedirect(*u) || u.RawQuery != "" || u.ForceQuery || u.RawPath != "" ||
		!utf8.ValidString(u.Path) || strings.ContainsRune(u.Path, '\\') || strings.ContainsFunc(u.Path, unicode.IsControl) {
		return url.URL{}, false
	}
	for part := range strings.SplitSeq(u.Path, "/") {
		if part == "." || part == ".." {
			return url.URL{}, false
		}
	}
	return *u, true
}

func rpLogoutVisible(value string, limit int) bool {
	if len(value) == 0 || len(value) > limit {
		return false
	}
	for i := range len(value) {
		if value[i] < '!' || value[i] > '~' {
			return false
		}
	}
	return true
}

// RPLogoutState is the opaque 32-byte state value. The native owner must
// generate it with cryptographic randomness, bind it to the original session
// and provider, and consume it once. The zero value is invalid.
type RPLogoutState struct{ value [rpLogoutStateSize]byte }

// NewRPLogoutState snapshots native-generated entropy. All-zero input is invalid.
func NewRPLogoutState(value [32]byte) RPLogoutState { return RPLogoutState{value: value} }

func (s RPLogoutState) valid() bool { return s.value != [rpLogoutStateSize]byte{} }

// Encode explicitly yields the original canonical state for protocol or native
// lookup. It returns empty for zero. Never log or serialize this value.
func (s RPLogoutState) Encode() string {
	if !s.valid() {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(s.value[:])
}

// Redirect renders the browser GET request with only client_id, the original
// state and the registered RP callback. Call it for disclosure only after
// local revocation and original one-use custody are durably acknowledged.
// Do not log the returned URL, which contains the state.
func (p RPLogoutProfile) Redirect(ctx context.Context, state RPLogoutState) (url.URL, error) {
	if ctx == nil || p.endpoint.Scheme == "" || !state.valid() {
		return url.URL{}, sso.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return url.URL{}, err
	}
	return p.render(state.Encode()), nil
}

func (p RPLogoutProfile) render(state string) url.URL {
	out := p.endpoint
	out.RawQuery = url.Values{"client_id": {p.config.ClientID}, "post_logout_redirect_uri": {p.config.CallbackURI}, "state": {state}}.Encode()
	return out
}

// RPLogoutCallback holds bounded state and the presence of a provider error.
// It does not select a provider or contain provider-supplied error text.
type RPLogoutCallback struct {
	state         RPLogoutState
	providerError bool
}

// ParseRPLogoutCallback accepts exactly one state, optional error, and an
// optional description only with an error. It rejects duplicate or unknown
// fields, including inbound issuer and redirect. It discards error text.
// Neither parsing nor matching state grants authority or consumes it.
func ParseRPLogoutCallback(rawQuery string) (RPLogoutCallback, error) {
	if len(rawQuery) == 0 || len(rawQuery) > maximumRPLogoutQuery || strings.Count(rawQuery, "&") > 2 || strings.Contains(rawQuery, "#") {
		return RPLogoutCallback{}, sso.ErrInvalidInput
	}
	for part := range strings.SplitSeq(rawQuery, "&") {
		if !strings.Contains(part, "=") {
			return RPLogoutCallback{}, sso.ErrInvalidInput
		}
	}
	fields, err := url.ParseQuery(rawQuery)
	if err != nil {
		return RPLogoutCallback{}, sso.ErrInvalidInput
	}
	for name, values := range fields {
		if len(values) != 1 || name != "state" && name != "error" && name != "error_description" {
			return RPLogoutCallback{}, sso.ErrInvalidInput
		}
	}
	encoded := fields.Get("state")
	var state RPLogoutState
	if len(encoded) != rpLogoutStateEncoded {
		return RPLogoutCallback{}, sso.ErrInvalidInput
	}
	if n, err := base64.RawURLEncoding.Strict().Decode(state.value[:], []byte(encoded)); err != nil || n != rpLogoutStateSize || !state.valid() {
		return RPLogoutCallback{}, sso.ErrInvalidInput
	}
	providerError := fields.Has("error")
	if providerError && !rpLogoutVisible(fields.Get("error"), 128) {
		return RPLogoutCallback{}, sso.ErrInvalidInput
	}
	if desc := fields.Get("error_description"); fields.Has("error_description") &&
		(!providerError || len(desc) > 1024 || !utf8.ValidString(desc) || strings.ContainsFunc(desc, unicode.IsControl)) {
		return RPLogoutCallback{}, sso.ErrInvalidInput
	}
	return RPLogoutCallback{state: state, providerError: providerError}, nil
}

// State returns the exact opaque value for native scoped lookup.
func (c RPLogoutCallback) State() RPLogoutState { return c.state }

// OutcomeFor classifies a correlated front-channel return, not independent
// proof of a provider session's status. The caller supplies the profile and
// expected state from sealed native custody and the exact received callback
// URI (without query) from trusted routing. Native code must still consume
// state once, enforce its original lifetime and preserve local revocation.
func (c RPLogoutCallback) OutcomeFor(ctx context.Context, profile RPLogoutProfile, expected RPLogoutState, receivedCallbackURI string) (OIDCLogoutOutcome, error) {
	if ctx == nil || profile.endpoint.Scheme == "" || !expected.valid() || !c.state.valid() {
		return OIDCLogoutInvalid, sso.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return OIDCLogoutInvalid, err
	}
	if receivedCallbackURI != profile.config.CallbackURI || subtle.ConstantTimeCompare(c.state.value[:], expected.value[:]) != 1 {
		return OIDCLogoutInvalid, sso.ErrForbidden
	}
	if c.providerError {
		return OIDCLogoutProviderError, nil
	}
	return OIDCLogoutProviderComplete, nil
}

func (RPLogoutState) Format(w fmt.State, _ rune) {
	_, _ = io.WriteString(w, "sso/oidc.RPLogoutState(redacted)")
}
func (RPLogoutState) LogValue() slog.Value {
	return slog.StringValue("sso/oidc.RPLogoutState(redacted)")
}
func (RPLogoutState) MarshalJSON() ([]byte, error) { return nil, sso.ErrSensitiveSerialization }
func (RPLogoutState) MarshalText() ([]byte, error) { return nil, sso.ErrSensitiveSerialization }

func (RPLogoutCallback) Format(w fmt.State, _ rune) {
	_, _ = io.WriteString(w, "sso/oidc.RPLogoutCallback(redacted)")
}
func (RPLogoutCallback) LogValue() slog.Value {
	return slog.StringValue("sso/oidc.RPLogoutCallback(redacted)")
}
func (RPLogoutCallback) MarshalJSON() ([]byte, error) { return nil, sso.ErrSensitiveSerialization }
func (RPLogoutCallback) MarshalText() ([]byte, error) { return nil, sso.ErrSensitiveSerialization }
