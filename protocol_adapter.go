package sso

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	organization "github.com/faustbrian/go-organization"
)

// ProtocolAdapter performs wire operations on behalf of the SSO coordinator.
// Only the coordinator selects the installed provider, reserves a callback
// transaction and applies identity, membership, session and token policy.
type ProtocolAdapter interface {
	Start(context.Context, ProtocolStartCommand) (ProtocolStartResult, error)
	Complete(context.Context, ProtocolCallback) (ProtocolAssertion, error)
}

// LoginTransaction projects the original SSO reservation scope. Construct it
// from authenticated, allowlisted owner state, not from an inbound URL or form.
// ID identifies the originating transaction; CommandID identifies the atomic
// completion. Neither the projection nor its validation reserves one-time use.
// Treat the exported fields as read-only; ValidateAt rejects changed copies.
type LoginTransaction struct {
	TenantID        identity.TenantID
	ID              string
	ProviderID      string
	OrganizationID  organization.ID
	Protocol        string
	Callback        url.URL
	ExpiresAt       time.Time
	ProviderVersion uint64
	MappingVersion  uint64
	RememberPolicy  session.RememberPolicy
	CommandID       identity.CommandID

	bound *loginTransactionBinding
}

type loginTransactionBinding struct {
	projection           LoginTransaction
	credentialGeneration uint64
}

// NewLoginTransaction binds an exact callback, retained expiry and activated
// credential generation. It checks the projection's shape but neither selects
// nor authorizes a provider. Use ValidateAt with the trusted operation clock.
func NewLoginTransaction(projection LoginTransaction, credentialGeneration uint64) (LoginTransaction, error) {
	if projection.bound != nil || credentialGeneration == 0 || projection.ProviderVersion == 0 || projection.MappingVersion == 0 || projection.ExpiresAt.IsZero() {
		return LoginTransaction{}, ErrInvalidInput
	}
	if !providerClaimName(string(projection.TenantID)) || !providerClaimName(projection.ProviderID) || !protocolAssertionOrganizationID(projection.OrganizationID) {
		return LoginTransaction{}, ErrInvalidInput
	}
	if _, err := identity.ParseCommandID(projection.ID); err != nil {
		return LoginTransaction{}, ErrInvalidInput
	}
	if _, err := identity.ParseCommandID(string(projection.CommandID)); err != nil {
		return LoginTransaction{}, ErrInvalidInput
	}
	switch projection.Protocol {
	case "oidc", "oauth2", "saml":
	default:
		return LoginTransaction{}, ErrInvalidInput
	}
	if !signinStartCallback(projection.Callback) || projection.Callback.RawQuery != "" || projection.Callback.ForceQuery {
		return LoginTransaction{}, ErrInvalidInput
	}
	if _, err := projection.RememberPolicy.Bindings(); err != nil {
		return LoginTransaction{}, ErrInvalidInput
	}
	projection.bound = &loginTransactionBinding{projection: projection, credentialGeneration: credentialGeneration}
	return projection, nil
}

// ValidateAt returns the originally bound credential generation for a valid
// unchanged projection before its exclusive expiry. Zero, modified, and
// expired values return ErrInvalidInput and no generation. Current authority
// and callback admission must still be established by the coordinator.
func (t LoginTransaction) ValidateAt(now time.Time) (uint64, error) {
	bound := t.bound
	t.bound = nil
	if bound == nil || t != bound.projection || now.IsZero() || !now.Before(t.ExpiresAt) {
		return 0, ErrInvalidInput
	}
	return bound.credentialGeneration, nil
}

// ProtocolStartCommand carries the coordinator's exact enabled provider and
// original transaction projection. The provider metadata is borrowed read-only
// until Start returns. Transaction.ValidateAt carries its credential generation
// independently of the metadata version.
type ProtocolStartCommand struct {
	Transaction LoginTransaction
	Provider    Provider
}

// ValidateAt checks that the provider metadata belongs to the unchanged login
// transaction. It does not replace the caller's current provider or domain check.
func (c ProtocolStartCommand) ValidateAt(now time.Time) (uint64, error) {
	generation, err := c.Transaction.ValidateAt(now)
	if err != nil {
		return 0, err
	}
	t, p := c.Transaction, c.Provider
	if !p.Enabled || p.ID != t.ProviderID || p.OrganizationID != string(t.OrganizationID) || p.Protocol != t.Protocol || p.Version != t.ProviderVersion || p.MappingVersion != t.MappingVersion {
		return 0, ErrInvalidInput
	}
	return generation, nil
}

// ProtocolStartResult contains the protocol-validated provider redirect and the
// original validity cutoff. Redirect can contain one-use state and must not be
// logged or serialized implicitly.
type ProtocolStartResult struct {
	Redirect  url.URL
	ExpiresAt time.Time
}

// Match the existing native OAuth/OIDC authorization redirect ceiling.
const maximumProtocolStartRedirectBytes = 8192

// ValidateFor checks the redirect's bounded HTTPS shape and validates its
// exclusive expiry against both the original transaction and capability. The
// adapter must separately enforce the exact authorized provider destination.
func (r ProtocolStartResult) ValidateFor(t LoginTransaction, now, capabilityExpiry time.Time) error {
	if _, err := t.ValidateAt(now); err != nil {
		return err
	}
	if !now.Before(r.ExpiresAt) || r.ExpiresAt.After(t.ExpiresAt) || r.ExpiresAt.After(capabilityExpiry) {
		return ErrInvalidInput
	}
	if !boundedSSOHTTPSURL(r.Redirect, maximumProtocolStartRedirectBytes) {
		return ErrInvalidInput
	}
	if _, err := url.QueryUnescape(r.Redirect.RawQuery); err != nil {
		return ErrInvalidInput
	}
	return nil
}

// ProtocolCallback transfers one bounded wire payload to Complete. The owner
// calls Complete only after reserving the original transaction. The adapter
// must consume at most MaximumBytes within its configured protocol limit and
// close Payload on every path, including refusal and cancellation. Do not reuse
// the payload or complete it concurrently.
type ProtocolCallback struct {
	Transaction  LoginTransaction
	Payload      io.ReadCloser
	MaximumBytes uint64
}

func (LoginTransaction) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "sso.LoginTransaction(redacted)")
}
func (LoginTransaction) LogValue() slog.Value {
	return slog.StringValue("sso.LoginTransaction(redacted)")
}
func (LoginTransaction) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (LoginTransaction) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

func (ProtocolStartResult) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "sso.ProtocolStartResult(redacted)")
}
func (ProtocolStartResult) LogValue() slog.Value {
	return slog.StringValue("sso.ProtocolStartResult(redacted)")
}
func (ProtocolStartResult) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (ProtocolStartResult) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

func (ProtocolCallback) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "sso.ProtocolCallback(redacted)")
}
func (ProtocolCallback) LogValue() slog.Value {
	return slog.StringValue("sso.ProtocolCallback(redacted)")
}
func (ProtocolCallback) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (ProtocolCallback) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
