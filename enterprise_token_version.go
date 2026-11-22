package sso

import (
	"fmt"
	"log/slog"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

// EnterpriseTokenPurpose is the fixed SSO enterprise-token custody namespace.
// It distinguishes token correlation from client credentials and other secret
// purposes and matches the retained providerLoginTokenAAD purpose. It grants
// neither storage nor access to provider tokens.
const EnterpriseTokenPurpose = "enterprise-provider-tokens"

// TokenVersionSpec is an explicit construction or trusted storage projection of
// nonsecret token-custody correlation. Tenant and provider use the existing SSO
// 1..128-byte printable ASCII owner grammar. Organization uses organization.ID's
// exact grammar; ProviderSubject uses ProtocolAssertion's 1..512-byte exact UTF-8
// subject grammar. CommandID is the original canonical callback command identity,
// not a newly allocated linkage or retry command. Both versions are positive,
// and Purpose must equal EnterpriseTokenPurpose. No normalization is performed.
//
// These fields do not authenticate protocol evidence or establish custody,
// retention, policy, read permission or recoverable token storage. Native Work
// must compare them with its separately reserved transaction and current owner
// state, including the tenant and activated provider credential generation.
// Callers must never place access/refresh tokens or credentials in these fields.
type TokenVersionSpec struct {
	TenantID             identity.TenantID
	OrganizationID       organization.ID
	ProviderID           ProviderID
	ProviderSubject      string
	CommandID            identity.CommandID
	CredentialGeneration uint64
	Version              uint64
	Purpose              string
}

// TokenVersion is immutable, comparable, opaque nonsecret token-custody
// correlation. Zero is invalid as a standalone value and denotes omission only
// in ProtocolAssertion.TokenReference. Copies are safe for concurrent reads.
// It owns no tokens, handles, network or storage resources and grants no access.
type TokenVersion struct {
	spec  TokenVersionSpec
	valid bool
}

// NewTokenVersion validates bounded shape only and copies the exact correlation.
// It performs no authentication, authorization, token exchange or storage lookup.
// Invalid input returns only ErrInvalidInput and an unusable zero value without
// retaining or disclosing supplied fields.
func NewTokenVersion(spec TokenVersionSpec) (TokenVersion, error) {
	if !providerClaimName(string(spec.TenantID)) || !protocolAssertionOrganizationID(spec.OrganizationID) || !providerClaimName(string(spec.ProviderID)) {
		return TokenVersion{}, ErrInvalidInput
	}
	if !protocolAssertionText(spec.ProviderSubject, 1, 512) || spec.CredentialGeneration == 0 || spec.Version == 0 || spec.Purpose != EnterpriseTokenPurpose {
		return TokenVersion{}, ErrInvalidInput
	}
	if _, err := identity.ParseCommandID(string(spec.CommandID)); err != nil {
		return TokenVersion{}, ErrInvalidInput
	}
	return TokenVersion{spec: spec, valid: true}, nil
}

// Spec explicitly projects detached correlation for trusted storage/composition.
// The projection is not a vault lookup or read permission. The zero reference
// returns ErrInvalidInput and no correlation; copies cannot mutate the original.
func (v TokenVersion) Spec() (TokenVersionSpec, error) {
	if !v.valid {
		return TokenVersionSpec{}, ErrInvalidInput
	}
	return v.spec, nil
}

func (TokenVersionSpec) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("sso.TokenVersionSpec(redacted)"))
}

func (TokenVersionSpec) LogValue() slog.Value {
	return slog.StringValue("sso.TokenVersionSpec(redacted)")
}

func (TokenVersionSpec) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (TokenVersionSpec) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

func (TokenVersion) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("sso.TokenVersion(redacted)"))
}

func (TokenVersion) LogValue() slog.Value {
	return slog.StringValue("sso.TokenVersion(redacted)")
}

func (TokenVersion) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (TokenVersion) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
