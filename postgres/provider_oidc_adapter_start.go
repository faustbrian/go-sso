package postgres

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"slices"
	"time"

	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-sso"
)

// OIDCStartAdapterFactory constructs a trusted renderer for an already
// committed native OIDC start. It must not delegate routing or state creation.
type OIDCStartAdapterFactory func(OIDCStartAdapterConfig) (sso.ProtocolAdapter, error)

// OIDCStartAdapterConfig supplies the retained transaction and installed
// static profile. It contains no credentials, callback hooks, signing keys
// or network client. Authorization remains private to this browser redirect.
type OIDCStartAdapterConfig struct {
	Transaction          sso.LoginTransaction
	CredentialGeneration uint64
	Profile              oauth.ProviderProfile
	Mapping              sso.AttributeMapping
	Authorization        oauth.AuthorizationParameters
	CapabilityExpiresAt  time.Time
	Clock                oauth.Clock
}

func (OIDCStartAdapterConfig) Format(w fmt.State, _ rune) {
	_, _ = io.WriteString(w, "postgres.OIDCStartAdapterConfig(redacted)")
}
func (OIDCStartAdapterConfig) LogValue() slog.Value {
	return slog.StringValue("postgres.OIDCStartAdapterConfig(redacted)")
}
func (OIDCStartAdapterConfig) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}
func (OIDCStartAdapterConfig) MarshalText() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}

type providerOIDCStartAdapter struct {
	factory  OIDCStartAdapterFactory
	profiles map[providerLoginProfileKey]oauth.ProviderProfile
}

// WithOIDCStartAdapter selects an adapter for Start on the exact static OIDC
// profiles installed in this completion service. The returned services retain
// the original routing, callback, explicit link, JIT, and role policy. The old
// pair remains unchanged. Construction does not invoke the factory or do I/O.
// Selected start disclosure fails closed if the adapter is unavailable or
// changes any retained redirect field. Other profiles remain native.
func (s *ProviderLoginCompletionService) WithOIDCStartAdapter(factory OIDCStartAdapterFactory) (*ProviderLoginService, *ProviderLoginCompletionService, error) {
	if s == nil || s.start == nil || s.start.oidcStartAdapter != nil || factory == nil || len(s.protocolProfiles) == 0 {
		return nil, nil, sso.ErrInvalidInput
	}
	start := *s.start
	start.oidcStartAdapter = &providerOIDCStartAdapter{factory: factory, profiles: s.protocolProfiles}
	complete := *s
	complete.start = &start
	return &start, &complete, nil
}

func (a *providerOIDCStartAdapter) redirect(ctx context.Context, wire oauth.ProviderProfile, original providerLoginStartInput, binding providerLoginBindingMetadata, installed providerLoginProfile, clock oauth.Clock, deadline time.Time) (url.URL, error) {
	if !clock.Now().Before(deadline) || wire.Issuer != original.Issuer || wire.AuthorizationEndpoint != original.AuthorizationEndpoint ||
		wire.Version != original.ProviderVersion || wire.ClientID != original.ClientID || wire.RedirectURI != original.ProtocolRedirectURI ||
		!slices.Equal(wire.Scopes, installed.configured.Scopes) || installed.mapping.Version != original.MappingVersion {
		return url.URL{}, sso.ErrForbidden
	}
	tx, err := binding.protocolTransaction(original)
	if err != nil {
		return url.URL{}, err
	}
	mapping, err := sso.NewAttributeMapping(installed.mapping)
	if err != nil {
		return url.URL{}, sso.ErrForbidden
	}
	expected, err := installed.authorizationRedirect(binding.Public)
	if err != nil {
		return url.URL{}, err
	}
	wire.Scopes = slices.Clone(wire.Scopes)
	wire.Algorithms = slices.Clone(wire.Algorithms)
	config := OIDCStartAdapterConfig{
		Transaction: tx, CredentialGeneration: original.Generation, Profile: wire, Mapping: mapping,
		Authorization:       oauth.AuthorizationParameters{State: binding.Public.State, Nonce: binding.Public.Nonce, PKCEChallenge: binding.Public.Challenge},
		CapabilityExpiresAt: tx.ExpiresAt, Clock: clock,
	}
	adapter, err := a.factory(config)
	if err != nil || adapter == nil {
		return url.URL{}, sso.ErrUnavailable
	}
	command := sso.ProtocolStartCommand{Transaction: tx, Provider: sso.Provider{
		ID: tx.ProviderID, OrganizationID: string(tx.OrganizationID), Protocol: tx.Protocol,
		Version: tx.ProviderVersion, MappingVersion: tx.MappingVersion, Enabled: true,
	}}
	result, err := adapter.Start(ctx, command)
	if ctx.Err() != nil {
		return url.URL{}, ctx.Err()
	}
	if err != nil {
		return url.URL{}, sso.ErrUnavailable
	}
	if err := validateOIDCAdapterStartRedirect(result, expected, tx, clock.Now()); err != nil {
		return url.URL{}, err
	}
	return result.Redirect, nil
}

func validateOIDCAdapterStartRedirect(result sso.ProtocolStartResult, expected url.URL, tx sso.LoginTransaction, now time.Time) error {
	// Only the original committed expiry is available to callback admission.
	// Use the native renderer as an independent oracle for the entire URL.
	if result.ValidateFor(tx, now, tx.ExpiresAt) != nil || !result.ExpiresAt.Equal(tx.ExpiresAt) || result.Redirect != expected {
		return sso.ErrForbidden
	}
	return nil
}
