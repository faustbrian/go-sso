package postgres

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-sso"
)

type providerOAuth2StartAdapter struct {
	factory  OAuth2ProtocolAdapterFactory
	profiles map[providerLoginProfileKey]StaticOAuth2CompletionProfile
}

// NewProviderOAuth2LoginServicesWithAdapter selects one implementation for
// native OAuth2 start disclosure and reserved callback completion. Provide a
// transport profile for every OAuth2 route on start. The returned services
// borrow the same immutable start configuration, but the supplied start is
// not changed. Start must preserve the exact stored capability expiry. OIDC is
// unaffected and selected OAuth2 never falls back.
func NewProviderOAuth2LoginServicesWithAdapter(start *ProviderLoginService, config ProviderLoginCompletionConfig, profiles []StaticOAuth2CompletionProfile, factory OAuth2ProtocolAdapterFactory) (*ProviderLoginService, *ProviderOAuth2LoginCompletionService, error) {
	if start == nil || len(profiles) != len(start.oauthProfiles) {
		return nil, nil, sso.ErrInvalidInput
	}
	selected := *start
	completion, err := NewProviderOAuth2LoginCompletionServiceWithAdapter(&selected, config, profiles, factory)
	if err != nil {
		return nil, nil, err
	}
	selected.oauthStartAdapter = &providerOAuth2StartAdapter{factory: factory, profiles: completion.profiles}
	return &selected, completion, nil
}

func (a *providerOAuth2StartAdapter) redirect(ctx context.Context, original providerLoginStartInput, binding providerLoginBindingMetadata, profile providerLoginProfile, clock oauth.Clock, disclosureDeadline time.Time) (url.URL, error) {
	selected := StaticOAuth2LoginProfile(profile.configured)
	transport, ok := a.profiles[providerLoginProfileKey{selected.OrganizationID, selected.ProviderID}]
	if !ok || binding.Public.Nonce != "" || !clock.Now().Before(disclosureDeadline) {
		return url.URL{}, sso.ErrForbidden
	}
	if err := validateProviderOAuth2ExchangeProfile(original, selected, transport, profile.oauthConfiguration); err != nil {
		return url.URL{}, err
	}
	tx, err := binding.protocolTransaction(original)
	if err != nil {
		return url.URL{}, err
	}
	proof, err := sso.NewIdentityProofPolicy(profile.oauthConfiguration.Proof)
	if err != nil {
		return url.URL{}, sso.ErrForbidden
	}
	mapping, err := sso.NewAttributeMapping(profile.oauthConfiguration.Mapping)
	if err != nil {
		return url.URL{}, sso.ErrForbidden
	}
	config := newOAuth2ProtocolAdapterConfig(tx, binding.Public, selected.CredentialGeneration, transport, clock, proof, mapping)
	config.HTTPClient = nil // Start has no transport or secret custody.
	adapter, err := a.factory(config)
	if err != nil || adapter == nil {
		return url.URL{}, sso.ErrUnavailable
	}
	command := sso.ProtocolStartCommand{Transaction: tx, Provider: sso.Provider{
		ID: tx.ProviderID, OrganizationID: string(tx.OrganizationID), Protocol: tx.Protocol,
		Version: tx.ProviderVersion, MappingVersion: tx.MappingVersion, Enabled: true,
	}}
	result, err := adapter.Start(ctx, command)
	if err != nil {
		if ctx.Err() != nil {
			return url.URL{}, ctx.Err()
		}
		return url.URL{}, sso.ErrUnavailable
	}
	// The factory received its own copy of the scopes. Validate against the
	// native profile, not a slice it could have mutated while rendering.
	config.Profile = transport.Profile
	if err := validateOAuth2AdapterStartRedirect(result, config, clock.Now()); err != nil {
		return url.URL{}, err
	}
	return result.Redirect, nil
}

func validateOAuth2AdapterStartRedirect(result sso.ProtocolStartResult, config OAuth2ProtocolAdapterConfig, now time.Time) error {
	// The browser response has no expiry field. The callback can enforce only
	// the committed expiry, so do not accept a different adapter cutoff.
	if !result.ExpiresAt.Equal(config.CapabilityExpiresAt) {
		return sso.ErrForbidden
	}
	if err := result.ValidateFor(config.Transaction, now, config.CapabilityExpiresAt); err != nil {
		return sso.ErrForbidden
	}
	profile := config.Profile.Profile
	endpoint := result.Redirect
	endpoint.RawQuery = ""
	if endpoint.String() != profile.AuthorizationEndpoint {
		return sso.ErrForbidden
	}
	query, err := url.ParseQuery(result.Redirect.RawQuery)
	if err != nil {
		return sso.ErrForbidden
	}
	// A rendering adapter cannot substitute the committed state, PKCE or
	// exact client scope. The selected native profile has no extra parameters.
	expected := map[string]string{
		"response_type": "code", "response_mode": "query", "client_id": profile.ClientID, "redirect_uri": profile.RedirectURI,
		"scope": strings.Join(profile.Scopes, " "), "state": config.Authorization.State,
		"code_challenge": config.Authorization.PKCEChallenge, "code_challenge_method": "S256",
	}
	if len(query) != len(expected) {
		return sso.ErrForbidden
	}
	for key, value := range expected {
		if matches := query[key]; len(matches) != 1 || matches[0] != value {
			return sso.ErrForbidden
		}
	}
	return nil
}
