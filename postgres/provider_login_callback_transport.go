package postgres

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	organization "github.com/faustbrian/go-organization"
	"github.com/faustbrian/go-sso"
)

type providerLoginOIDCExchangeInput struct {
	original                      providerLoginBindingMetadata
	observedAt, deadline          time.Time
	profile                       StaticOIDCLoginProfile
	metadata, pinnedMetadata      sso.OIDCStaticMetadataSpec
	credential, credentialContext []byte
	credentialVersion             uint64
	verifier                      []byte
	callback                      identity.OAuthCallbackInput
	clientAuthentication          oauth.ClientAuthentication
	algorithms, claimNames        []string
	keys                          oauth.SigningKeySet
	client                        *http.Client
	clock                         oauth.Clock
	beforePost                    func(context.Context, time.Time) error
}

// exchangeProviderLoginOIDC may run only in the native coordinator's
// acknowledged generation callback. It borrows the original PKCE and client
// credential for one Golib exchange and does not own reservation or retry.
func (c providerLoginPayloadConfig) exchangeProviderLoginOIDC(ctx context.Context, request providerLoginOIDCExchangeInput) (oauth.ExchangeResult, error) {
	if ctx == nil || request.clock == nil || request.beforePost == nil {
		return oauth.ExchangeResult{}, sso.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return oauth.ExchangeResult{}, err
	}
	now := request.clock.Now()
	if !request.authorizesExchangeAt(now) {
		return oauth.ExchangeResult{}, sso.ErrForbidden
	}
	// The observed deadline comes from native authority; translating its
	// remaining duration also preserves an earlier real caller deadline.
	ctx, cancel := context.WithTimeout(ctx, request.deadline.Sub(now))
	defer cancel()
	stateMatches := false
	if err := request.callback.Use(ctx, func(_ context.Context, _, state []byte) error {
		stateMatches = subtle.ConstantTimeCompare(state, []byte(request.original.Public.State)) == 1
		return nil
	}); err != nil {
		return oauth.ExchangeResult{}, err
	}
	if !stateMatches {
		return oauth.ExchangeResult{}, sso.ErrForbidden
	}

	input := request.original.Input
	var result oauth.ExchangeResult
	err := c.withCallbackVerifier(ctx, request.original, now, request.verifier, func(ctx context.Context, verifierBytes []byte) error {
		verifier, err := oauth.NewPKCEVerifier(verifierBytes)
		if err != nil {
			return err
		}
		defer verifier.Destroy()
		return withAuthenticatedStoredProviderCredential(ctx, c.Envelope, string(input.Command.TenantID), input.OrganizationID, input.ProviderID,
			request.credential, request.credentialContext, input.CredentialGeneration, request.credentialVersion, func(ctx context.Context, secret []byte) error {
				provider, err := request.newOIDCProvider(secret)
				if err != nil {
					return err
				}
				defer provider.Close()
				if err := ctx.Err(); err != nil {
					return err
				}
				at := request.clock.Now()
				if at.Before(now) || !at.Before(request.deadline) {
					return sso.ErrForbidden
				}
				if err := request.beforePost(ctx, at); err != nil {
					return err
				}
				result, err = provider.Exchange(ctx, request.callback, verifier, request.original.Public.Nonce)
				return err
			})
	})
	if err != nil {
		result.Tokens.Destroy()
		return oauth.ExchangeResult{}, err
	}
	return result, nil
}

func (p providerLoginOIDCExchangeInput) authorizesExchangeAt(now time.Time) bool {
	input := p.original.Input
	if now.IsZero() || p.observedAt.IsZero() || p.observedAt.Before(input.IssuedAt) || now.Before(p.observedAt) || !now.Before(p.deadline) ||
		p.deadline.After(p.observedAt.Add(20*time.Second)) || p.deadline.After(input.ExpiresAt) {
		return false
	}
	profile := p.profile
	if string(profile.ProviderID) != input.ProviderID || string(profile.OrganizationID) != input.OrganizationID ||
		profile.ClientID != input.ClientID || profile.ProtocolRedirectURI != input.RedirectURI || profile.ProviderVersion != input.ProviderVersion ||
		profile.CredentialGeneration != input.CredentialGeneration || profile.MappingVersion != input.MappingVersion {
		return false
	}
	if p.metadata != p.pinnedMetadata || p.metadata.Issuer != input.Issuer || p.credentialVersion < 2 || p.credentialVersion > input.ProviderVersion {
		return false
	}
	return p.clientAuthentication == oauth.ClientSecretBasic || p.clientAuthentication == oauth.ClientSecretPost
}

func (p providerLoginOIDCExchangeInput) newOIDCProvider(secret []byte) (*oauth.OIDCProvider, error) {
	protocolID, err := ssoOIDCTransportProviderID(p.profile.OrganizationID, p.profile.ProviderID)
	if err != nil {
		return nil, err
	}
	config := oauth.OIDCConfig{
		ID: protocolID, Issuer: p.metadata.Issuer, AuthorizationEndpoint: p.metadata.AuthorizationEndpoint, TokenEndpoint: p.metadata.TokenEndpoint,
		RedirectURI: p.profile.ProtocolRedirectURI, ClientID: p.profile.ClientID, Version: p.profile.ProviderVersion,
		ClientSecret: secret, ClientAuthentication: p.clientAuthentication, Scopes: p.profile.Scopes, Algorithms: p.algorithms,
		KeySet: p.keys, HTTPClient: p.client, Clock: p.clock,
	}
	if len(p.claimNames) == 0 {
		return oauth.NewOIDCProvider(config)
	}
	return oauth.NewOIDCProviderWithClaims(config, oauth.OIDCClaimProjectionConfig{Names: p.claimNames})
}

// The OAuth client accepts lowercase logical IDs, while native provider IDs
// can carry case-sensitive base64url bytes. Derive the logical identity from
// the original scoped digest instead of lowercasing the native identifier.
func ssoOIDCTransportProviderID(organizationID organization.ID, provider sso.ProviderID) (string, error) {
	namespace, err := SSOOIDCAccountProviderNamespace(organizationID, provider)
	return strings.ReplaceAll(namespace, ".", "-"), err
}
