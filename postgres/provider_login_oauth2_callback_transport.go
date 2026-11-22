package postgres

import (
	"context"
	"reflect"
	"slices"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/risk"
	organization "github.com/faustbrian/go-organization"
	"github.com/faustbrian/go-sso"
)

// Only acknowledged native generation may enter this operation. Reading the
// installed material is not permission to open either retained secret.
func (p *providerLoginCallbackInvocation) exchangeOAuth2Acknowledged(ctx context.Context, callback oauth.QueryCallback, transport StaticOAuth2CompletionProfile, admission risk.AuthenticationAdmission) (providerLoginCallbackExchange, error) {
	if p == nil || p.service == nil || p.service.router == nil || p.service.router.config.Clock == nil || p.authenticatedAt.IsZero() || ctx == nil || p.member != nil {
		return providerLoginCallbackExchange{}, identity.ForbiddenError{}
	}
	s := p.service
	clock := s.router.config.Clock
	now := clock.Now().UTC()
	if err := p.checkOriginal(now); err != nil {
		return providerLoginCallbackExchange{}, err
	}
	if err := admission.CheckAt(ctx, now); err != nil {
		return providerLoginCallbackExchange{}, err
	}
	key := providerLoginProfileKey{organization: organization.ID(p.found.Row.OrganizationID), provider: sso.ProviderID(p.found.Row.ProviderID)}
	selected, ok := s.oauthProfiles[key]
	if !ok {
		return providerLoginCallbackExchange{}, identity.ForbiddenError{}
	}
	material, err := s.readProviderOAuth2CallbackMaterial(ctx, p.found, p.original, p.authority)
	if err != nil {
		return providerLoginCallbackExchange{}, err
	}
	defer clear(material.credential)
	defer clear(material.credentialContext)
	defer clear(material.verifier)
	result, err := s.payload.exchangeProviderLoginOAuth2(ctx, providerLoginOAuth2ExchangeInput{
		original: p.original, binding: p.found.Binding.Metadata, observedAt: p.found.ObservedAt, deadline: p.authority.deadline,
		selected: selected, transport: transport, material: material, callback: callback, clock: clock,
		beforePost: func(ctx context.Context, at time.Time) error {
			if err := p.checkOriginal(at); err != nil {
				return err
			}
			return admission.CheckAt(ctx, at)
		},
	})
	return providerLoginCallbackExchange{ExchangeResult: result, mapping: material.configuration.Mapping, providerEnabled: err == nil}, err
}

type providerLoginOAuth2ExchangeInput struct {
	original             providerLoginStartInput
	binding              providerLoginBindingMetadata
	observedAt, deadline time.Time
	selected             StaticOAuth2LoginProfile
	transport            StaticOAuth2CompletionProfile
	material             providerOAuth2CallbackMaterial
	callback             oauth.QueryCallback
	clock                oauth.Clock
	beforePost           func(context.Context, time.Time) error
}

func (c providerLoginPayloadConfig) exchangeProviderLoginOAuth2(ctx context.Context, request providerLoginOAuth2ExchangeInput) (oauth.ExchangeResult, error) {
	if ctx == nil || request.clock == nil || request.beforePost == nil {
		return oauth.ExchangeResult{}, sso.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return oauth.ExchangeResult{}, err
	}
	now := request.clock.Now().UTC()
	input := request.binding.Input
	if request.original.Protocol != providerProtocolOAuth2 || input.Protocol != providerProtocolOAuth2 || request.original.Link != nil || input.Link != nil ||
		request.binding.Public.Nonce != "" || now.IsZero() || request.observedAt.IsZero() || request.observedAt.Before(input.IssuedAt) || now.Before(request.observedAt) ||
		!now.Before(request.deadline) || request.deadline.After(request.observedAt.Add(20*time.Second)) || request.deadline.After(input.ExpiresAt) ||
		string(request.original.ProviderID) != input.ProviderID || string(request.original.Proof.OrganizationID) != input.OrganizationID ||
		request.original.Issuer != input.Issuer || request.original.ClientID != input.ClientID || request.original.ProtocolRedirectURI != input.RedirectURI ||
		request.original.ProviderVersion != input.ProviderVersion || request.original.Generation != input.CredentialGeneration || request.original.MappingVersion != input.MappingVersion ||
		request.material.credentialVersion < 2 || request.material.credentialVersion > input.ProviderVersion {
		return oauth.ExchangeResult{}, sso.ErrForbidden
	}
	if err := validateProviderOAuth2ExchangeProfile(request.original, request.selected, request.transport, request.material.configuration); err != nil {
		return oauth.ExchangeResult{}, err
	}
	// Translate native authority's remaining lifetime without extending an
	// earlier caller deadline, even when the trusted clock is not wall time.
	ctx, cancel := context.WithTimeout(ctx, request.deadline.Sub(now))
	defer cancel()
	var result oauth.ExchangeResult
	err := c.withOAuth2CallbackVerifier(ctx, request.binding, now, request.material.verifier, func(ctx context.Context, verifierBytes []byte) error {
		verifier, err := oauth.NewPKCEVerifier(verifierBytes)
		if err != nil {
			return err
		}
		defer verifier.Destroy()
		return withAuthenticatedProtocolProviderCredential(ctx, c.Envelope, providerProtocolOAuth2, string(input.Command.TenantID), input.OrganizationID, input.ProviderID,
			request.material.credential, request.material.credentialContext, input.CredentialGeneration, request.material.credentialVersion,
			func(ctx context.Context, secret []byte) error {
				claims := providerOAuth2MappedClaimNames(request.material.configuration.Mapping)
				provider, err := newProviderOAuth2Transport(request.transport, request.clock, secret, claims)
				if err != nil {
					return err
				}
				defer provider.Close()
				if !reflect.DeepEqual(provider.Profile(), request.transport.Profile.Profile) {
					return sso.ErrForbidden
				}
				if err := ctx.Err(); err != nil {
					return err
				}
				at := request.clock.Now().UTC()
				if at.Before(now) || !at.Before(request.deadline) {
					return sso.ErrForbidden
				}
				if err := request.beforePost(ctx, at); err != nil {
					return err
				}
				result, err = provider.Exchange(ctx, request.callback, verifier, oauth.AuthorizationParameters{State: request.binding.Public.State, PKCEChallenge: request.binding.Public.Challenge})
				return err
			})
	})
	if err != nil {
		result.Tokens.Destroy()
		return oauth.ExchangeResult{}, err
	}
	return result, nil
}

func validateProviderOAuth2ExchangeProfile(original providerLoginStartInput, selected StaticOAuth2LoginProfile, transport StaticOAuth2CompletionProfile, installed providerOAuthConfiguration) error {
	base, details := transport.Profile.Profile, transport.Profile.Details
	if original.Protocol != providerProtocolOAuth2 || original.Link != nil || validateProviderOAuth2LoginConfiguration(installed) != nil {
		return sso.ErrForbidden
	}
	if selected.ProviderID != original.ProviderID || selected.OrganizationID != original.Proof.OrganizationID || selected.Domain != original.Proof.Domain ||
		selected.ClientID != original.ClientID || selected.ProtocolRedirectURI != original.ProtocolRedirectURI || selected.ProviderVersion != original.ProviderVersion ||
		selected.CredentialGeneration != original.Generation || selected.MappingVersion != original.MappingVersion ||
		transport.OrganizationID != selected.OrganizationID || transport.ProviderID != selected.ProviderID ||
		installed.Proof.Issuer != original.Issuer || installed.AuthorizationEndpoint != original.AuthorizationEndpoint ||
		installed.Mapping.Version != original.MappingVersion || len(installed.Domains) != 1 || installed.Domains[0] != original.Proof.Domain {
		return sso.ErrForbidden
	}
	namespace, err := SSOOAuth2AccountProviderNamespace(selected.OrganizationID, selected.ProviderID)
	if err != nil || base.ID != strings.ReplaceAll(namespace, ".", "-") || base.Version != original.ProviderVersion || base.Issuer != original.Issuer ||
		base.AuthorizationEndpoint != installed.AuthorizationEndpoint || base.TokenEndpoint != installed.TokenEndpoint || details.UserInfoEndpoint != installed.IdentityEndpoint ||
		base.ClientID != original.ClientID || base.RedirectURI != original.ProtocolRedirectURI || !slices.Equal(base.Scopes, selected.Scopes) ||
		base.ClientAuthentication != oauth.ClientSecretPost || details.SubjectClaim != installed.Mapping.SubjectClaim ||
		details.ProofLifetime < time.Second || details.ProofLifetime > 20*time.Second {
		return sso.ErrForbidden
	}
	kindMatches := installed.Proof.SubjectKind == sso.OAuthSubjectString && details.SubjectEncoding == oauth.OAuth2StringSubject ||
		installed.Proof.SubjectKind == sso.OAuthSubjectPositiveInteger && details.SubjectEncoding == oauth.OAuth2PositiveIntegerSubject
	if !kindMatches {
		return sso.ErrForbidden
	}
	return nil
}

func newProviderOAuth2Transport(profile StaticOAuth2CompletionProfile, clock oauth.Clock, secret []byte, claims []string) (*oauth.SharedOAuth2UserInfoProvider, error) {
	base, details := profile.Profile.Profile, profile.Profile.Details
	return oauth.NewSharedOAuth2UserInfoProvider(oauth.OAuth2UserInfoConfig{
		ID: base.ID, Version: base.Version, Issuer: base.Issuer, AuthorizationEndpoint: base.AuthorizationEndpoint, TokenEndpoint: base.TokenEndpoint,
		UserInfoEndpoint: details.UserInfoEndpoint, RedirectURI: base.RedirectURI, ClientID: base.ClientID,
		ClientSecret: secret, ClientAuthentication: base.ClientAuthentication, Scopes: base.Scopes,
		SubjectClaim: details.SubjectClaim, SubjectEncoding: details.SubjectEncoding, ProofLifetime: details.ProofLifetime,
		Clock: clock, HTTPClient: profile.HTTPClient, Timeout: base.Timeout, MaxResponseBytes: base.MaxResponseBytes, MaxTokenBytes: base.MaxTokenBytes, MaxCodeBytes: base.MaxCodeBytes,
	}, claims)
}

func providerOAuth2MappedClaimNames(mapping sso.AttributeMappingSpec) []string {
	var names []string
	for _, name := range []string{mapping.EmailClaim, mapping.DisplayNameClaim, mapping.VerifiedEmailClaim} {
		if name != "" && !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	return names
}
