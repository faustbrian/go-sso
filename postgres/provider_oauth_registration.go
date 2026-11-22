package postgres

import (
	"context"
	"encoding/json"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-sso"
)

const (
	providerProtocolOIDC   = "oidc"
	providerProtocolOAuth2 = "oauth2"
)

func (r providerCommandInput) providerProtocol() string {
	if r.protocol == providerProtocolOAuth2 {
		return providerProtocolOAuth2
	}
	return providerProtocolOIDC
}

func providerOAuthRegistrationOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "sso", OperationID: "identity.sso.provider.register-oauth", SchemaID: "sso-disabled-static-oauth2-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// WithOAuthRegistration returns an opt-in copy after the operator applies
// both provider protocol migrations. Its safe reads project both installed
// protocols. It installs no routes and enables no OAuth providers. All
// registry consumers for the primary must support this profile before the
// first OAuth registration; legacy binaries assume only OIDC records exist.
// The method performs no I/O and does not change the original service.
func (s *ProviderService) WithOAuthRegistration() (*ProviderService, error) {
	if s == nil || s.pool == nil {
		return nil, sso.ErrInvalidInput
	}
	selected := *s
	selected.oauthRegistration = true
	return &selected, nil
}

type providerOAuthConfiguration struct {
	AuthorizationEndpoint string
	TokenEndpoint         string
	IdentityEndpoint      string
	RevocationEndpoint    string
	Proof                 sso.IdentityProofPolicySpec
	Mapping               sso.AttributeMappingSpec
	Domains               []string
}

// ProviderRegisterOauth registers only disabled static metadata using the same
// coordinator, current administration, audit and outbox owners as OIDC. It
// accepts no credentials, does no provider I/O, and cannot create domain proof
// or a route. The exact key and request recover the original admission; the
// command and policy namespace differ from OIDC.
func (s *ProviderService) ProviderRegisterOauth(ctx context.Context, r sso.ProviderRegisterOauthRequest) (sso.ProviderRegisterOauthResult, error) {
	if s == nil || ctx == nil || r.Validate() != nil {
		return sso.ProviderRegisterOauthResult{}, sso.ErrInvalidInput
	}
	if !s.oauthRegistration {
		return sso.ProviderRegisterOauthResult{}, sso.ErrForbidden
	}
	proof, _ := r.IdentityProofPolicy.Spec()
	request := providerCommandInput{CommandID: r.CommandID, OrganizationID: r.OrganizationID,
		Issuer: proof.Issuer, Domains: r.Domains, Mapping: r.Mapping, protocol: providerProtocolOAuth2}
	result, err := s.registerDisabledProvider(ctx, request, r.IdempotencyKey, func() ([]byte, error) {
		mapping, _ := r.Mapping.Spec()
		return json.Marshal(providerOAuthConfiguration{
			AuthorizationEndpoint: r.AuthorizationEndpoint.String(), TokenEndpoint: r.TokenEndpoint.String(),
			IdentityEndpoint: r.IdentityEndpoint.String(), RevocationEndpoint: r.RevocationEndpoint.String(),
			Proof: proof, Mapping: mapping, Domains: r.Domains,
		})
	})
	return sso.ProviderRegisterOauthResult(result), err
}
