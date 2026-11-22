//go:build integration

package postgres

import (
	"context"

	"github.com/faustbrian/go-sso"
)

const ProviderOAuth2CallbackMaterialSQLForTest = providerOAuth2CallbackMaterialSQL

type ProviderOAuth2CallbackMaterialProjectionForTest struct {
	AuthorizationEndpoint, TokenEndpoint, IdentityEndpoint, RevocationEndpoint string
	Proof                                                                      sso.IdentityProofPolicySpec
	Mapping                                                                    sso.AttributeMappingSpec
	Domains                                                                    []string
	CredentialVersion                                                          uint64
	HasCredential, HasVerifier                                                 bool
}

// Return only nonsecret configuration and custody-presence metadata after the
// genuine native browser, original-request and authority boundaries.
func ReadProviderOAuth2CallbackMaterialForTest(ctx context.Context, service *ProviderLoginService, state string, browser ProviderLoginBrowser) (ProviderOAuth2CallbackMaterialProjectionForTest, error) {
	found, err := service.lookupProviderOAuth2LoginCallback(ctx, state)
	if err != nil {
		return ProviderOAuth2CallbackMaterialProjectionForTest{}, err
	}
	defer clear(found.Binding.Proof)
	flow, err := service.authenticateProviderLoginCallbackBrowser(ctx, found, browser)
	if err != nil {
		return ProviderOAuth2CallbackMaterialProjectionForTest{}, err
	}
	original, err := service.readProviderLoginCallbackOrigin(ctx, found, flow)
	if err != nil {
		return ProviderOAuth2CallbackMaterialProjectionForTest{}, err
	}
	authority, err := service.observeProviderLoginCallbackAuthority(ctx, found, original)
	if err != nil {
		return ProviderOAuth2CallbackMaterialProjectionForTest{}, err
	}
	material, err := service.readProviderOAuth2CallbackMaterial(ctx, found, original, authority)
	defer clear(material.credential)
	defer clear(material.credentialContext)
	defer clear(material.verifier)
	if err != nil {
		return ProviderOAuth2CallbackMaterialProjectionForTest{}, err
	}
	c := material.configuration
	return ProviderOAuth2CallbackMaterialProjectionForTest{
		AuthorizationEndpoint: c.AuthorizationEndpoint, TokenEndpoint: c.TokenEndpoint, IdentityEndpoint: c.IdentityEndpoint, RevocationEndpoint: c.RevocationEndpoint,
		Proof: c.Proof, Mapping: c.Mapping, Domains: c.Domains, CredentialVersion: material.credentialVersion,
		HasCredential: len(material.credential) != 0, HasVerifier: len(material.verifier) != 0,
	}, nil
}

// Preserve the production statement's actual driver binding types for bounded
// query-plan measurement. Do not print opaque state or ciphertext in evidence.
func ProviderOAuth2CallbackMaterialArgsForTest(ctx context.Context, service *ProviderLoginService, state string, browser ProviderLoginBrowser) ([]any, error) {
	found, err := service.lookupProviderOAuth2LoginCallback(ctx, state)
	if err != nil {
		return nil, err
	}
	defer clear(found.Binding.Proof)
	flow, err := service.authenticateProviderLoginCallbackBrowser(ctx, found, browser)
	if err != nil {
		return nil, err
	}
	original, err := service.readProviderLoginCallbackOrigin(ctx, found, flow)
	if err != nil {
		return nil, err
	}
	authority, err := service.observeProviderLoginCallbackAuthority(ctx, found, original)
	if err != nil {
		return nil, err
	}
	return providerLoginCallbackMaterialArgs(found, original, authority), nil
}
