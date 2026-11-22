//go:build integration

package postgres

import (
	"context"

	"github.com/faustbrian/go-sso"
)

const ProviderLoginCallbackMaterialSQLForTest = providerLoginCallbackMaterialSQL

// Only return nonsecret configuration after exercising the genuine lookup,
// browser, original-request and authority reads. Ciphertext stays scoped here.
func ReadProviderLoginCallbackMaterialForTest(ctx context.Context, service *ProviderLoginService, state string, browser ProviderLoginBrowser) (sso.OIDCStaticMetadataSpec, error) {
	found, err := service.lookupProviderLoginCallback(ctx, state)
	if err != nil {
		return sso.OIDCStaticMetadataSpec{}, err
	}
	defer clear(found.Binding.Proof)
	flow, err := service.authenticateProviderLoginCallbackBrowser(ctx, found, browser)
	if err != nil {
		return sso.OIDCStaticMetadataSpec{}, err
	}
	original, err := service.readProviderLoginCallbackOrigin(ctx, found, flow)
	if err != nil {
		return sso.OIDCStaticMetadataSpec{}, err
	}
	authority, err := service.observeProviderLoginCallbackAuthority(ctx, found, original)
	if err != nil {
		return sso.OIDCStaticMetadataSpec{}, err
	}
	material, err := service.readProviderLoginCallbackMaterial(ctx, found, original, authority)
	defer clear(material.credential)
	defer clear(material.credentialContext)
	defer clear(material.verifier)
	return material.metadata, err
}

// Preserve the exact production SQL's actual typed driver bindings for bounded
// local PostgreSQL query-plan evidence; no raw state or secret is returned.
func ProviderLoginCallbackMaterialArgsForTest(ctx context.Context, service *ProviderLoginService, state string, browser ProviderLoginBrowser) ([]any, error) {
	found, err := service.lookupProviderLoginCallback(ctx, state)
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
