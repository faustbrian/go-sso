//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"strconv"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	organization "github.com/faustbrian/go-organization"
	"github.com/faustbrian/go-sso"
)

// Run the exact shared provider-lock query through two real PostgreSQL transactions.
const ProviderLoginAdmissionFenceForTest = providerLoginAdmissionFenceSQL
const ProviderLoginInsertForTest = insertProviderLoginTransactionSQL

func ObserveProviderLoginAuthorityForTest(ctx context.Context, router *ProviderRouter, route sso.DomainRoute) (organization.CredentialAuthorityObservation, error) {
	authority, err := router.observeProviderLoginAuthority(ctx, route)
	return authority.organization, err
}

// Read only what a callback sees: the trusted tenant and returned opaque state.
// Use the fixture's single retained key to locate and authenticate the actual
// committed row. This makes no callback/consumption or freshness claim.
func InspectOriginalLoginIntentForTest(ctx context.Context, service *ProviderLoginService, tenant identity.TenantID, state string) (origin, success, failure string, remember session.RememberPolicySpec, err error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(state)
	defer clear(raw)
	if err != nil {
		return "", "", "", remember, err
	}
	version := service.payload.CurrentStateKey
	digest, err := providerLoginStateDigest(service.payload.StateKeys[version], version, tenant, raw)
	if err != nil {
		return "", "", "", remember, err
	}
	row := providerLoginRowIdentity{TenantID: tenant}
	var providerVersion, generation, mapping string
	var callback identity.CommandID
	var wire []byte
	err = service.router.pool.Raw().QueryRow(ctx, `SELECT organization_id,provider_id,provider_version::text,credential_generation::text,mapping_version::text,
 start_command_id,callback_command_id,issued_at,expires_at,binding_envelope FROM sso_providers.login_transactions
 WHERE tenant_id=$1 AND state_key_version=$2 AND state_digest=$3`, string(tenant), int64(version), digest[:]).Scan(
		&row.OrganizationID, &row.ProviderID, &providerVersion, &generation, &mapping, &row.StartCommandID, &callback, &row.IssuedAt, &row.ExpiresAt, &wire)
	defer clear(wire)
	if err != nil {
		return "", "", "", remember, err
	}
	for _, pair := range []struct {
		wire  string
		value *uint64
	}{{providerVersion, &row.ProviderVersion}, {generation, &row.CredentialGeneration}, {mapping, &row.MappingVersion}} {
		*pair.value, err = strconv.ParseUint(pair.wire, 10, 64)
		if err != nil {
			return "", "", "", remember, err
		}
	}
	row.IssuedAt, row.ExpiresAt = row.IssuedAt.UTC(), row.ExpiresAt.UTC()
	resolved, err := service.payload.openCommittedBinding(ctx, row, wire)
	defer clear(resolved.Proof)
	if err != nil || resolved.Metadata.StateKey != version || resolved.Metadata.StateDigest != digest || resolved.Metadata.CallbackCommand != callback {
		return "", "", "", remember, sso.ErrForbidden
	}
	i := resolved.Metadata.Input
	return i.BrowserOrigin, i.SuccessCallback, i.ErrorCallback, i.Remember, nil
}
