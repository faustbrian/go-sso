//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

type ProviderLoginCallbackLookupForTest struct {
	TenantID, OrganizationID, ProviderID, StartCommandID, CallbackCommandID string
	ProviderVersion, CredentialGeneration, MappingVersion                   uint64
	Origin, Success, Failure                                                string
	Remember                                                                session.RememberPolicySpec
	IssuedAt, ExpiresAt, ObservedAt                                         time.Time
	CompletedAt                                                             *time.Time
	HasProof                                                                bool
	HasPlan                                                                 bool
}

func LookupProviderLoginCallbackForTest(ctx context.Context, service *ProviderLoginService, state string) (ProviderLoginCallbackLookupForTest, error) {
	return projectProviderLoginCallbackLookupForTest(service.lookupProviderLoginCallback(ctx, state))
}

func LookupProviderOAuth2LoginCallbackForTest(ctx context.Context, service *ProviderLoginService, state string) (ProviderLoginCallbackLookupForTest, error) {
	return projectProviderLoginCallbackLookupForTest(service.lookupProviderOAuth2LoginCallback(ctx, state))
}

func projectProviderLoginCallbackLookupForTest(found providerLoginCallbackLookup, err error) (ProviderLoginCallbackLookupForTest, error) {
	if err != nil {
		return ProviderLoginCallbackLookupForTest{}, err
	}
	defer clear(found.Binding.Proof)
	row, metadata := found.Row, found.Binding.Metadata
	input := metadata.Input
	return ProviderLoginCallbackLookupForTest{
		TenantID: string(row.TenantID), OrganizationID: row.OrganizationID, ProviderID: row.ProviderID,
		StartCommandID: string(row.StartCommandID), CallbackCommandID: string(metadata.CallbackCommand),
		ProviderVersion: row.ProviderVersion, CredentialGeneration: row.CredentialGeneration, MappingVersion: row.MappingVersion,
		Origin: input.BrowserOrigin, Success: input.SuccessCallback, Failure: input.ErrorCallback, Remember: input.Remember,
		IssuedAt: row.IssuedAt, ExpiresAt: row.ExpiresAt, ObservedAt: found.ObservedAt,
		CompletedAt: found.CompletedAt, HasProof: len(found.Binding.Proof) != 0,
		HasPlan: found.Binding.Plan != (providerLoginStoredPlan{}),
	}, nil
}

func ProviderLoginCallbackStateDigestForTest(service *ProviderLoginService, version uint32, state string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(state)
	defer clear(raw)
	if err != nil {
		return nil, identity.ForbiddenError{}
	}
	digest, err := providerLoginStateDigest(service.payload.StateKeys[version], version, service.config.TenantID, raw)
	return digest[:], err
}

func ProviderLoginCallbackWithStateKeysForTest(service *ProviderLoginService, keys map[uint32][32]byte) *ProviderLoginService {
	copy := *service
	copy.payload.StateKeys = cloneProviderLoginKeys(keys)
	return &copy
}

// Move the genuine start's authenticated metadata into retained history without
// sleeping for its real lifetime. No callback or verifier API is substituted.
func AgeProviderLoginCallbackForTest(ctx context.Context, service *ProviderLoginService, state string, terminal bool) error {
	found, err := service.lookupProviderLoginCallback(ctx, state)
	if err != nil {
		return err
	}
	defer clear(found.Binding.Proof)
	found.Row.IssuedAt = found.Row.IssuedAt.Add(-11 * time.Minute)
	found.Row.ExpiresAt = found.Row.ExpiresAt.Add(-11 * time.Minute)
	found.Binding.Metadata.Input.IssuedAt = found.Row.IssuedAt
	found.Binding.Metadata.Input.ExpiresAt = found.Row.ExpiresAt
	grant := kernel.CapabilityPlan(found.Binding.Plan.Grant)
	grant.ExpiresAt = found.Row.ExpiresAt
	found.Binding.Plan.Grant = providerLoginStoredGrant(grant)
	aad, err := found.Row.aad()
	if err != nil {
		return err
	}
	plain, err := providerLoginPayloadEncode(found.Binding)
	defer clear(plain)
	if err != nil {
		return err
	}
	var wire []byte
	if terminal {
		found.ObservedAt = found.Row.IssuedAt
		wire, err = service.payload.sealProviderLoginCallbackTerminal(ctx, found)
	} else {
		wire, err = service.payload.seal(ctx, aad, plain, 65536)
	}
	defer clear(wire)
	if err != nil {
		return err
	}
	var completed *time.Time
	if terminal {
		at := found.Row.IssuedAt.Add(time.Second)
		completed = &at
	}
	_, err = service.router.pool.Raw().Exec(ctx, `UPDATE sso_providers.login_transactions
 SET issued_at=$2,expires_at=$3,binding_envelope=$4,completed_at=$5,
 verifier_envelope=CASE WHEN $5::timestamptz IS NULL THEN verifier_envelope ELSE NULL END
 WHERE start_command_id=$1`, string(found.Row.StartCommandID), found.Row.IssuedAt, found.Row.ExpiresAt, wire, completed)
	return err
}
