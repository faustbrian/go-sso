//go:build integration

package postgres

import (
	"context"
	"crypto/sha256"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// Export the actual statements for the existing native-Work measurement harness,
// not a second vault, transaction owner or test-only persistence implementation.
const ProviderLoginTokenOriginalSQLForTest = providerLoginTokenOriginalSQL
const ProviderLoginTokenInsertSQLForTest = providerLoginTokenInsertSQL

// RestoreOAuth2VaultFromRowForTest exposes only token fingerprints from a
// fresh service composed without the callback service or its temporary state.
func RestoreOAuth2VaultFromRowForTest(ctx context.Context, config ProviderLoginConfig, row interface{ Scan(...any) error }) ([2][32]byte, error) {
	var b providerLoginStoredTokenBinding
	var start, callback, tenant, user, account string
	var receivedSec, receivedNsec, expiresSec, expiresNsec int64
	var ciphertext []byte
	defer func() { clear(ciphertext) }()
	err := row.Scan(&b.Organization, &b.Provider, &start, &callback, &b.CallbackGeneration,
		&tenant, &user, &account, &b.Account.Provider, &b.Account.Issuer, &b.Account.Subject, &b.Account.Version, &b.SocialLinkVersion,
		&b.Version, &b.ProviderVersion, &b.CredentialGeneration, &b.MappingVersion,
		&b.RequestedScopes, &b.GrantedScopes, &b.ScopeReported, &receivedSec, &receivedNsec, &expiresSec, &expiresNsec, &ciphertext)
	if err != nil {
		return [2][32]byte{}, err
	}
	b.Start, b.Callback = identity.CommandID(start), identity.CommandID(callback)
	b.Account.TenantID, b.Account.UserID, b.Account.ID = identity.TenantID(tenant), identity.UserID(user), identity.AccountID(account)
	b.ReceivedAt, b.AccessExpiresAt = time.Unix(receivedSec, receivedNsec).UTC(), time.Unix(expiresSec, expiresNsec).UTC()
	reader := &ProviderLoginService{payload: providerLoginPayloadConfig{Envelope: config.Envelope, KeyReference: config.KeyReference}}
	var digests [2][32]byte
	err = reader.borrowStoredOAuth2Tokens(ctx, b, ciphertext, func(_ context.Context, access, refresh []byte) error {
		digests = [2][32]byte{sha256.Sum256(access), sha256.Sum256(refresh)}
		return nil
	})
	return digests, err
}
