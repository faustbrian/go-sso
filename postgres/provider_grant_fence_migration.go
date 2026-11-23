package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/faustbrian/go-sso"
)

// ProviderGrantFenceMigrationSource opts into one SSO-owned attempt fence per
// grant generation. Apply after the native identity command migrations and all
// ProviderLoginTokenVaultProtocolMigrationSource history on the same primary,
// before installing future grant-selection writers. This library source performs
// no deployment and owns neither a runner nor transaction lifetime. Version is a
// caller-selected unused positive history version after those prerequisites.
//
// Installation creates an empty table, with bounded foreign-key lock acquisition
// and no backfill or changes to existing readers, token custody or command
// history. Code rollback retains fences; no destructive down SQL is provided.
type ProviderGrantFenceMigrationSource struct{ Version migrations.Version }

var _ migrations.Source = ProviderGrantFenceMigrationSource{}

// Load returns additive forward-only history without I/O. Invalid versions, a
// nil context or cancellation return no partial history. An existing fence table
// is an installation error rather than data to adopt silently.
func (s ProviderGrantFenceMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, sso.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "sso_provider_grant_fences", migrations.TransactionModeDefault, providerGrantFenceSQL, "")
	if err != nil {
		return nil, sso.ErrUnavailable
	}
	return []migrations.Migration{m}, nil
}

// The grant-generation key arbitrates refresh and revoke across all actors. A
// fence has no expiry, renewal or recovery state, and is not evidence of a
// provider send or outcome. It deliberately has no token-row foreign key: a
// future acknowledged revoke must erase recoverable ciphertext while retaining
// the fence that prevents another attempt for that generation.
const providerGrantFenceSQL = `SET LOCAL lock_timeout='5s';
CREATE TABLE sso_providers.provider_grant_fences (
 tenant_id identity.directory_id NOT NULL,
 grant_command_id bytea NOT NULL CHECK(octet_length(grant_command_id)=16),
 grant_purpose text COLLATE "C" NOT NULL DEFAULT 'identity.sso.oauth-callback' CHECK(grant_purpose='identity.sso.oauth-callback'),
 token_version identity.version NOT NULL,
 attempt_command_id bytea NOT NULL CHECK(octet_length(attempt_command_id)=16),
 attempt_purpose text COLLATE "C" NOT NULL CHECK(attempt_purpose IN ('identity.sso.provider-token.revoke','identity.sso.provider-token.refresh')),
 attempt_generation identity.version NOT NULL,
 started_at timestamptz NOT NULL CHECK(isfinite(started_at)),
 PRIMARY KEY(tenant_id,grant_command_id,token_version),
 UNIQUE(tenant_id,attempt_purpose,attempt_command_id),
 FOREIGN KEY(tenant_id,grant_purpose,grant_command_id) REFERENCES identity.commands(tenant_id,purpose,command_id),
 FOREIGN KEY(tenant_id,attempt_purpose,attempt_command_id) REFERENCES identity.commands(tenant_id,purpose,command_id),
 CHECK(grant_command_id<>attempt_command_id)
);`
