package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/faustbrian/go-sso"
)

// ProviderGrantRefreshMigrationSource opts into native OAuth grant refresh
// generations and immutable outcome receipts. Apply all three entries after
// ProviderGrantFenceMigrationSource and both token-vault protocol migrations on
// the same primary, before enabling code that reads or writes refresh state.
// This optional library source owns no deployment, runner or transaction lifetime.
//
// Version atomically expands the legacy token-version check without scanning or
// rewriting populated grants. ValidationVersion validates that check in a
// separate committed migration; ReceiptVersion then creates an empty receipt
// table. Lock acquisition is bounded in each transaction. Versions are unused,
// positive caller-selected history identities in strictly increasing order.
//
// Installation does not backfill, refresh tokens or change existing readers.
// Code rollback retains grants, the expanded constraint and receipts: restoring
// the version-one-only check would reject already committed refresh generations.
// No destructive down SQL is provided.
type ProviderGrantRefreshMigrationSource struct {
	Version           migrations.Version
	ValidationVersion migrations.Version
	ReceiptVersion    migrations.Version
}

var _ migrations.Source = ProviderGrantRefreshMigrationSource{}

// Load returns three forward-only history entries without I/O. Invalid versions,
// a nil context or cancellation return no partial history. Installation fails if
// the exact legacy constraint is absent or the receipt table already exists,
// rather than silently adopting an unexpected schema or another owner's data.
func (s ProviderGrantRefreshMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.ValidationVersion <= s.Version || s.ReceiptVersion <= s.ValidationVersion || s.ReceiptVersion > migrations.Version(math.MaxInt64) {
		return nil, sso.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	expand, err := migrations.NewMigration(s.Version, "sso_provider_grant_refresh", migrations.TransactionModeDefault, providerGrantRefreshSQL, "")
	if err != nil {
		return nil, sso.ErrUnavailable
	}
	validate, err := migrations.NewMigration(s.ValidationVersion, "sso_provider_grant_refresh_validate", migrations.TransactionModeDefault, providerGrantRefreshValidationSQL, "")
	if err != nil {
		return nil, sso.ErrUnavailable
	}
	receipts, err := migrations.NewMigration(s.ReceiptVersion, "sso_provider_grant_refresh_receipts", migrations.TransactionModeDefault, providerGrantRefreshReceiptSQL, "")
	if err != nil {
		return nil, sso.ErrUnavailable
	}
	return []migrations.Migration{expand, validate, receipts}, nil
}

// The original vault migration's column-local check receives this PostgreSQL
// name. One atomic ALTER leaves no unchecked write window; NOT VALID avoids
// scanning grants under its exclusive lock. identity.version already requires a
// positive integer, and only native OAuth callbacks may advance past one.
const providerGrantRefreshSQL = `SET LOCAL lock_timeout='5s';
ALTER TABLE sso_providers.provider_login_token_sets
 DROP CONSTRAINT provider_login_token_sets_token_version_check,
 ADD CONSTRAINT provider_login_token_sets_token_version_check CHECK (token_version=1 OR origin_operation='identity.sso.oauth-callback') NOT VALID;`

const providerGrantRefreshValidationSQL = `SET LOCAL lock_timeout='5s';
ALTER TABLE sso_providers.provider_login_token_sets VALIDATE CONSTRAINT provider_login_token_sets_token_version_check;`

// Receipts reference the permanent attempt fence, not mutable token custody.
// Even a later grant revocation must retain the original refresh outcome. An
// explicit non-null successor guard prevents SQL CHECK's null semantics from
// accepting a successful refresh without its exact next generation.
const providerGrantRefreshReceiptSQL = `SET LOCAL lock_timeout='5s';
CREATE TABLE sso_providers.provider_grant_refresh_receipts (
 tenant_id identity.directory_id NOT NULL,
 user_id identity.directory_id NOT NULL,
 callback_command_id bytea NOT NULL CHECK(octet_length(callback_command_id)=16),
 token_version identity.version NOT NULL,
 attempt_command_id bytea NOT NULL CHECK(octet_length(attempt_command_id)=16),
 attempt_purpose text COLLATE "C" NOT NULL DEFAULT 'identity.sso.provider-token.refresh' CHECK(attempt_purpose='identity.sso.provider-token.refresh'),
 attempt_generation identity.version NOT NULL,
 intent_digest bytea NOT NULL CHECK(octet_length(intent_digest)=32),
 outcome text COLLATE "C" NOT NULL CHECK(outcome IN ('rotated','retained','rejected','refused','unknown','not_sent')),
 successor_version identity.version,
 PRIMARY KEY(tenant_id,user_id,attempt_command_id),
 UNIQUE(tenant_id,attempt_command_id),
 FOREIGN KEY(tenant_id,attempt_purpose,attempt_command_id) REFERENCES sso_providers.provider_grant_fences(tenant_id,attempt_purpose,attempt_command_id),
 CHECK(callback_command_id<>attempt_command_id),
 CHECK((outcome IN ('rotated','retained') AND successor_version IS NOT NULL AND successor_version=token_version+1)
  OR (outcome NOT IN ('rotated','retained') AND successor_version IS NULL))
);`
