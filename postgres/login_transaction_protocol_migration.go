package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/faustbrian/go-sso"
)

// LoginTransactionProtocolMigrationSource expands existing login custody to the
// closed OIDC/OAuth protocol set without rewriting encrypted bindings or PKCE
// material. Apply after LoginTransactionMigrationSource and the caller-selected
// ProviderProtocolMigrationSource history, before installing OAuth login writers.
// Version replaces the legacy check without scanning existing custody;
// ValidationVersion validates it in a separate committed migration.
//
// Both versions bound lock acquisition and retain the existing tables, data and
// indexes. Code rollback leaves this expansion installed: restoring the legacy
// OIDC-only check is unsafe once OAuth custody exists. No down SQL is provided.
type LoginTransactionProtocolMigrationSource struct {
	Version           migrations.Version
	ValidationVersion migrations.Version
}

var _ migrations.Source = LoginTransactionProtocolMigrationSource{}

// Load returns expansion and validation history without performing I/O.
// Versions must be positive, strictly ordered and within the migration ledger's
// signed 64-bit range. Invalid input or cancellation returns no partial history.
func (s LoginTransactionProtocolMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.ValidationVersion <= s.Version || s.ValidationVersion > migrations.Version(math.MaxInt64) {
		return nil, sso.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	expand, err := migrations.NewMigration(s.Version, "sso_login_transaction_protocol", migrations.TransactionModeDefault, loginTransactionProtocolSQL, "")
	if err != nil {
		return nil, sso.ErrUnavailable
	}
	validate, err := migrations.NewMigration(s.ValidationVersion, "sso_login_transaction_protocol_validate", migrations.TransactionModeDefault, loginTransactionProtocolValidationSQL, "")
	if err != nil {
		return nil, sso.ErrUnavailable
	}
	return []migrations.Migration{expand, validate}, nil
}

// Replace the legacy check in one atomic ALTER: new writes never pass through
// an unchecked protocol window, and NOT VALID avoids scanning populated custody
// while holding the expansion's exclusive lock.
const loginTransactionProtocolSQL = `SET LOCAL lock_timeout='5s';
ALTER TABLE sso_providers.login_transactions
 DROP CONSTRAINT login_transactions_protocol_check,
 ADD CONSTRAINT login_transactions_protocol_check CHECK (protocol IN ('oidc','oauth2')) NOT VALID;`

const loginTransactionProtocolValidationSQL = `SET LOCAL lock_timeout='5s';
ALTER TABLE sso_providers.login_transactions VALIDATE CONSTRAINT login_transactions_protocol_check;`
