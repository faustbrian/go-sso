package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/faustbrian/go-sso"
)

// ProviderLoginTokenVaultProtocolMigrationSource expands existing enterprise
// token custody to the closed OIDC/OAuth callback operation set. Apply after
// ProviderLoginTokenVaultMigrationSource and before opting into OAuth callback
// writers. This optional library source performs no deployment and owns neither
// the migration runner nor its transaction lifetime.
//
// Version atomically replaces the legacy check without scanning or rewriting
// populated grants; ValidationVersion validates it in a separate committed
// migration. Both bound lock acquisition and retain existing ciphertext, foreign
// keys and indexes. Keep this expansion on code rollback: restoring the OIDC-only
// check is unsafe once OAuth grants exist. No down SQL is provided.
type ProviderLoginTokenVaultProtocolMigrationSource struct {
	Version           migrations.Version
	ValidationVersion migrations.Version
}

var _ migrations.Source = ProviderLoginTokenVaultProtocolMigrationSource{}

// Load returns expansion and validation history without I/O. Versions must be
// positive, strictly ordered and within the migration ledger's signed 64-bit
// range. Invalid input or cancellation returns no partial history. Installation
// fails if the exact legacy constraint is absent rather than adopting an
// unexpected schema history.
func (s ProviderLoginTokenVaultProtocolMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.ValidationVersion <= s.Version || s.ValidationVersion > migrations.Version(math.MaxInt64) {
		return nil, sso.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	expand, err := migrations.NewMigration(s.Version, "sso_provider_login_token_vault_protocol", migrations.TransactionModeDefault, providerLoginTokenVaultProtocolSQL, "")
	if err != nil {
		return nil, sso.ErrUnavailable
	}
	validate, err := migrations.NewMigration(s.ValidationVersion, "sso_provider_login_token_vault_protocol_validate", migrations.TransactionModeDefault, providerLoginTokenVaultProtocolValidationSQL, "")
	if err != nil {
		return nil, sso.ErrUnavailable
	}
	return []migrations.Migration{expand, validate}, nil
}

// One atomic ALTER prevents an unchecked write window. NOT VALID avoids a scan
// under the expansion's exclusive lock while still checking every new write.
const providerLoginTokenVaultProtocolSQL = `SET LOCAL lock_timeout='5s';
ALTER TABLE sso_providers.provider_login_token_sets
 DROP CONSTRAINT provider_login_token_sets_origin_operation_check,
 ADD CONSTRAINT provider_login_token_sets_origin_operation_check CHECK (origin_operation IN ('identity.sso.oidc-callback','identity.sso.oauth-callback')) NOT VALID;`

const providerLoginTokenVaultProtocolValidationSQL = `SET LOCAL lock_timeout='5s';
ALTER TABLE sso_providers.provider_login_token_sets VALIDATE CONSTRAINT provider_login_token_sets_origin_operation_check;`
