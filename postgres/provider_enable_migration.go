package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/faustbrian/go-sso"
)

// ProviderEnableMigrationSource adds the opt-in enablement checkpoint and
// historical response projection. Install after disabled-provider metadata
// and credential migrations and before enabling the new service. Existing
// disabled rows are unchanged. Prior writers already require NOT enabled on
// mutation, so they continue to fail closed for newly enabled providers.
type ProviderEnableMigrationSource struct{ Version migrations.Version }

func (s ProviderEnableMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, sso.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "sso_static_oidc_enablement", migrations.TransactionModeDefault, providerEnableSQL, "")
	if err != nil {
		return nil, sso.ErrUnavailable
	}
	return []migrations.Migration{m}, nil
}

const providerEnableSQL = `SET LOCAL lock_timeout='5s';
ALTER TABLE sso_providers.providers
 ADD COLUMN enablement_proof bytea,
 ADD COLUMN enablement_credential_generation numeric(20,0),
 DROP CONSTRAINT providers_enabled_check,
 ADD CONSTRAINT providers_enablement_check CHECK (
  (NOT enabled AND enablement_proof IS NULL AND enablement_credential_generation IS NULL) OR
  (enabled AND enablement_proof IS NOT NULL AND octet_length(enablement_proof) BETWEEN 1 AND 16384
   AND enablement_credential_generation IS NOT NULL AND enablement_credential_generation BETWEEN 1 AND 18446744073709551615)
 ) NOT VALID;
CREATE TABLE sso_providers.enable_receipts (
 command_id text COLLATE "C" PRIMARY KEY REFERENCES sso_providers.command_effects(command_id),
 mapping_version numeric(20,0) NOT NULL CHECK(mapping_version BETWEEN 1 AND 18446744073709551615)
);`
