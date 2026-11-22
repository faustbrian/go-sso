package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/faustbrian/go-sso"
)

// ProviderUpdateMigrationSource expands the registered provider schema without
// rewriting or backfilling historical configuration. Install it after the
// unchanged ProviderMigrationSource and before update-aware service code.
// Legacy version/configuration/mapping columns remain an internally consistent
// disabled v1 projection for old binaries. Code rollback retains successors;
// old binaries cannot read or update them. There is no destructive down SQL.
type ProviderUpdateMigrationSource struct{ Version migrations.Version }

func (s ProviderUpdateMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, sso.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "sso_disabled_oidc_metadata_successors", migrations.TransactionModeDefault, providerUpdateSQL, "")
	if err != nil {
		return nil, sso.ErrUnavailable
	}
	return []migrations.Migration{m}, nil
}

const providerUpdateSQL = `SET LOCAL lock_timeout='5s';
ALTER TABLE sso_providers.providers
 ADD COLUMN metadata_version numeric(20,0) NOT NULL DEFAULT 1,
 ADD COLUMN metadata_configuration_envelope bytea,
 ADD COLUMN metadata_mapping_version numeric(20,0),
 ADD CONSTRAINT providers_metadata_successor_check CHECK (
  metadata_version BETWEEN 1 AND 18446744073709551615 AND
  ((metadata_version=1 AND metadata_configuration_envelope IS NULL AND metadata_mapping_version IS NULL) OR
   (metadata_version>1 AND metadata_configuration_envelope IS NOT NULL AND octet_length(metadata_configuration_envelope) BETWEEN 1 AND 65536 AND metadata_mapping_version IS NOT NULL AND metadata_mapping_version BETWEEN 1 AND 18446744073709551615))
 ) NOT VALID;`
