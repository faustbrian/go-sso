package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/faustbrian/go-sso"
)

// DirectorySyncGenerationMigrationSource adds the SSO-owned generation and
// cursor records. Install after ProviderMigrationSource and before selecting
// native directory synchronization. No existing provider or SCIM projection
// is copied or changed, and disabling the service leaves the records intact.
type DirectorySyncGenerationMigrationSource struct{ Version migrations.Version }

func (s DirectorySyncGenerationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, sso.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "sso_directory_sync_generations", migrations.TransactionModeDefault, directorySyncGenerationSQL, "")
	if err != nil {
		return nil, sso.ErrUnavailable
	}
	return []migrations.Migration{m}, nil
}

// A live generation serializes changes to one exact source, not to all
// connections for the provider. Settled generations retain their final
// checkpoint. Pending child dispositions live in their original identity
// command journal; SSO retains only the admitted batch commitment here.
const directorySyncGenerationSQL = `SET LOCAL lock_timeout='2s';
CREATE TABLE sso_providers.directory_sync_generations (
 tenant_id text COLLATE "C" NOT NULL,
 organization_id text COLLATE "C" NOT NULL,
 provider_id text COLLATE "C" NOT NULL,
 connection_id text COLLATE "C" NOT NULL CHECK(octet_length(connection_id) BETWEEN 1 AND 128),
 generation numeric(20,0) NOT NULL CHECK(generation BETWEEN 1 AND 18446744073709551615),
 generation_id text COLLATE "C" NOT NULL UNIQUE CHECK(generation_id ~ '^[A-Za-z0-9_-]{22}$'),
 provider_version numeric(20,0) NOT NULL CHECK(provider_version BETWEEN 1 AND 18446744073709551615),
 mapping_version numeric(20,0) NOT NULL CHECK(mapping_version BETWEEN 1 AND 18446744073709551615),
 version numeric(20,0) NOT NULL DEFAULT 1 CHECK(version BETWEEN 1 AND 18446744073709551615),
 mode text NOT NULL CHECK(mode IN ('apply','dry-run')),
 state text NOT NULL CHECK(state IN ('running','reconciling','canceling','canceled','finished')),
 checkpoint bytea NOT NULL CHECK(octet_length(checkpoint)=32 AND checkpoint<>decode(repeat('00',32),'hex')),
 initial_checkpoint bytea NOT NULL CHECK(octet_length(initial_checkpoint)=32 AND initial_checkpoint<>decode(repeat('00',32),'hex')),
 pending_batch bytea CHECK(octet_length(pending_batch)=32 AND pending_batch<>decode(repeat('00',32),'hex')),
 read_count numeric(20,0) NOT NULL DEFAULT 0 CHECK(read_count BETWEEN 0 AND 18446744073709551615),
 applied_count numeric(20,0) NOT NULL DEFAULT 0 CHECK(applied_count>=0),
 rejected_count numeric(20,0) NOT NULL DEFAULT 0 CHECK(rejected_count>=0),
 PRIMARY KEY(tenant_id,organization_id,provider_id,connection_id,generation),
 FOREIGN KEY(tenant_id,organization_id,provider_id) REFERENCES sso_providers.providers(tenant_id,organization_id,provider_id),
 CHECK(applied_count+rejected_count<=read_count),
 CHECK(mode='apply' OR applied_count=0),
 CHECK((state='running') OR (state IN ('reconciling','canceling'))=(pending_batch IS NOT NULL))
);
CREATE UNIQUE INDEX sso_directory_sync_one_open_generation
 ON sso_providers.directory_sync_generations(tenant_id,organization_id,provider_id,connection_id)
 WHERE state IN ('running','reconciling','canceling');`
