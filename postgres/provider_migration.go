package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/faustbrian/go-sso"
)

// ProviderMigrationSource installs the disabled static-OIDC administration
// profile. Apply before constructing ProviderService. It creates only new
// objects, does not backfill or alter other owners, and retains data on code
// rollback. DomainChallengeMigrationSource remains independently installable.
type ProviderMigrationSource struct{ Version migrations.Version }

func (s ProviderMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, sso.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "sso_disabled_oidc_providers", migrations.TransactionModeDefault, providerSQL, "")
	if err != nil {
		return nil, sso.ErrUnavailable
	}
	return []migrations.Migration{m}, nil
}

const providerSQL = `CREATE SCHEMA sso_providers;
CREATE TABLE sso_providers.providers (
 tenant_id text COLLATE "C" NOT NULL CHECK(octet_length(tenant_id) BETWEEN 1 AND 128),
 organization_id text COLLATE "C" NOT NULL CHECK(octet_length(organization_id) BETWEEN 1 AND 128),
 provider_id text COLLATE "C" NOT NULL CHECK(octet_length(provider_id) BETWEEN 1 AND 128),
 issuer_digest bytea NOT NULL CHECK(octet_length(issuer_digest)=32),
 configuration_envelope bytea NOT NULL CHECK(octet_length(configuration_envelope) BETWEEN 1 AND 65536),
 mapping_version numeric(20,0) NOT NULL CHECK(mapping_version BETWEEN 1 AND 18446744073709551615),
 pending_domains integer NOT NULL CHECK(pending_domains BETWEEN 1 AND 128),
 version bigint NOT NULL DEFAULT 1 CHECK(version=1),
 enabled boolean NOT NULL DEFAULT false CHECK(NOT enabled),
 PRIMARY KEY(tenant_id,organization_id,provider_id),
 UNIQUE(tenant_id,organization_id,issuer_digest)
);
CREATE TABLE sso_providers.command_effects (
 command_id text COLLATE "C" PRIMARY KEY CHECK(octet_length(command_id) BETWEEN 1 AND 128),
 tenant_id text COLLATE "C" NOT NULL,
 organization_id text COLLATE "C" NOT NULL,
 provider_id text COLLATE "C" NOT NULL,
 binding bytea NOT NULL CHECK(octet_length(binding) BETWEEN 1 AND 4096),
 fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 generation numeric(20,0) NOT NULL CHECK(generation BETWEEN 1 AND 18446744073709551615),
 FOREIGN KEY(tenant_id,organization_id,provider_id) REFERENCES sso_providers.providers(tenant_id,organization_id,provider_id)
);`
