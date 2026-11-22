package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/faustbrian/go-sso"
)

// ProviderCredentialsMigrationSource adds bounded current encrypted credential
// custody and exact atomic-effect evidence. Apply after ProviderUpdateMigrationSource
// and before constructing the credentials-only service. It neither rewrites nor
// backfills providers; old registration/read/update binaries remain compatible.
// The short lock timeout bounds new foreign-key acquisition on providers. Code
// rollback retains ciphertext and evidence; no destructive down SQL is provided.
type ProviderCredentialsMigrationSource struct{ Version migrations.Version }

func (s ProviderCredentialsMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, sso.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "sso_disabled_oidc_provider_credentials", migrations.TransactionModeDefault, providerCredentialsSQL, "")
	if err != nil {
		return nil, sso.ErrUnavailable
	}
	return []migrations.Migration{m}, nil
}

const providerCredentialsSQL = `SET LOCAL lock_timeout='5s';
CREATE TABLE sso_providers.credentials (
 tenant_id text COLLATE "C" NOT NULL,
 organization_id text COLLATE "C" NOT NULL,
 provider_id text COLLATE "C" NOT NULL,
 generation numeric(20,0) NOT NULL CHECK(generation BETWEEN 1 AND 18446744073709551615),
 provider_version numeric(20,0) NOT NULL CHECK(provider_version BETWEEN 2 AND 18446744073709551615),
 envelope bytea NOT NULL CHECK(octet_length(envelope) BETWEEN 1 AND 32768),
 credential_context bytea NOT NULL CHECK(octet_length(credential_context) BETWEEN 1 AND 4096),
 PRIMARY KEY(tenant_id,organization_id,provider_id),
 FOREIGN KEY(tenant_id,organization_id,provider_id) REFERENCES sso_providers.providers(tenant_id,organization_id,provider_id)
);
CREATE TABLE sso_providers.credential_effects (
 command_id text COLLATE "C" PRIMARY KEY CHECK(octet_length(command_id) BETWEEN 1 AND 128),
 tenant_id text COLLATE "C" NOT NULL,
 organization_id text COLLATE "C" NOT NULL,
 provider_id text COLLATE "C" NOT NULL,
 binding bytea NOT NULL CHECK(octet_length(binding) BETWEEN 1 AND 4096),
 fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 generation numeric(20,0) NOT NULL CHECK(generation BETWEEN 1 AND 18446744073709551615),
 FOREIGN KEY(tenant_id,organization_id,provider_id) REFERENCES sso_providers.providers(tenant_id,organization_id,provider_id)
);`
