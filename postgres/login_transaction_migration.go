package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/faustbrian/go-sso"
)

// LoginTransactionMigrationSource adds encrypted login-transaction custody and
// generation-bound provider drain/revocation evidence. Apply after
// ProviderEnableMigrationSource and before installing login or disable writers.
// It creates empty tables without changing existing provider data. Foreign-key
// lock acquisition is bounded, and code rollback retains custody and evidence;
// no destructive down SQL is provided.
type LoginTransactionMigrationSource struct{ Version migrations.Version }

func (s LoginTransactionMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, sso.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "sso_oidc_login_transaction_custody", migrations.TransactionModeDefault, loginTransactionSQL, "")
	if err != nil {
		return nil, sso.ErrUnavailable
	}
	return []migrations.Migration{m}, nil
}

// The reference OAuth/OIDC profile fixes state lifetime at ten minutes and
// requires terminal erasure of the recoverable PKCE verifier. The commitments
// are private keyed digests, never raw state or verifier material; only the
// state lookup and active-provider count need indexes in this schema slice.
const loginTransactionSQL = `SET LOCAL lock_timeout='5s';
CREATE TABLE sso_providers.login_transactions (
 tenant_id text COLLATE "C" NOT NULL CHECK(octet_length(tenant_id) BETWEEN 1 AND 128),
 organization_id text COLLATE "C" NOT NULL CHECK(octet_length(organization_id) BETWEEN 1 AND 128),
 provider_id text COLLATE "C" NOT NULL CHECK(octet_length(provider_id) BETWEEN 1 AND 128),
 provider_version numeric(20,0) NOT NULL CHECK(provider_version BETWEEN 1 AND 18446744073709551615),
 credential_generation numeric(20,0) NOT NULL CHECK(credential_generation BETWEEN 1 AND 18446744073709551615),
 mapping_version numeric(20,0) NOT NULL CHECK(mapping_version BETWEEN 1 AND 18446744073709551615),
 start_command_id text COLLATE "C" NOT NULL UNIQUE CHECK(octet_length(start_command_id) BETWEEN 1 AND 128),
 callback_command_id text COLLATE "C" NOT NULL UNIQUE CHECK(octet_length(callback_command_id) BETWEEN 1 AND 128),
 protocol text COLLATE "C" NOT NULL CHECK(protocol='oidc'),
 state_key_version bigint NOT NULL CHECK(state_key_version BETWEEN 1 AND 4294967295),
 state_digest bytea NOT NULL CHECK(octet_length(state_digest)=32),
 pkce_key_version bigint NOT NULL CHECK(pkce_key_version BETWEEN 1 AND 4294967295),
 pkce_commitment bytea NOT NULL CHECK(octet_length(pkce_commitment)=32),
 binding_envelope bytea NOT NULL CHECK(octet_length(binding_envelope) BETWEEN 1 AND 65536),
 verifier_envelope bytea CHECK(octet_length(verifier_envelope) BETWEEN 1 AND 4096),
 issued_at timestamptz NOT NULL CHECK(isfinite(issued_at)),
 expires_at timestamptz NOT NULL CHECK(isfinite(expires_at)),
 completed_at timestamptz CHECK(completed_at IS NULL OR (isfinite(completed_at) AND completed_at >= issued_at)),
 PRIMARY KEY(tenant_id,state_key_version,state_digest),
 FOREIGN KEY(tenant_id,organization_id,provider_id) REFERENCES sso_providers.providers(tenant_id,organization_id,provider_id),
 CHECK(start_command_id <> callback_command_id),
 CHECK(expires_at > issued_at AND expires_at <= issued_at + interval '10 minutes'),
 CHECK((completed_at IS NULL AND verifier_envelope IS NOT NULL) OR (completed_at IS NOT NULL AND verifier_envelope IS NULL))
);
CREATE INDEX login_transactions_active_provider_version_idx
 ON sso_providers.login_transactions(tenant_id,organization_id,provider_id,provider_version,expires_at)
 WHERE completed_at IS NULL;
CREATE TABLE sso_providers.provider_login_dispositions (
 tenant_id text COLLATE "C" NOT NULL CHECK(octet_length(tenant_id) BETWEEN 1 AND 128),
 organization_id text COLLATE "C" NOT NULL CHECK(octet_length(organization_id) BETWEEN 1 AND 128),
 provider_id text COLLATE "C" NOT NULL CHECK(octet_length(provider_id) BETWEEN 1 AND 128),
 provider_version numeric(20,0) NOT NULL CHECK(provider_version BETWEEN 1 AND 18446744073709551615),
 mode text COLLATE "C" NOT NULL CHECK(mode IN ('drain','revoke')),
 command_id text COLLATE "C" NOT NULL UNIQUE REFERENCES sso_providers.command_effects(command_id) CHECK(octet_length(command_id) BETWEEN 1 AND 128),
 active_transaction_count integer NOT NULL CHECK(active_transaction_count BETWEEN 0 AND 1000000),
 recorded_at timestamptz NOT NULL CHECK(isfinite(recorded_at)),
 PRIMARY KEY(tenant_id,organization_id,provider_id,provider_version),
 FOREIGN KEY(tenant_id,organization_id,provider_id) REFERENCES sso_providers.providers(tenant_id,organization_id,provider_id)
);`
