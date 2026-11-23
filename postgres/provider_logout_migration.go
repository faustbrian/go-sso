package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/faustbrian/go-sso"
)

// ProviderLogoutMigrationSource adds one-time encrypted RP-initiated OIDC
// logout custody. Apply after ProviderMigrationSource and the native identity
// command migrations on the same primary, before installing logout writers.
// Version is a caller-selected unused positive history version after those
// prerequisites; this source owns neither a runner nor transaction lifetime.
//
// Installation creates an empty table and leaves existing provider, login and
// command history unchanged. Foreign-key lock acquisition is bounded. Code
// rollback retains custody; no destructive down SQL is provided.
type ProviderLogoutMigrationSource struct{ Version migrations.Version }

var _ migrations.Source = ProviderLogoutMigrationSource{}

// Load returns additive history without I/O. Invalid versions, a nil context
// or cancellation return no partial history. An existing custody table is an
// installation error rather than data to adopt silently.
func (s ProviderLogoutMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, sso.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "sso_oidc_provider_logout_custody", migrations.TransactionModeDefault, providerLogoutSQL, "")
	if err != nil {
		return nil, sso.ErrUnavailable
	}
	return []migrations.Migration{m}, nil
}

// The OIDC logout profile shares login's ten-minute state lifetime. Only a
// private keyed digest is searchable; provider, issuer, session/version and
// allowlisted target remain in the opaque binding envelope. A native command
// may start or complete only one transaction, so replay cannot consume another
// state. MATCH SIMPLE permits pending rows without a completion command.
const providerLogoutSQL = `SET LOCAL lock_timeout='5s';
CREATE TABLE sso_providers.logout_transactions (
 tenant_id text COLLATE "C" NOT NULL CHECK(octet_length(tenant_id) BETWEEN 1 AND 128),
 state_key_version bigint NOT NULL CHECK(state_key_version BETWEEN 1 AND 4294967295),
 state_digest bytea NOT NULL CHECK(octet_length(state_digest)=32),
 start_command_id bytea NOT NULL CHECK(octet_length(start_command_id)=16),
 start_purpose text COLLATE "C" NOT NULL DEFAULT 'identity.sso.oidc-logout' CHECK(start_purpose='identity.sso.oidc-logout'),
 issued_at timestamptz NOT NULL CHECK(isfinite(issued_at)),
 expires_at timestamptz NOT NULL CHECK(isfinite(expires_at)),
 binding_envelope bytea NOT NULL CHECK(octet_length(binding_envelope) BETWEEN 1 AND 65536),
 completed_at timestamptz CHECK(completed_at IS NULL OR (isfinite(completed_at) AND completed_at>=issued_at)),
 completion_command_id bytea CHECK(completion_command_id IS NULL OR octet_length(completion_command_id)=16),
 completion_purpose text COLLATE "C" NOT NULL DEFAULT 'identity.sso.oidc-logout-complete' CHECK(completion_purpose='identity.sso.oidc-logout-complete'),
 completion_kind text COLLATE "C" CHECK(completion_kind IS NULL OR completion_kind IN ('provider_complete','provider_error','timeout')),
 PRIMARY KEY(tenant_id,state_key_version,state_digest),
 UNIQUE(tenant_id,start_command_id),
 UNIQUE(tenant_id,completion_command_id),
 FOREIGN KEY(start_command_id,tenant_id,start_purpose) REFERENCES identity.commands(command_id,tenant_id,purpose),
 FOREIGN KEY(completion_command_id,tenant_id,completion_purpose) REFERENCES identity.commands(command_id,tenant_id,purpose) MATCH SIMPLE,
 CHECK(expires_at>issued_at AND expires_at<=issued_at+interval '10 minutes'),
 CHECK(completion_command_id IS NULL OR completion_command_id<>start_command_id),
 CHECK((completed_at IS NULL AND completion_command_id IS NULL AND completion_kind IS NULL)
  OR (completed_at IS NOT NULL AND completion_command_id IS NOT NULL AND completion_kind IS NOT NULL))
);`
