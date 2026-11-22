package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/faustbrian/go-sso"
)

// ProviderLoginTokenVaultMigrationSource opts into the finite native static-OIDC
// callback token deposit. Apply after LoginTransactionMigrationSource and the
// identity AccountMigrationSource on the same primary, before enabling the
// callback writer. Version is an unused positive history version after those
// prerequisites. The source owns neither a runner nor transaction lifetime.
//
// This creates empty SSO-owned custody only; it does not adopt social-OAuth
// tokens, change existing providers/accounts, or enable refresh/revocation.
// Rollback retains encrypted custody; no destructive down SQL is provided.
type ProviderLoginTokenVaultMigrationSource struct{ Version migrations.Version }

var _ migrations.Source = ProviderLoginTokenVaultMigrationSource{}

// Load returns caller-owned additive history without I/O. Invalid versions,
// nil context and cancellation return no partial history. Installation fails on
// an existing custody table rather than silently adopting another owner's data.
func (s ProviderLoginTokenVaultMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, sso.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "sso_oidc_provider_login_token_vault", migrations.TransactionModeDefault, providerLoginTokenVaultSQL, "")
	if err != nil {
		return nil, sso.ErrUnavailable
	}
	return []migrations.Migration{m}, nil
}

// A callback creates exactly one immutable grant. Independent callbacks do not
// overwrite it or manufacture a refresh generation. Exact seconds/nanoseconds
// preserve TokenSet timestamps; PostgreSQL timestamptz would round to microseconds.
const providerLoginTokenVaultSQL = `SET LOCAL lock_timeout='5s';
CREATE TABLE sso_providers.provider_login_token_sets (
 tenant_id identity.directory_id NOT NULL,
 organization_id text COLLATE "C" NOT NULL CHECK(octet_length(organization_id) BETWEEN 1 AND 128),
 provider_id text COLLATE "C" NOT NULL CHECK(octet_length(provider_id) BETWEEN 1 AND 128),
 start_command_id text COLLATE "C" NOT NULL REFERENCES sso_providers.login_transactions(start_command_id),
 callback_command_id text COLLATE "C" NOT NULL REFERENCES sso_providers.login_transactions(callback_command_id),
 callback_generation identity.version NOT NULL,
 user_id identity.directory_id NOT NULL,
 account_id identity.directory_id NOT NULL,
 account_provider identity.directory_id NOT NULL,
 issuer text COLLATE "C" NOT NULL CHECK(octet_length(issuer) BETWEEN 1 AND 2048),
 subject text COLLATE "C" NOT NULL CHECK(octet_length(subject) BETWEEN 1 AND 512 AND subject !~ '[[:cntrl:]]'),
 account_version identity.version NOT NULL,
 social_link_version identity.version NOT NULL,
 provider_version identity.version NOT NULL,
 credential_generation identity.version NOT NULL,
 mapping_version identity.version NOT NULL,
 token_version identity.version NOT NULL CHECK(token_version=1),
 requested_scopes text[] NOT NULL CHECK(cardinality(requested_scopes) BETWEEN 1 AND 32 AND array_position(requested_scopes,NULL) IS NULL AND octet_length(array_to_string(requested_scopes,' ')) BETWEEN 1 AND 4127),
 granted_scopes text[] NOT NULL CHECK(cardinality(granted_scopes) BETWEEN 1 AND 32 AND array_position(granted_scopes,NULL) IS NULL AND octet_length(array_to_string(granted_scopes,' ')) BETWEEN 1 AND 4127),
 scope_reported boolean NOT NULL,
 received_at_seconds bigint NOT NULL CHECK(received_at_seconds BETWEEN 1 AND 253402300799),
 received_at_nanoseconds integer NOT NULL CHECK(received_at_nanoseconds BETWEEN 0 AND 999999999),
 access_expires_at_seconds bigint NOT NULL CHECK(access_expires_at_seconds BETWEEN 1 AND 253402300799),
 access_expires_at_nanoseconds integer NOT NULL CHECK(access_expires_at_nanoseconds BETWEEN 0 AND 999999999),
 token_ciphertext bytea NOT NULL CHECK(octet_length(token_ciphertext) BETWEEN 1 AND 65536),
 origin_operation text COLLATE "C" NOT NULL CHECK(origin_operation='identity.sso.oidc-callback'),
 origin_command_id bytea NOT NULL CHECK(octet_length(origin_command_id)=16),
 PRIMARY KEY(tenant_id,callback_command_id),
 FOREIGN KEY(tenant_id,organization_id,provider_id) REFERENCES sso_providers.providers(tenant_id,organization_id,provider_id),
 FOREIGN KEY(tenant_id,user_id,account_id) REFERENCES identity.accounts(tenant_id,user_id,account_id),
 FOREIGN KEY(tenant_id,origin_operation,origin_command_id) REFERENCES identity.commands(tenant_id,purpose,command_id),
 CHECK(start_command_id<>callback_command_id),
 CHECK(access_expires_at_seconds>received_at_seconds AND access_expires_at_seconds<=received_at_seconds+31536000 AND access_expires_at_nanoseconds=received_at_nanoseconds),
 CHECK(granted_scopes<@requested_scopes AND (scope_reported OR granted_scopes=requested_scopes))
);`
