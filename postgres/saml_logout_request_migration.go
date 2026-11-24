package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/faustbrian/go-sso"
)

// SAMLLogoutRequestMigrationSource installs encrypted outbound SAML request
// custody after ProviderMigrationSource, the native identity command migrations
// and SAMLLogoutSubjectMigrationSource on the same primary. Apply this schema
// before opting into the outbound logout writer. Installation neither enables
// logout nor backfills existing sessions. Version is a caller-selected unused
// positive history version after those prerequisites.
//
// Installation creates one empty table without rewriting or scanning existing
// provider, subject or command data. Foreign-key lock waits are bounded by a
// transaction-local lock timeout. Code rollback leaves request custody intact;
// no destructive down migration is provided.
type SAMLLogoutRequestMigrationSource struct{ Version migrations.Version }

var _ migrations.Source = SAMLLogoutRequestMigrationSource{}

// Load returns the single forward-only transactional migration without I/O.
// Invalid versions, a nil context or cancellation return no partial history.
// An existing table is an installation error, never custody to adopt or replace
// silently. This source owns neither a runner nor transaction lifetime.
func (s SAMLLogoutRequestMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, sso.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "sso_saml_logout_requests", migrations.TransactionModeDefault, samlLogoutRequestSQL, "")
	if err != nil {
		return nil, sso.ErrUnavailable
	}
	return []migrations.Migration{m}, nil
}

// Custody is inserted only after authoritative local revocation commits. The
// request and native start command each bind once; writers must never UPDATE or
// upsert an existing request. The encrypted envelope retains exact request and
// local-revocation context without a second session or response-state owner.
// The short expiry is the outbound SAML logout profile's five-minute window.
const samlLogoutRequestSQL = `SET LOCAL lock_timeout='5s';
CREATE TABLE sso_providers.saml_logout_requests (
 tenant_id identity.directory_id NOT NULL,
 organization_id text COLLATE "C" NOT NULL CHECK(octet_length(organization_id) BETWEEN 1 AND 128),
 provider_id text COLLATE "C" NOT NULL CHECK(octet_length(provider_id) BETWEEN 1 AND 128),
 request_id text COLLATE "C" NOT NULL CHECK(octet_length(request_id)=23 AND request_id ~ '^_[A-Za-z0-9_-]{22}$'),
 start_command_id bytea NOT NULL CHECK(octet_length(start_command_id)=16),
 start_purpose text COLLATE "C" NOT NULL DEFAULT 'identity.sso.saml-logout-start' CHECK(start_purpose='identity.sso.saml-logout-start'),
 issued_at timestamptz NOT NULL CHECK(isfinite(issued_at)),
 expires_at timestamptz NOT NULL CHECK(isfinite(expires_at) AND expires_at>issued_at AND expires_at<=issued_at+interval '5 minutes'),
 request_envelope bytea NOT NULL CHECK(octet_length(request_envelope) BETWEEN 1 AND 65536),
 PRIMARY KEY(tenant_id,request_id),
 UNIQUE(tenant_id,start_command_id),
 FOREIGN KEY(tenant_id,organization_id,provider_id) REFERENCES sso_providers.providers(tenant_id,organization_id,provider_id),
 FOREIGN KEY(start_command_id,tenant_id,start_purpose) REFERENCES identity.commands(command_id,tenant_id,purpose)
);`
