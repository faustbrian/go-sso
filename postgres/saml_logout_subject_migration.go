package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/faustbrian/go-sso"
)

// SAMLLogoutSubjectMigrationSource installs encrypted original-subject custody
// after ProviderMigrationSource and the native identity command migrations on
// the same primary. Apply this schema before selecting a logout-subject writer;
// loading or installing it does not activate a writer or backfill old sessions.
// Version is a caller-selected unused positive history version.
//
// Installation creates one empty table and its lookup index. Existing provider
// and command data are neither rewritten nor scanned; foreign-key lock waits
// are bounded by a transaction-local lock timeout. Custody has no dependency on
// a particular session-store schema or user-row lifetime. Code rollback leaves
// existing custody intact; no destructive down migration is provided.
type SAMLLogoutSubjectMigrationSource struct{ Version migrations.Version }

var _ migrations.Source = SAMLLogoutSubjectMigrationSource{}

// Load returns the single forward-only migration without I/O. Invalid versions,
// nil context or cancellation return no partial history. An existing table is
// an installation error, never custody to adopt or replace silently.
func (s SAMLLogoutSubjectMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, sso.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "sso_saml_logout_subjects", migrations.TransactionModeDefault, samlLogoutSubjectSQL, "")
	if err != nil {
		return nil, sso.ErrUnavailable
	}
	return []migrations.Migration{m}, nil
}

// The issuance command and local session are distinct identities. Both unique
// constraints prevent a later insert from replacing either original binding;
// writers must insert once, never UPDATE or upsert existing custody. Expiry is
// the session's original absolute expiry, not an independently renewable lease.
// Digests select candidates; only the sealed exact subject can establish a
// subject match. The coordinator remains the sole session/lifecycle authority.
const samlLogoutSubjectSQL = `SET LOCAL lock_timeout='5s';
CREATE TABLE sso_providers.saml_logout_subjects (
 tenant_id identity.directory_id NOT NULL,
 organization_id text COLLATE "C" NOT NULL CHECK(octet_length(organization_id) BETWEEN 1 AND 128),
 provider_id text COLLATE "C" NOT NULL CHECK(octet_length(provider_id) BETWEEN 1 AND 128),
 user_id identity.directory_id NOT NULL,
 session_id text COLLATE "C" NOT NULL CHECK(octet_length(session_id) BETWEEN 1 AND 128),
 family_id text COLLATE "C" NOT NULL CHECK(octet_length(family_id) BETWEEN 1 AND 128),
 issuance_command_id bytea NOT NULL CHECK(octet_length(issuance_command_id)=16),
 issuance_purpose text COLLATE "C" NOT NULL CHECK(issuance_purpose IN ('identity.sso.saml-acs','identity.sso.saml-idp-init')),
 issued_at timestamptz NOT NULL CHECK(isfinite(issued_at)),
 expires_at timestamptz NOT NULL CHECK(isfinite(expires_at) AND expires_at>issued_at),
 match_key_version bigint NOT NULL CHECK(match_key_version BETWEEN 1 AND 4294967295),
 subject_digest bytea NOT NULL CHECK(octet_length(subject_digest)=32),
 session_index_digest bytea CHECK(octet_length(session_index_digest)=32),
 subject_envelope bytea NOT NULL CHECK(octet_length(subject_envelope) BETWEEN 1 AND 65536),
 PRIMARY KEY(tenant_id,session_id),
 UNIQUE(tenant_id,issuance_command_id),
 FOREIGN KEY(tenant_id,organization_id,provider_id) REFERENCES sso_providers.providers(tenant_id,organization_id,provider_id),
 FOREIGN KEY(issuance_command_id,tenant_id,issuance_purpose) REFERENCES identity.commands(command_id,tenant_id,purpose)
);
CREATE INDEX saml_logout_subject_match ON sso_providers.saml_logout_subjects
 (tenant_id,organization_id,provider_id,match_key_version,subject_digest,session_index_digest);`
