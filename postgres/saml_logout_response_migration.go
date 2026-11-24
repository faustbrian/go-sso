package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/faustbrian/go-sso"
)

// SAMLLogoutResponseMigrationSource creates terminal response receipts after
// SAMLLogoutRequestMigrationSource. Apply the empty, indexed table before
// enabling response settlement. Prior readers and writers need no backfill;
// rolling back response support preserves the immutable receipts. There is no
// destructive down migration. Version is a caller-selected unused successor.
type SAMLLogoutResponseMigrationSource struct{ Version migrations.Version }

var _ migrations.Source = SAMLLogoutResponseMigrationSource{}

// Load returns one forward-only transactional migration without I/O.
func (s SAMLLogoutResponseMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, sso.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "sso_saml_logout_responses", migrations.TransactionModeDefault, samlLogoutResponseSQL, "")
	if err != nil {
		return nil, sso.ErrUnavailable
	}
	return []migrations.Migration{m}, nil
}

// The request key consumes the original once; the issuer-bound signed ID
// catches attempted reuse with another request. No raw SAML or subject is stored.
const samlLogoutResponseSQL = `SET LOCAL lock_timeout='5s';
CREATE TABLE sso_providers.saml_logout_responses (
 tenant_id identity.directory_id NOT NULL,
 request_id text COLLATE "C" NOT NULL,
 response_id_digest bytea NOT NULL CHECK(octet_length(response_id_digest)=32),
 response_digest bytea NOT NULL CHECK(octet_length(response_digest)=32),
 status_code text COLLATE "C" NOT NULL CHECK(octet_length(status_code) BETWEEN 1 AND 128),
 status_subcode text COLLATE "C" NOT NULL CHECK(octet_length(status_subcode) <= 128),
 settled_at timestamptz NOT NULL CHECK(isfinite(settled_at)),
 PRIMARY KEY(tenant_id,request_id),
 UNIQUE(tenant_id,response_id_digest),
 FOREIGN KEY(tenant_id,request_id) REFERENCES sso_providers.saml_logout_requests(tenant_id,request_id)
);`
