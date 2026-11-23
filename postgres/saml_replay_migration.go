package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/faustbrian/go-sso"
)

// SAMLReplayMigrationSource installs SSO-owned SAML replay-member custody. Apply
// after ProviderMigrationSource and the native identity command migrations on
// the same primary, before opting into SAML replay writers. Version is a
// caller-selected unused positive history version after those prerequisites.
// This source performs no deployment and owns neither a runner nor transaction
// lifetime.
//
// Installation creates one empty table, taking only short, bounded foreign-key
// locks on existing tables without scanning, backfilling or changing their data.
// Code rollback retains replay members; no destructive down SQL is provided.
type SAMLReplayMigrationSource struct{ Version migrations.Version }

var _ migrations.Source = SAMLReplayMigrationSource{}

// Load returns additive forward-only history without I/O. Invalid versions, a
// nil context or cancellation return no partial history. An existing replay
// table is an installation error rather than data to adopt silently.
func (s SAMLReplayMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, sso.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "sso_saml_replay_members", migrations.TransactionModeDefault, samlReplaySQL, "")
	if err != nil {
		return nil, sso.ErrUnavailable
	}
	return []migrations.Migration{m}, nil
}

// The closed ref.saml.replay_set policy requires a Response and every consumed
// Assertion to reserve atomically, with unknown outcomes retained for
// reconciliation (identity-platform REFERENCE_CONFIGURATION.md and sso-saml
// goal). Kind is deliberately absent from the replay key: switching an ID
// between Response (1) and Assertion (2) must not evade scoped single use. The
// command/member key identifies each member for authoritative reconciliation;
// this schema does not perform reservation, recovery or retention cleanup.
const samlReplaySQL = `SET LOCAL lock_timeout='5s';
CREATE TABLE sso_providers.saml_replay_members (
 tenant_id identity.directory_id NOT NULL,
 organization_id text COLLATE "C" NOT NULL CHECK(octet_length(organization_id) BETWEEN 1 AND 128),
 provider_id text COLLATE "C" NOT NULL CHECK(octet_length(provider_id) BETWEEN 1 AND 128),
 issuer_digest bytea NOT NULL CHECK(octet_length(issuer_digest)=32),
 member_digest bytea NOT NULL CHECK(octet_length(member_digest)=32),
 member_kind smallint NOT NULL CHECK(member_kind IN (1,2)),
 callback_command_id bytea NOT NULL CHECK(octet_length(callback_command_id)=16),
 callback_purpose text COLLATE "C" NOT NULL DEFAULT 'identity.sso.saml-acs' CHECK(callback_purpose='identity.sso.saml-acs'),
 execution_fingerprint bytea NOT NULL CHECK(octet_length(execution_fingerprint)=32),
 execution_generation identity.version NOT NULL,
 retain_until timestamptz NOT NULL CHECK(isfinite(retain_until)),
 CONSTRAINT saml_replay_member_scope_pkey PRIMARY KEY(tenant_id,organization_id,provider_id,issuer_digest,member_digest),
 CONSTRAINT saml_replay_command_member_key UNIQUE(tenant_id,callback_command_id,member_kind),
 FOREIGN KEY(tenant_id,organization_id,provider_id) REFERENCES sso_providers.providers(tenant_id,organization_id,provider_id),
 FOREIGN KEY(tenant_id,callback_purpose,callback_command_id) REFERENCES identity.commands(tenant_id,purpose,command_id)
);`
