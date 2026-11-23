package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/faustbrian/go-sso"
)

// SAMLIDPReplayMigrationSource expands shared SAML replay-member custody to
// accept IdP-initiated callback commands alongside SP-initiated ACS commands.
// Apply both versions after SAMLReplayMigrationSource and before installing
// IdP-initiated replay writers. This source does not enable unsolicited sign-in
// and owns neither the migration runner nor its transaction lifetime.
//
// Version atomically replaces only the callback-purpose check, enforcing the
// expanded purpose set immediately without scanning populated replay custody.
// ValidationVersion validates that check in a separate committed migration.
// Both bound lock acquisition and preserve the ACS default, shared replay and
// command/member keys, same-purpose command foreign key and existing data.
// Code rollback retains the expansion: narrowing the check is unsafe after
// IdP-initiated replay members exist. No down SQL is provided.
type SAMLIDPReplayMigrationSource struct {
	Version           migrations.Version
	ValidationVersion migrations.Version
}

var _ migrations.Source = SAMLIDPReplayMigrationSource{}

// Load returns expansion and validation history without I/O. Versions must be
// positive, strictly ordered and within the migration ledger's signed 64-bit
// range. Invalid input, nil context or cancellation returns no partial history.
// Installation fails if the named predecessor check is absent rather than
// adopting an unexpected schema history.
func (s SAMLIDPReplayMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.ValidationVersion <= s.Version || s.ValidationVersion > migrations.Version(math.MaxInt64) {
		return nil, sso.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	expand, err := migrations.NewMigration(s.Version, "sso_saml_idp_replay", migrations.TransactionModeDefault, samlIDPReplaySQL, "")
	if err != nil {
		return nil, sso.ErrUnavailable
	}
	validate, err := migrations.NewMigration(s.ValidationVersion, "sso_saml_idp_replay_validate", migrations.TransactionModeDefault, samlIDPReplayValidationSQL, "")
	if err != nil {
		return nil, sso.ErrUnavailable
	}
	return []migrations.Migration{expand, validate}, nil
}

const samlIDPReplaySQL = `SET LOCAL lock_timeout='5s';
ALTER TABLE sso_providers.saml_replay_members
 DROP CONSTRAINT saml_replay_members_callback_purpose_check,
 ADD CONSTRAINT saml_replay_members_callback_purpose_check CHECK (
  callback_purpose IN ('identity.sso.saml-acs','identity.sso.saml-idp-init')
 ) NOT VALID;`

const samlIDPReplayValidationSQL = `SET LOCAL lock_timeout='5s';
ALTER TABLE sso_providers.saml_replay_members
 VALIDATE CONSTRAINT saml_replay_members_callback_purpose_check;`
