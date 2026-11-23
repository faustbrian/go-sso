package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/faustbrian/go-sso"
)

// LoginTransactionSAMLProtocolMigrationSource expands shared login custody to
// SAML without rewriting existing OIDC/OAuth2 rows or their encrypted material.
// Apply both versions after LoginTransactionProtocolMigrationSource and before
// installing SAML sign-in writers. Existing OIDC/OAuth2 writers remain supported;
// every custody reader must understand SAML before SAML rows can be written.
// This source owns neither the migration runner nor its transaction lifetime.
//
// Version atomically replaces the protocol and verifier-lifecycle checks and
// permits absent PKCE keys and commitments only for SAML. New checks are enforced
// immediately without scanning populated custody; ValidationVersion validates
// them in a separate committed migration. Both bound lock acquisition and retain
// existing value bounds, rows, primary keys and indexes. Code rollback leaves
// the expansion installed: restoring PKCE requirements is unsafe after SAML
// custody exists. No down SQL is provided.
type LoginTransactionSAMLProtocolMigrationSource struct {
	Version           migrations.Version
	ValidationVersion migrations.Version
}

var _ migrations.Source = LoginTransactionSAMLProtocolMigrationSource{}

// Load returns expansion and validation history without I/O. Versions must be
// positive, strictly ordered and within the migration ledger's signed 64-bit
// range. Invalid input, nil context or cancellation returns no partial history.
// Installation fails if the exact predecessor checks are absent rather than
// adopting an unexpected schema history.
func (s LoginTransactionSAMLProtocolMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.ValidationVersion <= s.Version || s.ValidationVersion > migrations.Version(math.MaxInt64) {
		return nil, sso.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	expand, err := migrations.NewMigration(s.Version, "sso_login_transaction_saml_protocol", migrations.TransactionModeDefault, loginTransactionSAMLProtocolSQL, "")
	if err != nil {
		return nil, sso.ErrUnavailable
	}
	validate, err := migrations.NewMigration(s.ValidationVersion, "sso_login_transaction_saml_protocol_validate", migrations.TransactionModeDefault, loginTransactionSAMLProtocolValidationSQL, "")
	if err != nil {
		return nil, sso.ErrUnavailable
	}
	return []migrations.Migration{expand, validate}, nil
}

// login_transactions_check3 is the generated terminal-verifier check from
// LoginTransactionMigrationSource. Replacing it in the same ALTER as nullability
// and the protocol discriminator leaves no unchecked write window. SAML uses
// opaque RelayState rather than PKCE and shares the reference frontchannel
// correlation profile's five-minute maximum original transaction lifetime.
const loginTransactionSAMLProtocolSQL = `SET LOCAL lock_timeout='5s';
ALTER TABLE sso_providers.login_transactions
 DROP CONSTRAINT login_transactions_protocol_check,
 DROP CONSTRAINT login_transactions_check3,
 ALTER COLUMN pkce_key_version DROP NOT NULL,
 ALTER COLUMN pkce_commitment DROP NOT NULL,
 ADD CONSTRAINT login_transactions_protocol_check CHECK (protocol IN ('oidc','oauth2','saml')) NOT VALID,
 ADD CONSTRAINT login_transactions_pkce_check CHECK (
  (protocol='saml' AND pkce_key_version IS NULL AND pkce_commitment IS NULL AND verifier_envelope IS NULL)
  OR (protocol IN ('oidc','oauth2') AND pkce_key_version IS NOT NULL AND pkce_commitment IS NOT NULL
   AND ((completed_at IS NULL AND verifier_envelope IS NOT NULL)
    OR (completed_at IS NOT NULL AND verifier_envelope IS NULL)))
 ) NOT VALID,
 ADD CONSTRAINT login_transactions_saml_lifetime_check CHECK (
  protocol <> 'saml' OR expires_at <= issued_at + interval '5 minutes'
 ) NOT VALID;`

const loginTransactionSAMLProtocolValidationSQL = `SET LOCAL lock_timeout='5s';
ALTER TABLE sso_providers.login_transactions
 VALIDATE CONSTRAINT login_transactions_protocol_check,
 VALIDATE CONSTRAINT login_transactions_pkce_check,
 VALIDATE CONSTRAINT login_transactions_saml_lifetime_check;`
