package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/faustbrian/go-sso"
)

// ProviderSAMLProtocolMigrationSource expands the provider registry's closed
// protocol discriminator to OIDC, OAuth and SAML. Install both versions after
// both ProviderProtocolMigrationSource versions and before SAML registration,
// only when every registry reader and mutator understands SAML providers. This
// opt-in library source performs no deployment or provider activation and owns
// neither the migration runner nor its transaction lifetime.
//
// Version atomically replaces the existing check without scanning or rewriting
// provider rows, columns or indexes. ValidationVersion validates it in a separate
// committed migration. Both bound lock acquisition. Retain this expansion on
// code rollback: the OIDC/OAuth-only check is unsafe once SAML providers exist.
// No down SQL is provided.
type ProviderSAMLProtocolMigrationSource struct {
	Version           migrations.Version
	ValidationVersion migrations.Version
}

var _ migrations.Source = ProviderSAMLProtocolMigrationSource{}

// Load returns expansion and validation history without I/O. Versions must be
// positive, strictly ordered and within the migration ledger's signed 64-bit
// range. Invalid input, nil context or cancellation returns no partial history.
// Installation fails if the exact predecessor constraint is absent rather than
// adopting an unexpected schema history.
func (s ProviderSAMLProtocolMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.ValidationVersion <= s.Version || s.ValidationVersion > migrations.Version(math.MaxInt64) {
		return nil, sso.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	expand, err := migrations.NewMigration(s.Version, "sso_provider_saml_protocol", migrations.TransactionModeDefault, providerSAMLProtocolSQL, "")
	if err != nil {
		return nil, sso.ErrUnavailable
	}
	validate, err := migrations.NewMigration(s.ValidationVersion, "sso_provider_saml_protocol_validate", migrations.TransactionModeDefault, providerSAMLProtocolValidationSQL, "")
	if err != nil {
		return nil, sso.ErrUnavailable
	}
	return []migrations.Migration{expand, validate}, nil
}

// One atomic ALTER leaves no unchecked write window. NOT VALID avoids scanning
// existing rows under the expansion's exclusive lock and checks new writes.
const providerSAMLProtocolSQL = `SET LOCAL lock_timeout='5s';
ALTER TABLE sso_providers.providers
 DROP CONSTRAINT sso_providers_protocol_check,
 ADD CONSTRAINT sso_providers_protocol_check CHECK (protocol IN ('oidc','oauth2','saml')) NOT VALID;`

const providerSAMLProtocolValidationSQL = `SET LOCAL lock_timeout='5s';
ALTER TABLE sso_providers.providers VALIDATE CONSTRAINT sso_providers_protocol_check;`
