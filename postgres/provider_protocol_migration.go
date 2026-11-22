package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/faustbrian/go-sso"
)

// ProviderProtocolMigrationSource adds a closed protocol discriminator to the
// existing provider registry. Install both versions after ProviderMigrationSource
// and before selecting OAuth registration. The constant OIDC default preserves
// old inserts and reflects the only protocol accepted before this migration;
// neither payload envelopes nor existing authority are rewritten.
//
// Keep OAuth registration off until all registry readers and mutators support
// this history. The source does not activate any provider. Rollback retains the
// history; a legacy OIDC-only registry must not serve established OAuth records.
type ProviderProtocolMigrationSource struct {
	Version           migrations.Version
	ValidationVersion migrations.Version
}

var _ migrations.Source = ProviderProtocolMigrationSource{}

// Load returns the expansion and the separately committed constraint validation.
// It performs no I/O. Unsupported versions, nil context or cancellation return
// no partial history.
func (s ProviderProtocolMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.ValidationVersion <= s.Version || s.ValidationVersion > migrations.Version(math.MaxInt64) {
		return nil, sso.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	expand, err := migrations.NewMigration(s.Version, "sso_provider_protocol", migrations.TransactionModeDefault, providerProtocolSQL, "")
	if err != nil {
		return nil, sso.ErrUnavailable
	}
	validate, err := migrations.NewMigration(s.ValidationVersion, "sso_provider_protocol_validate", migrations.TransactionModeDefault, providerProtocolValidationSQL, "")
	if err != nil {
		return nil, sso.ErrUnavailable
	}
	return []migrations.Migration{expand, validate}, nil
}

// The constant default is metadata-only on supported PostgreSQL. Avoid checking
// populated rows under the expansion lock; new writes are checked immediately.
const providerProtocolSQL = `SET LOCAL lock_timeout='5s';
ALTER TABLE sso_providers.providers
 ADD COLUMN protocol text COLLATE "C" NOT NULL DEFAULT 'oidc',
 ADD CONSTRAINT sso_providers_protocol_check CHECK (protocol IN ('oidc','oauth2')) NOT VALID;`

const providerProtocolValidationSQL = `SET LOCAL lock_timeout='5s';
ALTER TABLE sso_providers.providers VALIDATE CONSTRAINT sso_providers_protocol_check;`
