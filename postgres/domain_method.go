package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
	sso "github.com/faustbrian/go-sso"
)

// DomainChallengeMethodMigrationSource adds method custody to the original
// immutable challenge row. Apply after DomainChallengeMigrationSource and before
// constructing NewHTTPSStore. The constant DNS default preserves old inserts
// and ciphertext AAD; old readers cannot decrypt HTTPS-bound ciphertext. Reverting
// code retains both rows and the column. No backfill or table rewrite is needed.
type DomainChallengeMethodMigrationSource struct{ Version migrations.Version }

func (s DomainChallengeMethodMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, sso.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "sso_domain_challenge_method", migrations.TransactionModeDefault, domainChallengeMethodSQL, "")
	if err != nil {
		return nil, sso.ErrUnavailable
	}
	return []migrations.Migration{m}, nil
}

const domainChallengeMethodSQL = `SET LOCAL lock_timeout = '1s';
ALTER TABLE sso.domain_challenges ADD COLUMN method smallint NOT NULL DEFAULT 1;
ALTER TABLE sso.domain_challenges ADD CONSTRAINT domain_challenge_method CHECK(method IN (1,2)) NOT VALID;`
