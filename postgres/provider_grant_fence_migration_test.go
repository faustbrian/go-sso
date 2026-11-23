package postgres

import (
	"context"
	"errors"
	"math"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/faustbrian/go-sso"
)

func TestProviderGrantFenceMigrationRejectsInvalidHistoryAndCancellation(t *testing.T) {
	for _, version := range []migrations.Version{0, migrations.Version(math.MaxInt64) + 1, migrations.Version(math.MaxUint64)} {
		if history, err := (ProviderGrantFenceMigrationSource{Version: version}).Load(context.Background()); !errors.Is(err, sso.ErrInvalidInput) || history != nil {
			t.Fatal("invalid version returned grant fence history", version, err)
		}
	}
	source := ProviderGrantFenceMigrationSource{Version: 370}
	if history, err := source.Load(nil); !errors.Is(err, sso.ErrInvalidInput) || history != nil {
		t.Fatal("nil context returned grant fence history", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if history, err := source.Load(ctx); !errors.Is(err, context.Canceled) || history != nil {
		t.Fatal("cancellation returned grant fence history", err)
	}
}

func TestProviderGrantFenceMigrationReturnsCallerSelectedForwardOnlyHistory(t *testing.T) {
	for _, version := range []migrations.Version{1, 370, migrations.Version(math.MaxInt64)} {
		history, err := (ProviderGrantFenceMigrationSource{Version: version}).Load(context.Background())
		if err != nil || len(history) != 1 {
			t.Fatal("supported version did not return one grant fence migration", version, err)
		}
		migration := history[0]
		if migration.Version() != version || migration.Name() != "sso_provider_grant_fences" {
			t.Fatal("grant fence migration changed its caller-selected history identity", migration.Version(), migration.Name())
		}
		if migration.TransactionMode() != migrations.TransactionModeDefault {
			t.Fatal("grant fence migration does not bound locks to its transaction")
		}
		if migration.UpSQL() == "" || migration.DownSQL() != "" {
			t.Fatal("grant fence migration is not additive forward-only history")
		}
	}
}
