package postgres

import (
	"context"
	"errors"
	"math"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/faustbrian/go-sso"
)

func TestProviderLogoutMigrationRejectsInvalidHistoryAndCancellation(t *testing.T) {
	for _, version := range []migrations.Version{0, migrations.Version(math.MaxInt64) + 1, migrations.Version(math.MaxUint64)} {
		if history, err := (ProviderLogoutMigrationSource{Version: version}).Load(context.Background()); !errors.Is(err, sso.ErrInvalidInput) || history != nil {
			t.Fatal("invalid version returned logout custody history", version, err)
		}
	}
	source := ProviderLogoutMigrationSource{Version: 360}
	if history, err := source.Load(nil); !errors.Is(err, sso.ErrInvalidInput) || history != nil {
		t.Fatal("nil context returned logout custody history", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if history, err := source.Load(ctx); !errors.Is(err, context.Canceled) || history != nil {
		t.Fatal("cancellation returned logout custody history", err)
	}
	if history, err := (ProviderLogoutMigrationSource{Version: migrations.Version(math.MaxInt64)}).Load(context.Background()); err != nil || len(history) != 1 {
		t.Fatal("maximum supported version rejected", err)
	}
}
