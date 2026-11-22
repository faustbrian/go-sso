package postgres

import (
	"context"
	"math"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestProviderLoginTokenVaultMigrationRejectsInvalidHistoryAndCancellation(t *testing.T) {
	for _, version := range []migrations.Version{0, migrations.Version(math.MaxUint64)} {
		if history, err := (ProviderLoginTokenVaultMigrationSource{Version: version}).Load(context.Background()); err == nil || history != nil {
			t.Fatal("invalid token custody history was accepted")
		}
	}
	if history, err := (ProviderLoginTokenVaultMigrationSource{Version: 500}).Load(nil); err == nil || history != nil {
		t.Fatal("nil migration context was accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if history, err := (ProviderLoginTokenVaultMigrationSource{Version: 500}).Load(ctx); err != context.Canceled || history != nil {
		t.Fatal("migration ignored cancellation", err)
	}
}
