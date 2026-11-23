package postgres

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/faustbrian/go-sso"
)

func TestProviderGrantRefreshMigrationRejectsInvalidHistoryAndCancellation(t *testing.T) {
	for _, source := range []ProviderGrantRefreshMigrationSource{
		{},
		{Version: 0, ValidationVersion: 2, ReceiptVersion: 3},
		{Version: 1, ValidationVersion: 0, ReceiptVersion: 3},
		{Version: 1, ValidationVersion: 2, ReceiptVersion: 0},
		{Version: 2, ValidationVersion: 2, ReceiptVersion: 3},
		{Version: 2, ValidationVersion: 1, ReceiptVersion: 3},
		{Version: 1, ValidationVersion: 2, ReceiptVersion: 2},
		{Version: 1, ValidationVersion: 3, ReceiptVersion: 2},
		{Version: 1, ValidationVersion: 2, ReceiptVersion: migrations.Version(math.MaxInt64) + 1},
		{Version: migrations.Version(math.MaxUint64), ValidationVersion: 2, ReceiptVersion: 3},
		{Version: 1, ValidationVersion: migrations.Version(math.MaxUint64), ReceiptVersion: 3},
	} {
		if history, err := source.Load(context.Background()); !errors.Is(err, sso.ErrInvalidInput) || history != nil {
			t.Fatal("invalid history versions returned refresh migrations", source, err)
		}
	}

	source := ProviderGrantRefreshMigrationSource{Version: 372, ValidationVersion: 373, ReceiptVersion: 374}
	if history, err := source.Load(nil); !errors.Is(err, sso.ErrInvalidInput) || history != nil {
		t.Fatal("nil context returned refresh history", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if history, err := source.Load(ctx); !errors.Is(err, context.Canceled) || history != nil {
		t.Fatal("cancellation returned partial refresh history", err)
	}
}

func TestProviderGrantRefreshMigrationReturnsOrderedForwardOnlyHistory(t *testing.T) {
	for _, source := range []ProviderGrantRefreshMigrationSource{
		{Version: 1, ValidationVersion: 2, ReceiptVersion: 3},
		{Version: 372, ValidationVersion: 373, ReceiptVersion: 374},
		{Version: migrations.Version(math.MaxInt64) - 2, ValidationVersion: migrations.Version(math.MaxInt64) - 1, ReceiptVersion: migrations.Version(math.MaxInt64)},
	} {
		history, err := source.Load(context.Background())
		if err != nil || len(history) != 3 {
			t.Fatal("supported history did not return three refresh migrations", source, err)
		}
		versions := []migrations.Version{source.Version, source.ValidationVersion, source.ReceiptVersion}
		names := []string{"sso_provider_grant_refresh", "sso_provider_grant_refresh_validate", "sso_provider_grant_refresh_receipts"}
		for i, migration := range history {
			if migration.Version() != versions[i] || migration.Name() != names[i] {
				t.Fatal("refresh history changed its caller-selected identity", i, migration.Version(), migration.Name())
			}
			if migration.TransactionMode() != migrations.TransactionModeDefault || !strings.HasPrefix(migration.UpSQL(), "SET LOCAL lock_timeout='5s';") {
				t.Fatal("refresh migration does not bound lock acquisition to its transaction", i)
			}
			if migration.DownSQL() != "" {
				t.Fatal("refresh migration supplied destructive rollback history", i)
			}
		}
		if history[0].UpSQL() != providerGrantRefreshSQL || history[1].UpSQL() != providerGrantRefreshValidationSQL || history[2].UpSQL() != providerGrantRefreshReceiptSQL {
			t.Fatal("refresh expansion, validation and receipt installation are not separate history entries")
		}
	}
}
