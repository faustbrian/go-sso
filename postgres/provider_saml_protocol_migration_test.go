package postgres

import (
	"context"
	"errors"
	"math"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/faustbrian/go-sso"
)

func TestProviderSAMLProtocolMigrationRejectsInvalidHistoryAndCancellation(t *testing.T) {
	for _, source := range []ProviderSAMLProtocolMigrationSource{
		{},
		{Version: 0, ValidationVersion: 2},
		{Version: 1, ValidationVersion: 0},
		{Version: 2, ValidationVersion: 2},
		{Version: 2, ValidationVersion: 1},
		{Version: migrations.Version(math.MaxInt64), ValidationVersion: migrations.Version(math.MaxInt64) + 1},
		{Version: 1, ValidationVersion: migrations.Version(math.MaxUint64)},
		{Version: migrations.Version(math.MaxUint64), ValidationVersion: 2},
	} {
		if history, err := source.Load(context.Background()); !errors.Is(err, sso.ErrInvalidInput) || history != nil {
			t.Fatal("invalid version pair returned SAML protocol history", source, err)
		}
	}

	source := ProviderSAMLProtocolMigrationSource{Version: 392, ValidationVersion: 393}
	if history, err := source.Load(nil); !errors.Is(err, sso.ErrInvalidInput) || history != nil {
		t.Fatal("nil context returned SAML protocol history", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if history, err := source.Load(ctx); !errors.Is(err, context.Canceled) || history != nil {
		t.Fatal("cancellation returned partial SAML protocol history", err)
	}
}

func TestProviderSAMLProtocolMigrationReturnsOrderedForwardOnlyHistory(t *testing.T) {
	for _, source := range []ProviderSAMLProtocolMigrationSource{
		{Version: 1, ValidationVersion: 2},
		{Version: 392, ValidationVersion: 393},
		{Version: migrations.Version(math.MaxInt64) - 1, ValidationVersion: migrations.Version(math.MaxInt64)},
	} {
		history, err := source.Load(context.Background())
		if err != nil || len(history) != 2 {
			t.Fatal("supported version pair did not return two SAML protocol migrations", source, err)
		}
		versions := []migrations.Version{source.Version, source.ValidationVersion}
		names := []string{"sso_provider_saml_protocol", "sso_provider_saml_protocol_validate"}
		for i, migration := range history {
			if migration.Version() != versions[i] || migration.Name() != names[i] {
				t.Fatal("SAML protocol history changed its caller-selected identity", i, migration.Version(), migration.Name())
			}
			if migration.TransactionMode() != migrations.TransactionModeDefault {
				t.Fatal("SAML protocol migration does not retain its own transaction", i)
			}
			if migration.UpSQL() == "" || migration.DownSQL() != "" {
				t.Fatal("SAML protocol migration did not return forward-only history", i)
			}
		}
	}
}
