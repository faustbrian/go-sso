package postgres

import (
	"context"
	"errors"
	"math"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/faustbrian/go-sso"
)

func TestSAMLIDPConfirmationMigrationIsForwardOnly(t *testing.T) {
	for _, version := range []migrations.Version{0, migrations.Version(math.MaxInt64) + 1} {
		if got, err := (SAMLIDPConfirmationMigrationSource{Version: version}).Load(t.Context()); !errors.Is(err, sso.ErrInvalidInput) || got != nil {
			t.Fatal("invalid version returned migration history", err)
		}
	}
	source := SAMLIDPConfirmationMigrationSource{Version: 391}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := source.Load(ctx); !errors.Is(err, context.Canceled) || got != nil {
		t.Fatal("cancellation returned migration history", err)
	}
	if got, err := source.Load(nil); !errors.Is(err, sso.ErrInvalidInput) || got != nil {
		t.Fatal("nil context returned migration history", err)
	}
	got, err := source.Load(t.Context())
	if err != nil || len(got) != 1 || got[0].Version() != 391 || got[0].Name() != "sso_saml_idp_confirmations" || got[0].TransactionMode() != migrations.TransactionModeDefault || got[0].UpSQL() == "" || got[0].DownSQL() != "" {
		t.Fatal("missing bounded additive confirmation history", err)
	}
}
