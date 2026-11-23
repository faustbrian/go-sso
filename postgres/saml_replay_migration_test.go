package postgres

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/faustbrian/go-sso"
)

func TestSAMLReplayMigrationRejectsInvalidHistoryAndContext(t *testing.T) {
	for _, version := range []migrations.Version{0, migrations.Version(math.MaxInt64) + 1, migrations.Version(math.MaxUint64)} {
		if history, err := (SAMLReplayMigrationSource{Version: version}).Load(context.Background()); !errors.Is(err, sso.ErrInvalidInput) || history != nil {
			t.Fatal("invalid version returned SAML replay history", version, err)
		}
	}

	source := SAMLReplayMigrationSource{Version: 390}
	if history, err := source.Load(nil); !errors.Is(err, sso.ErrInvalidInput) || history != nil {
		t.Fatal("nil context returned SAML replay history", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if history, err := source.Load(canceled); !errors.Is(err, context.Canceled) || history != nil {
		t.Fatal("cancellation returned SAML replay history", err)
	}
	expired, cancelDeadline := context.WithDeadline(context.Background(), time.Unix(1, 0))
	defer cancelDeadline()
	if history, err := source.Load(expired); !errors.Is(err, context.DeadlineExceeded) || history != nil {
		t.Fatal("expired deadline returned SAML replay history", err)
	}
}

func TestSAMLReplayMigrationReturnsCallerSelectedForwardOnlyHistory(t *testing.T) {
	for _, version := range []migrations.Version{1, 390, migrations.Version(math.MaxInt64)} {
		history, err := (SAMLReplayMigrationSource{Version: version}).Load(context.Background())
		if err != nil || len(history) != 1 {
			t.Fatal("supported version did not return one SAML replay migration", version, err)
		}
		migration := history[0]
		if migration.Version() != version || migration.Name() != "sso_saml_replay_members" {
			t.Fatal("SAML replay migration changed its caller-selected history identity", migration.Version(), migration.Name())
		}
		if migration.TransactionMode() != migrations.TransactionModeDefault {
			t.Fatal("SAML replay migration does not bound locks to its transaction")
		}
		if migration.UpSQL() == "" || migration.DownSQL() != "" {
			t.Fatal("SAML replay migration is not additive forward-only history")
		}
	}
}
