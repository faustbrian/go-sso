package postgres_test

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestSAMLLogoutRequestMigrationRejectsInvalidVersions(t *testing.T) {
	for _, version := range []migrations.Version{0, migrations.Version(math.MaxInt64) + 1, migrations.Version(math.MaxUint64)} {
		history, err := (ssopg.SAMLLogoutRequestMigrationSource{Version: version}).Load(t.Context())
		if !errors.Is(err, sso.ErrInvalidInput) || history != nil {
			t.Fatalf("invalid version %d returned history: %v", version, err)
		}
	}
}

func TestSAMLLogoutRequestMigrationRejectsInvalidContextWithoutPartialHistory(t *testing.T) {
	source := ssopg.SAMLLogoutRequestMigrationSource{Version: 395}
	if history, err := source.Load(nil); !errors.Is(err, sso.ErrInvalidInput) || history != nil {
		t.Fatal("nil context returned logout request history", err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if history, err := source.Load(canceled); !errors.Is(err, context.Canceled) || history != nil {
		t.Fatal("cancellation returned partial logout request history", err)
	}
	expired, cancelDeadline := context.WithDeadline(t.Context(), time.Time{})
	defer cancelDeadline()
	if history, err := source.Load(expired); !errors.Is(err, context.DeadlineExceeded) || history != nil {
		t.Fatal("expired context returned partial logout request history", err)
	}
}

func TestSAMLLogoutRequestMigrationReturnsCallerSelectedForwardOnlyHistory(t *testing.T) {
	for _, version := range []migrations.Version{1, 395, migrations.Version(math.MaxInt64)} {
		history, err := (ssopg.SAMLLogoutRequestMigrationSource{Version: version}).Load(t.Context())
		if err != nil || len(history) != 1 {
			t.Fatalf("version %d did not load one migration: %v", version, err)
		}
		migration := history[0]
		if migration.Version() != version || migration.Name() != "sso_saml_logout_requests" {
			t.Fatal("logout request migration lost its caller-selected version or name")
		}
		if migration.TransactionMode() != migrations.TransactionModeDefault || migration.UpSQL() == "" || migration.DownSQL() != "" {
			t.Fatal("logout request migration is not transactional forward-only history")
		}
	}
}
