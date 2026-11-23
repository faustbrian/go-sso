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

func TestSAMLIDPReplayMigrationRejectsInvalidHistoryAndContext(t *testing.T) {
	for _, source := range []SAMLIDPReplayMigrationSource{
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
			t.Fatal("invalid version pair returned SAML IdP replay history", source, err)
		}
	}

	source := SAMLIDPReplayMigrationSource{Version: 394, ValidationVersion: 395}
	if history, err := source.Load(nil); !errors.Is(err, sso.ErrInvalidInput) || history != nil {
		t.Fatal("nil context returned SAML IdP replay history", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if history, err := source.Load(canceled); !errors.Is(err, context.Canceled) || history != nil {
		t.Fatal("cancellation returned partial SAML IdP replay history", err)
	}
	expired, cancelDeadline := context.WithDeadline(context.Background(), time.Unix(1, 0))
	defer cancelDeadline()
	if history, err := source.Load(expired); !errors.Is(err, context.DeadlineExceeded) || history != nil {
		t.Fatal("expired deadline returned partial SAML IdP replay history", err)
	}
}

func TestSAMLIDPReplayMigrationReturnsOrderedForwardOnlyHistory(t *testing.T) {
	for _, source := range []SAMLIDPReplayMigrationSource{
		{Version: 1, ValidationVersion: 2},
		{Version: 394, ValidationVersion: 395},
		{Version: migrations.Version(math.MaxInt64) - 1, ValidationVersion: migrations.Version(math.MaxInt64)},
	} {
		history, err := source.Load(context.Background())
		if err != nil || len(history) != 2 {
			t.Fatal("supported version pair did not return expansion and validation", source, err)
		}
		versions := []migrations.Version{source.Version, source.ValidationVersion}
		names := []string{"sso_saml_idp_replay", "sso_saml_idp_replay_validate"}
		for i, migration := range history {
			if migration.Version() != versions[i] || migration.Name() != names[i] {
				t.Fatal("SAML IdP replay history changed its caller-selected identity", i, migration.Version(), migration.Name())
			}
			if migration.TransactionMode() != migrations.TransactionModeDefault {
				t.Fatal("SAML IdP replay migration does not retain its own transaction", i)
			}
			if migration.UpSQL() == "" || migration.DownSQL() != "" {
				t.Fatal("SAML IdP replay migration is not forward-only history", i)
			}
		}
	}
}

func TestSAMLIDPReplayMigrationOnlyExpandsPurposeBeforeSeparateValidation(t *testing.T) {
	history, err := (SAMLIDPReplayMigrationSource{Version: 394, ValidationVersion: 395}).Load(context.Background())
	if err != nil || len(history) != 2 {
		t.Fatal("load SAML IdP replay expansion and validation", err)
	}
	const expansion = `SET LOCAL lock_timeout='5s';
ALTER TABLE sso_providers.saml_replay_members
 DROP CONSTRAINT saml_replay_members_callback_purpose_check,
 ADD CONSTRAINT saml_replay_members_callback_purpose_check CHECK (
  callback_purpose IN ('identity.sso.saml-acs','identity.sso.saml-idp-init')
 ) NOT VALID;`
	if history[0].UpSQL() != expansion {
		t.Fatal("expansion must atomically replace only the purpose check without scanning or rewriting replay custody")
	}
	const validation = `SET LOCAL lock_timeout='5s';
ALTER TABLE sso_providers.saml_replay_members
 VALIDATE CONSTRAINT saml_replay_members_callback_purpose_check;`
	if history[1].UpSQL() != validation {
		t.Fatal("purpose check validation must have a separate bounded-lock transaction")
	}
}
