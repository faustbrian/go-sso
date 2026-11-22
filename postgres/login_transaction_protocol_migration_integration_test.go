//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"errors"
	"math"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestLoginTransactionProtocolMigrationRejectsInvalidHistory(t *testing.T) {
	for _, source := range []ssopg.LoginTransactionProtocolMigrationSource{
		{Version: 0, ValidationVersion: 2},
		{Version: 1, ValidationVersion: 0},
		{Version: 2, ValidationVersion: 2},
		{Version: 2, ValidationVersion: 1},
		{Version: migrations.Version(math.MaxInt64), ValidationVersion: migrations.Version(math.MaxInt64) + 1},
		{Version: migrations.Version(math.MaxUint64), ValidationVersion: migrations.Version(math.MaxUint64)},
	} {
		if history, err := source.Load(context.Background()); !errors.Is(err, sso.ErrInvalidInput) || history != nil {
			t.Fatal("invalid version pair returned history", source, err)
		}
	}
	source := ssopg.LoginTransactionProtocolMigrationSource{Version: 327, ValidationVersion: 328}
	if history, err := source.Load(nil); !errors.Is(err, sso.ErrInvalidInput) || history != nil {
		t.Fatal("nil context returned history", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if history, err := source.Load(ctx); !errors.Is(err, context.Canceled) || history != nil {
		t.Fatal("cancellation returned partial history", err)
	}
	if history, err := (ssopg.LoginTransactionProtocolMigrationSource{
		Version: migrations.Version(math.MaxInt64) - 1, ValidationVersion: migrations.Version(math.MaxInt64),
	}).Load(context.Background()); err != nil || len(history) != 2 {
		t.Fatal("maximum supported ordered versions rejected", err)
	}
}

func TestNativeLoginTransactionProtocolMigrationPreservesPopulatedCustody(t *testing.T) {
	x := newProviderEnableFixture(t)
	f := x.f
	config, err := pgx.ParseConfig(f.dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.Database = f.database
	db := stdlib.OpenDB(*config)
	defer db.Close()
	backend, err := migrationpg.New(db)
	if err != nil {
		t.Fatal(err)
	}
	history := append(migrationList(nil), f.history...)
	for _, source := range []migrations.Source{
		ssopg.ProviderUpdateMigrationSource{Version: 321},
		ssopg.ProviderCredentialsMigrationSource{Version: 322},
		ssopg.ProviderEnableMigrationSource{Version: 323},
		ssopg.LoginTransactionMigrationSource{Version: 324},
		ssopg.ProviderProtocolMigrationSource{Version: 325, ValidationVersion: 326},
	} {
		loaded, err := source.Load(f.ctx)
		if err != nil {
			t.Fatal("load existing caller-selected history", err)
		}
		history = append(history, loaded...)
	}
	apply := func(selected migrationList) {
		t.Helper()
		runner, err := migrations.NewRunner(selected, backend)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := runner.Up(f.ctx); err != nil {
			t.Fatal("apply unchanged prefix and selected additive history", err)
		}
	}
	apply(history)

	const insert = `INSERT INTO sso_providers.login_transactions
 (tenant_id,organization_id,provider_id,provider_version,credential_generation,mapping_version,
 start_command_id,callback_command_id,protocol,state_key_version,state_digest,pkce_key_version,
 pkce_commitment,binding_envelope,verifier_envelope,issued_at,expires_at)
 VALUES ($1,$2,$3,3,1,1,$4,$5,$6,1,$7,1,$8,$9,$10,
 '2026-11-22T10:00:00Z','2026-11-22T10:10:00Z')`
	insertProtocol := func(protocol, command string, digest byte) error {
		_, err := f.pool.Raw().Exec(f.ctx, insert,
			string(x.proof.TenantID), string(x.proof.OrganizationID), x.request.ProviderID,
			command+"-start", command+"-callback", protocol,
			bytes.Repeat([]byte{digest}, 32), bytes.Repeat([]byte{0x22}, 32),
			[]byte{0x33, 0x34, 0x35}, []byte{0x44, 0x45, 0x46})
		return err
	}
	if err := insertProtocol("oidc", "legacy", 0x11); err != nil {
		t.Fatal("seed legacy encrypted binding and pending PKCE custody", err)
	}
	assertRejected := func(protocol, command string, digest byte) {
		t.Helper()
		var databaseError *pgconn.PgError
		err := insertProtocol(protocol, command, digest)
		if !errors.As(err, &databaseError) || databaseError.Code != "23514" || databaseError.ConstraintName != "login_transactions_protocol_check" {
			t.Fatal("unsupported protocol did not fail closed at the protocol constraint", err)
		}
	}
	assertRejected("oauth2", "pre-expansion", 0x55)
	var beforeRow, beforeHistory []byte
	var beforeFile uint32
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT to_jsonb(t)::text,
 pg_relation_filenode('sso_providers.login_transactions'::regclass)
 FROM sso_providers.login_transactions t WHERE start_command_id='legacy-start'`).Scan(&beforeRow, &beforeFile); err != nil {
		t.Fatal("snapshot populated legacy custody and physical relation", err)
	}
	ledgerSnapshot := func() []byte {
		t.Helper()
		var snapshot []byte
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT jsonb_agg(to_jsonb(m) ORDER BY version)::text
 FROM public.migrations m WHERE version <= 326`).Scan(&snapshot); err != nil {
			t.Fatal("snapshot existing migration ledger prefix", err)
		}
		return snapshot
	}
	beforeHistory = ledgerSnapshot()
	expansion, err := (ssopg.LoginTransactionProtocolMigrationSource{Version: 327, ValidationVersion: 328}).Load(f.ctx)
	if err != nil || len(expansion) != 2 {
		t.Fatal("load separate expansion and validation migrations", err)
	}
	history = append(history, expansion[0])
	apply(history)
	assertConstraint := func(validated bool) {
		t.Helper()
		var count int
		var actualValidated bool
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*),bool_and(convalidated)
 FROM pg_constraint WHERE conrelid='sso_providers.login_transactions'::regclass
 AND contype='c' AND pg_get_constraintdef(oid) LIKE '%protocol%'`).Scan(&count, &actualValidated); err != nil || count != 1 || actualValidated != validated {
			t.Fatal("expected exactly one protocol constraint with separate validation", count, actualValidated, err)
		}
	}
	assertConstraint(false)
	if err := insertProtocol("oauth2", "expanded-oauth", 0x66); err != nil {
		t.Fatal("expanded protocol rejects OAuth pending encrypted custody", err)
	}
	if err := insertProtocol("oidc", "expanded-oidc", 0x77); err != nil {
		t.Fatal("expanded protocol rejects existing OIDC writers", err)
	}
	assertRejected("saml", "expanded-unknown", 0x88)
	history = append(history, expansion[1])
	apply(history)
	apply(history)
	assertConstraint(true)
	assertRejected("unknown", "validated-unknown", 0x99)
	var afterRow []byte
	var afterFile uint32
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT to_jsonb(t)::text,
 pg_relation_filenode('sso_providers.login_transactions'::regclass)
 FROM sso_providers.login_transactions t WHERE start_command_id='legacy-start'`).Scan(&afterRow, &afterFile); err != nil {
		t.Fatal("read retained legacy custody", err)
	}
	if !bytes.Equal(beforeRow, afterRow) || beforeFile != afterFile {
		t.Fatal("protocol expansion rewrote legacy custody bytes or physical relation")
	}
	if !bytes.Equal(beforeHistory, ledgerSnapshot()) {
		t.Fatal("additive protocol history changed the installed migration prefix")
	}
}
