//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"errors"
	"math"
	"testing"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestProviderLoginTokenVaultProtocolMigrationRejectsInvalidHistory(t *testing.T) {
	for _, source := range []ssopg.ProviderLoginTokenVaultProtocolMigrationSource{
		{Version: 0, ValidationVersion: 2},
		{Version: 1, ValidationVersion: 0},
		{Version: 2, ValidationVersion: 2},
		{Version: 2, ValidationVersion: 1},
		{Version: migrations.Version(math.MaxInt64), ValidationVersion: migrations.Version(math.MaxInt64) + 1},
		{Version: migrations.Version(math.MaxUint64), ValidationVersion: migrations.Version(math.MaxUint64)},
	} {
		if history, err := source.Load(context.Background()); !errors.Is(err, sso.ErrInvalidInput) || history != nil {
			t.Fatal("invalid version pair returned token-vault history", source, err)
		}
	}
	source := ssopg.ProviderLoginTokenVaultProtocolMigrationSource{Version: 346, ValidationVersion: 347}
	if history, err := source.Load(nil); !errors.Is(err, sso.ErrInvalidInput) || history != nil {
		t.Fatal("nil context returned token-vault history", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if history, err := source.Load(ctx); !errors.Is(err, context.Canceled) || history != nil {
		t.Fatal("cancellation returned partial token-vault history", err)
	}
	if history, err := (ssopg.ProviderLoginTokenVaultProtocolMigrationSource{
		Version: migrations.Version(math.MaxInt64) - 1, ValidationVersion: migrations.Version(math.MaxInt64),
	}).Load(context.Background()); err != nil || len(history) != 2 {
		t.Fatal("maximum supported ordered versions rejected", err)
	}
}

func TestNativeProviderLoginTokenVaultProtocolMigrationPreservesPopulatedGrant(t *testing.T) {
	x := newNativeCallbackJourneyFixture(t, "linked-member")
	f := x.start.enable.f
	got, err := x.completion.SigninCallback(f.ctx, x.request)
	if err != nil || got.Completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("seed an actual committed OIDC grant through the native callback", err)
	}

	configuration, err := pgx.ParseConfig(f.dsn)
	if err != nil {
		t.Fatal(err)
	}
	configuration.Database = f.database
	db := stdlib.OpenDB(*configuration)
	defer db.Close()
	backend, err := migrationpg.New(db)
	if err != nil {
		t.Fatal(err)
	}
	history := append(migrationList(nil), f.history...)
	apply := func() error {
		t.Helper()
		runner, err := migrations.NewRunner(history, backend)
		if err != nil {
			return err
		}
		_, err = runner.Up(f.ctx)
		return err
	}

	snapshot := func() []byte {
		t.Helper()
		var state []byte
		err := f.pool.Raw().QueryRow(f.ctx, `SELECT jsonb_build_object(
 'grants',(SELECT jsonb_agg(to_jsonb(v) ORDER BY callback_command_id) FROM sso_providers.provider_login_token_sets v),
 'relation',pg_relation_filenode('sso_providers.provider_login_token_sets'::regclass),
 'constraints',(SELECT jsonb_agg(jsonb_build_array(oid,conname,pg_get_constraintdef(oid),convalidated) ORDER BY conname)
 FROM pg_constraint WHERE conrelid='sso_providers.provider_login_token_sets'::regclass
 AND conname<>'provider_login_token_sets_origin_operation_check'),
 'indexes',(SELECT jsonb_agg(jsonb_build_array(indexrelid,pg_get_indexdef(indexrelid),indisvalid) ORDER BY indexrelid)
 FROM pg_index WHERE indrelid='sso_providers.provider_login_token_sets'::regclass),
 'history',(SELECT jsonb_agg(to_jsonb(m) ORDER BY version) FROM public.migrations m WHERE version<=345)
)::text`).Scan(&state)
		if err != nil {
			t.Fatal("snapshot the populated grant, physical relation, constraints, indexes and history", err)
		}
		return state
	}
	assertOperationRejected := func(operation, code, constraint string) {
		t.Helper()
		_, err := f.pool.Raw().Exec(f.ctx, `UPDATE sso_providers.provider_login_token_sets SET origin_operation=$1`, operation)
		var databaseError *pgconn.PgError
		if !errors.As(err, &databaseError) || databaseError.Code != code || (constraint != "" && databaseError.ConstraintName != constraint) {
			t.Fatal("unexpected origin operation did not fail at the expected integrity boundary", operation, err)
		}
	}
	const originConstraint = "provider_login_token_sets_origin_operation_check"
	assertOperationRejected("identity.sso.oauth-callback", "23514", originConstraint)
	before := snapshot()
	expansion, err := (ssopg.ProviderLoginTokenVaultProtocolMigrationSource{Version: 346, ValidationVersion: 347}).Load(f.ctx)
	if err != nil || len(expansion) != 2 {
		t.Fatal("load separately committed token-vault expansion and validation", err)
	}
	history = append(history, expansion[0])
	if err := apply(); err != nil {
		t.Fatal("expand the populated legacy token vault", err)
	}
	assertConstraint := func(validated bool) {
		t.Helper()
		var count int
		var actualValidated bool
		err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*),bool_and(convalidated)
 FROM pg_constraint WHERE conrelid='sso_providers.provider_login_token_sets'::regclass
 AND contype='c' AND pg_get_constraintdef(oid) LIKE '%origin_operation%'`).Scan(&count, &actualValidated)
		if err != nil || count != 1 || actualValidated != validated {
			t.Fatal("expected exactly one origin-operation check with separate validation", count, actualValidated, err)
		}
	}
	assertConstraint(false)
	assertOperationRejected("identity.sso.unknown-callback", "23514", originConstraint)
	// OAuth passes the expanded check but cannot borrow the OIDC command's
	// provenance: the original composite command foreign key still rejects it.
	assertOperationRejected("identity.sso.oauth-callback", "23503", "")
	if !bytes.Equal(before, snapshot()) {
		t.Fatal("expansion changed the encrypted OIDC grant, relation, foreign keys, indexes or migration prefix")
	}
	history = append(history, expansion[1])
	if err := apply(); err != nil {
		t.Fatal("validate the expanded token-vault origin-operation check", err)
	}
	if err := apply(); err != nil {
		t.Fatal("replay the unchanged additive token-vault migration history", err)
	}
	assertConstraint(true)
	assertOperationRejected("identity.sso.unknown-callback", "23514", originConstraint)
	assertOperationRejected("identity.sso.oauth-callback", "23503", "")
	if !bytes.Equal(before, snapshot()) {
		t.Fatal("validation or replay changed existing grant custody or unrelated schema/history")
	}

	if _, err := f.pool.Raw().Exec(f.ctx, `ALTER TABLE sso_providers.provider_login_token_sets
 RENAME CONSTRAINT provider_login_token_sets_origin_operation_check TO unexpected_origin_operation_check`); err != nil {
		t.Fatal("prepare an unexpected predecessor in the isolated fixture", err)
	}
	unexpected, err := (ssopg.ProviderLoginTokenVaultProtocolMigrationSource{Version: 348, ValidationVersion: 349}).Load(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	history = append(history, unexpected...)
	if err := apply(); err == nil {
		t.Fatal("migration silently adopted an unexpected predecessor constraint")
	}
	var recorded int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM public.migrations WHERE version IN (348,349)`).Scan(&recorded); err != nil || recorded != 0 {
		t.Fatal("failed expansion recorded partial migration history", recorded, err)
	}
}
