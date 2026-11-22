//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/jackc/pgx/v5"
)

func TestProviderLoginCallbackDispositionAllowsOnlyExactEnabledOrDrainPredecessor(t *testing.T) {
	for _, mode := range []sso.ActiveTransactionDispositionMode{sso.ActiveTransactionDrain, sso.ActiveTransactionRevoke} {
		t.Run(string(mode), func(t *testing.T) {
			x := newProviderLoginStartFixture(t)
			state, _ := startProviderLoginCallbackLookup(t, x)
			ctx, pool := x.enable.f.ctx, x.enable.f.pool.Raw()
			var now time.Time
			if err := pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
				t.Fatal(err)
			}
			observe := func(tx pgx.Tx) error {
				return ssopg.ObserveProviderLoginCallbackDispositionForTest(ctx, tx, x.service, state, now.Add(15*time.Second))
			}
			current, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := observe(current); err != nil {
				t.Fatal("unchanged enabled original was denied", err)
			}
			if err := current.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			out, err := nativeProviderDisableService(t, x, providerDisablePolicy{}).ProviderDisable(ctx, nativeProviderDisableRequest(t, x, mode))
			if err != nil || out.Completion.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("commit genuine native disable", err)
			}
			disabled, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			err = observe(disabled)
			if mode == sso.ActiveTransactionDrain && err != nil {
				t.Fatal("exact recorded native drain predecessor was denied", err)
			}
			if mode == sso.ActiveTransactionRevoke && !errors.Is(err, pgx.ErrNoRows) {
				t.Fatal("revoked predecessor was admitted", err)
			}
			if err := disabled.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			if mode != sso.ActiveTransactionDrain {
				return
			}

			for _, tc := range []struct{ name, sql string }{
				{"missing disposition", `DELETE FROM sso_providers.provider_login_dispositions`},
				{"wrong predecessor", `UPDATE sso_providers.provider_login_dispositions SET provider_version=2`},
				{"wrong native effect", `UPDATE sso_providers.provider_login_dispositions SET command_id=(SELECT command_id FROM sso_providers.command_effects WHERE command_id<>sso_providers.provider_login_dispositions.command_id ORDER BY command_id LIMIT 1)`},
				{"wrong native operation", `UPDATE sso_providers.command_effects SET binding=convert_to((convert_from(binding,'UTF8')::jsonb || '{"OperationID":"identity.sso.provider.enable"}'::jsonb)::text,'UTF8') WHERE command_id=(SELECT command_id FROM sso_providers.provider_login_dispositions)`},
				{"later disabled generation", `UPDATE sso_providers.providers SET metadata_version=5`},
				{"reenabled generation", `UPDATE sso_providers.providers SET enabled=true,metadata_version=5,enablement_proof=$1,enablement_credential_generation=1`},
				{"mapping drift", `UPDATE sso_providers.providers SET metadata_mapping_version=2`},
				{"credential drift", `UPDATE sso_providers.credentials SET generation=2`},
			} {
				t.Run(tc.name, func(t *testing.T) {
					tx, err := pool.Begin(ctx)
					if err != nil {
						t.Fatal(err)
					}
					defer func() { _ = tx.Rollback(ctx) }()
					var args []any
					if tc.name == "reenabled generation" {
						args = []any{[]byte{0x42}}
					}
					if _, err := tx.Exec(ctx, tc.sql, args...); err != nil {
						t.Fatal("stage isolated drift", err)
					}
					if err := observe(tx); err == nil {
						t.Fatal("changed or missing predecessor evidence was admitted")
					}
				})
			}
		})
	}
}

func TestProviderLoginCallbackDispositionRechecksDeadlineAfterProviderWait(t *testing.T) {
	x := newProviderLoginStartFixture(t)
	state, _ := startProviderLoginCallbackLookup(t, x)
	ctx, cancel := context.WithTimeout(x.enable.f.ctx, 5*time.Second)
	defer cancel()
	pool := x.enable.f.pool.Raw()
	writer, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = writer.Rollback(ctx) }()
	if _, err := writer.Exec(ctx, `UPDATE sso_providers.providers SET metadata_version=metadata_version WHERE provider_id=$1`, x.request.ProviderID); err != nil {
		t.Fatal(err)
	}
	var now time.Time
	if err := pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	deadline := now.Add(250 * time.Millisecond)
	callback, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = callback.Rollback(ctx) }()
	done := make(chan error, 1)
	go func() {
		done <- ssopg.ObserveProviderLoginCallbackDispositionForTest(ctx, callback, x.service, state, deadline)
	}()
	if err := waitForLoginFenceWait(ctx, pool.QueryRow, callback.Conn().PgConn().PID()); err != nil {
		cancel()
		<-done
		t.Fatal("callback did not wait for provider writer", err)
	}
	if _, err := writer.Exec(ctx, `SELECT pg_sleep(GREATEST(0,EXTRACT(EPOCH FROM ($1::timestamptz-clock_timestamp())))+0.02)`, deadline); err != nil {
		cancel()
		<-done
		t.Fatal(err)
	}
	if err := writer.Commit(ctx); err != nil {
		cancel()
		<-done
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("callback renewed its original deadline while blocked", err)
	}
}

func TestProviderLoginCallbackDispositionSeesNativeDrainCommittedDuringProviderWait(t *testing.T) {
	x := newProviderLoginStartFixture(t)
	state, _ := startProviderLoginCallbackLookup(t, x)
	ctx, cancel := context.WithTimeout(x.enable.f.ctx, 5*time.Second)
	defer cancel()
	pool := x.enable.f.pool.Raw()
	blocker, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blocker.Rollback(x.enable.f.ctx) }()
	if _, err := blocker.Exec(ctx, `SELECT pg_advisory_xact_lock(726001)`); err != nil {
		t.Fatal(err)
	}
	// Pause the genuine native command after its provider write, before its
	// disposition becomes visible, so the callback starts on the old snapshot.
	if _, err := pool.Exec(ctx, `CREATE FUNCTION sso_providers.hold_callback_test_drain() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(726001); RETURN NEW; END $$;
 CREATE TRIGGER hold_callback_test_drain BEFORE INSERT ON sso_providers.provider_login_dispositions
 FOR EACH ROW EXECUTE FUNCTION sso_providers.hold_callback_test_drain()`); err != nil {
		t.Fatal(err)
	}
	service := nativeProviderDisableService(t, x, providerDisablePolicy{})
	request := nativeProviderDisableRequest(t, x, sso.ActiveTransactionDrain)
	nativeDone := make(chan error, 1)
	go func() {
		out, err := service.ProviderDisable(ctx, request)
		if err == nil && out.Completion.Outcome != identity.CommitOutcomeCommitted {
			err = errors.New("native disable did not commit")
		}
		nativeDone <- err
	}()
	var callbackDone chan error
	var callback pgx.Tx
	defer func() {
		cancel()
		_ = blocker.Rollback(x.enable.f.ctx)
		if nativeDone != nil {
			<-nativeDone
		}
		if callbackDone != nil {
			<-callbackDone
		}
		if callback != nil {
			_ = callback.Rollback(x.enable.f.ctx)
		}
	}()
	if err := waitForProviderLoginCallbackDrainWriter(ctx, pool.QueryRow); err != nil {
		t.Fatal("native disable did not pause before recording its disposition", err)
	}
	var now time.Time
	if err := pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	callback, err = pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pid := callback.Conn().PgConn().PID()
	callbackDone = make(chan error, 1)
	go func() {
		callbackDone <- ssopg.ObserveProviderLoginCallbackDispositionForTest(ctx, callback, x.service, state, now.Add(15*time.Second))
	}()
	if err := waitForLoginFenceWait(ctx, pool.QueryRow, pid); err != nil {
		t.Fatal("callback did not wait behind the genuine provider disable", err)
	}
	if err := blocker.Commit(ctx); err != nil {
		t.Fatal("release native drain writer", err)
	}
	err = <-nativeDone
	nativeDone = nil
	if err != nil {
		t.Fatal("commit genuine native disable during callback lock wait", err)
	}
	err = <-callbackDone
	callbackDone = nil
	if err != nil {
		t.Fatal("callback failed to observe the native drain after acquiring its provider lock", err)
	}
}

func waitForProviderLoginCallbackDrainWriter(ctx context.Context, query func(context.Context, string, ...any) pgx.Row) error {
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		var waiting bool
		if err := query(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory'
 AND objid=726001 AND NOT granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database()))`).Scan(&waiting); err != nil {
			return err
		}
		if waiting {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}
