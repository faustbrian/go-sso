//go:build integration

package postgres_test

import (
	"context"
	"testing"
	"time"

	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/jackc/pgx/v5"
)

func TestProviderLoginCallbackTerminalCustodyRollsBackAndCommitsWithoutExecutionProof(t *testing.T) {
	x := newProviderLoginStartFixture(t)
	state, command := startProviderLoginCallbackLookup(t, x)
	ctx, pool := x.enable.f.ctx, x.enable.f.pool.Raw()
	pending, err := ssopg.LookupProviderLoginCallbackForTest(ctx, x.service, state)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if n, err := ssopg.StageProviderLoginCallbackTerminalForTest(ctx, tx, x.service, state, pending.ObservedAt.Add(20*time.Second)); err != nil || n != 1 {
		t.Fatal("stage exact pending terminal custody", n, err)
	}
	var erased bool
	if err := tx.QueryRow(ctx, `SELECT completed_at IS NOT NULL AND completed_at>=issued_at AND completed_at<expires_at AND verifier_envelope IS NULL FROM sso_providers.login_transactions WHERE start_command_id=$1`, command).Scan(&erased); err != nil || !erased {
		t.Fatal("terminal update did not erase verifier at an exclusive live cutoff", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	restored, err := ssopg.LookupProviderLoginCallbackForTest(ctx, x.service, state)
	if err != nil || restored.CompletedAt != nil || !restored.HasPlan || !restored.HasProof {
		t.Fatal("rollback lost pending capability custody", err)
	}
	completed, err := ssopg.RecordProviderLoginCallbackTerminalForTest(ctx, x.service, state)
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := ssopg.LookupProviderLoginCallbackForTest(ctx, x.service, state)
	if err != nil || terminal.CompletedAt == nil || !terminal.CompletedAt.Equal(completed) || terminal.HasPlan || terminal.HasProof || terminal.CallbackCommandID != pending.CallbackCommandID || terminal.StartCommandID != command {
		t.Fatal("committed terminal custody lost original correlation or retained executable proof", err)
	}
	if _, err := ssopg.RecordProviderLoginCallbackTerminalForTest(ctx, x.service, state); err == nil {
		t.Fatal("terminal callback could be completed again")
	}
}

func TestProviderLoginCallbackTerminalCutoffIsCheckedAfterPendingRowWait(t *testing.T) {
	x := newProviderLoginStartFixture(t)
	state, command := startProviderLoginCallbackLookup(t, x)
	assertProviderLoginCallbackTerminalCutoffAfterWait(t, x, state, command, ssopg.StageProviderLoginCallbackTerminalForTest, ssopg.LookupProviderLoginCallbackForTest)
}

func TestProviderOAuth2LoginCallbackTerminalCutoffIsCheckedAfterPendingRowWait(t *testing.T) {
	x := newProviderOAuthLoginStartFixture(t)
	started, err := x.service.SigninStartOAuth2(x.enable.f.ctx, x.request, x.browser)
	if err != nil {
		t.Fatal("commit original OAuth2 browser start", err)
	}
	assertProviderLoginCallbackTerminalCutoffAfterWait(t, x.providerLoginStartFixture, started.RedirectURI.Query().Get("state"), started.TransactionID,
		ssopg.StageProviderOAuth2LoginCallbackTerminalForTest, ssopg.LookupProviderOAuth2LoginCallbackForTest)
}

func assertProviderLoginCallbackTerminalCutoffAfterWait(t *testing.T, x providerLoginStartFixture, state, command string,
	stage func(context.Context, pgx.Tx, *ssopg.ProviderLoginService, string, time.Time) (int64, error),
	lookup func(context.Context, *ssopg.ProviderLoginService, string) (ssopg.ProviderLoginCallbackLookupForTest, error)) {
	t.Helper()
	ctx, cancel := context.WithTimeout(x.enable.f.ctx, 5*time.Second)
	defer cancel()
	pool := x.enable.f.pool.Raw()
	writer, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = writer.Rollback(x.enable.f.ctx) }()
	if _, err := writer.Exec(ctx, `SELECT 1 FROM sso_providers.login_transactions WHERE start_command_id=$1 FOR UPDATE`, command); err != nil {
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
	defer func() { _ = callback.Rollback(x.enable.f.ctx) }()
	type result struct {
		n   int64
		err error
	}
	done := make(chan result, 1)
	go func() {
		n, err := stage(ctx, callback, x.service, state, deadline)
		done <- result{n, err}
	}()
	if err := waitForLoginFenceWait(ctx, pool.QueryRow, callback.Conn().PgConn().PID()); err != nil {
		cancel()
		<-done
		t.Fatal("terminal custody update did not wait for exact pending row", err)
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
	if got := <-done; got.err != nil || got.n != 0 {
		t.Fatal("row lock wait renewed expired callback completion authority", got.n, got.err)
	}
	if err := callback.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	pending, err := lookup(ctx, x.service, state)
	if err != nil || pending.CompletedAt != nil || !pending.HasPlan || !pending.HasProof {
		t.Fatal("expired terminal attempt changed pending custody", err)
	}
}
