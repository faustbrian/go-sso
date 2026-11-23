//go:build integration

package postgres_test

import (
	"context"
	"testing"
	"time"

	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestNativeSAMLIDPPendingCompletionSamplesClockAfterRowLock(t *testing.T) {
	x := newNativeSAMLIDPAdmissionFixture(t)
	f := x.enable.f
	installSAMLIDPStorage(t, f, ssopg.SAMLIDPConfirmationMigrationSource{Version: 394})
	const prepare = "identity.sso.saml-idp-prepare"
	const complete = "identity.sso.saml-idp-init"
	tenant, org, provider := string(x.enable.proof.TenantID), string(x.profile.OrganizationID), string(x.profile.ProviderID)
	arrival := samlIDPMigrationCommandBytes(t, f, x.enable.proof.TenantID, prepare)
	completion := samlIDPMigrationCommandBytes(t, f, x.enable.proof.TenantID, complete)
	// Acquire the two fixture connections before selecting an intentionally
	// short deadline. Make the contention causal using PostgreSQL lock state.
	lock, err := f.pool.Raw().Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Rollback(f.ctx) }()
	second, err := f.pool.Raw().Acquire(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Release()
	var dbNow time.Time
	if err := lock.QueryRow(f.ctx, `SELECT clock_timestamp()`).Scan(&dbNow); err != nil {
		t.Fatal(err)
	}
	issued, expires := dbNow.Add(-time.Second), dbNow.Add(1500*time.Millisecond)
	sealed, browser, form := []byte{4}, [32]byte{1}, [32]byte{2}
	args := []any{tenant, arrival, org, provider, "owner", sealed, int64(1), browser[:], form[:], issued, expires, completion}
	if tag, err := lock.Exec(f.ctx, ssopg.SAMLIDPInsertPendingForTest, args[:11]...); err != nil || tag.RowsAffected() != 1 {
		t.Fatal("insert original pending custody", err)
	}
	if err := lock.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	hold, err := f.pool.Raw().Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hold.Rollback(f.ctx) }()
	var pending bool
	if err := hold.QueryRow(f.ctx, `SELECT completed_at IS NULL FROM sso_providers.saml_idp_confirmations WHERE tenant_id=$1 AND confirmation_id=$2 FOR UPDATE`, tenant, arrival).
		Scan(&pending); err != nil || !pending {
		t.Fatal("lock the still-pending original row", err)
	}
	ctx, cancel := context.WithTimeout(f.ctx, 5*time.Second)
	defer cancel()
	type execution struct {
		rows int64
		err  error
	}
	result := make(chan execution, 1)
	waiter, blocker := int32(second.Conn().PgConn().PID()), int32(hold.Conn().PgConn().PID())
	go func() {
		tag, err := second.Exec(ctx, ssopg.SAMLIDPCompletePendingForTest, args...)
		result <- execution{tag.RowsAffected(), err}
	}()
	defer func() {
		if result != nil {
			cancel()
			<-result
		}
	}()
	for {
		var waiting, stillFresh bool
		if err := hold.QueryRow(ctx, `SELECT $1::int=ANY(pg_blocking_pids($2)), clock_timestamp()<$3::timestamptz`, blocker, waiter, expires).
			Scan(&waiting, &stillFresh); err != nil || !stillFresh {
			t.Fatal("completion was not observed waiting on the original row before expiry", err)
		}
		if waiting {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("completion did not wait on the original row", ctx.Err())
		case <-time.After(5 * time.Millisecond):
		}
	}
	if _, err := hold.Exec(ctx, `SELECT pg_sleep(greatest(0,extract(epoch FROM ($1::timestamptz-clock_timestamp())))+0.01)`, expires); err != nil {
		t.Fatal("retain the exact lock until database expiry", err)
	}
	if err := hold.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	out := <-result
	result = nil
	if out.err != nil || out.rows != 0 {
		t.Fatal("completion used stale pre-lock time", out.rows, out.err)
	}
	if err := second.QueryRow(ctx, `SELECT completed_at IS NULL AND binding_envelope=$3 AND browser_digest=$4 AND form_digest=$5
FROM sso_providers.saml_idp_confirmations WHERE tenant_id=$1 AND confirmation_id=$2`, tenant, arrival, sealed, browser[:], form[:]).Scan(&pending); err != nil || !pending {
		t.Fatal("expired attempt altered original pending custody", err)
	}
}
