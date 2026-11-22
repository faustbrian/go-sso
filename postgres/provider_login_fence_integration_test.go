//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/jackc/pgx/v5"
)

func TestNativeProviderLoginFenceObservesExactCurrentDomain(t *testing.T) {
	x := newProviderEnableFixture(t)
	provider := enableRouteFixture(t, x, false)
	router := newProviderRouter(t, x, 2)
	request, err := sso.NewDomainRouteRequest(x.proof.TenantID, x.proof.Domain, provider)
	if err != nil {
		t.Fatal(err)
	}
	route, err := router.Route(x.f.ctx, request)
	if err != nil {
		t.Fatal("resolve before observation", err)
	}
	authority, err := ssopg.ObserveProviderLoginAuthorityForTest(x.f.ctx, router, route)
	if err != nil || authority.TenantID != x.proof.TenantID || authority.OrganizationID != x.proof.OrganizationID || authority.Version == 0 || authority.Actor.UserID != "" {
		t.Fatal("login observation did not bind the active organization without assuming a member", err)
	}
	revokeEnableTestProof(t, x)
	if after, err := ssopg.ObserveProviderLoginAuthorityForTest(x.f.ctx, router, route); !errors.Is(err, sso.ErrForbidden) || after.Version != 0 {
		t.Fatal("retained route obtained an organization snapshot after its proof was revoked", err)
	}
}

func TestNativeProviderLoginFencePersistsOnlyBeforeOriginalDeadline(t *testing.T) {
	x := newProviderEnableFixture(t)
	provider := enableRouteFixture(t, x, false)
	installLoginTransactionMigration(t, x.f)
	ctx, pool := x.f.ctx, x.f.pool.Raw()
	tenant, org, id := string(x.proof.TenantID), string(x.proof.OrganizationID), string(provider)
	var now time.Time
	if err := pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal("read original database time", err)
	}
	stateDigest := make([]byte, 32)
	stateDigest[0] = 0x71
	commitment := make([]byte, 32)
	commitment[0] = 0x72
	args := []any{tenant, org, id, "3", "1", "1", string(commandID(t)), string(commandID(t)), int64(1), stateDigest, int64(1), commitment, []byte{0x43}, []byte{0x42}, now, now.Add(time.Minute), now}
	if tag, err := pool.Exec(ctx, ssopg.ProviderLoginInsertForTest, args...); err != nil || tag.RowsAffected() != 0 {
		t.Fatal("expired original deadline did not deny persistence", err)
	}
	args[16] = now.Add(20 * time.Second)
	if tag, err := pool.Exec(ctx, ssopg.ProviderLoginInsertForTest, args...); err != nil || tag.RowsAffected() != 1 {
		t.Fatal("fresh transaction was not persisted", err)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM sso_providers.login_transactions WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND state_digest=$4 AND pkce_commitment=$5`, tenant, org, id, stateDigest, commitment).Scan(&count); err != nil || count != 1 {
		t.Fatal("no exact persisted transaction custody", count, err)
	}
}

func TestNativeProviderLoginFenceDoesNotAdmitAcrossDisable(t *testing.T) {
	x := newProviderEnableFixture(t)
	provider := enableRouteFixture(t, x, false)
	ctx, cancel := context.WithTimeout(x.f.ctx, 4*time.Second)
	defer cancel()
	pool := x.f.pool.Raw()
	scope := []any{string(x.proof.TenantID), string(x.proof.OrganizationID), string(provider)}
	var generation, mapping string
	var databaseNow time.Time
	if err := pool.QueryRow(ctx, `SELECT enablement_credential_generation::text,metadata_mapping_version::text,clock_timestamp() FROM sso_providers.providers WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`, scope...).Scan(&generation, &mapping, &databaseNow); err != nil {
		t.Fatal("read enabled predecessor", err)
	}
	args := append(append([]any(nil), scope...), "3", generation, mapping, databaseNow.Add(15*time.Second))
	var admitted bool
	if err := pool.QueryRow(ctx, ssopg.ProviderLoginAdmissionFenceForTest, args...).Scan(&admitted); err != nil || !admitted {
		t.Fatal("current predecessor did not admit", err)
	}
	for _, invalid := range []struct {
		name  string
		index int
		value any
	}{
		{"foreign tenant", 0, "other-tenant"},
		{"foreign organization", 1, "other-organization"},
		{"stale provider version", 3, "2"},
		{"wrong credential generation", 4, differentLoginVersion(t, generation)},
		{"wrong mapping", 5, differentLoginVersion(t, mapping)},
		{"expired route", 6, databaseNow},
	} {
		t.Run(invalid.name, func(t *testing.T) {
			params := append([]any(nil), args...)
			params[invalid.index] = invalid.value
			if err := pool.QueryRow(ctx, ssopg.ProviderLoginAdmissionFenceForTest, params...).Scan(&admitted); !errors.Is(err, pgx.ErrNoRows) {
				t.Fatal("invalid route admitted or query did not complete", err)
			}
		})
	}

	// Use the actual provider row transition; this verifies the database fence
	// and does not claim that the public administrative operation is wired.
	disable, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = disable.Rollback(ctx) }()
	tag, err := disable.Exec(ctx, `UPDATE sso_providers.providers SET enabled=false,enablement_proof=NULL,enablement_credential_generation=NULL WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`, scope...)
	if err != nil || tag.RowsAffected() != 1 {
		t.Fatal("stage provider disablement", err)
	}
	start, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = start.Rollback(ctx) }()
	pid := start.Conn().PgConn().PID()
	done := make(chan error, 1)
	go func() {
		var accepted bool
		done <- start.QueryRow(ctx, ssopg.ProviderLoginAdmissionFenceForTest, args...).Scan(&accepted)
	}()
	if err := waitForLoginFenceWait(ctx, pool.QueryRow, pid); err != nil {
		cancel()
		<-done
		t.Fatal("login did not wait for the provider mutation", err)
	}
	if err := disable.Commit(ctx); err != nil {
		cancel()
		<-done
		t.Fatal("commit provider disablement", err)
	}
	if err := <-done; !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("waiting login did not recheck committed disablement", err)
	}
}

func differentLoginVersion(t *testing.T, text string) string {
	t.Helper()
	version, err := strconv.ParseUint(text, 10, 64)
	if err != nil || version == 0 {
		t.Fatal("invalid fixture version", err)
	}
	return strconv.FormatUint(version+1, 10)
}

func waitForLoginFenceWait(ctx context.Context, query func(context.Context, string, ...any) pgx.Row, waiting uint32) error {
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		var blocked bool
		if err := query(ctx, `SELECT cardinality(pg_blocking_pids($1::integer))>0`, int32(waiting)).Scan(&blocked); err != nil {
			return err
		}
		if blocked {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}
