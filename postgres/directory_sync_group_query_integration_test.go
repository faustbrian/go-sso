//go:build integration

package postgres_test

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-sso"
)

func TestNativeDirectorySyncGroupCursorUsesScopedIndex(t *testing.T) {
	x := newDirectoryGroupApplyFixture(t)
	f := x.provider.f
	generation := x.start(t)
	const historical = 20000
	_, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO sso_providers.directory_sync_generations
 (tenant_id,organization_id,provider_id,connection_id,generation,generation_id,provider_version,mapping_version,mode,state,checkpoint,initial_checkpoint)
 SELECT $1,$2,$3,CASE WHEN n<=18000 THEN $4 ELSE 'test-source-'||(n%100)::text END,n,
  rtrim(translate(encode(int8send(n)||int8send(n),'base64'),'+/','-_'),'='),1,1,'apply','finished',seed.checkpoint,seed.checkpoint
 FROM generate_series(2,$5) n CROSS JOIN (SELECT decode(repeat('ab',32),'hex') AS checkpoint) seed`,
		string(x.scope.TenantID), string(x.scope.OrganizationID), x.scope.ProviderID, x.scope.ConnectionID, historical+1)
	if err != nil {
		t.Fatal("populate representative unrelated directory history", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, "ANALYZE sso_providers.directory_sync_generations"); err != nil {
		t.Fatal(err)
	}
	trace := new(providerTrace)
	provider, err := tracedProviderService(t, f, x.provider.config, trace).ForOrganization(string(x.scope.OrganizationID))
	if err != nil {
		t.Fatal(err)
	}
	sync, err := provider.DirectorySync(x.scope.ConnectionID, directoryAdminPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	service := x.worker(t, sync)
	batch := x.batch(t, generation, sso.DirectoryMembershipAdd)
	start := time.Now()
	result, err := service.Apply(f.ctx, generation.ID, batch)
	elapsed := time.Since(start)
	if err != nil || result.Checkpoint == ([32]byte{}) {
		t.Fatal("apply against representative native directory history", err)
	}
	var replays []time.Duration
	for range 5 {
		start := time.Now()
		replay, err := service.Apply(f.ctx, generation.ID, batch)
		replays = append(replays, time.Since(start))
		if err != nil || replay.Checkpoint != result.Checkpoint {
			t.Fatal("exact scoped replay", err)
		}
	}
	sort.Slice(replays, func(i, j int) bool { return replays[i] < replays[j] })
	t.Logf("isolated PostgreSQL; historical generations=%d; initial apply=%s; 5 warm exact replays median=%s max=%s, no concurrent load", historical, elapsed, replays[2], replays[4])
	trace.mu.Lock()
	queries, traceErr := append([]providerQuery(nil), trace.queries...), trace.err
	trace.mu.Unlock()
	if traceErr != nil {
		t.Fatal(traceErr)
	}
	commitment, err := batch.Commitment()
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool, 3)
	for _, query := range queries {
		var mode string
		switch {
		case strings.Contains(query.sql, "SELECT true FROM sso_providers.directory_sync_generations"):
			mode = "pending lookup"
		case strings.HasPrefix(query.sql, "UPDATE sso_providers.directory_sync_generations") && strings.Contains(query.sql, "SET state='reconciling'"):
			mode = "hold predecessor"
		case strings.HasPrefix(query.sql, "UPDATE sso_providers.directory_sync_generations") && strings.Contains(query.sql, "SET state='running',checkpoint"):
			mode = "advance successor"
		}
		if mode != "" && !seen[mode] {
			seen[mode] = true
			proveDirectoryGroupCursorPlan(t, f, query, mode, string(generation.ID), generation.Checkpoint, commitment)
		}
	}
	if len(seen) != 3 {
		t.Fatal("trace missed the actual hold, pending or advance statement", seen)
	}
}

func proveDirectoryGroupCursorPlan(t *testing.T, f *orgFixture, query providerQuery, mode, generation string, predecessor, batch [32]byte) {
	t.Helper()
	tx, err := f.pool.Raw().Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := tx.Rollback(f.ctx); err != nil {
			t.Error("rollback query measurement", err)
		}
	}()
	state, pending := "reconciling", batch[:]
	if mode == "hold predecessor" {
		state, pending = "running", nil
	}
	tag, err := tx.Exec(f.ctx, `UPDATE sso_providers.directory_sync_generations
 SET state=$2,checkpoint=$3,pending_batch=$4 WHERE generation_id=$1`, generation, state, predecessor[:], pending)
	if err != nil || tag.RowsAffected() != 1 {
		t.Fatal("retarget only the measured generation in a rollback-only transaction", err)
	}
	const explain = "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) "
	var raw []byte
	if len(query.oids) != 0 {
		result := tx.Conn().PgConn().ExecParams(f.ctx, explain+query.sql, query.values, query.oids, query.formats, nil).Read()
		if result.Err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
			t.Fatal("explain actual binary Work bindings", mode, result.Err)
		}
		raw = result.Rows[0][0]
	} else if err := tx.QueryRow(f.ctx, explain+query.sql, query.args...).Scan(&raw); err != nil {
		t.Fatal("explain actual native bindings", mode, err)
	}
	var result []struct {
		Plan      directoryGenerationPlanNode `json:"Plan"`
		Execution float64                     `json:"Execution Time"`
	}
	if err := json.Unmarshal(raw, &result); err != nil || len(result) != 1 {
		t.Fatal("read cursor plan", mode, err)
	}
	var indexes []string
	if !result[0].Plan.collect(&indexes) || len(indexes) == 0 {
		t.Fatalf("%s must use a scoped index without table scans: %s", mode, raw)
	}
	t.Logf("%s: indexes=%v execution=%.3fms native-OIDs=%v", mode, indexes, result[0].Execution, query.oids)
}
