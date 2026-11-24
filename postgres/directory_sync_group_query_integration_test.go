//go:build integration

package postgres_test

import (
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/jackc/pgx/v5"
)

func TestNativeDirectorySyncGroupCursorUsesScopedIndex(t *testing.T) {
	multi := newDirectoryMultiEdgeFixture(t)
	x := multi.fixture
	f := x.provider.f
	const historical = 20000
	populateDirectoryGroupQueryHistory(t, x, historical)
	generation, batch := multi.generation, multi.batch
	trace := new(providerTrace)
	provider, err := tracedProviderService(t, f, x.provider.config, trace).ForOrganization(string(x.scope.OrganizationID))
	if err != nil {
		t.Fatal(err)
	}
	sync, err := provider.DirectorySync(x.scope.ConnectionID, directoryAdminPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	service, err := sync.WithGroupEdges(multi.config)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	result, err := service.Apply(f.ctx, generation.ID, batch)
	elapsed := time.Since(start)
	if err != nil || result.Checkpoint == ([32]byte{}) || len(result.ChildOutcomes) != 2 {
		t.Fatal("apply against representative native directory history", err)
	}
	assertDirectoryMultiEdgeEffects(t, x, []string{x.groupID, multi.secondGroupID})
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
	beforeCancel, err := sync.Status(f.ctx, generation.ID)
	if err != nil {
		t.Fatal("read the exact cancellation predecessor", err)
	}
	cancelRequest := ssopg.DirectorySyncCancelRequest{
		GenerationID: generation.ID, ExpectedVersion: beforeCancel.Version,
		Key: directoryGenerationKey(t, "directory-cancel-query-scale"),
	}
	start = time.Now()
	canceled, err := sync.Cancel(f.ctx, cancelRequest)
	cancelElapsed := time.Since(start)
	if err != nil || canceled.Completion.Outcome != identity.CommitOutcomeCommitted || canceled.Generation.State != ssopg.DirectorySyncCanceled {
		t.Fatal("cancel against representative native directory history", err)
	}
	var cancelReplays []time.Duration
	for range 5 {
		start = time.Now()
		replay, err := sync.Cancel(f.ctx, cancelRequest)
		cancelReplays = append(cancelReplays, time.Since(start))
		if err != nil || !reflect.DeepEqual(replay, canceled) {
			t.Fatal("exact scoped cancellation replay", err)
		}
	}
	sort.Slice(cancelReplays, func(i, j int) bool { return cancelReplays[i] < cancelReplays[j] })
	var server string
	if err := f.pool.Raw().QueryRow(f.ctx, "SHOW server_version").Scan(&server); err != nil {
		t.Fatal(err)
	}
	t.Logf("isolated PostgreSQL %s; historical generations=%d (17999 on the selected source); cancel=%s; 5 warm exact cancel replays median=%s max=%s; no concurrent load",
		server, historical, cancelElapsed, cancelReplays[2], cancelReplays[4])
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
	seen := make(map[string]bool, 5)
	for _, query := range queries {
		var mode string
		switch {
		case strings.Contains(query.sql, "SELECT true FROM sso_providers.directory_sync_generations") && strings.HasSuffix(query.sql, "state='reconciling' FOR UPDATE"):
			mode = "continue original batch"
		case strings.Contains(query.sql, "SELECT true FROM sso_providers.directory_sync_generations"):
			mode = "pending lookup"
		case strings.HasPrefix(query.sql, "UPDATE sso_providers.directory_sync_generations") && strings.Contains(query.sql, "SET state='reconciling'"):
			mode = "hold predecessor"
		case strings.HasPrefix(query.sql, "UPDATE sso_providers.directory_sync_generations") && strings.Contains(query.sql, "SET state=CASE state WHEN 'canceling' THEN 'canceled' ELSE 'running' END,checkpoint="):
			mode = "advance successor"
		case strings.HasPrefix(query.sql, "UPDATE sso_providers.directory_sync_generations") && strings.Contains(query.sql, "SET state=CASE state WHEN 'running' THEN 'canceled' ELSE 'canceling' END,version="):
			mode = "cancel generation"
		}
		if mode != "" && !seen[mode] {
			seen[mode] = true
			if mode == "cancel generation" {
				proveDirectoryCancelPlan(t, f, query, beforeCancel, commitment)
				continue
			}
			if mode == "continue original batch" {
				proveDirectoryContinuePlan(t, f, query, string(generation.ID), generation.Checkpoint, commitment)
				continue
			}
			proveDirectoryGroupCursorPlan(t, f, query, mode, string(generation.ID), generation.Checkpoint, commitment)
			if mode == "pending lookup" || mode == "advance successor" {
				proveDirectoryGroupCursorPlan(t, f, query, mode+" while canceling", string(generation.ID), generation.Checkpoint, commitment)
			}
			if mode == "advance successor" {
				proveDirectoryGroupCursorPlan(t, f, query, mode+" stale scope", string(generation.ID), generation.Checkpoint, commitment)
				proveDirectoryGroupCursorPlan(t, f, query, "advance rejected from running", string(generation.ID), generation.Checkpoint, commitment)
				proveDirectoryGroupCursorPlan(t, f, query, "advance rejected after stop", string(generation.ID), generation.Checkpoint, commitment)
			}
		}
	}
	if len(seen) != 5 {
		t.Fatal("trace missed the actual hold, pending, continuation, advance or cancel statement", seen)
	}
	if status, err := sync.Status(f.ctx, generation.ID); err != nil || status != canceled.Generation {
		t.Fatal("rollback-only query measurements changed the public canceled generation", err)
	}
}

func TestNativeDirectorySyncStoppedGroupBatchUsesScopedIndex(t *testing.T) {
	multi := newDirectoryMultiEdgeFixture(t)
	x := multi.fixture
	f := x.provider.f
	const historical = 20000
	populateDirectoryGroupQueryHistory(t, x, historical)
	held, original := multi.holdFirstChild(t)
	trace := new(providerTrace)
	provider, err := tracedProviderService(t, f, x.provider.config, trace).ForOrganization(string(x.scope.OrganizationID))
	if err != nil {
		t.Fatal(err)
	}
	sync, err := provider.DirectorySync(x.scope.ConnectionID, directoryAdminPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	worker, err := sync.WithGroupEdges(multi.config)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = sync.Cancel(f.ctx, ssopg.DirectorySyncCancelRequest{
		GenerationID: held.ID, ExpectedVersion: held.Version,
		Key: directoryGenerationKey(t, "directory-stop-query-scale"),
	})
	if err != nil && !errors.Is(err, sso.ErrDirectoryReconciliation) {
		t.Fatal("cancel the actually committed original prefix", err)
	}
	cancelElapsed := time.Since(start)
	var resumes []time.Duration
	var stopped ssopg.DirectorySyncGeneration
	for attempt := range 5 {
		start = time.Now()
		prefix, err := worker.Apply(f.ctx, held.ID, multi.batch)
		resumes = append(resumes, time.Since(start))
		if !errors.Is(err, sso.ErrDirectoryReconciliation) || prefix.Checkpoint != ([32]byte{}) ||
			len(prefix.ChildOutcomes) != 1 || !reflect.DeepEqual(prefix.ChildOutcomes[0], original) {
			t.Fatal("canceled resume must retain only the original committed prefix", attempt, err)
		}
		status, err := sync.Status(f.ctx, held.ID)
		if err != nil || status.State != ssopg.DirectorySyncCanceled || status.Checkpoint != held.Checkpoint ||
			status.ReadCount != 0 || status.AppliedCount != 0 || status.RejectedCount != 0 {
			t.Fatal("canceled resume settled an incomplete batch or moved its predecessor", attempt, err)
		}
		if attempt == 0 {
			stopped = status
		} else if status != stopped {
			t.Fatal("exact canceled resume changed the settled generation", attempt)
		}
		multi.assertOnlyOriginalPrefixEffects(t, original)
	}
	sort.Slice(resumes, func(i, j int) bool { return resumes[i] < resumes[j] })
	t.Logf("isolated PostgreSQL; historical generations=%d; lost-first-ack cancellation=%s; 5 exact canceled resumes median=%s max=%s; no concurrent load", historical, cancelElapsed, resumes[2], resumes[4])
	trace.mu.Lock()
	queries, traceErr := append([]providerQuery(nil), trace.queries...), trace.err
	trace.mu.Unlock()
	if traceErr != nil {
		t.Fatal(traceErr)
	}
	commitment, err := multi.batch.Commitment()
	if err != nil {
		t.Fatal(err)
	}
	seen := false
	for _, query := range queries {
		if strings.HasPrefix(query.sql, "UPDATE sso_providers.directory_sync_generations") && strings.Contains(query.sql, "SET state='canceled',pending_batch=NULL,version=version+1") {
			proveDirectoryStopPlan(t, f, query, string(held.ID), held.Checkpoint, commitment)
			seen = true
			break
		}
	}
	if !seen {
		t.Fatal("trace missed actual canceled-prefix settlement")
	}
	if status, err := sync.Status(f.ctx, held.ID); err != nil || status != stopped {
		t.Fatal("rollback-only stop measurements changed the canceled generation", err)
	}
}

func populateDirectoryGroupQueryHistory(t *testing.T, x directoryGroupApplyFixture, historical int) {
	t.Helper()
	f := x.provider.f
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
}

func proveDirectoryGroupCursorPlan(t *testing.T, f *orgFixture, query providerQuery, mode, generation string, predecessor, batch [32]byte) {
	t.Helper()
	for range 3 {
		proveDirectoryGroupCursorSample(t, f, query, mode, generation, predecessor, batch)
	}
}

func proveDirectoryGroupCursorSample(t *testing.T, f *orgFixture, query providerQuery, mode, generation string, predecessor, batch [32]byte) {
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
	rejectedBatch := strings.HasPrefix(mode, "advance rejected")
	if mode == "hold predecessor" {
		state, pending = "running", nil
	} else if rejectedBatch {
		state, pending = "running", nil
		if len(query.args) != 15 {
			t.Fatal("rejection cases require the captured argument types")
		}
		// Keep the captured native parameter shapes and vary only the
		// receipt counts to exercise the all-rejected predicate.
		query.args = append(append([]any(nil), query.args[:12]...), "2", "0", "2")
		if mode == "advance rejected after stop" {
			state = "canceled"
		}
	} else if strings.HasSuffix(mode, " while canceling") {
		state = "canceling"
	}
	tag, err := tx.Exec(f.ctx, `UPDATE sso_providers.directory_sync_generations
 SET state=$2,checkpoint=$3,pending_batch=$4,read_count=0,applied_count=0,rejected_count=0,
 connection_id=CASE WHEN $5 THEN connection_id||'-stale' ELSE connection_id END
 WHERE generation_id=$1`, generation, state, predecessor[:], pending, strings.HasSuffix(mode, " stale scope"))
	if err != nil || tag.RowsAffected() != 1 {
		t.Fatal("retarget only the measured generation in a rollback-only transaction", err)
	}
	rows := explainDirectoryCursorPlan(t, f, tx, query, mode)
	if strings.HasPrefix(mode, "pending lookup") && rows != 1 {
		t.Fatal("captured pending lookup did not find its exact held batch", mode, rows)
	}
	if strings.HasPrefix(mode, "advance ") {
		wantCounts := []any{"2", "2", "0"}
		if rejectedBatch {
			wantCounts = []any{"2", "0", "2"}
		}
		if len(query.args) != 15 || !reflect.DeepEqual(query.args[12:], wantCounts) {
			t.Fatal("advance measurement requires the actual two-child read/applied/rejected count bindings")
		}
		wantState := "running"
		wantRead, wantApplied, wantRejected := "2", "2", "0"
		wantCleared := true
		if rejectedBatch {
			wantApplied, wantRejected = "0", "2"
		}
		if state == "canceling" {
			wantState = "canceled"
		}
		if strings.HasSuffix(mode, " stale scope") {
			wantState, wantRead, wantApplied, wantCleared = state, "0", "0", false
		}
		if mode == "advance rejected after stop" {
			wantState, wantRead, wantRejected = "canceled", "0", "0"
		}
		var actualState, read, applied, rejected string
		var cleared bool
		var checkpoint []byte
		err := tx.QueryRow(f.ctx, `SELECT state,pending_batch IS NULL,read_count::text,applied_count::text,rejected_count::text,checkpoint
 FROM sso_providers.directory_sync_generations WHERE generation_id=$1`, generation).Scan(&actualState, &cleared, &read, &applied, &rejected, &checkpoint)
		wantCheckpoint := query.args[10]
		if !wantCleared || mode == "advance rejected after stop" {
			wantCheckpoint = predecessor[:]
		}
		if err != nil || actualState != wantState || cleared != wantCleared || read != wantRead || applied != wantApplied || rejected != wantRejected ||
			!reflect.DeepEqual(checkpoint, wantCheckpoint) {
			t.Fatal("captured advance did not preserve exact two-child counts and successor or scoped no-match", mode, err)
		}
	}
}

func proveDirectoryContinuePlan(t *testing.T, f *orgFixture, query providerQuery, generation string, predecessor, batch [32]byte) {
	t.Helper()
	if len(query.oids) != 10 || len(query.values) != 10 {
		t.Fatal("continuation measurement requires the actual ten driver-typed Work bindings")
	}
	for _, partition := range []string{"reconciling hit", "canceling miss", "stale scope miss"} {
		for range 3 {
			tx, err := f.pool.Raw().Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			func() {
				defer func() {
					if err := tx.Rollback(f.ctx); err != nil {
						t.Error("rollback continuation measurement", err)
					}
				}()
				state, wantRows := "reconciling", float64(1)
				if partition == "canceling miss" {
					state, wantRows = "canceling", 0
				} else if partition == "stale scope miss" {
					wantRows = 0
				}
				tag, err := tx.Exec(f.ctx, `UPDATE sso_providers.directory_sync_generations
 SET state=$2,checkpoint=$3,pending_batch=$4,
 connection_id=CASE WHEN $5 THEN connection_id||'-stale' ELSE connection_id END
 WHERE generation_id=$1`, generation, state, predecessor[:], batch[:], partition == "stale scope miss")
				if err != nil || tag.RowsAffected() != 1 {
					t.Fatal("restore only the measured continuation predecessor", err)
				}
				if rows := explainDirectoryCursorPlan(t, f, tx, query, "continue "+partition); rows != wantRows {
					t.Fatal("captured continuation did not lock only its exact reconciling batch", partition, rows)
				}
			}()
		}
	}
}

func proveDirectoryStopPlan(t *testing.T, f *orgFixture, query providerQuery, generation string, predecessor, batch [32]byte) {
	t.Helper()
	if len(query.args) != 11 {
		t.Fatal("stop measurement requires the actual eleven native bindings")
	}
	for _, partition := range []string{"canceling hit", "reconciling miss", "stale scope miss"} {
		for range 3 {
			tx, err := f.pool.Raw().Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			func() {
				defer func() {
					if err := tx.Rollback(f.ctx); err != nil {
						t.Error("rollback stopped-batch measurement", err)
					}
				}()
				state, wantState, wantVersion, wantCleared := "canceling", "canceled", "2", true
				if partition == "reconciling miss" {
					state, wantState, wantVersion, wantCleared = "reconciling", "reconciling", "1", false
				} else if partition == "stale scope miss" {
					wantState, wantVersion, wantCleared = state, "1", false
				}
				tag, err := tx.Exec(f.ctx, `UPDATE sso_providers.directory_sync_generations
 SET state=$2,checkpoint=$3,pending_batch=$4,version=1,read_count=0,applied_count=0,rejected_count=0,
 connection_id=CASE WHEN $5 THEN connection_id||'-stale' ELSE connection_id END
 WHERE generation_id=$1`, generation, state, predecessor[:], batch[:], partition == "stale scope miss")
				if err != nil || tag.RowsAffected() != 1 {
					t.Fatal("restore only the measured stopped predecessor", err)
				}
				explainDirectoryCursorPlan(t, f, tx, query, "stop "+partition)
				var actualState, version, read, applied, rejected string
				var cleared bool
				var checkpoint []byte
				err = tx.QueryRow(f.ctx, `SELECT state,version::text,pending_batch IS NULL,checkpoint,
 read_count::text,applied_count::text,rejected_count::text
 FROM sso_providers.directory_sync_generations WHERE generation_id=$1`, generation).
					Scan(&actualState, &version, &cleared, &checkpoint, &read, &applied, &rejected)
				if err != nil || actualState != wantState || version != wantVersion || cleared != wantCleared ||
					!reflect.DeepEqual(checkpoint, predecessor[:]) || read != "0" || applied != "0" || rejected != "0" {
					t.Fatal("captured stop changed the predecessor or settled incomplete counts", partition, err)
				}
			}()
		}
	}
}

func proveDirectoryCancelPlan(t *testing.T, f *orgFixture, query providerQuery, predecessor ssopg.DirectorySyncGeneration, batch [32]byte) {
	t.Helper()
	if len(query.oids) != 5 || len(query.values) != 5 {
		t.Fatal("cancellation measurement requires the actual five driver-typed Work bindings")
	}
	for _, partition := range []string{"running hit", "reconciling hit", "stale version miss"} {
		for sample := range 3 {
			tx, err := f.pool.Raw().Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			func() {
				defer func() {
					if err := tx.Rollback(f.ctx); err != nil {
						t.Error("rollback cancellation measurement", err)
					}
				}()
				state, version := "running", predecessor.Version
				var pending []byte
				wantState, wantVersion := "canceled", version+1
				switch partition {
				case "reconciling hit":
					state, pending, wantState = "reconciling", batch[:], "canceling"
				case "stale version miss":
					version++
					wantState, wantVersion = state, version
				}
				tag, err := tx.Exec(f.ctx, `UPDATE sso_providers.directory_sync_generations
 SET state=$2,version=$3::numeric,pending_batch=$4 WHERE generation_id=$1`,
					string(predecessor.ID), state, strconv.FormatUint(version, 10), pending)
				if err != nil || tag.RowsAffected() != 1 {
					t.Fatal("restore only the measured cancellation predecessor", err)
				}
				explainDirectoryCursorPlan(t, f, tx, query, "cancel "+partition)
				var actualState, actualVersion string
				err = tx.QueryRow(f.ctx, `SELECT state,version::text FROM sso_providers.directory_sync_generations
 WHERE generation_id=$1`, string(predecessor.ID)).Scan(&actualState, &actualVersion)
				if err != nil || actualState != wantState || actualVersion != strconv.FormatUint(wantVersion, 10) {
					t.Fatal("captured cancellation did not produce the measured hit or no-match", partition, sample, err)
				}
			}()
		}
	}
}

func explainDirectoryCursorPlan(t *testing.T, f *orgFixture, tx pgx.Tx, query providerQuery, mode string) float64 {
	t.Helper()
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
		Plan struct {
			directoryGenerationPlanNode
			Rows float64 `json:"Actual Rows"`
		} `json:"Plan"`
		Execution float64 `json:"Execution Time"`
	}
	if err := json.Unmarshal(raw, &result); err != nil || len(result) != 1 {
		t.Fatal("read cursor plan", mode, err)
	}
	var indexes []string
	if !result[0].Plan.collect(&indexes) || len(indexes) == 0 {
		t.Fatalf("%s must use a scoped index without table scans: %s", mode, raw)
	}
	t.Logf("%s: indexes=%v execution=%.3fms root-rows=%g native-OIDs=%v", mode, indexes, result[0].Execution, result[0].Plan.Rows, query.oids)
	return result[0].Plan.Rows
}
