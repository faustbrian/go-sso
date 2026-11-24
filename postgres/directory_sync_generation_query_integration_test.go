//go:build integration

package postgres_test

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestNativeDirectoryGenerationQueryScale(t *testing.T) {
	x := newProviderEnableFixture(t)
	f := x.f
	installNativeDirectoryGeneration(t, f, ssopg.ProviderCredentialsMigrationSource{Version: 322}, ssopg.ProviderEnableMigrationSource{Version: 323})
	enabled, err := x.service.ProviderEnable(f.ctx, x.request)
	if err != nil || !enabled.Provider.Enabled {
		t.Fatal("enable native directory provider", err)
	}
	_, err = f.pool.Raw().Exec(f.ctx, `INSERT INTO sso_providers.providers
 (tenant_id,organization_id,provider_id,issuer_digest,configuration_envelope,mapping_version,pending_domains)
 SELECT CASE WHEN n<=10000 THEN tenant_id ELSE 'scale-'||(n%1000)::text END,organization_id,
  'scale-'||n::text,decode(md5(n::text)||md5('directory-'||n::text),'hex'),configuration_envelope,mapping_version,pending_domains
 FROM sso_providers.providers CROSS JOIN generate_series(1,100000) AS n WHERE provider_id=$1`, enabled.Provider.ID)
	if err != nil {
		t.Fatal("populate synthetic providers for the provider lock", err)
	}
	const source = "source-loaded"
	const hotCount = 18000
	_, err = f.pool.Raw().Exec(f.ctx, `INSERT INTO sso_providers.directory_sync_generations
 (tenant_id,organization_id,provider_id,connection_id,generation,generation_id,provider_version,mapping_version,mode,state,checkpoint,initial_checkpoint)
 SELECT 'org-test-basic',$1,$2,CASE WHEN n<=$3 THEN $4 ELSE 'synthetic-'||(n%100)::text END,n,
  rtrim(translate(encode(int8send(n)||int8send(n),'base64'),'+/','-_'),'='),1,1,'apply','finished',checkpoint,checkpoint
 FROM generate_series(1,20000) AS n CROSS JOIN (SELECT decode(repeat('ab',32),'hex') AS checkpoint) AS seed`,
		string(x.proof.OrganizationID), enabled.Provider.ID, hotCount, source)
	if err != nil {
		t.Fatal("populate synthetic directory history", err)
	}
	if _, err = f.pool.Raw().Exec(f.ctx, "ANALYZE sso_providers.providers; ANALYZE sso_providers.directory_sync_generations"); err != nil {
		t.Fatal(err)
	}

	trace := new(providerTrace)
	bound, err := tracedProviderService(t, f, x.config, trace).ForOrganization(string(x.proof.OrganizationID))
	if err != nil {
		t.Fatal(err)
	}
	service, err := bound.DirectorySync(source, directoryAdminPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	request := ssopg.DirectorySyncStartRequest{
		ProviderID: sso.ProviderID(enabled.Provider.ID), ProviderVersion: enabled.Provider.Version, MappingVersion: 1,
		Mode: ssopg.DirectorySyncApply, Key: directoryGenerationKey(t, "directory-scale-start"),
	}
	started := time.Now()
	created, err := service.Start(f.ctx, request)
	startElapsed := time.Since(started)
	if err != nil || created.Completion.Outcome != identity.CommitOutcomeCommitted || created.Generation.Number != hotCount+1 {
		t.Fatal("start did not append to the loaded source", err)
	}
	var statusElapsed, replayElapsed []time.Duration
	for range 5 {
		started = time.Now()
		status, err := service.Status(f.ctx, created.Generation.ID)
		statusElapsed = append(statusElapsed, time.Since(started))
		if err != nil || status != created.Generation {
			t.Fatal("read loaded source generation", err)
		}
		started = time.Now()
		replayed, err := service.Start(f.ctx, request)
		replayElapsed = append(replayElapsed, time.Since(started))
		if err != nil || replayed.Generation != created.Generation {
			t.Fatal("replay loaded source generation", err)
		}
	}
	sort.Slice(statusElapsed, func(i, j int) bool { return statusElapsed[i] < statusElapsed[j] })
	sort.Slice(replayElapsed, func(i, j int) bool { return replayElapsed[i] < replayElapsed[j] })
	var server string
	if err := f.pool.Raw().QueryRow(f.ctx, "SHOW server_version").Scan(&server); err != nil {
		t.Fatal(err)
	}
	t.Logf("isolated PostgreSQL %s; 100k synthetic providers and 20k generations (%d on one source); start=%s; 5 warm calls each: status median=%s max=%s, replay median=%s max=%s; no concurrent load",
		server, hotCount, startElapsed, statusElapsed[2], statusElapsed[4], replayElapsed[2], replayElapsed[4])
	missing, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	if value, err := service.Status(f.ctx, missing); !errors.Is(err, sso.ErrForbidden) || value.ID != "" {
		t.Fatal("loaded status leaked a missing generation", err)
	}

	trace.mu.Lock()
	queries, traceErr := append([]providerQuery(nil), trace.queries...), trace.err
	trace.mu.Unlock()
	if traceErr != nil {
		t.Fatal(traceErr)
	}
	seen := map[string]bool{}
	for _, query := range queries {
		var partition string
		switch {
		case strings.HasPrefix(query.sql, "SELECT provider_id FROM sso_providers.providers") && strings.HasSuffix(query.sql, "FOR SHARE"):
			partition = "provider lock"
		case strings.HasPrefix(query.sql, "INSERT INTO sso_providers.directory_sync_generations"):
			partition = "generation insert"
		case strings.HasPrefix(query.sql, "SELECT provider_id,generation::text,"):
			partition = "generation read miss"
			if len(query.args) != 0 && query.args[0] == string(created.Generation.ID) {
				partition = "generation read hit"
			}
		}
		if partition == "" || seen[partition] {
			continue
		}
		seen[partition] = true
		proveDirectoryGenerationPlan(t, f, query, partition, created.Generation.ID)
	}
	if len(seen) != 4 {
		t.Fatal("missing actual provider-lock, append, or exact status SQL partitions", seen)
	}
}

type directoryGenerationPlanNode struct {
	Type     string                        `json:"Node Type"`
	Index    string                        `json:"Index Name"`
	Children []directoryGenerationPlanNode `json:"Plans"`
}

func (n directoryGenerationPlanNode) collect(indexes *[]string) bool {
	if n.Index != "" {
		*indexes = append(*indexes, n.Index)
	}
	bounded := n.Type != "Seq Scan"
	for _, child := range n.Children {
		bounded = child.collect(indexes) && bounded
	}
	return bounded
}

func proveDirectoryGenerationPlan(t *testing.T, f *orgFixture, query providerQuery, partition string, created identity.CommandID) {
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
	if partition == "generation insert" {
		tag, err := tx.Exec(f.ctx, "DELETE FROM sso_providers.directory_sync_generations WHERE generation_id=$1", string(created))
		if err != nil || tag.RowsAffected() != 1 {
			t.Fatal("restore captured append predecessor only inside measurement transaction", err)
		}
	}
	var raw []byte
	const explain = "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) "
	if len(query.oids) != 0 {
		result := tx.Conn().PgConn().ExecParams(f.ctx, explain+query.sql, query.values, query.oids, query.formats, nil).Read()
		if result.Err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
			t.Fatal("explain binary native Work bindings", partition, result.Err)
		}
		raw = result.Rows[0][0]
	} else if err := tx.QueryRow(f.ctx, explain+query.sql, query.args...).Scan(&raw); err != nil {
		t.Fatal("explain native query bindings", partition, err)
	}
	var result []struct {
		Plan      directoryGenerationPlanNode `json:"Plan"`
		Execution float64                     `json:"Execution Time"`
	}
	if err := json.Unmarshal(raw, &result); err != nil || len(result) != 1 {
		t.Fatal("read captured directory query plan", partition, err)
	}
	var indexes []string
	if !result[0].Plan.collect(&indexes) || len(indexes) == 0 {
		t.Fatalf("%s must use an indexed lookup without table scans: %s", partition, raw)
	}
	t.Logf("%s: indexes=%v execution=%.3fms native-OIDs=%v", partition, indexes, result[0].Execution, query.oids)
}
