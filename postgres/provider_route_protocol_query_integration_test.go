//go:build integration

package postgres_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-clock"
	database "github.com/faustbrian/go-postgres"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

// Synthetic disabled rows provide cardinality and protocol skew only. Their
// copied configuration ciphertext is never decrypted or treated as authority.
func TestNativeProviderRouteProtocolRegistryQueryScale(t *testing.T) {
	x := newProviderEnableFixture(t)
	oidc := enableRouteFixture(t, x, false)
	installProviderRouteProtocolHistory(t, x.f)
	insertUnusableOAuthRouteFixture(t, x)
	if _, err := x.f.pool.Raw().Exec(x.f.ctx, `INSERT INTO sso_providers.providers
 (tenant_id,organization_id,provider_id,issuer_digest,configuration_envelope,mapping_version,pending_domains,protocol)
 SELECT CASE WHEN n<=10000 THEN tenant_id ELSE 'route-scale-'||(n%1000)::text END,
 CASE WHEN n<=10000 THEN organization_id ELSE 'route-scale-org-'||(n%100)::text END,
 'route-scale-'||lpad(n::text,8,'0'),decode(md5(n::text)||md5('route-issuer-'||n::text),'hex'),
 configuration_envelope,mapping_version,pending_domains,CASE WHEN n%2=0 THEN 'oidc' ELSE 'oauth2' END
 FROM sso_providers.providers CROSS JOIN generate_series(1,100000) n
 WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`,
		string(x.proof.TenantID), string(x.proof.OrganizationID), string(oidc)); err != nil {
		t.Fatal("populate mixed routing cardinality", err)
	}
	if _, err := x.f.pool.Raw().Exec(x.f.ctx, `INSERT INTO sso_providers.providers
 (tenant_id,organization_id,provider_id,issuer_digest,configuration_envelope,mapping_version,pending_domains,protocol)
 SELECT 'route-sparse-tenant','route-sparse-org','route-sparse-provider',
 decode(md5('route-sparse-issuer')||md5('route-sparse-issuer-2'),'hex'),
 configuration_envelope,mapping_version,pending_domains,'oauth2'
 FROM sso_providers.providers WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`,
		string(x.proof.TenantID), string(x.proof.OrganizationID), string(oidc)); err != nil {
		t.Fatal("populate isolated sparse route scope", err)
	}
	if _, err := x.f.pool.Raw().Exec(x.f.ctx, `ANALYZE sso_providers.providers`); err != nil {
		t.Fatal(err)
	}
	var total, hot, oauthRows int
	var engine, primary, columns string
	if err := x.f.pool.Raw().QueryRow(x.f.ctx, `SELECT count(*),
 count(*) FILTER(WHERE tenant_id=$1 AND organization_id=$2),count(*) FILTER(WHERE protocol='oauth2'),
 current_setting('server_version'),pg_get_indexdef('sso_providers.providers_pkey'::regclass),
 (SELECT string_agg(attname||' '||format_type(atttypid,atttypmod),', ' ORDER BY attnum)
 FROM pg_attribute WHERE attrelid='sso_providers.providers'::regclass AND attnum>0 AND NOT attisdropped)
 FROM sso_providers.providers`, string(x.proof.TenantID), string(x.proof.OrganizationID)).Scan(&total, &hot, &oauthRows, &engine, &primary, &columns); err != nil || total != 100003 || hot != 10002 || oauthRows != 50002 {
		t.Fatal("routing scale/schema mismatch", total, hot, oauthRows, err)
	}
	t.Logf("isolated PostgreSQL=%s providers=%d hot-scope=%d oauth2=%d sparse-scope=1; no concurrent load; index=%s; columns=%s", engine, total, hot, oauthRows, primary, columns)

	trace := new(providerTrace)
	legacy := newTracedProtocolProviderRouter(t, x, trace)
	selected, err := legacy.WithProtocolRegistry()
	if err != nil {
		t.Fatal(err)
	}
	type operation struct {
		name     string
		explicit sso.ProviderID
		want     sso.ProviderID
		err      error
		queries  int
	}
	operations := []operation{
		{name: "exact-hit", explicit: oidc, want: oidc, queries: 3},
		{name: "exact-miss", explicit: "route-missing-provider", err: sso.ErrForbidden, queries: 1},
		{name: "dense-capped-window", err: sso.ErrConflict, queries: 1},
	}
	for _, mode := range []struct {
		name   string
		router *ssopg.ProviderRouter
	}{{"legacy", legacy}, {"protocol-registry", selected}} {
		for _, operation := range operations {
			request, err := sso.NewDomainRouteRequest(x.proof.TenantID, x.proof.Domain, operation.explicit)
			if err != nil {
				t.Fatal(err)
			}
			var captured providerQuery
			var elapsed []time.Duration
			for sample := range 3 {
				trace.mu.Lock()
				trace.queries, trace.err = nil, nil
				trace.mu.Unlock()
				started := time.Now()
				route, err := mode.router.Route(x.f.ctx, request)
				elapsed = append(elapsed, time.Since(started))
				if !errors.Is(err, operation.err) || route.Value != string(operation.want) {
					t.Fatal(mode.name, operation.name, "native routing outcome changed", err)
				}
				trace.mu.Lock()
				queries := append([]providerQuery(nil), trace.queries...)
				traceErr := trace.err
				trace.mu.Unlock()
				if traceErr != nil || len(queries) != operation.queries {
					t.Fatal(mode.name, operation.name, "unexpected provider query amplification", len(queries), traceErr)
				}
				candidate := queries[0]
				if !strings.HasPrefix(candidate.sql, "SELECT provider_id,") && !strings.HasPrefix(candidate.sql, "SELECT p.provider_id,") {
					t.Fatal("actual route candidate query not captured")
				}
				if len(candidate.args) != 3 {
					t.Fatal("route candidate scope/binding count changed")
				}
				if _, ok := candidate.args[0].(string); !ok {
					t.Fatal("tenant binding is not native text")
				}
				if _, ok := candidate.args[1].(string); !ok {
					t.Fatal("organization binding is not native text")
				}
				if operation.explicit == "" {
					if limit, ok := candidate.args[2].(int32); !ok || limit != 129 {
						t.Fatal("automatic window lost native bounded int32 binding")
					}
				} else if id, ok := candidate.args[2].(string); !ok || id != string(operation.explicit) {
					t.Fatal("exact provider lost native text binding")
				}
				if sample > 0 && (candidate.sql != captured.sql || !reflect.DeepEqual(candidate.args, captured.args)) {
					t.Fatal("repeated route changed its candidate statement or bindings")
				}
				captured = candidate
			}
			sort.Slice(elapsed, func(i, j int) bool { return elapsed[i] < elapsed[j] })
			t.Logf("native %s %s: samples=3 median=%s max=%s provider-queries-per-call=%d; includes organization/proof/envelope and pool/client work; first call may be cold", mode.name, operation.name, elapsed[1], elapsed[2], operation.queries)
			bound := 1
			wantRows := 0
			if operation.want != "" {
				wantRows = 1
			}
			if operation.explicit == "" {
				bound, wantRows = 129, 129
			}
			measureProtocolRouteQuery(t, x, mode.name+"/"+operation.name, captured, bound, wantRows)
			if operation.explicit == "" {
				sparse := captured
				sparse.args = append([]any(nil), captured.args...)
				sparse.args[0], sparse.args[1] = "route-sparse-tenant", "route-sparse-org"
				measureProtocolRouteQuery(t, x, mode.name+"/sparse-window-replay", sparse, 129, 1)
			}
		}
	}
}

func newTracedProtocolProviderRouter(t *testing.T, x providerEnableFixture, trace *providerTrace) *ssopg.ProviderRouter {
	t.Helper()
	pool, err := database.Connect(x.f.ctx, database.Config{DSN: x.f.dsn, MaxConns: 2, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database = x.f.database
		c.ConnConfig.Tracer = trace
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := pool.Close(ctx); err != nil {
			t.Error("close route trace pool", err)
		}
	})
	router, err := ssopg.NewProviderRouter(pool, ssopg.ProviderRouterConfig{
		Clock: clock.System{}, Envelope: x.config.Envelope, MaximumDuration: 3 * time.Second,
		Lifetime: 8 * time.Second, PolicyVersion: 1, MaximumProviders: 128,
	})
	if err != nil {
		t.Fatal(err)
	}
	return router
}

type protocolRouteQueryPlan struct {
	NodeType     string                   `json:"Node Type"`
	IndexName    string                   `json:"Index Name"`
	IndexCond    string                   `json:"Index Cond"`
	ActualRows   float64                  `json:"Actual Rows"`
	ActualLoops  int                      `json:"Actual Loops"`
	FilteredRows float64                  `json:"Rows Removed by Filter"`
	ChildPlans   []protocolRouteQueryPlan `json:"Plans"`
}

func measureProtocolRouteQuery(t *testing.T, x providerEnableFixture, name string, query providerQuery, bound, wantRows int) {
	t.Helper()
	types := make([]string, len(query.args))
	for i, arg := range query.args {
		types[i] = fmt.Sprintf("%T", arg)
	}
	for sample := range 3 {
		var wire []byte
		if err := x.f.pool.Raw().QueryRow(x.f.ctx, "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) "+query.sql, query.args...).Scan(&wire); err != nil {
			t.Fatal(name, "actual typed route plan", err)
		}
		var plan []struct {
			Plan protocolRouteQueryPlan `json:"Plan"`
		}
		if err := json.Unmarshal(wire, &plan); err != nil || len(plan) != 1 || plan[0].Plan.ActualRows != float64(wantRows) {
			t.Fatal(name, "unexpected route result cardinality in executed plan", err)
		}
		var inspect func(protocolRouteQueryPlan)
		indexScans := 0
		inspect = func(node protocolRouteQueryPlan) {
			if node.ActualLoops > 1 || node.ActualRows > float64(bound) || node.FilteredRows != 0 {
				t.Fatal(name, "route plan examined unbounded/repeated/filtered work", node.NodeType, node.ActualRows, node.ActualLoops, node.FilteredRows)
			}
			switch node.NodeType {
			case "Limit":
			case "Index Scan", "Index Only Scan":
				indexScans++
				if node.IndexName != "providers_pkey" || !strings.Contains(node.IndexCond, "tenant_id") || !strings.Contains(node.IndexCond, "organization_id") || (bound == 1 && !strings.Contains(node.IndexCond, "provider_id")) {
					t.Fatal(name, "route did not use its exact scoped primary-key access path")
				}
			default:
				t.Fatal(name, "unexpected route scan/sort/join work", node.NodeType)
			}
			for _, child := range node.ChildPlans {
				inspect(child)
			}
		}
		inspect(plan[0].Plan)
		if indexScans != 1 {
			t.Fatal(name, "expected one bounded scoped primary-key scan", indexScans)
		}
		t.Logf("%s sample=%d actual-SQL=%s native-binding-types=%v; actual-plan=%s", name, sample, query.sql, types, wire)
	}
}
