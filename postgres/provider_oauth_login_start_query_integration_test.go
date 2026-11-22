//go:build integration

package postgres_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

// Copied ciphertext supplies cardinality only, never authority. All population
// and EXPLAIN writes roll back; original wire parameters remain in memory only.
func TestNativeOAuth2SigninStartQueryScale(t *testing.T) {
	x := newProviderOAuthLoginStartFixture(t)
	f, trace := x.enable.f, new(providerTrace)
	seed, err := x.service.SigninStartOAuth2(f.ctx, x.request, x.browser)
	if err != nil {
		t.Fatal("commit genuine historical-row source", err)
	}
	pool, err := database.Connect(f.ctx, database.Config{DSN: f.dsn, MaxConns: 2, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database, c.ConnConfig.Tracer = f.database, trace
		c.ConnConfig.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			return &providerWireConn{Conn: conn, trace: trace}, nil
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := pool.Close(ctx); err != nil {
			t.Error("close OAuth trace pool", err)
		}
	})
	router, err := ssopg.NewProviderRouter(pool, ssopg.ProviderRouterConfig{Clock: clock.System{}, Envelope: x.config.Envelope, MaximumDuration: 3 * time.Second, Lifetime: 8 * time.Second, PolicyVersion: 1, MaximumProviders: 4})
	if err != nil {
		t.Fatal(err)
	}
	router, err = router.WithProtocolRegistry()
	if err != nil {
		t.Fatal(err)
	}
	service, err := ssopg.NewProviderLoginServiceWithOAuth2(router, x.config, []ssopg.StaticOAuth2LoginProfile{x.profile})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.pool.Raw().Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.ctx)
	for _, sql := range []string{
		`SET LOCAL statement_timeout='10s'; SET LOCAL lock_timeout='1s'`,
		`INSERT INTO sso_providers.providers(tenant_id,organization_id,provider_id,issuer_digest,configuration_envelope,mapping_version,pending_domains,protocol)
SELECT CASE WHEN n<=10000 THEN tenant_id ELSE 'oauth-cost-'||(n%1000)::text END,CASE WHEN n<=10000 THEN organization_id ELSE 'oauth-cost-org-'||(n%100)::text END,
'oauth-cost-'||n::text,decode(md5(n::text)||md5('issuer-'||n::text),'hex'),configuration_envelope,mapping_version,pending_domains,CASE WHEN n%2=0 THEN 'oidc' ELSE 'oauth2' END
FROM sso_providers.providers CROSS JOIN generate_series(1,100000) n WHERE provider_id=$1`,
		`INSERT INTO sso_providers.credentials(tenant_id,organization_id,provider_id,generation,provider_version,envelope,credential_context)
SELECT p.tenant_id,p.organization_id,p.provider_id,c.generation,c.provider_version,c.envelope,c.credential_context FROM sso_providers.providers p CROSS JOIN sso_providers.credentials c WHERE p.provider_id LIKE 'oauth-cost-%' AND c.provider_id=$1`,
		`INSERT INTO sso_providers.login_transactions(tenant_id,organization_id,provider_id,provider_version,credential_generation,mapping_version,start_command_id,callback_command_id,protocol,state_key_version,state_digest,pkce_key_version,pkce_commitment,binding_envelope,verifier_envelope,issued_at,expires_at,completed_at)
SELECT p.tenant_id,p.organization_id,p.provider_id,l.provider_version,l.credential_generation,l.mapping_version,'cost-start-'||p.provider_id,'cost-callback-'||p.provider_id,p.protocol,l.state_key_version,decode(md5(p.provider_id)||md5('state-'||p.provider_id),'hex'),l.pkce_key_version,l.pkce_commitment,l.binding_envelope,NULL,l.issued_at-interval '1 day',l.expires_at-interval '1 day',l.expires_at-interval '1 day'
FROM sso_providers.providers p CROSS JOIN sso_providers.login_transactions l WHERE p.provider_id LIKE 'oauth-cost-%' AND l.start_command_id=$1`,
		`INSERT INTO sso_providers.login_transactions(tenant_id,organization_id,provider_id,provider_version,credential_generation,mapping_version,start_command_id,callback_command_id,protocol,state_key_version,state_digest,pkce_key_version,pkce_commitment,binding_envelope,verifier_envelope,issued_at,expires_at)
SELECT l.tenant_id,l.organization_id,l.provider_id,l.provider_version,l.credential_generation,l.mapping_version,'cost-active-start-'||n::text,'cost-active-callback-'||n::text,l.protocol,l.state_key_version,decode(md5('active-a-'||n::text)||md5('active-b-'||n::text),'hex'),l.pkce_key_version,l.pkce_commitment,l.binding_envelope,l.verifier_envelope,l.issued_at,l.expires_at
FROM sso_providers.login_transactions l CROSS JOIN generate_series(1,1024) n WHERE l.start_command_id=$1`,
		`ANALYZE sso_providers.providers; ANALYZE sso_providers.credentials; ANALYZE sso_providers.login_transactions`,
	} {
		args := []any(nil)
		if strings.Contains(sql, "l.start_command_id=$1") {
			args = []any{seed.TransactionID}
		} else if strings.Contains(sql, "$1") {
			args = []any{x.request.ProviderID}
		}
		if _, err := tx.Exec(f.ctx, sql, args...); err != nil {
			t.Fatal("rollback-only OAuth cost population", err)
		}
	}
	var providers, hot, history, active int
	var engine string
	if err := tx.QueryRow(f.ctx, `SELECT count(*),count(*) FILTER(WHERE tenant_id=$1 AND organization_id=$2),(SELECT count(*) FROM sso_providers.login_transactions WHERE completed_at IS NOT NULL),(SELECT count(*) FROM sso_providers.login_transactions WHERE completed_at IS NULL),current_setting('server_version') FROM sso_providers.providers`, string(x.config.TenantID), string(x.profile.OrganizationID)).Scan(&providers, &hot, &history, &active, &engine); err != nil || providers != 100002 || hot != 10002 || history != 100000 || active != 1025 {
		t.Fatal("representative OAuth scale mismatch", providers, hot, history, active, err)
	}
	request := x.request
	request.CommandID = commandID(t)
	request.IdempotencyKey, err = identity.NewIdempotencyKey([]byte("oauth-cost-fresh-native-start"))
	if err != nil {
		t.Fatal(err)
	}
	startedAt := time.Now()
	started, err := service.SigninStartOAuth2(f.ctx, request, x.browser)
	if err != nil || started.Completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("capture genuine typed OAuth start", err)
	}
	t.Logf("PostgreSQL=%s; rollback-only providers=%d hot=%d historical-login-rows=%d active-hot=%d; isolated, no concurrent workload, first plans may be cold; native start=%s at committed fixture cardinality, separate from scaled statement replay", engine, providers, hot, history, active, time.Since(startedAt))
	trace.mu.Lock()
	queries, traceErr := trace.queries, trace.err
	trace.queries = nil
	trace.mu.Unlock()
	if traceErr != nil {
		t.Fatal(traceErr)
	}
	selected := map[string]providerQuery{}
	for _, q := range queries {
		switch {
		case strings.HasPrefix(q.sql, "SELECT p.issuer_digest,"):
			selected["profile"] = q
		case strings.HasPrefix(q.sql, "WITH eligible_provider AS MATERIALIZED") && strings.Contains(q.sql, "p.protocol='oauth2'"):
			selected["fence"] = q
		case strings.HasPrefix(q.sql, "WITH exact_oauth_login AS MATERIALIZED") && strings.Contains(q.sql, "SELECT binding_envelope,completed_at"):
			selected["redirect"] = q
		case strings.HasPrefix(q.sql, "INSERT INTO sso_providers.login_transactions") && strings.Contains(q.sql, "'oauth2'"):
			selected["insert"] = q
		}
	}
	if len(selected) != 4 || len(selected["fence"].oids) == 0 || len(selected["insert"].oids) == 0 {
		t.Fatal("missing actual OAuth read/fence/redirect/insertion or Work wire types")
	}
	recovery := selected["redirect"]
	recovery.sql = ssopg.OAuth2SigninStartRecoverySQLForTest
	selected["recovery"] = recovery
	for _, name := range []string{"profile", "fence", "redirect", "recovery", "insert"} {
		q := selected[name]
		types := make([]string, len(q.args))
		for i, arg := range q.args {
			types[i] = fmt.Sprintf("%T", arg)
		}
		for sample := range 2 {
			if _, err := tx.Exec(f.ctx, "SAVEPOINT oauth_sample"); err != nil {
				t.Fatal(err)
			}
			if name == "insert" {
				if _, err := tx.Exec(f.ctx, `DELETE FROM sso_providers.login_transactions WHERE start_command_id=$1`, started.TransactionID); err != nil {
					t.Fatal(err)
				}
			}
			var wire []byte
			if len(q.oids) > 0 {
				result := tx.Conn().PgConn().ExecParams(f.ctx, "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) "+q.sql, q.values, q.oids, q.formats, nil).Read()
				if result.Err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
					t.Fatal("captured native OAuth plan", name, result.Err)
				}
				wire = result.Rows[0][0]
			} else if err := tx.QueryRow(f.ctx, "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) "+q.sql, q.args...).Scan(&wire); err != nil {
				t.Fatal(name, err)
			}
			var plans []struct {
				Plan          protocolRouteQueryPlan
				ExecutionTime float64 `json:"Execution Time"`
			}
			if err := json.Unmarshal(wire, &plans); err != nil || len(plans) != 1 || plans[0].ExecutionTime > 100 {
				t.Fatal("unbounded OAuth plan", name, err)
			}
			if name != "insert" && plans[0].Plan.ActualRows != 1 {
				t.Fatal("scaled replay did not perform the expected exact read", name)
			}
			if name == "insert" {
				var inserted bool
				if err := tx.QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM sso_providers.login_transactions WHERE start_command_id=$1 AND protocol='oauth2')`, started.TransactionID).Scan(&inserted); err != nil || !inserted {
					t.Fatal("scaled insertion did not execute its original bounded write", err)
				}
			}
			indexes := map[string]bool{}
			var inspect func(protocolRouteQueryPlan)
			inspect = func(n protocolRouteQueryPlan) {
				if n.ActualRows > 1 || n.ActualLoops > 1 || n.FilteredRows > 1 || n.NodeType == "Seq Scan" || n.NodeType == "Sort" {
					t.Fatal("OAuth query examined unbounded work", name, n.NodeType, n.IndexName, n.ActualRows, n.ActualLoops, n.FilteredRows)
				}
				indexes[n.IndexName] = true
				for _, child := range n.ChildPlans {
					inspect(child)
				}
			}
			inspect(plans[0].Plan)
			if (name == "profile" || name == "fence") && (!indexes["providers_pkey"] || !indexes["credentials_pkey"]) || (name == "redirect" || name == "recovery") && !indexes["login_transactions_start_command_id_key"] {
				t.Fatal("OAuth query lost exact indexed access", name, indexes)
			}
			t.Logf("%s sample=%d SQL=%s types=%v native-OIDs=%v formats=%v plan=%s", name, sample, q.sql, types, q.oids, q.formats, wire)
			if _, err := tx.Exec(f.ctx, "ROLLBACK TO SAVEPOINT oauth_sample"); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tx.Rollback(f.ctx); err != nil {
		t.Fatal("rollback all scaled population and measured writes", err)
	}
	t.Log("exact exported recovery SELECT measured with observed redirect transaction arguments; recovery lifecycle is not exercised; original short fence/insertion deadlines are never renewed")
}
