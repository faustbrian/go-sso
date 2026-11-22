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
	"github.com/jackc/pgx/v5"
)

func nativeOAuth2CallbackTracedRouter(t *testing.T, x providerOAuthLoginStartFixture, trace *providerTrace) *ssopg.ProviderRouter {
	t.Helper()
	f := x.enable.f
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
		t.Fatal("connect native OAuth2 callback trace pool", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := pool.Close(ctx); err != nil {
			t.Error("close native OAuth2 callback trace pool", err)
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
	return router
}

// Plan predicates can contain provider/state digests and ciphertext. Decode
// only structural counters, never retain or print the server's predicate text.
type nativeOAuth2CallbackPlan struct {
	NodeType     string                     `json:"Node Type"`
	IndexName    string                     `json:"Index Name,omitempty"`
	RelationName string                     `json:"Relation Name,omitempty"`
	ActualRows   float64                    `json:"Actual Rows"`
	ActualLoops  int                        `json:"Actual Loops"`
	FilteredRows float64                    `json:"Rows Removed by Filter"`
	JoinFiltered float64                    `json:"Rows Removed by Join Filter"`
	SharedHit    int                        `json:"Shared Hit Blocks"`
	SharedRead   int                        `json:"Shared Read Blocks"`
	ChildPlans   []nativeOAuth2CallbackPlan `json:"Plans,omitempty"`
}

// The real TLS exchange and native coordinator produce every measured SQL and
// binding. Synthetic ciphertext supplies only rollback-only cardinality; it
// never grants authority. The native operation sees committed fixture rows,
// while exact statement replay sees the uncommitted representative population.
func TestNativeOAuth2LoginCallbackQueryScale(t *testing.T) {
	trace := new(providerTrace)
	x := newNativeOAuth2JourneyFixture(t, "linked-member", trace)
	f := x.start.enable.f
	var pendingBinding, pendingVerifier []byte
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT binding_envelope,verifier_envelope FROM sso_providers.login_transactions WHERE start_command_id=$1`, x.startedID).Scan(&pendingBinding, &pendingVerifier); err != nil {
		t.Fatal("retain original pending custody in memory only", err)
	}
	defer clear(pendingBinding)
	defer clear(pendingVerifier)
	tx, err := f.pool.Raw().Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.ctx)
	for _, statement := range []string{
		`SET LOCAL statement_timeout='10s'; SET LOCAL lock_timeout='1s'`,
		`INSERT INTO sso_providers.providers(tenant_id,organization_id,provider_id,issuer_digest,configuration_envelope,mapping_version,pending_domains,protocol)
SELECT CASE WHEN n<=10000 THEN tenant_id ELSE 'oauth-callback-cost-'||(n%1000)::text END,CASE WHEN n<=10000 THEN organization_id ELSE 'oauth-callback-org-'||(n%100)::text END,
'oauth-callback-cost-'||n::text,decode(md5(n::text)||md5('callback-issuer-'||n::text),'hex'),configuration_envelope,mapping_version,pending_domains,CASE WHEN n%2=0 THEN 'oidc' ELSE 'oauth2' END
FROM sso_providers.providers CROSS JOIN generate_series(1,100000) n WHERE provider_id=$1`,
		`INSERT INTO sso_providers.credentials(tenant_id,organization_id,provider_id,generation,provider_version,envelope,credential_context)
SELECT p.tenant_id,p.organization_id,p.provider_id,c.generation,c.provider_version,c.envelope,c.credential_context FROM sso_providers.providers p CROSS JOIN sso_providers.credentials c WHERE p.provider_id LIKE 'oauth-callback-cost-%' AND c.provider_id=$1`,
		`INSERT INTO sso_providers.login_transactions(tenant_id,organization_id,provider_id,provider_version,credential_generation,mapping_version,start_command_id,callback_command_id,protocol,state_key_version,state_digest,pkce_key_version,pkce_commitment,binding_envelope,verifier_envelope,issued_at,expires_at,completed_at)
SELECT p.tenant_id,p.organization_id,p.provider_id,l.provider_version,l.credential_generation,l.mapping_version,'callback-cost-start-'||p.provider_id,'callback-cost-callback-'||p.provider_id,p.protocol,l.state_key_version,decode(md5(p.provider_id)||md5('callback-state-'||p.provider_id),'hex'),l.pkce_key_version,l.pkce_commitment,l.binding_envelope,NULL,l.issued_at-interval '1 day',l.expires_at-interval '1 day',l.expires_at-interval '1 day'
FROM sso_providers.providers p CROSS JOIN sso_providers.login_transactions l WHERE p.provider_id LIKE 'oauth-callback-cost-%' AND l.start_command_id=$1`,
		`INSERT INTO sso_providers.login_transactions(tenant_id,organization_id,provider_id,provider_version,credential_generation,mapping_version,start_command_id,callback_command_id,protocol,state_key_version,state_digest,pkce_key_version,pkce_commitment,binding_envelope,verifier_envelope,issued_at,expires_at)
SELECT l.tenant_id,l.organization_id,l.provider_id,l.provider_version,l.credential_generation,l.mapping_version,'callback-cost-active-start-'||n::text,'callback-cost-active-callback-'||n::text,l.protocol,l.state_key_version,decode(md5('callback-active-a-'||n::text)||md5('callback-active-b-'||n::text),'hex'),l.pkce_key_version,l.pkce_commitment,l.binding_envelope,l.verifier_envelope,l.issued_at,l.expires_at
FROM sso_providers.login_transactions l CROSS JOIN generate_series(1,1024) n WHERE l.start_command_id=$1`,
		`ANALYZE sso_providers.providers; ANALYZE sso_providers.credentials; ANALYZE sso_providers.login_transactions`,
	} {
		var args []any
		if strings.Contains(statement, "l.start_command_id=$1") {
			args = []any{x.startedID}
		} else if strings.Contains(statement, "$1") {
			args = []any{x.start.profile.ProviderID}
		}
		if _, err := tx.Exec(f.ctx, statement, args...); err != nil {
			t.Fatal("rollback-only callback cost population", err)
		}
	}
	var providers, hot, history, active int
	var engine string
	if err := tx.QueryRow(f.ctx, `SELECT count(*),count(*) FILTER(WHERE tenant_id=$1 AND organization_id=$2),(SELECT count(*) FROM sso_providers.login_transactions WHERE completed_at IS NOT NULL),(SELECT count(*) FROM sso_providers.login_transactions WHERE completed_at IS NULL),current_setting('server_version') FROM sso_providers.providers`, string(x.start.config.TenantID), string(x.start.profile.OrganizationID)).Scan(&providers, &hot, &history, &active, &engine); err != nil || providers != 100002 || hot != 10002 || history != 100000 || active != 1025 {
		t.Fatal("representative callback population mismatch", providers, hot, history, active, err)
	}
	var columnTypes, indexes []byte
	if err := tx.QueryRow(f.ctx, `SELECT
(SELECT jsonb_agg(jsonb_build_object('table',c.relname,'column',a.attname,'type',format_type(a.atttypid,a.atttypmod)) ORDER BY c.relname,a.attnum)
 FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='sso_providers' AND c.relname IN ('providers','credentials','login_transactions','provider_login_token_sets') AND a.attnum>0 AND NOT a.attisdropped),
(SELECT jsonb_agg(jsonb_build_object('table',tablename,'definition',indexdef) ORDER BY tablename,indexname)
 FROM pg_indexes WHERE schemaname='sso_providers' AND tablename IN ('providers','credentials','login_transactions','provider_login_token_sets'))`).Scan(&columnTypes, &indexes); err != nil {
		t.Fatal("inspect actual callback column types and indexes", err)
	}
	t.Logf("actual-column-types=%s actual-indexes=%s", columnTypes, indexes)
	startedAt := time.Now()
	got, err := x.completion.SigninCallbackOAuth2(f.ctx, x.request)
	callbackElapsed := time.Since(startedAt)
	if err != nil || got.Completion.Outcome != identity.CommitOutcomeCommitted || got.Issuance.CommitOutcome != identity.CommitOutcomeCommitted || x.posts.Load() != 1 || x.identities.Load() != 1 {
		t.Fatal("capture genuine native callback SQL", err)
	}
	trace.mu.Lock()
	queries, traceErr := append([]providerQuery(nil), trace.queries...), trace.err
	trace.queries = nil
	trace.mu.Unlock()
	if traceErr != nil {
		t.Fatal(traceErr)
	}
	selected := map[string]providerQuery{}
	for _, query := range queries {
		name := ""
		switch {
		case query.sql == ssopg.ProviderOAuth2CallbackMaterialSQLForTest:
			name = "material"
		case strings.HasPrefix(query.sql, "WITH eligible_provider AS MATERIALIZED") && strings.Contains(query.sql, "p.protocol='oauth2'"):
			name = "disposition"
		case strings.HasPrefix(query.sql, "SELECT tenant_id,organization_id,provider_id,provider_version::text") && strings.Contains(query.sql, "protocol='oauth2'") && strings.Contains(query.sql, "FOR SHARE"):
			name = "token-original"
		case strings.HasPrefix(query.sql, "INSERT INTO sso_providers.provider_login_token_sets") && strings.Contains(query.sql, "'identity.sso.oauth-callback'"):
			name = "token-insert"
		case strings.Contains(query.sql, "UPDATE sso_providers.login_transactions l") && strings.Contains(query.sql, "protocol='oauth2'") && strings.Contains(query.sql, "verifier_envelope=NULL"):
			name = "complete"
		}
		if name != "" {
			if previous, found := selected[name]; !found || len(query.oids) > len(previous.oids) {
				selected[name] = query
			}
		}
	}
	if len(selected) != 5 {
		t.Fatal("missing one of the five executed native OAuth2 callback queries", len(selected))
	}
	for _, name := range []string{"disposition", "token-original", "token-insert", "complete"} {
		if len(selected[name].oids) == 0 {
			t.Fatal("native callback Work binding types not captured", name)
		}
	}
	if _, err := tx.Exec(f.ctx, `UPDATE sso_providers.login_transactions SET completed_at=NULL,binding_envelope=$2,verifier_envelope=$3 WHERE start_command_id=$1`, x.startedID, pendingBinding, pendingVerifier); err != nil {
		t.Fatal("restore original pending snapshot for rollback-only plans", err)
	}
	t.Logf("PostgreSQL=%s providers=%d hot=%d historical-login-rows=%d active-hot=%d; isolated, no concurrent load; native callback=%s at committed fixture cardinality, separate from scaled statement replay; original deadlines never renewed", engine, providers, hot, history, active, callbackElapsed)
	for _, name := range []string{"material", "disposition", "complete"} {
		measureNativeOAuth2CallbackQuery(t, f, tx, x, name, selected[name])
	}
	// Token insertion has account/command foreign keys. Populate only the hot
	// tenant using the genuine account and committed origin command, never a
	// manufactured authority row; these copies are storage cardinality alone.
	if _, err := tx.Exec(f.ctx, `INSERT INTO sso_providers.provider_login_token_sets(
tenant_id,organization_id,provider_id,start_command_id,callback_command_id,callback_generation,user_id,account_id,account_provider,issuer,subject,account_version,social_link_version,provider_version,credential_generation,mapping_version,token_version,requested_scopes,granted_scopes,scope_reported,received_at_seconds,received_at_nanoseconds,access_expires_at_seconds,access_expires_at_nanoseconds,token_ciphertext,origin_operation,origin_command_id)
SELECT l.tenant_id,l.organization_id,l.provider_id,l.start_command_id,l.callback_command_id,v.callback_generation,v.user_id,v.account_id,v.account_provider,v.issuer,v.subject,v.account_version,v.social_link_version,l.provider_version,l.credential_generation,l.mapping_version,v.token_version,v.requested_scopes,v.granted_scopes,v.scope_reported,v.received_at_seconds,v.received_at_nanoseconds,v.access_expires_at_seconds,v.access_expires_at_nanoseconds,v.token_ciphertext,v.origin_operation,v.origin_command_id
FROM sso_providers.login_transactions l CROSS JOIN sso_providers.provider_login_token_sets v WHERE l.tenant_id=$1 AND l.provider_id LIKE 'oauth-callback-cost-%' AND v.start_command_id=$2`, string(x.start.config.TenantID), x.startedID); err != nil {
		t.Fatal("rollback-only hot token custody population", err)
	}
	if _, err := tx.Exec(f.ctx, `ANALYZE sso_providers.provider_login_token_sets`); err != nil {
		t.Fatal(err)
	}
	var tokenRows int
	if err := tx.QueryRow(f.ctx, `SELECT count(*) FROM sso_providers.provider_login_token_sets`).Scan(&tokenRows); err != nil || tokenRows != 10001 {
		t.Fatal("representative token custody count", tokenRows, err)
	}
	t.Logf("rollback-only token-custody=%d; original foreign keys and usable indexes retained", tokenRows)
	for _, name := range []string{"token-original", "token-insert"} {
		measureNativeOAuth2CallbackQuery(t, f, tx, x, name, selected[name])
	}
	if err := tx.Rollback(f.ctx); err != nil {
		t.Fatal("rollback scaled callback population and measured writes", err)
	}
}

func measureNativeOAuth2CallbackQuery(t *testing.T, f *orgFixture, tx pgx.Tx, x nativeOAuth2JourneyFixture, name string, query providerQuery) {
	t.Helper()
	types := make([]string, len(query.args))
	for i, argument := range query.args {
		types[i] = fmt.Sprintf("%T", argument)
	}
	for _, match := range []bool{true, false} {
		for sample := range 2 {
			if _, err := tx.Exec(f.ctx, "SAVEPOINT callback_sample"); err != nil {
				t.Fatal(err)
			}
			if name == "token-insert" && match {
				if _, err := tx.Exec(f.ctx, `DELETE FROM sso_providers.provider_login_token_sets WHERE start_command_id=$1`, x.startedID); err != nil {
					t.Fatal(err)
				}
			} else if !match && name == "disposition" {
				if _, err := tx.Exec(f.ctx, `UPDATE sso_providers.credentials SET generation=generation+1 WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`, string(x.start.config.TenantID), string(x.start.profile.OrganizationID), string(x.start.profile.ProviderID)); err != nil {
					t.Fatal(err)
				}
			} else if !match && name != "token-insert" {
				if _, err := tx.Exec(f.ctx, `UPDATE sso_providers.login_transactions SET completed_at=clock_timestamp(),verifier_envelope=NULL WHERE start_command_id=$1`, x.startedID); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := tx.Exec(f.ctx, "SAVEPOINT callback_plan"); err != nil {
				t.Fatal(err)
			}
			var wire []byte
			if len(query.oids) > 0 {
				result := tx.Conn().PgConn().ExecParams(f.ctx, "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) "+query.sql, query.values, query.oids, query.formats, nil).Read()
				if result.Err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
					t.Fatal("captured callback wire plan", name, result.Err)
				}
				wire = result.Rows[0][0]
			} else if err := tx.QueryRow(f.ctx, "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) "+query.sql, query.args...).Scan(&wire); err != nil {
				t.Fatal("captured callback driver plan", name, err)
			}
			var plans []struct {
				Plan          nativeOAuth2CallbackPlan `json:"Plan"`
				ExecutionTime float64                  `json:"Execution Time"`
			}
			err := json.Unmarshal(wire, &plans)
			clear(wire)
			if err != nil || len(plans) != 1 || plans[0].ExecutionTime > 100 {
				t.Fatal("unbounded native callback plan", name, err)
			}
			want := int64(0)
			if match {
				want = 1
			}
			if _, err := tx.Exec(f.ctx, "ROLLBACK TO SAVEPOINT callback_plan"); err != nil {
				t.Fatal(err)
			}
			var actual int64
			if len(query.oids) > 0 {
				result := tx.Conn().PgConn().ExecParams(f.ctx, query.sql, query.values, query.oids, query.formats, nil).Read()
				if result.Err != nil {
					t.Fatal("execute original callback wire parameters", name, result.Err)
				}
				actual = result.CommandTag.RowsAffected()
				for _, row := range result.Rows {
					for _, value := range row {
						clear(value)
					}
				}
			} else {
				tag, err := tx.Exec(f.ctx, query.sql, query.args...)
				if err != nil {
					t.Fatal("execute original callback driver parameters", name, err)
				}
				actual = tag.RowsAffected()
			}
			if actual != want {
				t.Fatal("native callback plan result/affected cardinality", name, match, actual, want)
			}
			indexes := map[string]bool{}
			var inspect func(nativeOAuth2CallbackPlan)
			inspect = func(node nativeOAuth2CallbackPlan) {
				if node.ActualRows > 1 || node.ActualLoops > 1 || node.FilteredRows > 1 || node.JoinFiltered > 1 || node.NodeType == "Seq Scan" || node.NodeType == "Sort" {
					t.Fatal("native callback examined unbounded work", name, node.NodeType, node.IndexName, node.ActualRows, node.ActualLoops, node.FilteredRows)
				}
				indexes[node.IndexName] = true
				for _, child := range node.ChildPlans {
					inspect(child)
				}
			}
			inspect(plans[0].Plan)
			// Material additionally has the exact issuer digest, so the
			// tenant/organization/issuer unique index is equally bounded.
			providerIndex := indexes["providers_pkey"] || name == "material" && indexes["providers_tenant_id_organization_id_issuer_digest_key"]
			if match && (name == "material" || name == "disposition") && (!providerIndex || !indexes["credentials_pkey"]) {
				t.Fatal("callback lost exact provider/credential indexed access", name, indexes)
			}
			if match && (name == "material" || name == "token-original" || name == "complete") && !indexes["login_transactions_pkey"] {
				t.Fatal("callback lost exact login indexed access", name)
			}
			safePlan, err := json.Marshal(plans)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("%s match=%t sample=%d SQL=%s types=%v native-OIDs=%v formats=%v rows=%d safe-plan=%s", name, match, sample, query.sql, types, query.oids, query.formats, actual, safePlan)
			if _, err := tx.Exec(f.ctx, "ROLLBACK TO SAVEPOINT callback_sample"); err != nil {
				t.Fatal(err)
			}
		}
	}
}
