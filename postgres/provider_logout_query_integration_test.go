//go:build integration

package postgres_test

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-clock"
	database "github.com/faustbrian/go-postgres"
	"github.com/faustbrian/go-sso/oidc"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

func nativeProviderLogoutTracedRouter(t *testing.T, x providerEnableFixture, trace *providerTrace) *ssopg.ProviderRouter {
	t.Helper()
	f := x.f
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
		t.Fatal("connect logout trace pool", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := pool.Close(ctx); err != nil {
			t.Error("close logout trace pool", err)
		}
	})
	router, err := ssopg.NewProviderRouter(pool, ssopg.ProviderRouterConfig{Clock: clock.System{}, Envelope: x.config.Envelope,
		MaximumDuration: 3 * time.Second, Lifetime: 8 * time.Second, PolicyVersion: 1, MaximumProviders: 4})
	if err != nil {
		t.Fatal(err)
	}
	return router
}

// Native first/retry calls use only real linked-member authority. Synthetic
// references, claims and copied envelopes below are rollback-only cardinality,
// never inputs accepted by a service. Plans discard predicates and wire values.
func TestNativeProviderLogoutStartQueryScale(t *testing.T) {
	trace := new(providerTrace)
	x := newNativeProviderLogoutFixture(t, true, trace)
	f := x.journey.start.enable.f
	for sample := range 3 {
		trace.mu.Lock()
		trace.queries = nil
		trace.mu.Unlock()
		started := time.Now()
		got, err := x.service.Start(f.ctx, x.request, x.browser)
		elapsed := time.Since(started)
		if err != nil || got.Outcome() != oidc.OIDCLogoutRedirect {
			t.Fatal("capture original native logout first/retry", err)
		}
		trace.mu.Lock()
		queries, traceErr := append([]providerQuery(nil), trace.queries...), trace.err
		trace.mu.Unlock()
		if traceErr != nil {
			t.Fatal(traceErr)
		}
		t.Logf("native logout sample=%d first=%t elapsed=%s provider-statements=%d; committed fixture cardinality, includes client/pool/coordinator work; kernel/session query count not traced", sample, sample == 0, elapsed, len(queries))
		if sample == 0 {
			measureNativeProviderLogoutQueries(t, f, queries)
		}
	}
}

func measureNativeProviderLogoutQueries(t *testing.T, f *orgFixture, queries []providerQuery) {
	t.Helper()
	selected := map[string]providerQuery{}
	for _, query := range queries {
		name := ""
		switch {
		case strings.HasPrefix(query.sql, "WITH account AS MATERIALIZED"):
			name = "issuer-read"
			if strings.Contains(query.sql, "FOR SHARE") {
				name = "issuer-lock"
			}
		case strings.HasPrefix(query.sql, "INSERT INTO sso_providers.logout_transactions"):
			name = "insert"
		case strings.HasPrefix(query.sql, "SELECT state_key_version,state_digest,issued_at,expires_at,binding_envelope,"):
			name = "by-start"
		}
		if name != "" {
			if previous, ok := selected[name]; !ok || len(query.oids) > len(previous.oids) {
				selected[name] = query
			}
		}
	}
	if len(selected) != 4 || len(selected["issuer-lock"].oids) != 8 || len(selected["insert"].oids) != 7 {
		t.Fatal("missing actual logout read/lock/insertion/lookup or native Work wire types")
	}
	tx, err := f.pool.Raw().Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.ctx)
	if _, err := tx.Exec(f.ctx, "SET LOCAL statement_timeout='15s'; SET LOCAL lock_timeout='1s'"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"issuer-read", "issuer-lock", "insert", "by-start"} {
		measureNativeProviderLogoutStatement(t, f, tx, "before-scale", name, selected[name], 1)
	}
	populateNativeProviderLogoutScale(t, f, tx, selected["issuer-read"], selected["by-start"])
	var engine string
	var providers, hotProviders, accounts, associations, logouts, hotLogouts int
	issuer := selected["issuer-read"]
	if err := tx.QueryRow(f.ctx, `SELECT current_setting('server_version'),
 (SELECT count(*) FROM sso_providers.providers),
 (SELECT count(*) FROM sso_providers.providers WHERE tenant_id=$1 AND organization_id=$2),
 (SELECT count(*) FROM identity.accounts), (SELECT count(*) FROM identity.account_credentials),
 (SELECT count(*) FROM sso_providers.logout_transactions),
 (SELECT count(*) FROM sso_providers.logout_transactions WHERE tenant_id=$1)`, issuer.args[0], issuer.args[1]).Scan(&engine, &providers, &hotProviders, &accounts, &associations, &logouts, &hotLogouts); err != nil || providers < 100001 || hotProviders < 10001 || accounts < 100001 || associations < 100001 || logouts != 100001 || hotLogouts != 10001 {
		t.Fatal("logout representative population mismatch", providers, hotProviders, accounts, associations, logouts, hotLogouts, err)
	}
	var columns, indexes []byte
	if err := tx.QueryRow(f.ctx, `SELECT
 (SELECT jsonb_agg(jsonb_build_object('table',c.relname,'column',a.attname,'type',format_type(a.atttypid,a.atttypmod)) ORDER BY c.relname,a.attnum)
 FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE ((n.nspname='sso_providers' AND c.relname IN ('providers','logout_transactions')) OR (n.nspname='identity' AND c.relname IN ('accounts','account_credentials')))
 AND a.attnum>0 AND NOT a.attisdropped),
 (SELECT jsonb_agg(jsonb_build_object('table',tablename,'definition',indexdef) ORDER BY schemaname,tablename,indexname)
 FROM pg_indexes WHERE (schemaname='sso_providers' AND tablename IN ('providers','logout_transactions')) OR (schemaname='identity' AND tablename IN ('accounts','account_credentials')))`).Scan(&columns, &indexes); err != nil {
		t.Fatal("inspect installed logout column types/indexes", err)
	}
	t.Logf("PostgreSQL=%s rollback-only providers=%d hot-providers=%d accounts=%d associations=%d logout-rows=%d hot-logout=%d; 1000 colder tenants, 90 rows each; original scope has 10000 added rows; isolated, no concurrent load, no forced planner settings; first sample may be cold", engine, providers, hotProviders, accounts, associations, logouts, hotLogouts)
	t.Logf("actual-column-types=%s actual-indexes=%s", columns, indexes)
	for _, name := range []string{"issuer-read", "issuer-lock", "insert", "by-start"} {
		query := selected[name]
		measureNativeProviderLogoutStatement(t, f, tx, "dense-known", name, query, 1)
		if name == "insert" {
			// VALUES always inserts one row; no-match is not its contract.
			continue
		}
		missingChanges := map[int]any{5: "logout-cost-missing"}
		if name == "by-start" {
			command := md5.Sum([]byte("logout-cost-missing"))
			missingChanges = map[int]any{1: command[:]}
		}
		missing := nativeProviderLogoutQueryBindings(t, query, missingChanges)
		measureNativeProviderLogoutStatement(t, f, tx, "no-match", name, missing, 0)
		changes := map[int]any{0: "logout-cost-tenant-1"}
		if strings.HasPrefix(name, "issuer-") {
			changes[1], changes[2], changes[5] = "logout-cost-org-1", "logout-cost-10001", "logout-cost-10001"
		} else {
			command := md5.Sum([]byte("logout-cost-start-10001"))
			changes[1] = command[:]
		}
		// A selective synthetic row proves SQL cardinality/access only; its
		// copied issuer/envelope does not establish an accepted issuer binding.
		measureNativeProviderLogoutStatement(t, f, tx, "selective-known", name, nativeProviderLogoutQueryBindings(t, query, changes), 1)
	}
	// Install the exact additive protocol SQL in the same rollback-only schema.
	// These are structural suffix variants with observed native bindings, not
	// an independently authenticated protocol-registry logout journey.
	protocol, err := (ssopg.ProviderProtocolMigrationSource{Version: 370, ValidationVersion: 371}).Load(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, migration := range protocol {
		if _, err := tx.Exec(f.ctx, migration.UpSQL()); err != nil {
			t.Fatal("install protocol suffix prerequisite", err)
		}
	}
	for _, name := range []string{"issuer-read", "issuer-lock"} {
		query := selected[name]
		query.sql = strings.Replace(query.sql, " AND p.issuer_digest=account.digest", " AND p.protocol='oidc' AND p.issuer_digest=account.digest", 1)
		measureNativeProviderLogoutStatement(t, f, tx, "protocol-suffix-dense", name, query, 1)
		measureNativeProviderLogoutStatement(t, f, tx, "protocol-suffix-missing", name, nativeProviderLogoutQueryBindings(t, query, map[int]any{5: "logout-cost-missing"}), 0)
	}
	if err := tx.Rollback(f.ctx); err != nil {
		t.Fatal("rollback scaled logout population and measured writes", err)
	}
}

func populateNativeProviderLogoutScale(t *testing.T, f *orgFixture, tx pgx.Tx, issuer, lookup providerQuery) {
	t.Helper()
	statements := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO sso_providers.providers(tenant_id,organization_id,provider_id,issuer_digest,configuration_envelope,mapping_version,pending_domains,version,enabled,enablement_proof,enablement_credential_generation,metadata_version,metadata_configuration_envelope,metadata_mapping_version)
 SELECT CASE WHEN n<=10000 THEN tenant_id ELSE 'logout-cost-tenant-'||(n%1000)::text END,
 CASE WHEN n<=10000 THEN organization_id ELSE 'logout-cost-org-'||(n%100)::text END,
 'logout-cost-'||n::text,sha256(convert_to('https://logout-cost-'||n::text||'.example.test','UTF8')),configuration_envelope,mapping_version,pending_domains,version,enabled,enablement_proof,enablement_credential_generation,metadata_version,metadata_configuration_envelope,metadata_mapping_version
 FROM sso_providers.providers CROSS JOIN generate_series(1,100000) n WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`, issuer.args[:3]},
		{`INSERT INTO identity.users(tenant_id,user_id,status,version)
 SELECT DISTINCT tenant_id,$1::text,'active',1 FROM sso_providers.providers WHERE provider_id LIKE 'logout-cost-%' ON CONFLICT DO NOTHING`, []any{issuer.args[6]}},
		{`INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled)
 SELECT tenant_id,$1::text,provider_id,3,'sso',1,true FROM sso_providers.providers WHERE provider_id LIKE 'logout-cost-%'`, []any{issuer.args[6]}},
		{`INSERT INTO identity.accounts(tenant_id,user_id,account_id,provider,issuer,subject,subject_key,version,social_link_version,linked)
 SELECT p.tenant_id,$2::text,p.provider_id,a.provider,issuer.value,p.provider_id,
 sha256(convert_to(octet_length(a.provider)::text||':'||a.provider||octet_length(issuer.value)::text||':'||issuer.value||octet_length(p.provider_id)::text||':'||p.provider_id,'UTF8')),1,1,true
 FROM sso_providers.providers p CROSS JOIN identity.accounts a JOIN identity.account_credentials m
 ON (m.tenant_id,m.user_id,m.account_id)=(a.tenant_id,a.user_id,a.account_id)
 CROSS JOIN LATERAL (SELECT 'https://'||p.provider_id||'.example.test' AS value) issuer
 WHERE p.provider_id LIKE 'logout-cost-%' AND m.tenant_id=$1 AND m.user_id=$2 AND m.credential_id=$3`, []any{issuer.args[0], issuer.args[6], issuer.args[5]}},
		{`INSERT INTO identity.account_credentials(tenant_id,user_id,credential_id,account_id)
 SELECT tenant_id,$1::text,provider_id,provider_id FROM sso_providers.providers WHERE provider_id LIKE 'logout-cost-%'`, []any{issuer.args[6]}},
		{`INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields)
 SELECT decode(md5('logout-cost-start-'||n::text),'hex'),CASE WHEN n<=10000 THEN $1::text ELSE 'logout-cost-tenant-'||(n%1000)::text END,
 'identity.sso.oidc-logout',decode(md5(n::text)||md5('logout-claim-'||n::text),'hex'),1,decode('01','hex') FROM generate_series(1,100000) n`, issuer.args[:1]},
		{`INSERT INTO identity.commands(command_id,tenant_id,purpose)
 SELECT decode(md5('logout-cost-start-'||n::text),'hex'),CASE WHEN n<=10000 THEN $1::text ELSE 'logout-cost-tenant-'||(n%1000)::text END,
 'identity.sso.oidc-logout' FROM generate_series(1,100000) n`, issuer.args[:1]},
		{`INSERT INTO sso_providers.logout_transactions(tenant_id,state_key_version,state_digest,start_command_id,issued_at,expires_at,binding_envelope)
 SELECT CASE WHEN n<=10000 THEN l.tenant_id ELSE 'logout-cost-tenant-'||(n%1000)::text END,l.state_key_version,
 decode(md5(n::text)||md5('logout-state-'||n::text),'hex'),decode(md5('logout-cost-start-'||n::text),'hex'),l.issued_at,l.expires_at,l.binding_envelope
 FROM sso_providers.logout_transactions l CROSS JOIN generate_series(1,100000) n WHERE l.tenant_id=$1 AND l.start_command_id=$2`, lookup.args},
		{`ANALYZE sso_providers.providers; ANALYZE identity.users; ANALYZE identity.accounts; ANALYZE identity.account_credentials; ANALYZE identity.commands; ANALYZE sso_providers.logout_transactions`, nil},
	}
	for _, statement := range statements {
		if _, err := tx.Exec(f.ctx, statement.sql, statement.args...); err != nil {
			t.Fatal("rollback-only logout cost population", err)
		}
	}
}

func nativeProviderLogoutQueryBindings(t *testing.T, query providerQuery, changes map[int]any) providerQuery {
	t.Helper()
	query.args = append([]any(nil), query.args...)
	query.values = append([][]byte(nil), query.values...)
	for index, value := range changes {
		query.args[index] = value
		if len(query.oids) == 0 {
			continue
		}
		format := int16(0)
		if len(query.formats) == 1 {
			format = query.formats[0]
		} else if len(query.formats) == len(query.args) {
			format = query.formats[index]
		}
		var err error
		query.values[index], err = pgtype.NewMap().Encode(query.oids[index], format, value, nil)
		if err != nil {
			t.Fatal("encode scope variant using captured native type/format", err)
		}
	}
	return query
}

func measureNativeProviderLogoutStatement(t *testing.T, f *orgFixture, tx pgx.Tx, scope, name string, query providerQuery, want int64) {
	t.Helper()
	types := make([]string, len(query.args))
	for index, argument := range query.args {
		types[index] = fmt.Sprintf("%T", argument)
	}
	for sample := range 3 {
		if _, err := tx.Exec(f.ctx, "SAVEPOINT logout_sample"); err != nil {
			t.Fatal(err)
		}
		if name == "insert" {
			if _, err := tx.Exec(f.ctx, `DELETE FROM sso_providers.logout_transactions WHERE tenant_id=$1 AND start_command_id=$2`, query.args[0], query.args[3]); err != nil {
				t.Fatal("prepare exact original insertion replay", err)
			}
		}
		if _, err := tx.Exec(f.ctx, "SAVEPOINT logout_plan"); err != nil {
			t.Fatal(err)
		}
		var wire []byte
		if len(query.oids) > 0 {
			result := tx.Conn().PgConn().ExecParams(f.ctx, "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) "+query.sql, query.values, query.oids, query.formats, nil).Read()
			if result.Err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
				t.Fatal("captured logout wire plan", name, result.Err)
			}
			wire = result.Rows[0][0]
		} else if err := tx.QueryRow(f.ctx, "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) "+query.sql, query.args...).Scan(&wire); err != nil {
			t.Fatal("captured logout driver plan", name, err)
		}
		var plans []struct {
			Plan          nativeOAuth2CallbackPlan `json:"Plan"`
			ExecutionTime float64                  `json:"Execution Time"`
		}
		err := json.Unmarshal(wire, &plans)
		clear(wire)
		if err != nil || len(plans) != 1 {
			t.Fatal("decode structural logout plan", name, err)
		}
		var inspect func(nativeOAuth2CallbackPlan)
		inspect = func(node nativeOAuth2CallbackPlan) {
			// Exact equality keys bound work independently of elapsed-time
			// noise. Tiny native tables may legitimately use sequential scans.
			if node.ActualRows*float64(node.ActualLoops) > 4 || node.FilteredRows*float64(node.ActualLoops) > 4 || node.JoinFiltered*float64(node.ActualLoops) > 4 {
				t.Fatal("logout exact query examined growing work", scope, name, node.NodeType, node.RelationName, node.IndexName, node.ActualRows, node.ActualLoops, node.FilteredRows)
			}
			for _, child := range node.ChildPlans {
				inspect(child)
			}
		}
		inspect(plans[0].Plan)
		if _, err := tx.Exec(f.ctx, "ROLLBACK TO SAVEPOINT logout_plan"); err != nil {
			t.Fatal(err)
		}
		started := time.Now()
		var actual int64
		if len(query.oids) > 0 {
			result := tx.Conn().PgConn().ExecParams(f.ctx, query.sql, query.values, query.oids, query.formats, nil).Read()
			if result.Err != nil {
				t.Fatal("execute captured logout parameters", name, result.Err)
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
				t.Fatal("execute logout driver parameters", name, err)
			}
			actual = tag.RowsAffected()
		}
		elapsed := time.Since(started)
		if actual != want {
			t.Fatal("logout returned/inserted cardinality", scope, name, actual, want)
		}
		safePlan, err := json.Marshal(plans)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("scope=%s query=%s sample=%d SQL=%s types=%v native-OIDs=%v formats=%v rows=%d client-elapsed=%s safe-plan=%s", scope, name, sample, query.sql, types, query.oids, query.formats, actual, elapsed, safePlan)
		if _, err := tx.Exec(f.ctx, "ROLLBACK TO SAVEPOINT logout_sample; RELEASE SAVEPOINT logout_sample"); err != nil {
			t.Fatal(err)
		}
	}
}
