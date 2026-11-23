//go:build integration

package postgres_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/jackc/pgx/v5"
)

// Only the original native grant is presented to the claim function. Synthetic
// grants and command provenance below supply rollback-only storage cardinality;
// copied ciphertext is not authenticated authority or a provider-send fixture.
func TestNativeProviderGrantFenceQueryScale(t *testing.T) {
	x := newNativeOAuth2JourneyFixture(t, "restorable-vault")
	f := x.start.enable.f
	result, err := x.completion.SigninCallbackOAuth2(f.ctx, x.request)
	if err != nil || result.Completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("commit native enterprise grant for cost measurement", err)
	}
	history, err := (ssopg.ProviderGrantFenceMigrationSource{Version: 355}).Load(f.ctx)
	if err != nil || len(history) != 1 {
		t.Fatal("load grant fence prerequisite", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, history[0].UpSQL()); err != nil {
		t.Fatal("install grant fence prerequisite", err)
	}
	claim := ssopg.ProviderGrantFenceClaimForTest{Tenant: result.Completion.Binding.TenantID,
		Callback: result.Completion.Binding.CommandID, TokenVersion: 1,
		Operation: "identity.sso.provider-token.revoke", Generation: 1}
	var digest []byte
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT sha256(token_ciphertext) FROM sso_providers.provider_login_token_sets
WHERE tenant_id=$1 AND callback_command_id=$2`, string(claim.Tenant), string(claim.Callback)).Scan(&digest); err != nil || len(digest) != 32 {
		t.Fatal("read native committed grant fingerprint", err)
	}
	claim.CiphertextDigest = [32]byte(digest)
	claim.Attempt, err = identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := base64.RawURLEncoding.Strict().DecodeString(string(claim.Attempt))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `WITH claim AS (
 INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields)
 VALUES($1,$2,$3,sha256($1),1,decode('01','hex')) RETURNING command_id,tenant_id,purpose
) INSERT INTO identity.commands(command_id,tenant_id,purpose) SELECT command_id,tenant_id,purpose FROM claim`, attempt, string(claim.Tenant), claim.Operation); err != nil {
		t.Fatal("seed storage-only attempt command provenance", err)
	}
	trace := new(providerTrace)
	pool, err := database.Connect(f.ctx, database.Config{DSN: f.dsn, MaxConns: 1, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database, c.ConnConfig.Tracer = f.database, trace
		// CacheDescribe uses the same backend-described types and pgx codecs
		// as cached statements, but exposes explicit OIDs to the wire tracer.
		c.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeCacheDescribe
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
		t.Fatal("connect bounded native grant fence trace pool", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := pool.Close(ctx); err != nil {
			t.Error("close native grant fence trace pool", err)
		}
	})
	var query providerQuery
	for sample := range 3 {
		trace.mu.Lock()
		trace.queries = nil
		trace.mu.Unlock()
		started := time.Now()
		err := ssopg.ClaimProviderGrantFenceForTest(f.ctx, pool.Raw(), claim)
		elapsed := time.Since(started)
		if sample == 0 && err != nil || sample > 0 && !errors.Is(err, identity.ConflictError{}) {
			t.Fatal("native first/duplicate fence result", sample, err)
		}
		trace.mu.Lock()
		queries, traceErr := append([]providerQuery(nil), trace.queries...), trace.err
		trace.mu.Unlock()
		if traceErr != nil {
			t.Fatal(traceErr)
		}
		var calls int
		for _, captured := range queries {
			if !strings.HasPrefix(captured.sql, "INSERT INTO sso_providers.provider_grant_fences") {
				t.Fatal("native fence performed an unexpected storage statement")
			}
			if len(captured.oids) == 0 {
				calls++
			} else {
				query = captured
			}
		}
		if calls != 1 || len(query.oids) != 7 || len(query.values) != 7 {
			t.Fatal("native fence did not expose one statement and seven typed wire bindings", calls, len(query.oids))
		}
		t.Logf("native-grant-fence sample=%d first=%t operation-elapsed=%s statements=%d; committed fixture cardinality, includes client/pool work", sample, sample == 0, elapsed, calls)
	}

	tx, err := f.pool.Raw().Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.ctx)
	if _, err := tx.Exec(f.ctx, "SET LOCAL statement_timeout='15s'; SET LOCAL lock_timeout='1s'"); err != nil {
		t.Fatal(err)
	}
	measureNativeProviderGrantFenceQuery(t, f, tx, "before-scale-duplicate", query, 0)
	populateNativeProviderGrantFenceScale(t, f, tx, query)
	var engine string
	var grants, hotGrants, fences, hotFences int
	if err := tx.QueryRow(f.ctx, `SELECT current_setting('server_version'),
 (SELECT count(*) FROM sso_providers.provider_login_token_sets),
 (SELECT count(*) FROM sso_providers.provider_login_token_sets WHERE tenant_id=$1),
 (SELECT count(*) FROM sso_providers.provider_grant_fences),
 (SELECT count(*) FROM sso_providers.provider_grant_fences WHERE tenant_id=$1)`, query.args[0]).Scan(&engine, &grants, &hotGrants, &fences, &hotFences); err != nil || grants != 40001 || hotGrants != 4001 || fences != 39999 || hotFences != 4000 {
		t.Fatal("representative grant/fence population mismatch", grants, hotGrants, fences, hotFences, err)
	}
	var columns, indexes []byte
	if err := tx.QueryRow(f.ctx, `SELECT
 (SELECT jsonb_agg(jsonb_build_object('table',c.relname,'column',a.attname,'type',format_type(a.atttypid,a.atttypmod)) ORDER BY c.relname,a.attnum)
 FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='sso_providers' AND c.relname IN ('provider_login_token_sets','provider_grant_fences') AND a.attnum>0 AND NOT a.attisdropped),
 (SELECT jsonb_agg(jsonb_build_object('table',tablename,'definition',indexdef) ORDER BY tablename,indexname)
 FROM pg_indexes WHERE schemaname='sso_providers' AND tablename IN ('provider_login_token_sets','provider_grant_fences'))`).Scan(&columns, &indexes); err != nil {
		t.Fatal("inspect installed grant fence types/indexes", err)
	}
	t.Logf("PostgreSQL=%s rollback-only grants=%d hot-grants=%d fences=%d hot-fences=%d; 400 colder tenants, 90 grants each; isolated, no concurrent load or forced planner settings; first sample may be cold", engine, grants, hotGrants, fences, hotFences)
	t.Logf("actual-column-types=%s actual-indexes=%s", columns, indexes)
	for _, fixture := range []struct {
		name string
		n    int
		want int64
	}{{"hot-known", 1, 1}, {"cold-known", 4001, 1}, {"duplicate-generation", 2, 0}} {
		var tenant, callback, purpose string
		var attempt []byte
		if err := tx.QueryRow(f.ctx, `SELECT tenant_id,callback_command_id,attempt_command_id,attempt_purpose FROM grant_fence_cost_rows WHERE n=$1`, fixture.n).Scan(&tenant, &callback, &attempt, &purpose); err != nil {
			t.Fatal("select rollback-only cardinality variant", err)
		}
		variant := nativeProviderLogoutQueryBindings(t, query, map[int]any{0: tenant, 1: callback, 3: attempt, 4: purpose})
		measureNativeProviderGrantFenceQuery(t, f, tx, fixture.name, variant, fixture.want)
		if fixture.name == "hot-known" {
			for _, missing := range []struct {
				name    string
				changes map[int]any
			}{{"absent-grant", map[int]any{1: "grant-fence-cost-missing"}},
				{"stale-version", map[int]any{2: "2"}},
				{"stale-ciphertext", map[int]any{6: make([]byte, 32)}}} {
				measureNativeProviderGrantFenceQuery(t, f, tx, missing.name, nativeProviderLogoutQueryBindings(t, variant, missing.changes), 0)
			}
		}
	}
	if err := tx.Rollback(f.ctx); err != nil {
		t.Fatal("rollback scaled grant custody, fences and measured writes", err)
	}
}

func populateNativeProviderGrantFenceScale(t *testing.T, f *orgFixture, tx pgx.Tx, query providerQuery) {
	t.Helper()
	statements := []string{
		`CREATE TEMP TABLE grant_fence_cost_rows ON COMMIT DROP AS
SELECT n,CASE WHEN n<=4000 THEN $1::text ELSE 'grant-fence-cost-tenant-'||(n%400)::text END AS tenant_id,
 'grant-fence-cost-'||n::text AS provider_id,'grant-fence-cost-start-'||n::text AS start_command_id,
 translate(rtrim(encode(decode(md5('grant-fence-cost-grant-'||n::text),'hex'),'base64'),'='),'+/','-_') AS callback_command_id,
 decode(md5('grant-fence-cost-grant-'||n::text),'hex') AS grant_command_id,
 decode(md5('grant-fence-cost-attempt-'||n::text),'hex') AS attempt_command_id,
 CASE WHEN n%2=0 THEN 'identity.sso.provider-token.refresh' ELSE 'identity.sso.provider-token.revoke' END AS attempt_purpose
FROM generate_series(1,40000) n`,
		`INSERT INTO identity.users(tenant_id,user_id,status,version)
SELECT DISTINCT r.tenant_id,u.user_id,u.status,u.version FROM grant_fence_cost_rows r
CROSS JOIN sso_providers.provider_login_token_sets v JOIN identity.users u ON (u.tenant_id,u.user_id)=(v.tenant_id,v.user_id)
WHERE v.tenant_id=$1 AND v.callback_command_id=$2 ON CONFLICT DO NOTHING`,
		`INSERT INTO identity.accounts(tenant_id,user_id,account_id,provider,issuer,subject,subject_key,version,social_link_version,linked)
SELECT DISTINCT r.tenant_id,a.user_id,a.account_id,a.provider,a.issuer,a.subject,a.subject_key,a.version,a.social_link_version,a.linked
FROM grant_fence_cost_rows r CROSS JOIN sso_providers.provider_login_token_sets v
JOIN identity.accounts a ON (a.tenant_id,a.user_id,a.account_id)=(v.tenant_id,v.user_id,v.account_id)
WHERE v.tenant_id=$1 AND v.callback_command_id=$2 ON CONFLICT DO NOTHING`,
		`INSERT INTO sso_providers.providers(tenant_id,organization_id,provider_id,issuer_digest,configuration_envelope,mapping_version,pending_domains,protocol)
SELECT r.tenant_id,v.organization_id,r.provider_id,sha256(convert_to(r.provider_id,'UTF8')),p.configuration_envelope,p.mapping_version,p.pending_domains,p.protocol
FROM grant_fence_cost_rows r CROSS JOIN sso_providers.provider_login_token_sets v
JOIN sso_providers.providers p ON (p.tenant_id,p.organization_id,p.provider_id)=(v.tenant_id,v.organization_id,v.provider_id)
WHERE v.tenant_id=$1 AND v.callback_command_id=$2`,
		`INSERT INTO sso_providers.login_transactions(tenant_id,organization_id,provider_id,provider_version,credential_generation,mapping_version,start_command_id,callback_command_id,protocol,state_key_version,state_digest,pkce_key_version,pkce_commitment,binding_envelope,verifier_envelope,issued_at,expires_at,completed_at)
SELECT r.tenant_id,v.organization_id,r.provider_id,l.provider_version,l.credential_generation,l.mapping_version,r.start_command_id,r.callback_command_id,l.protocol,l.state_key_version,sha256(convert_to(r.provider_id,'UTF8')),l.pkce_key_version,l.pkce_commitment,l.binding_envelope,l.verifier_envelope,l.issued_at,l.expires_at,l.completed_at
FROM grant_fence_cost_rows r CROSS JOIN sso_providers.provider_login_token_sets v
JOIN sso_providers.login_transactions l ON l.start_command_id=v.start_command_id
WHERE v.tenant_id=$1 AND v.callback_command_id=$2`,
		`WITH seed AS (
 SELECT r.tenant_id,c.command_id,c.purpose FROM grant_fence_cost_rows r
 CROSS JOIN LATERAL (VALUES(r.grant_command_id,'identity.sso.oauth-callback'),(r.attempt_command_id,r.attempt_purpose)) c(command_id,purpose)
) INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields)
SELECT command_id,tenant_id,purpose,sha256(command_id),1,decode('01','hex') FROM seed`,
		`INSERT INTO identity.commands(command_id,tenant_id,purpose)
SELECT c.command_id,r.tenant_id,c.purpose FROM grant_fence_cost_rows r
CROSS JOIN LATERAL (VALUES(r.grant_command_id,'identity.sso.oauth-callback'),(r.attempt_command_id,r.attempt_purpose)) c(command_id,purpose)`,
		`INSERT INTO sso_providers.provider_login_token_sets(tenant_id,organization_id,provider_id,start_command_id,callback_command_id,callback_generation,user_id,account_id,account_provider,issuer,subject,account_version,social_link_version,provider_version,credential_generation,mapping_version,token_version,requested_scopes,granted_scopes,scope_reported,received_at_seconds,received_at_nanoseconds,access_expires_at_seconds,access_expires_at_nanoseconds,token_ciphertext,origin_operation,origin_command_id)
SELECT r.tenant_id,v.organization_id,r.provider_id,r.start_command_id,r.callback_command_id,v.callback_generation,v.user_id,v.account_id,v.account_provider,v.issuer,v.subject,v.account_version,v.social_link_version,v.provider_version,v.credential_generation,v.mapping_version,v.token_version,v.requested_scopes,v.granted_scopes,v.scope_reported,v.received_at_seconds,v.received_at_nanoseconds,v.access_expires_at_seconds,v.access_expires_at_nanoseconds,v.token_ciphertext,v.origin_operation,r.grant_command_id
FROM grant_fence_cost_rows r CROSS JOIN sso_providers.provider_login_token_sets v WHERE v.tenant_id=$1 AND v.callback_command_id=$2`,
		`INSERT INTO sso_providers.provider_grant_fences(tenant_id,grant_command_id,token_version,attempt_command_id,attempt_purpose,attempt_generation,started_at)
SELECT tenant_id,grant_command_id,1,attempt_command_id,attempt_purpose,1,clock_timestamp() FROM grant_fence_cost_rows WHERE n NOT IN (1,4001)`,
		`ANALYZE sso_providers.provider_login_token_sets; ANALYZE sso_providers.provider_grant_fences; ANALYZE identity.commands`,
	}
	for _, statement := range statements {
		var args []any
		if strings.Contains(statement, "$2") {
			args = query.args[:2]
		} else if strings.Contains(statement, "$1") {
			args = query.args[:1]
		}
		if _, err := tx.Exec(f.ctx, statement, args...); err != nil {
			t.Fatal("populate rollback-only grant fence query cardinality", err)
		}
	}
}

func measureNativeProviderGrantFenceQuery(t *testing.T, f *orgFixture, tx pgx.Tx, scope string, query providerQuery, want int64) {
	t.Helper()
	types := make([]string, len(query.args))
	for index, argument := range query.args {
		types[index] = fmt.Sprintf("%T", argument)
	}
	for sample := range 3 {
		if _, err := tx.Exec(f.ctx, "SAVEPOINT grant_fence_sample"); err != nil {
			t.Fatal(err)
		}
		result := tx.Conn().PgConn().ExecParams(f.ctx, "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) "+query.sql, query.values, query.oids, query.formats, nil).Read()
		if result.Err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
			t.Fatal("capture native grant fence wire plan", scope, result.Err)
		}
		var plans []struct {
			Plan          nativeOAuth2CallbackPlan `json:"Plan"`
			ExecutionTime float64                  `json:"Execution Time"`
		}
		err := json.Unmarshal(result.Rows[0][0], &plans)
		clear(result.Rows[0][0])
		if err != nil || len(plans) != 1 {
			t.Fatal("decode structural grant fence plan", scope, err)
		}
		indexes := map[string]bool{}
		var inspect func(nativeOAuth2CallbackPlan)
		inspect = func(node nativeOAuth2CallbackPlan) {
			if node.ActualRows*float64(node.ActualLoops) > 4 || node.FilteredRows*float64(node.ActualLoops) > 4 || node.JoinFiltered*float64(node.ActualLoops) > 4 {
				t.Fatal("grant fence exact query examined growing work", scope, node.NodeType, node.RelationName, node.IndexName)
			}
			if node.IndexName != "" {
				indexes[node.IndexName] = true
			}
			for _, child := range node.ChildPlans {
				inspect(child)
			}
		}
		inspect(plans[0].Plan)
		if _, err := tx.Exec(f.ctx, "ROLLBACK TO SAVEPOINT grant_fence_sample"); err != nil {
			t.Fatal(err)
		}
		started := time.Now()
		executed := tx.Conn().PgConn().ExecParams(f.ctx, query.sql, query.values, query.oids, query.formats, nil).Read()
		elapsed := time.Since(started)
		if executed.Err != nil || executed.CommandTag.RowsAffected() != want {
			t.Fatal("native grant fence affected cardinality", scope, executed.CommandTag.RowsAffected(), want, executed.Err)
		}
		used := make([]string, 0, len(indexes))
		for index := range indexes {
			used = append(used, index)
		}
		sort.Strings(used)
		t.Logf("scope=%s sample=%d SQL=%s types=%v native-OIDs=%v formats=%v affected=%d client-elapsed=%s server-execution-ms=%g indexes=%v; no predicate or plan payload retained", scope, sample, query.sql, types, query.oids, query.formats, want, elapsed, plans[0].ExecutionTime, used)
		if _, err := tx.Exec(f.ctx, "ROLLBACK TO SAVEPOINT grant_fence_sample; RELEASE SAVEPOINT grant_fence_sample"); err != nil {
			t.Fatal(err)
		}
	}
}
