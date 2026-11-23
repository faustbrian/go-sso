//go:build integration

package postgres_test

import (
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-sso/oidc"
	"github.com/jackc/pgx/v5"
)

// This companion SELECT is a typed fixture of the recovery query in
// provider_logout_complete_phase.go, not an observed recovery lifecycle.
// Its exact row arguments/OIDs/formats come from the real completion UPDATE.
const nativeLogoutCompletionEvidenceFixtureSQL = `SELECT COALESCE(completion_kind,''),COALESCE(completion_command_id,''::bytea)
 FROM sso_providers.logout_transactions WHERE (tenant_id,state_key_version,state_digest)=($1,$2,$3)
 AND start_command_id=$4 AND binding_envelope=$5 AND issued_at=$6 AND expires_at=$7`

// The real callback produces the measured SELECT and UPDATE. Scaled custody
// copies and foundation-only command rows roll back and never reach a service;
// only the original native command establishes committed start authority.
func TestNativeProviderLogoutCompleteQueryScale(t *testing.T) {
	trace := new(providerTrace)
	x := newNativeProviderLogoutFixture(t, true, trace)
	f := x.journey.start.enable.f
	request, _ := startNativeProviderLogoutCallback(t, x)
	trace.mu.Lock()
	trace.queries = nil
	trace.mu.Unlock()
	started := time.Now()
	completed, err := x.service.Complete(f.ctx, request)
	elapsed := time.Since(started)
	if err != nil || completed.Validate() != nil || completed.Outcome() != oidc.OIDCLogoutRedirect {
		t.Fatal("capture actual successful native logout completion", err)
	}
	trace.mu.Lock()
	queries, traceErr := append([]providerQuery(nil), trace.queries...), trace.err
	trace.mu.Unlock()
	if traceErr != nil {
		t.Fatal(traceErr)
	}
	selected := map[string]providerQuery{}
	for _, query := range queries {
		name := ""
		switch {
		case strings.HasPrefix(query.sql, "SELECT t.state_key_version,t.state_digest,t.start_command_id,t.issued_at,t.expires_at,t.binding_envelope"):
			name = "pending"
		case strings.HasPrefix(query.sql, "WITH locked AS MATERIALIZED (") && strings.Contains(query.sql, "RETURNING t.completion_kind"):
			name = "complete"
		}
		if name != "" {
			if previous, exists := selected[name]; !exists || len(query.oids) > len(previous.oids) {
				selected[name] = query
			}
		}
	}
	if len(selected) != 2 || len(selected["pending"].args) != 3 || len(selected["complete"].oids) != 9 {
		t.Fatal("actual native completion SELECT/UPDATE or Work wire types missing")
	}
	t.Logf("native successful completion elapsed=%s provider-statements=%d; committed fixture cardinality, includes client/pool/coordinator work; kernel/session SQL is not counted; scaled statements below are separate rollback-only cost evidence", elapsed, len(queries))
	update := selected["complete"]
	recovery := update
	recovery.sql = nativeLogoutCompletionEvidenceFixtureSQL
	recovery.args, recovery.oids, recovery.values = recovery.args[:7], recovery.oids[:7], recovery.values[:7]
	if len(recovery.formats) == len(update.args) {
		recovery.formats = recovery.formats[:7]
	}
	selected["recovery-fixture"] = recovery
	tx, err := f.pool.Raw().Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.ctx)
	if _, err := tx.Exec(f.ctx, "SET LOCAL statement_timeout='15s'; SET LOCAL lock_timeout='1s'"); err != nil {
		t.Fatal(err)
	}
	// Restore only the fixture's original pre-completion custody inside this
	// transaction. The real committed completion and its native command remain
	// unchanged outside it; every measured UPDATE rolls back to this snapshot.
	if _, err := tx.Exec(f.ctx, `UPDATE sso_providers.logout_transactions
 SET completed_at=NULL,completion_command_id=NULL,completion_kind=NULL
 WHERE tenant_id=$1 AND start_command_id=$2`, update.args[0], update.args[3]); err != nil {
		t.Fatal("restore rollback-only pending snapshot", err)
	}
	// The pending SELECT also reads command history. A sequential scan of a
	// tiny native journal is legitimate; enforce bounded index work only once
	// that relation has representative cardinality, without forcing its planner.
	for _, name := range []string{"complete", "recovery-fixture"} {
		measureNativeProviderLogoutStatement(t, f, tx, "completion-before-scale", name, selected[name], 1)
	}
	var engine string
	var columns, indexes []byte
	if err := tx.QueryRow(f.ctx, `SELECT current_setting('server_version'),
 (SELECT jsonb_agg(jsonb_build_object('table',c.relname,'column',a.attname,'type',format_type(a.atttypid,a.atttypmod)) ORDER BY c.relname,a.attnum)
 FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE ((n.nspname='sso_providers' AND c.relname='logout_transactions') OR (n.nspname='identity' AND c.relname='commands')) AND a.attnum>0 AND NOT a.attisdropped),
 (SELECT jsonb_agg(jsonb_build_object('table',tablename,'definition',indexdef) ORDER BY schemaname,tablename,indexname)
 FROM pg_indexes WHERE (schemaname='sso_providers' AND tablename='logout_transactions') OR (schemaname='identity' AND tablename='commands'))`).Scan(&engine, &columns, &indexes); err != nil {
		t.Fatal("inspect installed completion schema/indexes", err)
	}
	t.Logf("PostgreSQL=%s actual-column-types=%s actual-indexes=%s; isolated, no concurrent load or forced planner settings; first sample may be cold", engine, columns, indexes)
	for _, scale := range []struct {
		name        string
		first, last int
		rows, hot   int
	}{
		{"selective-known", 10001, 100000, 90001, 1},
		{"dense-known", 1, 10000, 100001, 10001},
	} {
		populateNativeProviderLogoutCompletionScale(t, f, tx, update, scale.first, scale.last)
		var rows, hot int
		if err := tx.QueryRow(f.ctx, `SELECT count(*),count(*) FILTER(WHERE tenant_id=$1) FROM sso_providers.logout_transactions`, update.args[0]).Scan(&rows, &hot); err != nil || rows != scale.rows || hot != scale.hot {
			t.Fatal("completion representative population mismatch", scale.name, rows, hot, err)
		}
		t.Logf("completion scope=%s rollback-only logout-rows=%d original-tenant-rows=%d; 1000 colder tenants with 90 rows each; synthetic command rows retain NULL state and do not establish committed authority", scale.name, rows, hot)
		for _, name := range []string{"pending", "complete", "recovery-fixture"} {
			query := selected[name]
			measureNativeProviderLogoutStatement(t, f, tx, "completion-"+scale.name, name, query, 1)
			missing := sha256.Sum256([]byte("logout-completion-cost-missing-state"))
			var digest any = missing[:]
			if name == "pending" {
				versions, ok := query.args[1].([]int64)
				if !ok || len(versions) == 0 {
					t.Fatal("native pending state-key array type missing")
				}
				digests := make([][]byte, len(versions))
				for index := range digests {
					digests[index] = missing[:]
				}
				digest = digests
			}
			noMatch := nativeProviderLogoutQueryBindings(t, query, map[int]any{2: digest})
			measureNativeProviderLogoutStatement(t, f, tx, "completion-"+scale.name+"-no-match", name, noMatch, 0)
		}
	}
	// The recovery SELECT must also examine terminal evidence, not just the
	// pending snapshot. Use the actual completion's native command and kind.
	if _, err := tx.Exec(f.ctx, `UPDATE sso_providers.logout_transactions
 SET completed_at=expires_at,completion_command_id=$3,completion_kind=$4
 WHERE tenant_id=$1 AND start_command_id=$2`, update.args[0], update.args[3], update.args[7], update.args[8]); err != nil {
		t.Fatal("restore rollback-only terminal evidence", err)
	}
	measureNativeProviderLogoutStatement(t, f, tx, "completion-dense-terminal", "recovery-fixture", recovery, 1)
	measureNativeProviderLogoutStatement(t, f, tx, "completion-dense-terminal", "pending", selected["pending"], 0)
	measureNativeProviderLogoutStatement(t, f, tx, "completion-dense-terminal", "complete", update, 0)
	if err := tx.Rollback(f.ctx); err != nil {
		t.Fatal("rollback all completion scale population and measured writes", err)
	}
}

func populateNativeProviderLogoutCompletionScale(t *testing.T, f *orgFixture, tx pgx.Tx, update providerQuery, first, last int) {
	t.Helper()
	for _, statement := range []string{
		`INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields)
 SELECT decode(md5('logout-completion-cost-start-'||n::text),'hex'),CASE WHEN n<=10000 THEN $3::text ELSE 'logout-completion-cost-tenant-'||(n%1000)::text END,
 'identity.sso.oidc-logout',decode(md5(n::text)||md5('logout-completion-claim-'||n::text),'hex'),1,decode('01','hex') FROM generate_series($1::int,$2::int) n`,
		`INSERT INTO identity.commands(command_id,tenant_id,purpose)
 SELECT decode(md5('logout-completion-cost-start-'||n::text),'hex'),CASE WHEN n<=10000 THEN $3::text ELSE 'logout-completion-cost-tenant-'||(n%1000)::text END,
 'identity.sso.oidc-logout' FROM generate_series($1::int,$2::int) n`,
		`INSERT INTO sso_providers.logout_transactions(tenant_id,state_key_version,state_digest,start_command_id,issued_at,expires_at,binding_envelope)
 SELECT CASE WHEN n<=10000 THEN l.tenant_id ELSE 'logout-completion-cost-tenant-'||(n%1000)::text END,l.state_key_version,
 decode(md5(n::text)||md5('logout-completion-state-'||n::text),'hex'),decode(md5('logout-completion-cost-start-'||n::text),'hex'),l.issued_at,l.expires_at,l.binding_envelope
 FROM sso_providers.logout_transactions l CROSS JOIN generate_series($1::int,$2::int) n WHERE l.tenant_id=$3 AND l.start_command_id=$4`,
	} {
		args := []any{first, last, update.args[0]}
		if strings.Contains(statement, "$4") {
			args = append(args, update.args[3])
		}
		if _, err := tx.Exec(f.ctx, statement, args...); err != nil {
			t.Fatal("rollback-only completion cost population", err)
		}
	}
	if _, err := tx.Exec(f.ctx, `ANALYZE identity.commands; ANALYZE sso_providers.logout_transactions`); err != nil {
		t.Fatal(err)
	}
}
