//go:build integration

package postgres_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// The genuine callback supplies the exact disposition/terminal Work SQL and
// binary bindings. Only representative storage cardinality and repeated writes
// use the rollback-only transaction; they never establish protocol authority.
func TestNativeSAMLCallbackQueryScale(t *testing.T) {
	for _, scale := range []string{"tiny", "hot"} {
		t.Run(scale, func(t *testing.T) {
			x := newNativeSAMLCallbackFixture(t)
			f := x.start.start.enable.f
			var pending []byte
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT binding_envelope FROM sso_providers.login_transactions WHERE start_command_id=$1`, x.started.TransactionID).Scan(&pending); err != nil {
				t.Fatal("retain original pending ciphertext in memory only", err)
			}
			defer clear(pending)
			tx, err := f.pool.Raw().Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(f.ctx)
			if _, err := tx.Exec(f.ctx, `SET LOCAL statement_timeout='15s'; SET LOCAL lock_timeout='1s'`); err != nil {
				t.Fatal(err)
			}
			if scale == "hot" {
				var issuer []byte
				if err := tx.QueryRow(f.ctx, `SELECT issuer_digest FROM sso_providers.providers WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`, string(x.start.start.config.TenantID), string(x.start.profiles[0].OrganizationID), string(x.start.profiles[0].ProviderID)).Scan(&issuer); err != nil {
					t.Fatal("read genuine issuer binding for replay distribution only", err)
				}
				// The existing scale loader consumes only these provider/generation/
				// retention fields and creates its own foundation-only command rows.
				// Do all expensive distribution setup before observing the callback's
				// short original deadlines; no captured deadline is later renewed.
				populateNativeSAMLReplayScale(t, f, tx, providerQuery{tracedQuery: tracedQuery{args: []any{
					string(x.start.start.config.TenantID), string(x.start.profiles[0].OrganizationID), string(x.start.profiles[0].ProviderID),
					issuer, nil, nil, "1", x.expires,
				}}})
				populateNativeSAMLCallbackScale(t, f, tx, x)
			}
			trace := new(providerTrace)
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
				t.Fatal("connect same-primary SAML callback trace pool", err)
			}
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				if err := pool.Close(ctx); err != nil {
					t.Error("close SAML callback trace pool", err)
				}
			})
			completion := ssopg.ProviderSAMLCallbackWithPoolForTest(x.completion, pool)
			startedAt := time.Now()
			got, err := completion.SigninCallback(f.ctx, x.request)
			elapsed := time.Since(startedAt)
			if err != nil || got.Completion.Outcome != identity.CommitOutcomeCommitted || got.Issuance.CommitOutcome != identity.CommitOutcomeCommitted || x.calls != 1 {
				t.Fatal("capture one genuine native SAML callback", err)
			}
			trace.mu.Lock()
			queries, traceErr := append([]providerQuery(nil), trace.queries...), trace.err
			trace.queries = nil
			trace.mu.Unlock()
			if traceErr != nil {
				t.Fatal(traceErr)
			}
			selected := map[string]providerQuery{}
			var replayInsert providerQuery
			for _, query := range queries {
				if len(query.oids) == 0 {
					continue
				}
				switch {
				case query.sql == ssopg.ProviderSAMLCallbackDispositionSQLForTest:
					selected["disposition"] = query
				case query.sql == ssopg.CompleteProviderSAMLCallbackSQLForTest:
					selected["terminal"] = query
				case strings.HasPrefix(query.sql, "INSERT INTO sso_providers.saml_replay_members"):
					replayInsert = query
				}
			}
			if len(selected) != 2 || len(selected["disposition"].oids) != 7 || len(selected["terminal"].oids) != 15 || len(replayInsert.oids) != 10 || len(replayInsert.formats) != 10 {
				t.Fatal("missing exact native SAML callback SQL or binary Work bindings")
			}
			wantDispositionOIDs := []uint32{pgtype.TextOID, pgtype.TextOID, pgtype.TextOID, pgtype.TextOID, pgtype.TextOID, pgtype.TextOID, pgtype.TimestamptzOID}
			wantTerminalOIDs := []uint32{pgtype.TextOID, pgtype.TextOID, pgtype.TextOID, pgtype.TextOID, pgtype.TextOID, pgtype.TextOID, pgtype.TextOID, pgtype.TextOID,
				pgtype.Int8OID, pgtype.ByteaOID, pgtype.TimestamptzOID, pgtype.TimestamptzOID, pgtype.TimestamptzOID, pgtype.ByteaOID, pgtype.ByteaOID}
			replayTypesMatch := replayInsert.oids[0] == pgtype.TextOID && replayInsert.oids[4] == pgtype.ByteaOID
			if !slices.Equal(selected["disposition"].oids, wantDispositionOIDs) || !slices.Equal(selected["terminal"].oids, wantTerminalOIDs) || !replayTypesMatch {
				t.Fatal("SAML Work binding types changed from native text/version, state, time and ciphertext primitives")
			}
			// Recovery uses the same tenant text and binary command as the native
			// replay reservation. Preserve those observed OIDs, formats and bytes; this
			// measures the exact recovery statement, not a recovery lifecycle.
			selected["replay-exists"] = providerQuery{
				tracedQuery: tracedQuery{sql: ssopg.SAMLReplayCommandExistsSQLForTest, args: []any{replayInsert.args[0], replayInsert.args[4]}},
				oids:        []uint32{replayInsert.oids[0], replayInsert.oids[4]},
				formats:     []int16{replayInsert.formats[0], replayInsert.formats[4]},
				values:      [][]byte{replayInsert.values[0], replayInsert.values[4]},
			}
			t.Logf("native callback client-elapsed=%s provider-statements=%d at committed fixture cardinality; scaled exact-statement replay below is separate, isolated, rollback-only, with no concurrent load", elapsed, len(queries))
			if _, err := tx.Exec(f.ctx, `UPDATE sso_providers.login_transactions SET completed_at=NULL,binding_envelope=$2 WHERE start_command_id=$1`, x.started.TransactionID, pending); err != nil {
				t.Fatal("restore original pending snapshot only inside rollback fixture", err)
			}
			var engine string
			var columns, indexes []byte
			if err := tx.QueryRow(f.ctx, `SELECT current_setting('server_version'),
 (SELECT jsonb_agg(jsonb_build_object('table',c.relname,'column',a.attname,'type',format_type(a.atttypid,a.atttypmod)) ORDER BY c.relname,a.attnum)
 FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='sso_providers' AND c.relname IN ('providers','credentials','login_transactions','saml_replay_members') AND a.attnum>0 AND NOT a.attisdropped),
 (SELECT jsonb_agg(jsonb_build_object('table',tablename,'definition',indexdef) ORDER BY tablename,indexname)
 FROM pg_indexes WHERE schemaname='sso_providers' AND tablename IN ('providers','credentials','login_transactions','saml_replay_members'))`).Scan(&engine, &columns, &indexes); err != nil {
				t.Fatal("inspect actual SAML callback storage types and usable indexes", err)
			}
			t.Logf("PostgreSQL=%s actual-column-types=%s actual-indexes=%s; normal planner; original native callback deadlines and ciphertext are never renewed", engine, columns, indexes)
			if _, err := tx.Exec(f.ctx, `ANALYZE sso_providers.providers; ANALYZE sso_providers.credentials; ANALYZE sso_providers.login_transactions; ANALYZE sso_providers.saml_replay_members`); err != nil {
				t.Fatal(err)
			}
			var providers, hot, history, active, members int
			if err := tx.QueryRow(f.ctx, `SELECT count(*),count(*) FILTER(WHERE tenant_id=$1 AND organization_id=$2),
 (SELECT count(*) FROM sso_providers.login_transactions WHERE completed_at IS NOT NULL),
 (SELECT count(*) FROM sso_providers.login_transactions WHERE completed_at IS NULL),
 (SELECT count(*) FROM sso_providers.saml_replay_members) FROM sso_providers.providers`, string(x.start.start.config.TenantID), string(x.start.profiles[0].OrganizationID)).Scan(&providers, &hot, &history, &active, &members); err != nil {
				t.Fatal("read actual SAML callback fixture distribution", err)
			}
			if scale == "hot" && (providers != 10101 || hot != 1001 || history != 10000 || active != 1025 || members != 40002) {
				t.Fatal("representative SAML callback skew mismatch", providers, hot, history, active, members)
			}
			t.Logf("scale=%s providers=%d hot-tenant-provider-scopes=%d retained-login-history=%d active-hot-logins=%d replay-members=%d; copied ciphertext supplies cardinality only", scale, providers, hot, history, active, members)
			for _, name := range []string{"disposition", "terminal", "replay-exists"} {
				measureNativeSAMLCallbackStatement(t, f, tx, scale, name, selected[name], pending)
			}
			if err := tx.Rollback(f.ctx); err != nil {
				t.Fatal("rollback SAML callback scale population and all measured writes", err)
			}
			var terminal, emptyPopulation bool
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT
 EXISTS(SELECT 1 FROM sso_providers.login_transactions WHERE start_command_id=$1 AND completed_at IS NOT NULL AND binding_envelope=$2),
 NOT EXISTS(SELECT 1 FROM sso_providers.providers WHERE provider_id LIKE 'saml-callback-cost-%' OR provider_id LIKE 'replay-cost-provider-%')`, x.started.TransactionID, selected["terminal"].args[13]).Scan(&terminal, &emptyPopulation); err != nil || !terminal || !emptyPopulation {
				t.Fatal("rollback leaked scaled rows or changed the genuine committed terminal", err)
			}
		})
	}
}

func populateNativeSAMLCallbackScale(t *testing.T, f *orgFixture, tx pgx.Tx, x *nativeSAMLCallbackFixture) {
	t.Helper()
	for _, population := range []struct {
		sql string
		arg any
	}{
		{`INSERT INTO sso_providers.providers(tenant_id,organization_id,provider_id,issuer_digest,configuration_envelope,mapping_version,pending_domains,protocol)
 SELECT CASE WHEN n<=1000 THEN tenant_id ELSE 'saml-callback-cost-'||(n%900)::text END,
 CASE WHEN n<=1000 THEN organization_id ELSE 'saml-callback-org-'||(n%100)::text END,
 'saml-callback-cost-'||n::text,decode(md5(n::text)||md5('callback-issuer-'||n::text),'hex'),configuration_envelope,mapping_version,pending_domains,'saml'
 FROM sso_providers.providers CROSS JOIN generate_series(1,10000) n WHERE provider_id=$1`, string(x.start.profiles[0].ProviderID)},
		{`INSERT INTO sso_providers.credentials(tenant_id,organization_id,provider_id,generation,provider_version,envelope,credential_context)
 SELECT p.tenant_id,p.organization_id,p.provider_id,c.generation,c.provider_version,c.envelope,c.credential_context
 FROM sso_providers.providers p CROSS JOIN sso_providers.credentials c WHERE p.provider_id LIKE 'saml-callback-cost-%' AND c.provider_id=$1`, string(x.start.profiles[0].ProviderID)},
		{`INSERT INTO sso_providers.login_transactions(tenant_id,organization_id,provider_id,provider_version,credential_generation,mapping_version,start_command_id,callback_command_id,protocol,state_key_version,state_digest,pkce_key_version,pkce_commitment,binding_envelope,verifier_envelope,issued_at,expires_at,completed_at)
 SELECT p.tenant_id,p.organization_id,p.provider_id,l.provider_version,l.credential_generation,l.mapping_version,
 'saml-callback-history-start-'||p.provider_id,'saml-callback-history-callback-'||p.provider_id,'saml',l.state_key_version,
 decode(md5(p.provider_id)||md5('state-'||p.provider_id),'hex'),NULL,NULL,l.binding_envelope,NULL,
 l.issued_at-interval '1 day',l.expires_at-interval '1 day',l.expires_at-interval '1 day'
 FROM sso_providers.providers p CROSS JOIN sso_providers.login_transactions l WHERE p.provider_id LIKE 'saml-callback-cost-%' AND l.start_command_id=$1`, x.started.TransactionID},
		{`INSERT INTO sso_providers.login_transactions(tenant_id,organization_id,provider_id,provider_version,credential_generation,mapping_version,start_command_id,callback_command_id,protocol,state_key_version,state_digest,pkce_key_version,pkce_commitment,binding_envelope,verifier_envelope,issued_at,expires_at)
 SELECT l.tenant_id,l.organization_id,l.provider_id,l.provider_version,l.credential_generation,l.mapping_version,
 'saml-callback-active-start-'||n::text,'saml-callback-active-callback-'||n::text,'saml',l.state_key_version,
 decode(md5('callback-active-a-'||n::text)||md5('callback-active-b-'||n::text),'hex'),NULL,NULL,l.binding_envelope,NULL,l.issued_at,l.expires_at
 FROM sso_providers.login_transactions l CROSS JOIN generate_series(1,1024) n WHERE l.start_command_id=$1`, x.started.TransactionID},
	} {
		if _, err := tx.Exec(f.ctx, population.sql, population.arg); err != nil {
			t.Fatal("populate rollback-only SAML callback history/hot provider", err)
		}
	}
}

func measureNativeSAMLCallbackStatement(t *testing.T, f *orgFixture, tx pgx.Tx, scale, name string, original providerQuery, pending []byte) {
	t.Helper()
	types := make([]string, len(original.args))
	for i, arg := range original.args {
		types[i] = fmt.Sprintf("%T", arg)
	}
	partitions := []string{"active", "missing", "profile-drift", "expired"}
	if name == "terminal" {
		partitions = append(partitions, "custody-drift", "retained")
	} else if name == "replay-exists" {
		partitions = []string{"exists", "missing", "partial"}
	}
	for _, partition := range partitions {
		query := original
		changes := map[int]any{}
		switch partition {
		case "missing":
			digest := sha256.Sum256([]byte("absent-native-saml-callback-cost"))
			switch name {
			case "disposition":
				changes[2] = "missing-saml-callback-provider"
			case "terminal":
				changes[9] = digest[:]
			case "replay-exists":
				changes[1] = digest[:16]
			}
		case "profile-drift":
			changes[5] = "99"
		case "expired":
			index := 6
			if name == "terminal" {
				index = 12
			}
			changes[index] = time.Now().UTC().Add(-time.Hour)
		case "custody-drift":
			digest := sha256.Sum256([]byte("different-native-saml-pending-custody"))
			changes[14] = digest[:]
		}
		query = nativeProviderLogoutQueryBindings(t, query, changes)
		var samples []time.Duration
		for sample := range 6 {
			if _, err := tx.Exec(f.ctx, "SAVEPOINT saml_callback_sample"); err != nil {
				t.Fatal(err)
			}
			if partition == "partial" {
				if _, err := tx.Exec(f.ctx, `DELETE FROM sso_providers.saml_replay_members WHERE tenant_id=$1 AND callback_command_id=$2 AND member_kind=2`, query.args...); err != nil {
					t.Fatal("stage rollback-only partial replay pair", err)
				}
			} else if partition == "retained" {
				if _, err := tx.Exec(f.ctx, `UPDATE sso_providers.login_transactions SET completed_at=issued_at WHERE start_command_id=$1`, query.args[6]); err != nil {
					t.Fatal("stage rollback-only retained transaction", err)
				}
			}
			if _, err := tx.Exec(f.ctx, "SAVEPOINT saml_callback_plan"); err != nil {
				t.Fatal(err)
			}
			result := tx.Conn().PgConn().ExecParams(f.ctx, "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) "+query.sql, query.values, query.oids, query.formats, nil).Read()
			if result.Err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
				t.Fatal("exact native SAML callback typed plan", name, partition, result.Err)
			}
			var plans []struct {
				Plan          nativeOAuth2CallbackPlan `json:"Plan"`
				PlanningTime  float64                  `json:"Planning Time"`
				ExecutionTime float64                  `json:"Execution Time"`
			}
			err := json.Unmarshal(result.Rows[0][0], &plans)
			clear(result.Rows[0][0])
			if err != nil || len(plans) != 1 || plans[0].ExecutionTime > 100 {
				t.Fatal("unbounded native SAML callback plan", name, partition, err)
			}
			indexes := map[string]bool{}
			rowWorkBound := float64(1)
			if name == "replay-exists" {
				rowWorkBound = 2
			}
			var inspect func(nativeOAuth2CallbackPlan)
			inspect = func(node nativeOAuth2CallbackPlan) {
				if node.ActualRows*float64(node.ActualLoops) > rowWorkBound || node.FilteredRows*float64(node.ActualLoops) > rowWorkBound || node.JoinFiltered*float64(node.ActualLoops) > rowWorkBound || scale == "hot" && (node.NodeType == "Seq Scan" || node.NodeType == "Sort") {
					t.Fatal("SAML callback examined growing row work", scale, name, partition, node.NodeType, node.RelationName, node.IndexName)
				}
				indexes[node.IndexName] = true
				for _, child := range node.ChildPlans {
					inspect(child)
				}
			}
			inspect(plans[0].Plan)
			if scale == "hot" {
				missingProviderIndexes := name == "disposition" && partition == "active" && (!indexes["providers_pkey"] || !indexes["credentials_pkey"])
				missingLoginIndex := name == "terminal" && !indexes["login_transactions_pkey"]
				missingCommandIndex := name == "replay-exists" && !indexes["saml_replay_command_member_key"]
				if missingProviderIndexes || missingLoginIndex || missingCommandIndex {
					t.Fatal("SAML callback lost exact indexed access", name, partition, indexes)
				}
			}
			if _, err := tx.Exec(f.ctx, "ROLLBACK TO SAVEPOINT saml_callback_plan; RELEASE SAVEPOINT saml_callback_plan"); err != nil {
				t.Fatal(err)
			}
			startedAt := time.Now()
			result = tx.Conn().PgConn().ExecParams(f.ctx, query.sql, query.values, query.oids, query.formats, nil).Read()
			elapsed := time.Since(startedAt)
			if result.Err != nil {
				t.Fatal("execute exact typed SAML callback statement", name, partition, result.Err)
			}
			if name == "replay-exists" {
				want := "t"
				if partition == "missing" {
					want = "f"
				}
				if len(result.Rows) != 1 || len(result.Rows[0]) != 1 || string(result.Rows[0][0]) != want || plans[0].Plan.ActualRows != 1 {
					t.Fatal("replay command existence lost exact Boolean/partial-pair semantics", partition)
				}
			} else {
				want := int64(0)
				if partition == "active" {
					want = 1
				}
				if result.CommandTag.RowsAffected() != want {
					t.Fatal("SAML callback changed result/affected cardinality", name, partition, result.CommandTag.RowsAffected(), want)
				}
				if name == "terminal" {
					var custodyMatches, completed, emptyVerifier bool
					wire := pending
					if partition == "active" {
						wire = original.args[13].([]byte)
					}
					if err := tx.QueryRow(f.ctx, `SELECT binding_envelope=$2,completed_at IS NOT NULL,pkce_key_version IS NULL AND pkce_commitment IS NULL AND verifier_envelope IS NULL FROM sso_providers.login_transactions WHERE start_command_id=$1`, original.args[6], wire).Scan(&custodyMatches, &completed, &emptyVerifier); err != nil || !custodyMatches || !emptyVerifier || completed != (partition == "active" || partition == "retained") {
						t.Fatal("measured SAML terminal write violated exact custody/NULL semantics", partition, err)
					}
				}
			}
			for _, row := range result.Rows {
				for _, value := range row {
					clear(value)
				}
			}
			if sample > 0 {
				samples = append(samples, elapsed)
				safePlan, err := json.Marshal(plans)
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("scale=%s query=%s partition=%s sample=%d client-elapsed=%s safe-plan=%s", scale, name, partition, sample, elapsed, safePlan)
			}
			if _, err := tx.Exec(f.ctx, "ROLLBACK TO SAVEPOINT saml_callback_sample; RELEASE SAVEPOINT saml_callback_sample"); err != nil {
				t.Fatal("restore exact pre-sample callback snapshot", err)
			}
		}
		sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
		t.Logf("scale=%s query=%s partition=%s SQL=%s Go-types=%v native-OIDs=%v formats=%v five samples after one warmup min=%s median=%s max=%s; statement time excludes setup, planning and rollback", scale, name, partition, query.sql, types, query.oids, query.formats, samples[0], samples[2], samples[4])
	}
}
