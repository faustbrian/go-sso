//go:build integration

package postgres_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// This measures the two real storage statements, not a SAML callback or kernel
// recovery lifecycle. All cost population and measured writes roll back; copied
// provider custody and foundation-only commands never establish SAML authority.
func TestNativeSAMLReplayQueryScale(t *testing.T) {
	testNativeSAMLReplayQueryScale(t, false)
}

func TestNativeSAMLIDPReplayQueryScale(t *testing.T) {
	testNativeSAMLReplayQueryScale(t, true)
}

func testNativeSAMLReplayQueryScale(t *testing.T, idp bool) {
	t.Helper()
	f, providers, _ := newProviderFixtureWithUpdates(t, false)
	registration := providerRequest(t, "https://replay-cost.example.com", "saml-replay-cost")
	created, err := providers.ProviderRegisterOidc(f.ctx, registration)
	if err != nil || created.Completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("register real provider ownership for replay cost fixture", err)
	}
	history, err := (ssopg.SAMLReplayMigrationSource{Version: 390}).Load(f.ctx)
	if err != nil || len(history) != 1 {
		t.Fatal("load installed replay-member schema", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, history[0].UpSQL()); err != nil {
		t.Fatal("install replay-member schema on populated provider fixture", err)
	}
	purpose := "identity.sso.saml-acs"
	reserve := ssopg.ReserveSAMLReplayForTest
	if idp {
		purpose = "identity.sso.saml-idp-init"
		reserve = ssopg.ReserveSAMLIDPReplayForTest
		installSAMLIDPStorage(t, f, ssopg.SAMLIDPReplayMigrationSource{Version: 391, ValidationVersion: 392})
	}
	const tenant identity.TenantID = "org-test-basic"
	claim := ssopg.SAMLReplayClaimForTest{
		Tenant: tenant, OrganizationID: registration.OrganizationID, ProviderID: created.Provider.ID,
		ResponseDigest:  sha256.Sum256([]byte("replay-cost-response")),
		AssertionDigest: sha256.Sum256([]byte("replay-cost-assertion")),
		Fingerprint:     sha256.Sum256([]byte("replay-cost-execution")),
		CommandID:       seedProviderGrantAttemptForTest(t, f, tenant, purpose),
		Generation:      1, RetainUntil: time.Now().UTC().Truncate(time.Microsecond).Add(time.Hour),
	}
	var issuer []byte
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT issuer_digest FROM sso_providers.providers
 WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`, string(tenant), claim.OrganizationID, claim.ProviderID).Scan(&issuer); err != nil || len(issuer) != sha256.Size {
		t.Fatal("read real provider issuer binding", err)
	}
	claim.IssuerDigest = [32]byte(issuer)

	trace := new(providerTrace)
	config, err := pgx.ParseConfig(f.dsn)
	if err != nil {
		t.Fatal("parse isolated replay fixture connection", err)
	}
	config.Database, config.Tracer = f.database, trace
	conn, err := pgx.ConnectConfig(f.ctx, config)
	if err != nil {
		t.Fatal("connect traced replay fixture", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := conn.Close(ctx); err != nil {
			t.Error("close replay trace connection", err)
		}
	})
	tx, err := conn.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.ctx)
	if _, err := tx.Exec(f.ctx, "SET LOCAL statement_timeout='15s'; SET LOCAL lock_timeout='1s'"); err != nil {
		t.Fatal(err)
	}
	if err := reserve(f.ctx, tx, claim); err != nil {
		t.Fatal("capture real pair insertion", err)
	}
	var found bool
	if idp {
		found, err = ssopg.ObserveSAMLIDPReplayForTest(f.ctx, tx, claim)
	} else {
		found, err = ssopg.ObserveSAMLReplayForTest(f.ctx, tx, claim)
	}
	if err != nil || !found {
		t.Fatal("capture real exact-pair Boolean recovery query", found, err)
	}
	trace.mu.Lock()
	queries, traceErr := append([]providerQuery(nil), trace.queries...), trace.err
	trace.mu.Unlock()
	if traceErr != nil {
		t.Fatal(traceErr)
	}
	selected := map[string]providerQuery{}
	for _, query := range queries {
		switch {
		case strings.HasPrefix(query.sql, "INSERT INTO sso_providers.saml_replay_members"):
			selected["insert"] = query
		case strings.HasPrefix(query.sql, "SELECT count(*)=2\nFROM sso_providers.saml_replay_members"):
			selected["observe"] = query
		}
	}
	if len(selected) != 2 {
		t.Fatal("missing export-driven replay INSERT or Boolean SELECT")
	}
	for name, query := range selected {
		if len(query.args) != 10 {
			t.Fatal("replay statement lost complete native bindings", name)
		}
		// Reuse the existing pgx describe/ExtendedQueryBuilder helper: these
		// direct exports use ordinary pgx, not Work's explicit-OID ExecParams.
		selected[name] = nativeProviderGrantRevocationWireBindings(t, f, tx, query)
	}
	if _, err := tx.Exec(f.ctx, "SAVEPOINT replay_conflict_api"); err != nil {
		t.Fatal(err)
	}
	if err := reserve(f.ctx, tx, claim); !errors.Is(err, identity.ConflictError{}) {
		t.Fatal("real pair conflict did not retain its API meaning", err)
	}
	if _, err := tx.Exec(f.ctx, "ROLLBACK TO SAVEPOINT replay_conflict_api; RELEASE SAVEPOINT replay_conflict_api"); err != nil {
		t.Fatal(err)
	}

	var version string
	var columns, indexes []byte
	if err := tx.QueryRow(f.ctx, `SELECT current_setting('server_version'),
 (SELECT jsonb_agg(jsonb_build_object('table',c.relname,'column',a.attname,'type',format_type(a.atttypid,a.atttypmod)) ORDER BY c.relname,a.attnum)
 FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE ((n.nspname='sso_providers' AND c.relname IN ('saml_replay_members','providers')) OR (n.nspname='identity' AND c.relname='commands')) AND a.attnum>0 AND NOT a.attisdropped),
 (SELECT jsonb_agg(jsonb_build_object('table',tablename,'definition',indexdef) ORDER BY schemaname,tablename,indexname)
 FROM pg_indexes WHERE (schemaname='sso_providers' AND tablename IN ('saml_replay_members','providers')) OR (schemaname='identity' AND tablename='commands'))`).Scan(&version, &columns, &indexes); err != nil {
		t.Fatal("inspect actual replay and foreign-key schema/indexes", err)
	}
	t.Logf("PostgreSQL=%s actual-column-types=%s actual-indexes=%s; isolated normal planner, no concurrent load; statements only, not production latency", version, columns, indexes)
	for _, scale := range []string{"small", "scaled"} {
		if scale == "scaled" {
			populateNativeSAMLReplayScale(t, f, tx, selected["insert"])
		}
		if _, err := tx.Exec(f.ctx, "ANALYZE sso_providers.saml_replay_members; ANALYZE sso_providers.providers; ANALYZE identity.commands"); err != nil {
			t.Fatal(err)
		}
		var members, hot, commands, providers int
		if err := tx.QueryRow(f.ctx, `SELECT count(*),count(*) FILTER(WHERE tenant_id=$1),
 (SELECT count(*) FROM identity.commands),(SELECT count(*) FROM sso_providers.providers)
 FROM sso_providers.saml_replay_members`, string(tenant)).Scan(&members, &hot, &commands, &providers); err != nil {
			t.Fatal("read replay measurement cardinality", err)
		}
		wantMembers, wantHot := 2, 2
		if scale == "scaled" {
			wantMembers, wantHot = 40002, 32002
		}
		if members != wantMembers || hot != wantHot {
			t.Fatal("representative replay population mismatch", scale, members, hot)
		}
		t.Logf("scope=%s members=%d hot-tenant-members=%d commands=%d providers=%d; scaled background has 100 cold tenant/provider scopes with 80 members each, same digest widths and real foreign keys; no protocol authority", scale, members, hot, commands, providers)
		for _, name := range []string{"insert-new", "insert-conflict", "observe-hit", "observe-no-match", "observe-partial"} {
			query := selected["observe"]
			if strings.HasPrefix(name, "insert-") {
				query = selected["insert"]
			}
			if name == "observe-no-match" {
				response, assertion := sha256.Sum256([]byte("absent-response")), sha256.Sum256([]byte("absent-assertion"))
				query = nativeProviderLogoutQueryBindings(t, query, map[int]any{8: response[:], 9: assertion[:]})
			}
			measureNativeSAMLReplayStatement(t, f, tx, scale, name, query)
		}
	}
	if err := tx.Rollback(f.ctx); err != nil {
		t.Fatal("rollback replay cost population and measured writes", err)
	}
}

func populateNativeSAMLReplayScale(t *testing.T, f *orgFixture, tx pgx.Tx, query providerQuery) {
	t.Helper()
	if _, err := tx.Exec(f.ctx, `INSERT INTO sso_providers.providers
 (tenant_id,organization_id,provider_id,issuer_digest,configuration_envelope,mapping_version,pending_domains)
 SELECT 'replay-cost-cold-'||n::text,organization_id,'replay-cost-provider-'||n::text,
 issuer_digest,configuration_envelope,mapping_version,pending_domains
 FROM sso_providers.providers CROSS JOIN generate_series(0,99) n
 WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`, query.args[:3]...); err != nil {
		t.Fatal("populate cold provider foreign-key owners", err)
	}
	for _, statement := range []string{
		`INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields)
 SELECT decode(md5('replay-cost-command-'||n::text),'hex'),
 CASE WHEN n<=16000 THEN $1::text ELSE 'replay-cost-cold-'||(n%100)::text END,
 'identity.sso.saml-acs',sha256(convert_to('replay-cost-execution-'||n::text,'UTF8')),1,decode('01','hex')
 FROM generate_series(1,20000) n`,
		`INSERT INTO identity.commands(command_id,tenant_id,purpose)
 SELECT decode(md5('replay-cost-command-'||n::text),'hex'),
 CASE WHEN n<=16000 THEN $1::text ELSE 'replay-cost-cold-'||(n%100)::text END,
 'identity.sso.saml-acs' FROM generate_series(1,20000) n`,
	} {
		if _, err := tx.Exec(f.ctx, statement, query.args[0]); err != nil {
			t.Fatal("populate real foundation-only replay command foreign keys", err)
		}
	}
	// The bulk fixture inserts 40,000 FK-checked rows immediately after
	// growing the parent tables from one row. Refresh parent estimates before
	// that unmeasured load; real measured writes still use both foreign keys.
	if _, err := tx.Exec(f.ctx, `ANALYZE identity.commands; ANALYZE sso_providers.providers`); err != nil {
		t.Fatal("refresh replay fixture parent statistics", err)
	}
	if tag, err := tx.Exec(f.ctx, `INSERT INTO sso_providers.saml_replay_members
 (tenant_id,organization_id,provider_id,issuer_digest,member_digest,member_kind,
 callback_command_id,execution_fingerprint,execution_generation,retain_until)
 SELECT CASE WHEN n<=16000 THEN $1::text ELSE 'replay-cost-cold-'||(n%100)::text END,$2,
 CASE WHEN n<=16000 THEN $3::text ELSE 'replay-cost-provider-'||(n%100)::text END,$4,
 sha256(convert_to('replay-cost-member-'||n::text||'-'||kind::text,'UTF8')),kind,
 decode(md5('replay-cost-command-'||n::text),'hex'),sha256(convert_to('replay-cost-execution-'||n::text,'UTF8')),
 $5::text::identity.version,$6::timestamptz
 FROM generate_series(1,20000) n CROSS JOIN (VALUES(1::smallint),(2::smallint)) m(kind)`,
		query.args[0], query.args[1], query.args[2], query.args[3], query.args[6], query.args[7]); err != nil || tag.RowsAffected() != 40000 {
		t.Fatal("populate 40,000 replay members with installed command/provider constraints", err)
	}
}

func measureNativeSAMLReplayStatement(t *testing.T, f *orgFixture, tx pgx.Tx, scope, name string, query providerQuery) {
	t.Helper()
	types := make([]string, len(query.args))
	for index, argument := range query.args {
		types[index] = fmt.Sprintf("%T", argument)
	}
	var elapsedSamples []time.Duration
	for sample := range 6 {
		if _, err := tx.Exec(f.ctx, "SAVEPOINT saml_sample"); err != nil {
			t.Fatal(err)
		}
		if name == "insert-new" || name == "observe-partial" {
			statement := `DELETE FROM sso_providers.saml_replay_members WHERE tenant_id=$1 AND callback_command_id=$2`
			if name == "observe-partial" {
				statement += " AND member_kind=2"
			}
			if _, err := tx.Exec(f.ctx, statement, query.args[0], query.args[4]); err != nil {
				t.Fatal("stage rollback-only replay insertion/partial snapshot", err)
			}
		}
		// EXPLAIN ANALYZE cannot return a plan for an INSERT that raises a
		// unique violation. Measure that real error separately below; never
		// substitute ON CONFLICT or a different statement to obtain a plan.
		if name != "insert-conflict" {
			if _, err := tx.Exec(f.ctx, "SAVEPOINT saml_plan"); err != nil {
				t.Fatal(err)
			}
			result := tx.Conn().PgConn().ExecParams(f.ctx, "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) "+query.sql, query.values, query.oids, query.formats, nil).Read()
			if result.Err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
				t.Fatal("exact typed replay statement plan", name, result.Err)
			}
			var plans []struct {
				Plan          nativeOAuth2CallbackPlan `json:"Plan"`
				PlanningTime  float64                  `json:"Planning Time"`
				ExecutionTime float64                  `json:"Execution Time"`
				Triggers      []struct {
					Constraint string  `json:"Constraint Name"`
					Time       float64 `json:"Time"`
					Calls      int     `json:"Calls"`
				} `json:"Triggers,omitempty"`
			}
			err := json.Unmarshal(result.Rows[0][0], &plans)
			clear(result.Rows[0][0])
			if err != nil || len(plans) != 1 {
				t.Fatal("decode replay structural plan without argument values", err)
			}
			var inspect func(nativeOAuth2CallbackPlan)
			inspect = func(node nativeOAuth2CallbackPlan) {
				if node.ActualRows*float64(node.ActualLoops) > 2 || node.FilteredRows*float64(node.ActualLoops) > 2 || node.JoinFiltered*float64(node.ActualLoops) > 2 {
					t.Fatal("exact replay statement examined growing row work", scope, name, node.NodeType, node.RelationName, node.IndexName)
				}
				for _, child := range node.ChildPlans {
					inspect(child)
				}
			}
			inspect(plans[0].Plan)
			if sample > 0 {
				safePlan, err := json.Marshal(plans)
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("scope=%s query=%s sample=%d safe-plan=%s", scope, name, sample, safePlan)
			}
			if _, err := tx.Exec(f.ctx, "ROLLBACK TO SAVEPOINT saml_plan; RELEASE SAVEPOINT saml_plan"); err != nil {
				t.Fatal("restore exact pre-plan replay snapshot", err)
			}
		}
		started := time.Now()
		result := tx.Conn().PgConn().ExecParams(f.ctx, query.sql, query.values, query.oids, query.formats, nil).Read()
		elapsed := time.Since(started)
		switch {
		case name == "insert-conflict":
			var conflict *pgconn.PgError
			if !errors.As(result.Err, &conflict) || conflict.Code != "23505" || conflict.TableName != "saml_replay_members" ||
				(conflict.ConstraintName != "saml_replay_member_scope_pkey" && conflict.ConstraintName != "saml_replay_command_member_key") {
				t.Fatal("exact replay pair did not conflict on installed replay uniqueness", result.Err)
			}
		case name == "insert-new":
			if result.Err != nil || result.CommandTag.RowsAffected() != 2 {
				t.Fatal("fresh exact replay statement did not insert both members", result.Err)
			}
		default:
			if result.Err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
				t.Fatal("recovery statement did not return one Boolean", name, result.Err)
			}
			want := "f"
			if name == "observe-hit" {
				want = "t"
			}
			if string(result.Rows[0][0]) != want {
				t.Fatal("exact recovery Boolean changed", name)
			}
			clear(result.Rows[0][0])
		}
		if sample > 0 {
			elapsedSamples = append(elapsedSamples, elapsed)
			t.Logf("scope=%s query=%s sample=%d client-elapsed=%s", scope, name, sample, elapsed)
		}
		if _, err := tx.Exec(f.ctx, "ROLLBACK TO SAVEPOINT saml_sample; RELEASE SAVEPOINT saml_sample"); err != nil {
			t.Fatal("restore measured replay sample including failed INSERT", err)
		}
	}
	sort.Slice(elapsedSamples, func(i, j int) bool { return elapsedSamples[i] < elapsedSamples[j] })
	t.Logf("scope=%s query=%s SQL=%s Go-types=%v native-OIDs=%v formats=%v samples=5 after one warmup min=%s median=%s max=%s; client statement time excludes setup/planning/rollback; conflicts have no successful ANALYZE plan", scope, name, query.sql, types, query.oids, query.formats, elapsedSamples[0], elapsedSamples[2], elapsedSamples[4])
}
