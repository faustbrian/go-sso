//go:build integration

package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// This is storage-statement evidence, not a session issuance/recovery benchmark.
// Internal-package ownership keeps both measured statements tied to production
// constants. All synthetic retained rows and measured writes are rollback-only.
func TestNativeSAMLLogoutSubjectQueryScale(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	t.Cleanup(cancel)
	conn := samlSubjectQueryDatabase(t, ctx)
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := tx.Rollback(cleanup); err != nil && err != pgx.ErrTxClosed {
			t.Error("rollback subject query fixture", err)
		}
	})
	for _, source := range []migrations.Source{kernel.MigrationSource{}, ProviderMigrationSource{Version: 320}, SAMLLogoutSubjectMigrationSource{Version: 394}} {
		history, err := source.Load(ctx)
		if err != nil {
			t.Fatal("load exact query fixture schema", err)
		}
		for _, step := range history {
			if _, err := tx.Exec(ctx, step.UpSQL()); err != nil {
				t.Fatal("install source-owned query fixture schema", err)
			}
		}
	}
	if _, err := tx.Exec(ctx, "SET LOCAL statement_timeout='15s'; SET LOCAL lock_timeout='1s'"); err != nil {
		t.Fatal(err)
	}
	const tenant, organization, provider = "subject-cost-hot", "subject-cost-organization", "subject-cost-provider"
	// These are real FK owners under the installed provider/command schemas,
	// not assertions or authentication authority. No session schema is needed.
	if _, err := tx.Exec(ctx, `INSERT INTO sso_providers.providers
 (tenant_id,organization_id,provider_id,issuer_digest,configuration_envelope,mapping_version,pending_domains)
 SELECT CASE WHEN n=0 THEN $1::text ELSE 'subject-cost-cold-'||n::text END,$2,$3,
 sha256(convert_to('subject-cost-issuer','UTF8')),decode('01','hex'),1,1
 FROM generate_series(0,100) n`, tenant, organization, provider); err != nil {
		t.Fatal("seed installed provider FK owners", err)
	}
	for _, statement := range []string{
		`INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields)
 SELECT decode(md5('subject-cost-command-'||n::text),'hex'),
 CASE WHEN n<=16000 OR n>20000 THEN $1::text ELSE 'subject-cost-cold-'||(1+n%100)::text END,
 CASE WHEN n%2=0 THEN 'identity.sso.saml-acs' ELSE 'identity.sso.saml-idp-init' END,
 sha256(convert_to('subject-cost-execution-'||n::text,'UTF8')),1,decode('01','hex')
 FROM generate_series(1,20002) n`,
		`INSERT INTO identity.commands(command_id,tenant_id,purpose)
 SELECT decode(md5('subject-cost-command-'||n::text),'hex'),
 CASE WHEN n<=16000 OR n>20000 THEN $1::text ELSE 'subject-cost-cold-'||(1+n%100)::text END,
 CASE WHEN n%2=0 THEN 'identity.sso.saml-acs' ELSE 'identity.sso.saml-idp-init' END
 FROM generate_series(1,20002) n`,
	} {
		if tag, err := tx.Exec(ctx, statement, tenant); err != nil || tag.RowsAffected() != 20002 {
			t.Fatal("seed retained command FK population", err)
		}
	}
	if _, err := tx.Exec(ctx, "ANALYZE identity.commands; ANALYZE sso_providers.providers"); err != nil {
		t.Fatal(err)
	}
	if tag, err := tx.Exec(ctx, `INSERT INTO sso_providers.saml_logout_subjects
 (tenant_id,organization_id,provider_id,user_id,session_id,family_id,issuance_command_id,issuance_purpose,
 issued_at,expires_at,match_key_version,subject_digest,session_index_digest,subject_envelope)
 SELECT CASE WHEN n<=16000 THEN $1::text ELSE 'subject-cost-cold-'||(1+n%100)::text END,$2,$3,
 'subject-cost-user-'||(n%200)::text,'subject-cost-session-'||n::text,'subject-cost-family-'||n::text,
 decode(md5('subject-cost-command-'||n::text),'hex'),
 CASE WHEN n%2=0 THEN 'identity.sso.saml-acs' ELSE 'identity.sso.saml-idp-init' END,
 statement_timestamp()-interval '1 day',statement_timestamp()+interval '29 days',1+n%3,
 sha256(convert_to('subject-cost-subject-'||(n%200)::text,'UTF8')),
 CASE WHEN n%4=0 THEN NULL ELSE sha256(convert_to('subject-cost-index-'||n::text,'UTF8')) END,
 convert_to(repeat('a',2048),'UTF8') FROM generate_series(1,20000) n`, tenant, organization, provider); err != nil || tag.RowsAffected() != 20000 {
		t.Fatal("seed retained subjects with real provider/command constraints", err)
	}
	if _, err := tx.Exec(ctx, "ANALYZE sso_providers.saml_logout_subjects; SET LOCAL statement_timeout='1s'"); err != nil {
		t.Fatal(err)
	}
	var engine string
	var rows, hot, absent int
	var columns, indexes []byte
	if err := tx.QueryRow(ctx, `SELECT current_setting('server_version'),count(*),count(*) FILTER(WHERE tenant_id=$1),
 count(*) FILTER(WHERE session_index_digest IS NULL),
 (SELECT jsonb_agg(jsonb_build_object('table',c.relname,'column',a.attname,'type',format_type(a.atttypid,a.atttypmod)) ORDER BY c.relname,a.attnum)
 FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE ((n.nspname='sso_providers' AND c.relname IN ('saml_logout_subjects','providers')) OR (n.nspname='identity' AND c.relname='commands')) AND a.attnum>0 AND NOT a.attisdropped),
 (SELECT jsonb_agg(jsonb_build_object('table',c.relname,'definition',pg_get_indexdef(i.indexrelid),'valid',i.indisvalid) ORDER BY c.relname,i.indexrelid)
 FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE (n.nspname='sso_providers' AND c.relname IN ('saml_logout_subjects','providers')) OR (n.nspname='identity' AND c.relname='commands'))
 FROM sso_providers.saml_logout_subjects`, tenant).Scan(&engine, &rows, &hot, &absent, &columns, &indexes); err != nil || rows != 20000 || hot != 16000 || absent != 5000 {
		t.Fatal("inspect representative retained-subject distribution", rows, hot, absent, err)
	}
	t.Logf("PostgreSQL=%s subjects=%d hot-provider/tenant=%d absent-index=%d; 100 cold scopes with 40 rows each, 200 recurring subjects, 3 key versions, 2048-byte synthetic envelopes; actual-column-types=%s actual-indexes=%s; isolated normal planner, refreshed statistics, no concurrent load; statement costs exclude coordinator/commit and are not production latency", engine, rows, hot, absent, columns, indexes)
	commandBytes := func(n int) []byte {
		t.Helper()
		var command []byte
		if err := tx.QueryRow(ctx, "SELECT decode(md5('subject-cost-command-'||$1::int::text),'hex')", n).Scan(&command); err != nil {
			t.Fatal(err)
		}
		return command
	}
	measureSAMLSubjectStatement(t, ctx, tx, "recovery-hit", samlLogoutSubjectExistsSQL, []any{tenant, commandBytes(16000)}, true, true)
	measureSAMLSubjectStatement(t, ctx, tx, "recovery-miss", samlLogoutSubjectExistsSQL, []any{tenant, commandBytes(20002)}, true, false)
	issued := time.Now().UTC().Truncate(time.Microsecond)
	subject, sessionIndex := sha256.Sum256([]byte("subject-cost-fresh")), sha256.Sum256([]byte("subject-cost-fresh-index"))
	insert := []any{tenant, organization, provider, "subject-cost-user", "subject-cost-fresh-session", "subject-cost-fresh-family", commandBytes(20002), "identity.sso.saml-acs", issued, issued.Add(30 * 24 * time.Hour), int64(1), subject[:], sessionIndex[:], bytes.Repeat([]byte{3}, 2048)}
	measureSAMLSubjectStatement(t, ctx, tx, "insert-with-index", insertSAMLLogoutSubjectSQL, insert, false, false)
	insert = slices.Clone(insert)
	insert[4], insert[6], insert[7], insert[12] = "subject-cost-fresh-idp", commandBytes(20001), "identity.sso.saml-idp-init", []byte(nil)
	measureSAMLSubjectStatement(t, ctx, tx, "insert-without-index", insertSAMLLogoutSubjectSQL, insert, false, false)
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM sso_providers.saml_logout_subjects").Scan(&rows); err != nil || rows != 20000 {
		t.Fatal("measurements retained a new subject row", rows, err)
	}
}

func samlSubjectQueryDatabase(t *testing.T, ctx context.Context) *pgx.Conn {
	t.Helper()
	dsn := os.Getenv("GOLIB_ORGANIZATION_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("GOLIB_ORGANIZATION_TEST_POSTGRES_DSN must identify the task-owned isolated PostgreSQL fixture")
	}
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal("connect task-owned PostgreSQL fixture")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := admin.Close(cleanup); err != nil {
			t.Error("close query fixture administrator", err)
		}
	})
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	// Subject IDs are opaque text, so use a fixed-length digest for the native
	// database-name bound rather than depending on their encoded representation.
	digest := sha256.Sum256([]byte(id))
	name := "saml_subject_query_" + hex.EncodeToString(digest[:12])
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+quoted); err != nil {
		t.Fatal("create disposable query database", err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+quoted); err != nil {
			t.Error("drop disposable query database", err)
		}
	})
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("parse isolated query database connection")
	}
	config.Database = name
	conn, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal("connect disposable query database")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := conn.Close(cleanup); err != nil {
			t.Error("close disposable query connection", err)
		}
	})
	return conn
}

type samlSubjectQueryPlan struct {
	NodeType   string                 `json:"Node Type"`
	Relation   string                 `json:"Relation Name,omitempty"`
	Index      string                 `json:"Index Name,omitempty"`
	Rows       float64                `json:"Actual Rows"`
	Loops      float64                `json:"Actual Loops"`
	Filtered   float64                `json:"Rows Removed by Filter"`
	SharedHit  int                    `json:"Shared Hit Blocks"`
	SharedRead int                    `json:"Shared Read Blocks"`
	Plans      []samlSubjectQueryPlan `json:"Plans,omitempty"`
}

func measureSAMLSubjectStatement(t *testing.T, ctx context.Context, tx pgx.Tx, name, sql string, args []any, recovery, want bool) {
	t.Helper()
	// Match Work's explicit binary ExecParams encoding, not pgx's inferred
	// directory-domain OIDs or query-mode selection. See kernel work_values.go.
	codecs := pgtype.NewMap()
	values, oids, formats := make([][]byte, len(args)), make([]uint32, len(args)), make([]int16, len(args))
	types := make([]string, len(args))
	for n, arg := range args {
		types[n], formats[n] = fmt.Sprintf("%T", arg), pgtype.BinaryFormatCode
		switch arg.(type) {
		case string:
			oids[n] = pgtype.TextOID
		case []byte:
			oids[n] = pgtype.ByteaOID
		case int64:
			oids[n] = pgtype.Int8OID
		case time.Time:
			oids[n] = pgtype.TimestamptzOID
		default:
			t.Fatal("unexpected production binding type", types[n])
		}
		var err error
		values[n], err = codecs.Encode(oids[n], formats[n], arg, make([]byte, 0))
		if err != nil {
			t.Fatal("encode native Work-shaped query argument", err)
		}
	}
	var elapsed []time.Duration
	for sample := range 6 {
		if _, err := tx.Exec(ctx, "SAVEPOINT subject_query_sample"); err != nil {
			t.Fatal(err)
		}
		result := tx.Conn().PgConn().ExecParams(ctx, "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) "+sql, values, oids, formats, nil).Read()
		if result.Err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
			t.Fatal("explain exact production subject statement", name, result.Err)
		}
		var plans []struct {
			Plan      samlSubjectQueryPlan `json:"Plan"`
			Planning  float64              `json:"Planning Time"`
			Execution float64              `json:"Execution Time"`
			Triggers  []struct {
				Constraint string  `json:"Constraint Name"`
				Time       float64 `json:"Time"`
				Calls      int     `json:"Calls"`
			} `json:"Triggers,omitempty"`
		}
		if err := json.Unmarshal(result.Rows[0][0], &plans); err != nil || len(plans) != 1 {
			t.Fatal("decode sanitized query plan", err)
		}
		clear(result.Rows[0][0])
		lookups := 0
		var inspect func(samlSubjectQueryPlan)
		inspect = func(p samlSubjectQueryPlan) {
			if p.Rows*p.Loops > 1 || p.Filtered*p.Loops > 1 {
				t.Fatal("subject statement examined growing retained-row work", name, p.NodeType)
			}
			if recovery && p.Relation == "saml_logout_subjects" {
				if p.Index == "" {
					t.Fatal("exact recovery performed a non-index lookup", name, p.NodeType)
				}
				lookups++
			}
			for _, child := range p.Plans {
				inspect(child)
			}
		}
		inspect(plans[0].Plan)
		if recovery && lookups != 1 {
			t.Fatal("recovery did not select one bounded installed lookup", name, lookups)
		}
		if sample == 0 {
			safe, err := json.Marshal(plans)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("query=%s sanitized-first-plan=%s", name, safe)
		}
		if _, err := tx.Exec(ctx, "ROLLBACK TO SAVEPOINT subject_query_sample"); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		result = tx.Conn().PgConn().ExecParams(ctx, sql, values, oids, formats, nil).Read()
		took := time.Since(start)
		if result.Err != nil {
			t.Fatal("execute exact native subject statement", name, result.Err)
		}
		if recovery {
			wantBoolean := "f"
			if want {
				wantBoolean = "t"
			}
			if len(result.Rows) != 1 || len(result.Rows[0]) != 1 || string(result.Rows[0][0]) != wantBoolean {
				t.Fatal("recovery returned the wrong Boolean", name)
			}
			clear(result.Rows[0][0])
		} else {
			if result.CommandTag.RowsAffected() != 1 {
				t.Fatal("fresh subject insertion did not affect one row", name)
			}
			var absent bool
			if err := tx.QueryRow(ctx, "SELECT session_index_digest IS NULL FROM sso_providers.saml_logout_subjects WHERE tenant_id=$1 AND session_id=$2", args[0], args[4]).Scan(&absent); err != nil || absent != (len(args[12].([]byte)) == 0) {
				t.Fatal("measured insert changed optional original index presence", name, err)
			}
		}
		if sample > 0 {
			elapsed = append(elapsed, took)
		}
		if _, err := tx.Exec(ctx, "ROLLBACK TO SAVEPOINT subject_query_sample; RELEASE SAVEPOINT subject_query_sample"); err != nil {
			t.Fatal(err)
		}
	}
	slices.Sort(elapsed)
	t.Logf("query=%s SQL=%s Go-types=%v native-OIDs=%v formats=%v; 5 warmed client statement executions after one warmup: min=%s median=%s max=%s; per-statement database timeout=1s; excludes setup, EXPLAIN, rollback, pool acquisition, coordinator and commit", name, sql, types, oids, formats, elapsed[0], elapsed[2], elapsed[4])
}
