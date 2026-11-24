//go:build integration

package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// Baselines use the raw pool's inferred pgx bindings; relay insertion,
// recovery reads and the local-commit fence use Work's fixed binary OIDs
// through ExecParams. RecoveryWork.Query delegates to that same Work profile.
// The transaction only isolates synthetic measurements;
// this is not a signing, encryption, revocation, commit or contention benchmark.
func TestNativeSAMLLogoutRequestQueryScale(t *testing.T) {
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
			t.Error("rollback request query fixture", err)
		}
	})
	for _, source := range []migrations.Source{
		kernel.MigrationSource{}, ProviderMigrationSource{Version: 320}, ProviderUpdateMigrationSource{Version: 321},
		ProviderCredentialsMigrationSource{Version: 322}, ProviderEnableMigrationSource{Version: 323},
		ProviderProtocolMigrationSource{Version: 330, ValidationVersion: 331},
		ProviderSAMLProtocolMigrationSource{Version: 332, ValidationVersion: 333},
		SAMLLogoutSubjectMigrationSource{Version: 394}, SAMLLogoutRequestMigrationSource{Version: 395},
	} {
		history, err := source.Load(ctx)
		if err != nil {
			t.Fatal("load production request query schema", err)
		}
		for _, migration := range history {
			if _, err := tx.Exec(ctx, migration.UpSQL()); err != nil {
				t.Fatal("install production request query schema", err)
			}
		}
	}
	if _, err := tx.Exec(ctx, "SET LOCAL statement_timeout='15s'; SET LOCAL lock_timeout='1s'"); err != nil {
		t.Fatal(err)
	}
	const tenant, organization = "request-cost-hot", "request-cost-organization"
	for _, statement := range []string{
		`INSERT INTO sso_providers.providers
 (tenant_id,organization_id,provider_id,issuer_digest,configuration_envelope,mapping_version,pending_domains,
 protocol,enabled,enablement_proof,enablement_credential_generation)
 SELECT CASE WHEN n<=16000 THEN $1::text ELSE 'request-cost-cold-'||(1+n%100)::text END,$2,
 'request-cost-provider-'||n::text,sha256(convert_to('request-cost-issuer-'||n::text,'UTF8')),
 decode('01','hex'),1,1,'saml',true,decode('01','hex'),1 FROM generate_series(1,20000) n`,
		`ANALYZE sso_providers.providers`,
		`INSERT INTO identity.identity_command_id_claims
 (command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields)
 SELECT substring(sha256(convert_to('request-cost-'||kind||'-'||n::text,'UTF8')) from 1 for 16),
 CASE WHEN n<=16000 OR n>20000 THEN $1::text ELSE 'request-cost-cold-'||(1+n%100)::text END,
 CASE WHEN kind='request' THEN 'identity.sso.saml-logout-start' ELSE 'identity.sso.saml-acs' END,
 sha256(convert_to('request-cost-fingerprint-'||kind||'-'||n::text,'UTF8')),1,decode('01','hex')
 FROM generate_series(1,20002) n CROSS JOIN (VALUES('request'),('subject')) kinds(kind)`,
		`INSERT INTO identity.commands
 (command_id,tenant_id,purpose,state,generation,attempt,lease_owner,lease_until,heartbeat_at,created_at,updated_at,
 result_version,terminal_class,result,terminal_at)
 SELECT command_id,tenant_id,purpose,'committed',1,1,command_id,statement_timestamp(),statement_timestamp(),
 statement_timestamp(),statement_timestamp(),1,'committed',decode('01','hex'),statement_timestamp()
 FROM identity.identity_command_id_claims
 WHERE command_id<>substring(sha256(convert_to('request-cost-request-20002','UTF8')) from 1 for 16)`,
		`INSERT INTO identity.commands(command_id,tenant_id,purpose)
 SELECT command_id,tenant_id,purpose
 FROM identity.identity_command_id_claims
 WHERE command_id=substring(sha256(convert_to('request-cost-request-20002','UTF8')) from 1 for 16)`,
		`ANALYZE identity.commands`,
		`INSERT INTO sso_providers.saml_logout_requests
 (tenant_id,organization_id,provider_id,request_id,start_command_id,issued_at,expires_at,request_envelope)
 SELECT CASE WHEN n<=16000 THEN $1::text ELSE 'request-cost-cold-'||(1+n%100)::text END,$2,
 'request-cost-provider-'||n::text,
 '_'||translate(rtrim(encode(substring(sha256(convert_to('request-cost-request-'||n::text,'UTF8')) from 1 for 16),'base64'),'='),'+/','-_'),
 substring(sha256(convert_to('request-cost-request-'||n::text,'UTF8')) from 1 for 16),statement_timestamp()-interval '1 day',
 statement_timestamp()-interval '1 day'+interval '5 minutes',convert_to(repeat('r',2048),'UTF8')
 FROM generate_series(1,20000) n`,
		`INSERT INTO sso_providers.saml_logout_subjects
 (tenant_id,organization_id,provider_id,user_id,session_id,family_id,issuance_command_id,issuance_purpose,
 issued_at,expires_at,match_key_version,subject_digest,session_index_digest,subject_envelope)
 SELECT CASE WHEN n<=16000 THEN $1::text ELSE 'request-cost-cold-'||(1+n%100)::text END,$2,
 'request-cost-provider-'||n::text,'request-cost-user-'||(n%200)::text,'request-cost-session-'||n::text,
 'request-cost-family-'||n::text,substring(sha256(convert_to('request-cost-subject-'||n::text,'UTF8')) from 1 for 16),'identity.sso.saml-acs',
 statement_timestamp()-interval '1 day',statement_timestamp()+interval '29 days',1+n%3,
 sha256(convert_to('request-cost-subject-'||(n%200)::text,'UTF8')),
 CASE WHEN n%4=0 THEN NULL ELSE sha256(convert_to('request-cost-index-'||n::text,'UTF8')) END,
 convert_to(repeat('s',2048),'UTF8') FROM generate_series(1,20000) n`,
	} {
		// Setup statements differ in arity; keep measurement bindings untouched.
		var args []any
		if strings.Contains(statement, "$1") {
			args = []any{tenant}
		}
		if strings.Contains(statement, "$2") {
			args = append(args, organization)
		}
		if _, err := tx.Exec(ctx, statement, args...); err != nil {
			t.Fatal("seed schema-valid retained request query population", err)
		}
	}
	if _, err := tx.Exec(ctx, `ANALYZE sso_providers.providers; ANALYZE identity.commands;
 ANALYZE sso_providers.saml_logout_requests; ANALYZE sso_providers.saml_logout_subjects;
 SET LOCAL statement_timeout='1s'`); err != nil {
		t.Fatal(err)
	}
	var engine string
	var requests, subjects, hot, providers int
	var columns, indexes []byte
	if err := tx.QueryRow(ctx, `SELECT current_setting('server_version'),
 (SELECT count(*) FROM sso_providers.saml_logout_requests),
 (SELECT count(*) FROM sso_providers.saml_logout_subjects),
 (SELECT count(*) FROM sso_providers.saml_logout_requests WHERE tenant_id=$1),
 (SELECT count(*) FROM sso_providers.providers),
 (SELECT jsonb_agg(jsonb_build_object('table',c.relname,'column',a.attname,'type',format_type(a.atttypid,a.atttypmod)) ORDER BY c.relname,a.attnum)
 FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE ((n.nspname='sso_providers' AND c.relname IN ('saml_logout_requests','saml_logout_subjects','providers')) OR (n.nspname='identity' AND c.relname='commands')) AND a.attnum>0 AND NOT a.attisdropped),
 (SELECT jsonb_agg(jsonb_build_object('table',c.relname,'definition',pg_get_indexdef(i.indexrelid),'valid',i.indisvalid) ORDER BY c.relname,i.indexrelid)
 FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE (n.nspname='sso_providers' AND c.relname IN ('saml_logout_requests','saml_logout_subjects','providers')) OR (n.nspname='identity' AND c.relname='commands'))`, tenant).Scan(
		&engine, &requests, &subjects, &hot, &providers, &columns, &indexes); err != nil || requests != 20000 || subjects != 20000 || hot != 16000 || providers != 20000 {
		t.Fatal("inspect representative request query distribution", requests, subjects, hot, providers, err)
	}
	t.Logf("PostgreSQL=%s retained-requests=%d subjects=%d providers=%d hot-tenant=%d; 100 cold tenants with 40 rows each, 2048-byte synthetic envelopes; actual-column-types=%s actual-indexes=%s; normal planner, refreshed statistics, no competing load; statement evidence, not production latency", engine, requests, subjects, providers, hot, columns, indexes)
	command := func(n int) []byte {
		digest := sha256.Sum256(fmt.Appendf(nil, "request-cost-request-%d", n))
		return digest[:16]
	}
	for _, test := range []struct {
		name, tenant string
		n            int
		want         bool
	}{
		{"hot-hit", tenant, 16000, true}, {"cold-hit", "request-cost-cold-2", 19901, true},
		{"missing-command", tenant, 20001, false}, {"foreign-tenant", "request-cost-cold-2", 16000, false},
	} {
		requestID := "_" + base64.RawURLEncoding.EncodeToString(command(test.n))
		measureSAMLLogoutRequestStatement(t, ctx, tx, "request/"+test.name, selectSAMLLogoutRequestSQL, []any{test.tenant, command(test.n)}, false, test.want, 2, requestID, samlLogoutRequestInferredBindings)
		measureSAMLLogoutRequestStatement(t, ctx, tx, "relay-recovery/"+test.name, selectSAMLLogoutRequestSQL, []any{test.tenant, command(test.n)}, false, test.want, 2, requestID, samlLogoutRequestWorkBindings)
		measureSAMLLogoutRequestStatement(t, ctx, tx, "subject/"+test.name, readSAMLLogoutSubjectSQL,
			[]any{test.tenant, fmt.Sprintf("request-cost-session-%d", test.n)}, false, test.want, 4, fmt.Sprintf("request-cost-session-%d", test.n), samlLogoutRequestInferredBindings)
	}
	for _, test := range []struct {
		name, tenant string
		n            int
		want         bool
	}{
		{"committed-hot", tenant, 16000, true}, {"committed-cold", "request-cost-cold-2", 19901, true},
		{"pending-command", tenant, 20002, false}, {"missing-command", tenant, 20003, false},
		{"foreign-tenant", "request-cost-cold-2", 16000, false},
	} {
		measureSAMLLogoutRequestStatement(t, ctx, tx, "relay-local-commit/"+test.name, requireSAMLLogoutRelayLocalCommitSQL,
			[]any{test.tenant, command(test.n)}, false, test.want, 0, "", samlLogoutRequestWorkBindings)
	}
	foreignPurpose := sha256.Sum256([]byte("request-cost-subject-16000"))
	measureSAMLLogoutRequestStatement(t, ctx, tx, "relay-local-commit/foreign-purpose", requireSAMLLogoutRelayLocalCommitSQL,
		[]any{tenant, foreignPurpose[:16]}, false, false, 0, "", samlLogoutRequestWorkBindings)
	issued := time.Now().UTC().Truncate(time.Microsecond)
	args := []any{tenant, organization, "request-cost-provider-16000", "_" + base64.RawURLEncoding.EncodeToString(command(20001)), command(20001),
		issued, issued.Add(5 * time.Minute), bytes.Repeat([]byte{3}, 2048), "1", "1"}
	measureSAMLLogoutRequestStatement(t, ctx, tx, "insert/first", insertSAMLLogoutRequestSQL, args, true, true, 0, "", samlLogoutRequestInferredBindings)
	measureSAMLLogoutRequestStatement(t, ctx, tx, "relay-insert/first", insertSAMLLogoutRequestSQL, args, true, true, 0, "", samlLogoutRequestWorkBindings)
	duplicate := slices.Clone(args)
	duplicate[3], duplicate[4] = "_"+base64.RawURLEncoding.EncodeToString(command(16000)), command(16000)
	measureSAMLLogoutRequestStatement(t, ctx, tx, "insert/duplicate", insertSAMLLogoutRequestSQL, duplicate, true, false, 0, "", samlLogoutRequestInferredBindings)
	measureSAMLLogoutRequestStatement(t, ctx, tx, "relay-insert/duplicate", insertSAMLLogoutRequestSQL, duplicate, true, false, 0, "", samlLogoutRequestWorkBindings)
	for _, fence := range []struct {
		name  string
		index int
		value any
	}{{"stale-provider", 8, "2"}, {"stale-credential", 9, "2"}, {"missing-provider", 2, "request-cost-missing"}, {"uncommitted-command", 4, command(20002)}} {
		fenced := slices.Clone(args)
		fenced[fence.index] = fence.value
		if fence.name == "uncommitted-command" {
			fenced[3] = "_" + base64.RawURLEncoding.EncodeToString(command(20002))
		}
		measureSAMLLogoutRequestStatement(t, ctx, tx, "insert/"+fence.name, insertSAMLLogoutRequestSQL, fenced, true, false, 0, "", samlLogoutRequestInferredBindings)
		measureSAMLLogoutRequestStatement(t, ctx, tx, "relay-insert/"+fence.name, insertSAMLLogoutRequestSQL, fenced, true, false, 0, "", samlLogoutRequestWorkBindings)
	}
	expired := slices.Clone(args)
	expired[5], expired[6] = issued.Add(-6*time.Minute), issued.Add(-time.Minute)
	measureSAMLLogoutRequestStatement(t, ctx, tx, "insert/expired", insertSAMLLogoutRequestSQL, expired, true, false, 0, "", samlLogoutRequestInferredBindings)
	measureSAMLLogoutRequestStatement(t, ctx, tx, "relay-insert/expired", insertSAMLLogoutRequestSQL, expired, true, false, 0, "", samlLogoutRequestWorkBindings)
	if _, err := tx.Exec(ctx, `UPDATE sso_providers.providers SET enabled=false,enablement_proof=NULL,enablement_credential_generation=NULL
 WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`, args[:3]...); err != nil {
		t.Fatal("disable exact provider fence", err)
	}
	measureSAMLLogoutRequestStatement(t, ctx, tx, "insert/disabled", insertSAMLLogoutRequestSQL, args, true, false, 0, "", samlLogoutRequestInferredBindings)
	measureSAMLLogoutRequestStatement(t, ctx, tx, "relay-insert/disabled", insertSAMLLogoutRequestSQL, args, true, false, 0, "", samlLogoutRequestWorkBindings)
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM sso_providers.saml_logout_requests").Scan(&requests); err != nil || requests != 20000 {
		t.Fatal("measurements retained an inserted request", requests, err)
	}
}

type samlLogoutRequestQueryBindings string

const (
	samlLogoutRequestInferredBindings samlLogoutRequestQueryBindings = "inferred pgx"
	samlLogoutRequestWorkBindings     samlLogoutRequestQueryBindings = "Work fixed binary ExecParams"
)

func measureSAMLLogoutRequestStatement(t *testing.T, ctx context.Context, tx pgx.Tx, name, sql string, args []any, insert, want bool, keyColumn int, key string, bindingMode samlLogoutRequestQueryBindings) {
	t.Helper()
	native := bindingMode == samlLogoutRequestWorkBindings
	var oids []uint32
	var formats []int16
	if !native {
		description, err := tx.Conn().Prepare(ctx, "", sql)
		if err != nil {
			t.Fatal("describe exact raw-pool statement", name, err)
		}
		oids = description.ParamOIDs
	}
	query := func(statement string) (pgx.Rows, error) {
		if native {
			var rows pgx.Rows
			rows, oids, formats = samlLogoutRelayQueryRows(t, ctx, tx, statement, args)
			return rows, nil
		}
		return tx.Query(ctx, statement, args...)
	}
	types := make([]string, len(args))
	for i, arg := range args {
		types[i] = fmt.Sprintf("%T", arg)
	}
	var elapsed []time.Duration
	for sample := range 6 {
		if _, err := tx.Exec(ctx, "SAVEPOINT saml_request_query_sample"); err != nil {
			t.Fatal(err)
		}
		rows, err := query("EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) " + sql)
		if err != nil {
			t.Fatal("execute exact request query plan", name, err)
		}
		wire, err := pgx.CollectExactlyOneRow(rows, pgx.RowTo[[]byte])
		if err != nil {
			t.Fatal("explain exact request statement", name, err)
		}
		var plans []struct {
			Plan      samlLogoutAccountQueryPlan `json:"Plan"`
			Planning  float64                    `json:"Planning Time"`
			Execution float64                    `json:"Execution Time"`
			Triggers  []struct {
				Constraint string  `json:"Constraint Name"`
				Time       float64 `json:"Time"`
				Calls      int     `json:"Calls"`
			} `json:"Triggers,omitempty"`
		}
		err = json.Unmarshal(wire, &plans)
		clear(wire)
		if err != nil || len(plans) != 1 {
			t.Fatal("decode structural request query plan", name, err)
		}
		var inspect func(samlLogoutAccountQueryPlan)
		inspect = func(p samlLogoutAccountQueryPlan) {
			if p.Rows*p.Loops > 1 || p.Filtered*p.Loops > 1 || p.JoinFiltered*p.Loops > 1 {
				t.Fatal("exact request query examined growing retained-row work", name, p.Node, p.Relation, p.Rows, p.Loops, p.Filtered)
			}
			if strings.Contains(p.Node, "Scan") && p.Relation != "" && p.Index == "" {
				t.Fatal("exact request query did not use an installed index", name, p.Node, p.Relation)
			}
			for _, child := range p.Plans {
				inspect(child)
			}
		}
		inspect(plans[0].Plan)
		if sample == 0 {
			safe, err := json.Marshal(plans)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("query=%s first-sanitized-plan=%s", name, safe)
		}
		if _, err := tx.Exec(ctx, "ROLLBACK TO SAVEPOINT saml_request_query_sample"); err != nil {
			t.Fatal(err)
		}
		started := time.Now()
		actual := int64(0)
		if insert && native {
			rows, err := query(sql)
			if err != nil {
				t.Fatal("execute native Work insert bindings", name, err)
			}
			for rows.Next() {
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				t.Fatal("drain native Work insert", name, err)
			}
			actual = rows.CommandTag().RowsAffected()
		} else if insert {
			tag, err := tx.Exec(ctx, sql, args...)
			if err != nil {
				t.Fatal("execute raw-pool inferred insert bindings", name, err)
			}
			actual = tag.RowsAffected()
		} else {
			rows, err := query(sql)
			if err != nil {
				t.Fatal("execute exact retained-custody read bindings", name, err)
			}
			for rows.Next() {
				values, err := rows.Values()
				if err != nil || len(values) <= keyColumn {
					rows.Close()
					t.Fatal("exact read returned invalid retained custody", name, err)
				}
				if sql == requireSAMLLogoutRelayLocalCommitSQL {
					if values[0] != true {
						rows.Close()
						t.Fatal("local-commit read returned a false fence", name)
					}
				} else if values[keyColumn] != key {
					rows.Close()
					t.Fatal("exact read returned different retained custody", name, err)
				}
				for _, value := range values {
					if raw, ok := value.([]byte); ok {
						clear(raw)
					}
				}
				actual++
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				t.Fatal("drain exact retained-custody read", name, err)
			}
		}
		took := time.Since(started)
		wantRows := int64(0)
		if want {
			wantRows = 1
		}
		if actual != wantRows {
			t.Fatal("statement returned wrong retained-custody cardinality", name, actual, wantRows)
		}
		if sample > 0 {
			elapsed = append(elapsed, took)
		}
		if _, err := tx.Exec(ctx, "ROLLBACK TO SAVEPOINT saml_request_query_sample; RELEASE SAVEPOINT saml_request_query_sample"); err != nil {
			t.Fatal(err)
		}
	}
	slices.Sort(elapsed)
	t.Logf("query=%s SQL=%s Go-types=%v binding-mode=%s parameter-OIDs=%v parameter-formats=%v returned=%t; 5 warm client executions after one warmup: min=%s median=%s max=%s; timeout=1s; excludes setup, EXPLAIN, rollback, pool acquisition, encryption, coordinator and commit", name, sql, types, bindingMode, oids, formats, want, elapsed[0], elapsed[2], elapsed[4])
}

// Mirror only the text, bytea and timestamp parameters these relay statements
// pass to go-identity/postgres Work.Query (work_values.go), also used by
// Work.Exec and RecoveryWork.Query. This measures its
// fixed codec and extended wire profile, not Work admission or row budgets.
func samlLogoutRelayQueryRows(t *testing.T, ctx context.Context, tx pgx.Tx, sql string, args []any) (pgx.Rows, []uint32, []int16) {
	t.Helper()
	codecs := pgtype.NewMap()
	values := make([][]byte, len(args))
	oids := make([]uint32, len(args))
	formats := make([]int16, len(args))
	for i, value := range args {
		formats[i] = pgtype.BinaryFormatCode
		switch v := value.(type) {
		case string:
			oids[i] = pgtype.TextOID
		case []byte:
			oids[i] = pgtype.ByteaOID
			value = bytes.Clone(v)
		case time.Time:
			if v.Nanosecond()%1000 != 0 || v.Year() < 1 || v.Year() > 9999 {
				t.Fatal("relay query timestamp is outside Work's microsecond-exact profile")
			}
			oids[i] = pgtype.TimestamptzOID
			value = v.UTC()
		default:
			t.Fatalf("relay query uses an unmeasured Work scalar type %T", value)
		}
		encoded, err := codecs.Encode(oids[i], formats[i], value, make([]byte, 0))
		if err != nil {
			t.Fatal("encode relay Work query parameter", i, err)
		}
		values[i] = encoded
	}
	rows := pgx.RowsFromResultReader(codecs, tx.Conn().PgConn().ExecParams(ctx, sql, values, oids, formats, nil))
	return rows, oids, formats
}
