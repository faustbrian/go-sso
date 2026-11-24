//go:build integration

package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// Named risks: retained-row scan amplification, stale provider/credential
// fencing, and duplicate-receipt fallback cost. These exact raw-pool statements
// use inferred pgx bindings on one isolated primary connection. All writes roll
// back; this does not measure signature checks, contention, commit or the full
// logout operation, and does not introduce a session or response-state owner.
func TestNativeSAMLLogoutResponseQueryScale(t *testing.T) {
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
			t.Error("rollback response query fixture", err)
		}
	})
	for _, source := range []migrations.Source{
		kernel.MigrationSource{}, ProviderMigrationSource{Version: 320}, ProviderUpdateMigrationSource{Version: 321},
		ProviderCredentialsMigrationSource{Version: 322}, ProviderEnableMigrationSource{Version: 323},
		ProviderProtocolMigrationSource{Version: 330, ValidationVersion: 331},
		ProviderSAMLProtocolMigrationSource{Version: 332, ValidationVersion: 333},
		SAMLLogoutSubjectMigrationSource{Version: 394}, SAMLLogoutRequestMigrationSource{Version: 395},
		SAMLLogoutResponseMigrationSource{Version: 396},
	} {
		history, err := source.Load(ctx)
		if err != nil {
			t.Fatal("load production response query schema", err)
		}
		for _, migration := range history {
			if _, err := tx.Exec(ctx, migration.UpSQL()); err != nil {
				t.Fatal("install production response query schema", err)
			}
		}
	}
	if _, err := tx.Exec(ctx, "SET LOCAL statement_timeout='15s'; SET LOCAL lock_timeout='1s'"); err != nil {
		t.Fatal(err)
	}
	const tenant, organization = "response-cost-hot", "response-cost-organization"
	issued := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Minute)
	expires := issued.Add(5 * time.Minute)
	// Refresh each populated FK parent before seeding its dependent table,
	// rather than leaving that fan-in planned with fresh-table statistics.
	for step, statement := range []string{
		`INSERT INTO sso_providers.providers
 (tenant_id,organization_id,provider_id,issuer_digest,configuration_envelope,mapping_version,pending_domains,
 protocol,enabled,enablement_proof,enablement_credential_generation)
 SELECT CASE WHEN n<=16000 THEN $1::text ELSE 'response-cost-cold-'||(1+n%100)::text END,$2,
 'response-cost-provider-'||n::text,sha256(convert_to('response-cost-issuer-'||n::text,'UTF8')),
 decode('01','hex'),1,1,'saml',true,decode('01','hex'),1 FROM generate_series(1,20000) n`,
		`ANALYZE sso_providers.providers`,
		`INSERT INTO sso_providers.credentials
 (tenant_id,organization_id,provider_id,generation,provider_version,envelope,credential_context)
 SELECT tenant_id,organization_id,provider_id,1,2,convert_to(repeat('c',2048),'UTF8'),decode('01','hex')
 FROM sso_providers.providers`,
		`ANALYZE sso_providers.credentials`,
		`INSERT INTO identity.identity_command_id_claims
 (command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields)
 SELECT substring(sha256(convert_to('response-cost-request-'||n::text,'UTF8')) from 1 for 16),
 CASE WHEN n<=16000 OR n>20000 THEN $1::text ELSE 'response-cost-cold-'||(1+n%100)::text END,
 'identity.sso.saml-logout-start',sha256(convert_to('response-cost-fingerprint-'||n::text,'UTF8')),1,decode('01','hex')
 FROM generate_series(1,20002) n`,
		`INSERT INTO identity.commands(command_id,tenant_id,purpose)
 SELECT command_id,tenant_id,purpose FROM identity.identity_command_id_claims`,
		`ANALYZE identity.commands`,
		`INSERT INTO sso_providers.saml_logout_requests
 (tenant_id,organization_id,provider_id,request_id,start_command_id,issued_at,expires_at,request_envelope)
 SELECT CASE WHEN n<=16000 OR n>20000 THEN $1::text ELSE 'response-cost-cold-'||(1+n%100)::text END,$2,
 'response-cost-provider-'||(CASE WHEN n>20000 THEN 16000 ELSE n END)::text,
 '_'||translate(rtrim(encode(substring(sha256(convert_to('response-cost-request-'||n::text,'UTF8')) from 1 for 16),'base64'),'='),'+/','-_'),
 substring(sha256(convert_to('response-cost-request-'||n::text,'UTF8')) from 1 for 16),$3,$4,
 convert_to(repeat('r',2048),'UTF8') FROM generate_series(1,20002) n`,
		`ANALYZE sso_providers.saml_logout_requests`,
		`INSERT INTO sso_providers.saml_logout_responses
 (tenant_id,request_id,response_id_digest,response_digest,status_code,status_subcode,settled_at)
 SELECT tenant_id,request_id,sha256(convert_to('response-cost-id-'||request_id,'UTF8')),
 sha256(convert_to('response-cost-wire-'||request_id,'UTF8')),'urn:oasis:names:tc:SAML:2.0:status:Success','',statement_timestamp()
 FROM sso_providers.saml_logout_requests
 WHERE start_command_id NOT IN (
 substring(sha256(convert_to('response-cost-request-20001','UTF8')) from 1 for 16),
 substring(sha256(convert_to('response-cost-request-20002','UTF8')) from 1 for 16))`,
	} {
		var args []any
		if strings.Contains(statement, "$1") {
			args = []any{tenant}
		}
		if strings.Contains(statement, "$2") {
			args = append(args, organization)
		}
		if strings.Contains(statement, "$3") {
			args = append(args, issued, expires)
		}
		label, _, _ := strings.Cut(statement, "\n")
		started := time.Now()
		if _, err := tx.Exec(ctx, statement, args...); err != nil {
			t.Fatalf("response query fixture step %d (%s) after %s: %v", step+1, label, time.Since(started), err)
		}
		t.Logf("response query fixture step %d (%s): %s", step+1, label, time.Since(started))
	}
	if _, err := tx.Exec(ctx, `ANALYZE sso_providers.saml_logout_requests; ANALYZE sso_providers.saml_logout_responses;
 SET LOCAL statement_timeout='1s'`); err != nil {
		t.Fatal(err)
	}
	var engine string
	var requests, receipts, providers, credentials, hot int
	var columns, indexes []byte
	if err := tx.QueryRow(ctx, `SELECT current_setting('server_version'),
 (SELECT count(*) FROM sso_providers.saml_logout_requests),
 (SELECT count(*) FROM sso_providers.saml_logout_responses),
 (SELECT count(*) FROM sso_providers.providers),(SELECT count(*) FROM sso_providers.credentials),
 (SELECT count(*) FROM sso_providers.saml_logout_responses WHERE tenant_id=$1),
 (SELECT jsonb_agg(jsonb_build_object('table',c.relname,'column',a.attname,'type',format_type(a.atttypid,a.atttypmod)) ORDER BY c.relname,a.attnum)
 FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='sso_providers' AND c.relname IN ('saml_logout_requests','saml_logout_responses','providers','credentials') AND a.attnum>0 AND NOT a.attisdropped),
 (SELECT jsonb_agg(jsonb_build_object('table',c.relname,'definition',pg_get_indexdef(i.indexrelid),'valid',i.indisvalid) ORDER BY c.relname,i.indexrelid)
 FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='sso_providers' AND c.relname IN ('saml_logout_requests','saml_logout_responses','providers','credentials'))`, tenant).Scan(
		&engine, &requests, &receipts, &providers, &credentials, &hot, &columns, &indexes); err != nil || requests != 20002 || receipts != 20000 || providers != 20000 || credentials != 20000 || hot != 16000 {
		t.Fatal("inspect representative response query distribution", requests, receipts, providers, credentials, hot, err)
	}
	t.Logf("PostgreSQL=%s requests=%d receipts=%d providers=%d credentials=%d hot-tenant-receipts=%d; 100 cold tenants with 40 rows each, two additional unreceipted hot requests, 2048-byte synthetic request/credential envelopes; actual-column-types=%s actual-indexes=%s; normal planner, refreshed statistics, one isolated primary connection, no competing load; synthetic warm statement evidence, not production or full logout latency", engine, requests, receipts, providers, credentials, hot, columns, indexes)
	requestID := func(n int) string {
		digest := sha256.Sum256(fmt.Appendf(nil, "response-cost-request-%d", n))
		return "_" + base64.RawURLEncoding.EncodeToString(digest[:16])
	}
	id, digest := sha256.Sum256([]byte("response-cost-fresh-id")), sha256.Sum256([]byte("response-cost-fresh-wire"))
	const success = "urn:oasis:names:tc:SAML:2.0:status:Success"
	args := []any{tenant, requestID(20001), organization, "response-cost-provider-16000", expires, "1", "1", expires, id[:], digest[:], success, ""}
	first := measureSAMLLogoutResponseStatement(t, ctx, tx, "insert/first-hot", insertSAMLLogoutResponseSQL, args, samlLogoutResponseQueryWant{eligible: true, written: true})
	duplicate := slices.Clone(args)
	duplicate[1] = requestID(16000)
	replay := measureSAMLLogoutResponseStatement(t, ctx, tx, "insert/duplicate-hot", insertSAMLLogoutResponseSQL, duplicate, samlLogoutResponseQueryWant{eligible: true})
	reusedID := sha256.Sum256([]byte("response-cost-id-" + requestID(16000)))
	conflict := slices.Clone(args)
	conflict[8] = reusedID[:]
	measureSAMLLogoutResponseStatement(t, ctx, tx, "insert/reused-response-id", insertSAMLLogoutResponseSQL, conflict, samlLogoutResponseQueryWant{eligible: true})
	for _, fence := range []struct {
		name  string
		index int
		value any
	}{
		{"stale-provider", 5, "2"}, {"stale-credential", 6, "2"},
		{"missing-request", 1, requestID(20003)}, {"missing-provider", 3, "response-cost-missing"},
		{"foreign-tenant", 0, "response-cost-cold-2"}, {"changed-expiry", 4, expires.Add(-time.Microsecond)},
		{"expired-cutoff", 7, issued},
	} {
		fenced := slices.Clone(args)
		fenced[fence.index] = fence.value
		measureSAMLLogoutResponseStatement(t, ctx, tx, "insert/"+fence.name, insertSAMLLogoutResponseSQL, fenced, samlLogoutResponseQueryWant{})
	}
	for _, fence := range []struct{ name, sql string }{
		{"rotated-credential", `UPDATE sso_providers.credentials SET generation=2 WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`},
		{"missing-credential", `DELETE FROM sso_providers.credentials WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`},
		{"disabled-provider", `UPDATE sso_providers.providers SET enabled=false,enablement_proof=NULL,enablement_credential_generation=NULL WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`},
	} {
		if _, err := tx.Exec(ctx, "SAVEPOINT response_query_fence"); err != nil {
			t.Fatal(err)
		}
		if tag, err := tx.Exec(ctx, fence.sql, tenant, organization, args[3]); err != nil || tag.RowsAffected() != 1 {
			t.Fatal("set exact response query fence", fence.name, err)
		}
		measureSAMLLogoutResponseStatement(t, ctx, tx, "insert/"+fence.name, insertSAMLLogoutResponseSQL, args, samlLogoutResponseQueryWant{})
		if _, err := tx.Exec(ctx, "ROLLBACK TO SAVEPOINT response_query_fence; RELEASE SAVEPOINT response_query_fence"); err != nil {
			t.Fatal(err)
		}
	}
	var receiptHit time.Duration
	for _, test := range []struct {
		name, tenant string
		n            int
		want         bool
	}{
		{"hot-hit", tenant, 16000, true}, {"cold-hit", "response-cost-cold-2", 19901, true},
		{"receipt-miss", tenant, 20002, false}, {"request-miss", tenant, 20003, false},
		{"foreign-tenant", "response-cost-cold-2", 16000, false},
	} {
		key := requestID(test.n)
		wantDigest := sha256.Sum256([]byte("response-cost-wire-" + key))
		want := samlLogoutResponseQueryWant{}
		if test.want {
			want.digest = wantDigest[:]
		}
		median := measureSAMLLogoutResponseStatement(t, ctx, tx, "read/"+test.name, readSAMLLogoutResponseSQL, []any{test.tenant, key}, want)
		if test.name == "hot-hit" {
			receiptHit = median
		}
	}
	cold := slices.Clone(args)
	cold[0], cold[1], cold[3] = "response-cost-cold-2", requestID(19901), "response-cost-provider-19901"
	measureSAMLLogoutResponseStatement(t, ctx, tx, "insert/duplicate-cold", insertSAMLLogoutResponseSQL, cold, samlLogoutResponseQueryWant{eligible: true})
	t.Logf("incremental response-settlement SQL only: first=1 insert, median=%s; duplicate=1 insert+1 receipt read, sum of isolated statement medians=%s; not an end-to-end transaction measurement; earlier profile/request reads, signature validation, pool acquisition, waits and commit excluded", first, replay+receiptHit)
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM sso_providers.saml_logout_responses").Scan(&receipts); err != nil || receipts != 20000 {
		t.Fatal("measurements retained a new response receipt", receipts, err)
	}
}

type samlLogoutResponseQueryWant struct {
	eligible, written bool
	digest            []byte
}

func measureSAMLLogoutResponseStatement(t *testing.T, ctx context.Context, tx pgx.Tx, name, sql string, args []any, want samlLogoutResponseQueryWant) time.Duration {
	t.Helper()
	description, err := tx.Conn().Prepare(ctx, "", sql)
	if err != nil {
		t.Fatal("describe exact raw-pool response statement", name, err)
	}
	types := make([]string, len(args))
	for i, arg := range args {
		types[i] = fmt.Sprintf("%T", arg)
	}
	var elapsed []time.Duration
	var server []float64
	for sample := range 6 {
		if _, err := tx.Exec(ctx, "SAVEPOINT saml_response_query_sample"); err != nil {
			t.Fatal(err)
		}
		var wire []byte
		if err := tx.QueryRow(ctx, "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) "+sql, args...).Scan(&wire); err != nil {
			t.Fatal("explain exact inferred-binding response statement", name, err)
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
		err := json.Unmarshal(wire, &plans)
		clear(wire)
		if err != nil || len(plans) != 1 {
			t.Fatal("decode structural response query plan", name, err)
		}
		var inspect func(samlLogoutAccountQueryPlan)
		inspect = func(p samlLogoutAccountQueryPlan) {
			if p.Rows*p.Loops > 1 || p.Filtered*p.Loops > 1 || p.JoinFiltered*p.Loops > 1 {
				t.Fatal("exact response query examined growing retained-row work", name, p.Node, p.Relation, p.Rows, p.Loops, p.Filtered)
			}
			if strings.Contains(p.Node, "Scan") && p.Relation != "" && p.Index == "" {
				t.Fatal("exact response query did not use an installed index", name, p.Node, p.Relation)
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
		if _, err := tx.Exec(ctx, "ROLLBACK TO SAVEPOINT saml_response_query_sample"); err != nil {
			t.Fatal(err)
		}
		started := time.Now()
		if sql == insertSAMLLogoutResponseSQL {
			var eligible, written bool
			if err := tx.QueryRow(ctx, sql, args...).Scan(&eligible, &written); err != nil || eligible != want.eligible || written != want.written {
				t.Fatal("response statement returned wrong eligibility/write outcome", name, eligible, written, err)
			}
		} else {
			var digest []byte
			var code, subcode string
			err := tx.QueryRow(ctx, sql, args...).Scan(&digest, &code, &subcode)
			if want.digest != nil {
				if err != nil || !bytes.Equal(digest, want.digest) || code != "urn:oasis:names:tc:SAML:2.0:status:Success" || subcode != "" {
					t.Fatal("response read returned different retained receipt", name, err)
				}
			} else if !errors.Is(err, pgx.ErrNoRows) {
				t.Fatal("response read did not preserve receipt absence", name, err)
			}
			clear(digest)
		}
		took := time.Since(started)
		if sample > 0 {
			elapsed = append(elapsed, took)
			server = append(server, plans[0].Execution)
		}
		if _, err := tx.Exec(ctx, "ROLLBACK TO SAVEPOINT saml_response_query_sample; RELEASE SAVEPOINT saml_response_query_sample"); err != nil {
			t.Fatal(err)
		}
	}
	slices.Sort(elapsed)
	slices.Sort(server)
	t.Logf("query=%s SQL=%s Go-types=%v inferred-parameter-OIDs=%v eligible=%t written=%t receipt-hit=%t; 5 warm executions after one warmup: client min=%s median=%s max=%s; EXPLAIN server execution milliseconds min=%.3f median=%.3f max=%.3f; timeout=1s; excludes setup, rollback, pool acquisition, signature validation and commit; EXPLAIN timing is separate from client timing", name, sql, types, description.ParamOIDs, want.eligible, want.written, want.digest != nil, elapsed[0], elapsed[2], elapsed[4], server[0], server[2], server[4])
	return elapsed[2]
}
