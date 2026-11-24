//go:build integration

package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// These rollback-only rows measure exact account correlation, not SAML proof,
// the complete logout operation, or behavior under competing lock owners.
func TestNativeSAMLLogoutStartLinkedProviderQueryScale(t *testing.T) {
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
			t.Error("rollback SAML logout account-query fixture", err)
		}
	})
	source := kernel.AccountMigrationSource{Version: 22, Base: kernel.CredentialMigrationSource{Version: 21, Base: kernel.MigrationSource{}}}
	history, err := source.Load(ctx)
	if err != nil {
		t.Fatal("load native account-query schema", err)
	}
	for _, migration := range history {
		if _, err := tx.Exec(ctx, migration.UpSQL()); err != nil {
			t.Fatal("install native account-query schema", err)
		}
	}
	if _, err := tx.Exec(ctx, "SET LOCAL statement_timeout='15s'; SET LOCAL lock_timeout='1s'"); err != nil {
		t.Fatal(err)
	}
	const tenant, user, provider = "saml-logout-cost-hot", "saml-logout-cost-user", "saml-cost-provider"
	if _, err := tx.Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version)
 SELECT CASE WHEN n=0 THEN $1::text ELSE 'saml-logout-cost-cold-'||n::text END,$2,'active',1
 FROM generate_series(0,100) n`, tenant, user); err != nil {
		t.Fatal("seed native account user owners", err)
	}
	if tag, err := tx.Exec(ctx, `INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled)
 SELECT CASE WHEN n<=20000 THEN $1::text ELSE 'saml-logout-cost-cold-'||(1+n%100)::text END,$2,
 'saml-cost-credential-'||n::text,3,'sso',1,true FROM generate_series(1,40000) n`, tenant, user); err != nil || tag.RowsAffected() != 40000 {
		t.Fatal("seed native credential-reference population", err)
	}
	if tag, err := tx.Exec(ctx, `WITH population AS (
 SELECT tenant_id,user_id,credential_id,'saml-cost-account-'||substring(credential_id FROM '[0-9]+$') AS account_id,
 $1::text AS provider,'urn:example:saml-cost-idp'::text AS issuer,credential_id::text AS subject
 FROM identity.credential_references)
 INSERT INTO identity.accounts(tenant_id,user_id,account_id,provider,issuer,subject,subject_key,version,social_link_version,linked)
 SELECT tenant_id,user_id,account_id,provider,issuer,subject,
 sha256(convert_to(octet_length(provider)::text||':'||provider||octet_length(issuer)::text||':'||issuer||octet_length(subject)::text||':'||subject,'UTF8')),
 1,1,credential_id<>'saml-cost-credential-20000' FROM population`, provider); err != nil || tag.RowsAffected() != 40000 {
		t.Fatal("seed native account population including an unlinked hot account", err)
	}
	if tag, err := tx.Exec(ctx, `INSERT INTO identity.account_credentials(tenant_id,user_id,credential_id,account_id)
 SELECT tenant_id,user_id,credential_id,'saml-cost-account-'||substring(credential_id FROM '[0-9]+$')
 FROM identity.credential_references`); err != nil || tag.RowsAffected() != 40000 {
		t.Fatal("seed exact native credential-account associations", err)
	}
	if _, err := tx.Exec(ctx, "ANALYZE identity.accounts; ANALYZE identity.account_credentials; SET LOCAL statement_timeout='1s'"); err != nil {
		t.Fatal(err)
	}
	var engine string
	var accounts, associations, hot, unlinked int
	var columns, indexes []byte
	if err := tx.QueryRow(ctx, `SELECT current_setting('server_version'),count(*),
 (SELECT count(*) FROM identity.account_credentials),count(*) FILTER(WHERE tenant_id=$1 AND user_id=$2),count(*) FILTER(WHERE NOT linked),
 (SELECT jsonb_agg(jsonb_build_object('table',c.relname,'column',a.attname,'type',format_type(a.atttypid,a.atttypmod)) ORDER BY c.relname,a.attnum)
 FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='identity' AND c.relname IN ('accounts','account_credentials') AND a.attnum>0 AND NOT a.attisdropped),
 (SELECT jsonb_agg(jsonb_build_object('table',c.relname,'definition',pg_get_indexdef(i.indexrelid),'valid',i.indisvalid) ORDER BY c.relname,i.indexrelid)
 FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='identity' AND c.relname IN ('accounts','account_credentials')) FROM identity.accounts`, tenant, user).Scan(
		&engine, &accounts, &associations, &hot, &unlinked, &columns, &indexes); err != nil || accounts != 40000 || associations != 40000 || hot != 20000 || unlinked != 1 {
		t.Fatal("inspect representative SAML account-query distribution", accounts, associations, hot, unlinked, err)
	}
	t.Logf("PostgreSQL=%s accounts=%d associations=%d hot-tenant/user=%d unlinked=%d; 100 cold tenants with 200 accounts each, one user and one provider namespace per tenant; actual-column-types=%s actual-indexes=%s; normal planner, refreshed statistics, isolated connection, no competing lock owners; not production or complete logout latency", engine, accounts, associations, hot, unlinked, columns, indexes)
	for _, mode := range []struct {
		name, sql string
		work      bool
	}{{"read", samlLogoutLinkedProviderSQL, false}, {"locked", samlLogoutLinkedProviderSQL + " FOR SHARE OF a,m", true}} {
		for _, test := range []struct {
			name, tenant, credential, provider string
			want                               int
		}{
			{"hot-hit", tenant, "saml-cost-credential-19999", provider, 1},
			{"cold-hit", "saml-logout-cost-cold-2", "saml-cost-credential-20001", provider, 1},
			{"wrong-provider", tenant, "saml-cost-credential-19999", "saml-other-provider", 0},
			{"missing-credential", tenant, "saml-cost-missing", provider, 0},
			{"unlinked", tenant, "saml-cost-credential-20000", provider, 0},
		} {
			phase := providerSAMLLogoutStartPhase{record: session.SessionSpec{TenantID: identity.TenantID(test.tenant), UserID: identity.UserID(user)}, accountProvider: test.provider}
			phase.record.Authentication.CredentialID = test.credential
			measureSAMLLogoutAccountStatement(t, ctx, tx, mode.name+"/"+test.name, mode.sql, phase.linkedProviderArgs(), mode.work, test.want)
		}
	}
}

type samlLogoutAccountQueryPlan struct {
	Node         string                       `json:"Node Type"`
	Relation     string                       `json:"Relation Name,omitempty"`
	Index        string                       `json:"Index Name,omitempty"`
	Rows         float64                      `json:"Actual Rows"`
	Loops        float64                      `json:"Actual Loops"`
	Filtered     float64                      `json:"Rows Removed by Filter"`
	JoinFiltered float64                      `json:"Rows Removed by Join Filter"`
	SharedHit    int                          `json:"Shared Hit Blocks"`
	SharedRead   int                          `json:"Shared Read Blocks"`
	Plans        []samlLogoutAccountQueryPlan `json:"Plans,omitempty"`
}

func measureSAMLLogoutAccountStatement(t *testing.T, ctx context.Context, tx pgx.Tx, name, sql string, args []any, work bool, want int) {
	t.Helper()
	codecs := pgtype.NewMap()
	values, oids, formats, types := make([][]byte, len(args)), make([]uint32, len(args)), make([]int16, len(args)), make([]string, len(args))
	for n, arg := range args {
		types[n] = fmt.Sprintf("%T", arg)
		if _, ok := arg.(string); !ok {
			t.Fatal("native account-query binding is no longer a string", types[n])
		}
		oids[n], formats[n] = pgtype.TextOID, pgtype.BinaryFormatCode
		var err error
		values[n], err = codecs.Encode(oids[n], formats[n], arg, make([]byte, 0))
		if err != nil {
			t.Fatal("encode native Work account-query binding", err)
		}
	}
	description, err := tx.Conn().Prepare(ctx, "", sql)
	if err != nil {
		t.Fatal("inspect ordinary driver account-query parameter types", err)
	}
	var elapsed []time.Duration
	for sample := range 6 {
		if _, err := tx.Exec(ctx, "SAVEPOINT saml_logout_account_sample"); err != nil {
			t.Fatal(err)
		}
		var wire []byte
		if work {
			result := tx.Conn().PgConn().ExecParams(ctx, "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) "+sql, values, oids, formats, nil).Read()
			if result.Err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
				t.Fatal("explain native Work account-query bindings", name, result.Err)
			}
			wire = result.Rows[0][0]
		} else if err := tx.QueryRow(ctx, "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) "+sql, args...).Scan(&wire); err != nil {
			t.Fatal("explain ordinary driver account-query bindings", name, err)
		}
		var plans []struct {
			Plan      samlLogoutAccountQueryPlan `json:"Plan"`
			Planning  float64                    `json:"Planning Time"`
			Execution float64                    `json:"Execution Time"`
		}
		err := json.Unmarshal(wire, &plans)
		clear(wire)
		if err != nil || len(plans) != 1 {
			t.Fatal("decode structural SAML account-query plan", name, err)
		}
		var inspect func(samlLogoutAccountQueryPlan)
		inspect = func(p samlLogoutAccountQueryPlan) {
			// The association PK selects at most one account. LIMIT 2 must not
			// hide a scan through all of the hot user's linked accounts.
			if p.Rows*p.Loops > 1 || p.Filtered*p.Loops > 1 || p.JoinFiltered*p.Loops > 1 {
				t.Fatal("exact SAML account query examined growing work", name, p.Node, p.Relation, p.Rows, p.Loops, p.Filtered, p.JoinFiltered)
			}
			if (p.Relation == "accounts" || p.Relation == "account_credentials") && p.Index == "" {
				t.Fatal("dense SAML account-query plan did not use an installed index", name, p.Node, p.Relation)
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
		if _, err := tx.Exec(ctx, "ROLLBACK TO SAVEPOINT saml_logout_account_sample"); err != nil {
			t.Fatal(err)
		}
		started := time.Now()
		actual := 0
		if work {
			result := tx.Conn().PgConn().ExecParams(ctx, sql, values, oids, formats, nil).Read()
			if result.Err != nil {
				t.Fatal("execute native Work account-query bindings", name, result.Err)
			}
			actual = len(result.Rows)
			for _, row := range result.Rows {
				if len(row) != 1 || string(row[0]) != args[3].(string) {
					t.Fatal("exact account query returned a different provider", name)
				}
				clear(row[0])
			}
		} else {
			rows, err := tx.Query(ctx, sql, args...)
			if err != nil {
				t.Fatal("execute ordinary driver account-query bindings", name, err)
			}
			for rows.Next() {
				var provider string
				if err := rows.Scan(&provider); err != nil || provider != args[3].(string) {
					rows.Close()
					t.Fatal("ordinary driver returned a different provider", name, err)
				}
				actual++
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				t.Fatal("drain ordinary driver account query", name, err)
			}
		}
		took := time.Since(started)
		if actual != want {
			t.Fatal("exact account query returned incorrect cardinality", name, actual, want)
		}
		if sample > 0 {
			elapsed = append(elapsed, took)
		}
		if _, err := tx.Exec(ctx, "ROLLBACK TO SAVEPOINT saml_logout_account_sample; RELEASE SAVEPOINT saml_logout_account_sample"); err != nil {
			t.Fatal(err)
		}
	}
	slices.Sort(elapsed)
	t.Logf("query=%s SQL=%s Go-types=%v driver-parameter-OIDs=%v Work=%t native-text-OIDs=%v binary-formats=%v returned=%d; 5 warm client executions after one warmup: min=%s median=%s max=%s; timeout=1s; excludes setup, EXPLAIN, rollback, pool acquisition, coordinator and commit", name, sql, types, description.ParamOIDs, work, oids, formats, want, elapsed[0], elapsed[2], elapsed[4])
}
