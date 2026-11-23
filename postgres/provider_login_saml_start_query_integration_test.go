//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/jackc/pgx/v5/pgtype"
)

// Copied ciphertext supplies distribution only, never authority. Population,
// retained-row changes and measured writes remain in one rollback-only fixture.
func TestNativeSAMLSigninStartQueryScale(t *testing.T) {
	for _, scale := range []string{"tiny", "hot"} {
		t.Run(scale, func(t *testing.T) {
			x := newSAMLStartFixture(t)
			f := x.start.enable.f
			seed, err := x.start.service.SigninStartSAML(f.ctx, x.request, x.start.browser)
			if err != nil {
				t.Fatal("commit genuine SAML ciphertext source", err)
			}
			tx, err := f.pool.Raw().Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(f.ctx)
			if _, err := tx.Exec(f.ctx, `SET LOCAL statement_timeout='10s'; SET LOCAL lock_timeout='1s'`); err != nil {
				t.Fatal(err)
			}
			if scale == "hot" {
				for _, population := range []struct {
					sql string
					arg string
				}{
					{`INSERT INTO sso_providers.providers(tenant_id,organization_id,provider_id,issuer_digest,configuration_envelope,mapping_version,pending_domains,protocol)
SELECT CASE WHEN n<=10000 THEN tenant_id ELSE 'saml-cost-'||(n%1000)::text END,
CASE WHEN n<=10000 THEN organization_id ELSE 'saml-cost-org-'||(n%100)::text END,
'saml-cost-'||n::text,decode(md5(n::text)||md5('issuer-'||n::text),'hex'),configuration_envelope,mapping_version,pending_domains,'saml'
FROM sso_providers.providers CROSS JOIN generate_series(1,100000) n WHERE provider_id=$1`, string(x.request.ProviderID)},
					{`INSERT INTO sso_providers.credentials(tenant_id,organization_id,provider_id,generation,provider_version,envelope,credential_context)
SELECT p.tenant_id,p.organization_id,p.provider_id,c.generation,c.provider_version,c.envelope,c.credential_context
FROM sso_providers.providers p CROSS JOIN sso_providers.credentials c WHERE p.provider_id LIKE 'saml-cost-%' AND c.provider_id=$1`, string(x.request.ProviderID)},
					{`INSERT INTO sso_providers.login_transactions(tenant_id,organization_id,provider_id,provider_version,credential_generation,mapping_version,start_command_id,callback_command_id,protocol,state_key_version,state_digest,pkce_key_version,pkce_commitment,binding_envelope,verifier_envelope,issued_at,expires_at,completed_at)
SELECT p.tenant_id,p.organization_id,p.provider_id,l.provider_version,l.credential_generation,l.mapping_version,
'saml-cost-start-'||p.provider_id,'saml-cost-callback-'||p.provider_id,'saml',l.state_key_version,
decode(md5(p.provider_id)||md5('state-'||p.provider_id),'hex'),NULL,NULL,l.binding_envelope,NULL,
l.issued_at-interval '1 day',l.expires_at-interval '1 day',l.expires_at-interval '1 day'
FROM sso_providers.providers p CROSS JOIN sso_providers.login_transactions l WHERE p.provider_id LIKE 'saml-cost-%' AND l.start_command_id=$1`, seed.TransactionID},
					{`INSERT INTO sso_providers.login_transactions(tenant_id,organization_id,provider_id,provider_version,credential_generation,mapping_version,start_command_id,callback_command_id,protocol,state_key_version,state_digest,pkce_key_version,pkce_commitment,binding_envelope,verifier_envelope,issued_at,expires_at)
SELECT l.tenant_id,l.organization_id,l.provider_id,l.provider_version,l.credential_generation,l.mapping_version,
'saml-active-start-'||n::text,'saml-active-callback-'||n::text,'saml',l.state_key_version,
decode(md5('active-a-'||n::text)||md5('active-b-'||n::text),'hex'),NULL,NULL,l.binding_envelope,NULL,l.issued_at,l.expires_at
FROM sso_providers.login_transactions l CROSS JOIN generate_series(1,1024) n WHERE l.start_command_id=$1`, seed.TransactionID},
				} {
					if _, err := tx.Exec(f.ctx, population.sql, population.arg); err != nil {
						t.Fatal("rollback-only SAML scale population", err)
					}
				}
			}
			if _, err := tx.Exec(f.ctx, `ANALYZE sso_providers.providers; ANALYZE sso_providers.credentials; ANALYZE sso_providers.login_transactions`); err != nil {
				t.Fatal(err)
			}
			var providers, hot, history, active int
			var engine string
			if err := tx.QueryRow(f.ctx, `SELECT count(*),count(*) FILTER(WHERE tenant_id=$1 AND organization_id=$2),
(SELECT count(*) FROM sso_providers.login_transactions WHERE completed_at IS NOT NULL),
(SELECT count(*) FROM sso_providers.login_transactions WHERE completed_at IS NULL),current_setting('server_version')
FROM sso_providers.providers`, string(x.start.config.TenantID), string(x.profiles[0].OrganizationID)).Scan(&providers, &hot, &history, &active, &engine); err != nil {
				t.Fatal(err)
			}
			if scale == "hot" && (providers < 100001 || hot < 10001 || history != 100000 || active != 1025) {
				t.Fatal("representative SAML skew mismatch", providers, hot, history, active)
			}
			var schema []byte
			if err := tx.QueryRow(f.ctx, `SELECT jsonb_build_object(
'columns',(SELECT jsonb_agg(jsonb_build_object('table',table_name,'column',column_name,'type',data_type,'precision',numeric_precision,'scale',numeric_scale) ORDER BY table_name,ordinal_position)
 FROM information_schema.columns WHERE table_schema='sso_providers' AND table_name IN ('providers','credentials','login_transactions')),
'indexes',(SELECT jsonb_agg(indexdef ORDER BY tablename,indexname) FROM pg_indexes
 WHERE schemaname='sso_providers' AND tablename IN ('providers','credentials','login_transactions')))`).Scan(&schema); err != nil {
				t.Fatal("inspect actual fixture column types and available indexes", err)
			}
			t.Logf("actual fixture schema=%s", schema)
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
				t.Fatal(err)
			}
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				if err := pool.Close(ctx); err != nil {
					t.Error("close SAML trace pool", err)
				}
			})
			router, err := ssopg.NewProviderRouter(pool, ssopg.ProviderRouterConfig{Clock: clock.System{}, Envelope: x.start.config.Envelope,
				MaximumDuration: 3 * time.Second, Lifetime: 8 * time.Second, PolicyVersion: 1, MaximumProviders: 4})
			if err != nil {
				t.Fatal(err)
			}
			router, err = router.WithProtocolRegistry()
			if err != nil {
				t.Fatal(err)
			}
			expectedBundle := bytes.Repeat([]byte("fixture-activation-SP-signing/"), 2)
			defer clear(expectedBundle)
			cutoff := time.Now().UTC().Add(30 * time.Minute)
			router, err = router.WithSAMLRouteValidation(func(ctx context.Context, bundle []byte, at time.Time) (time.Time, error) {
				if ctx.Err() != nil || !bytes.Equal(bundle, expectedBundle) || !at.Before(cutoff) {
					return time.Time{}, sso.ErrInvalidInput
				}
				return cutoff, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			service, err := ssopg.NewProviderLoginServiceWithSAML(router, x.start.config, x.profiles, x.sign)
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := x.start.flowIssuer.Prepare(session.PreAuthPrepareInput{CommandID: commandID(t), TenantID: x.start.config.TenantID,
				CorrelationID: "native-saml-cost-browser", Remember: x.start.originalFlow.Intent.Remember})
			if err != nil {
				t.Fatal(err)
			}
			issued, err := x.start.flowIssuer.Issue(f.ctx, prepared)
			if err != nil || issued.CommitOutcome != identity.CommitOutcomeCommitted {
				t.Fatal("issue fresh original browser before measured start", err)
			}
			flow, err := issued.Flow.Bindings()
			if err != nil {
				t.Fatal(err)
			}
			cookie, err := issued.Token.Reveal()
			if err != nil {
				t.Fatal(err)
			}
			browser := x.start.browser
			browser.FlowID, browser.FlowCookie = flow.Binding.ID, authentication.NewBearerCredential(cookie)
			startedAt := time.Now()
			started, err := service.SigninStartSAML(f.ctx, x.request, browser)
			if err != nil || started.Completion.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("capture genuine typed native SAML start", err)
			}
			elapsed := time.Since(startedAt)
			trace.mu.Lock()
			queries, traceErr := trace.queries, trace.err
			trace.queries = nil
			trace.mu.Unlock()
			if traceErr != nil {
				t.Fatal(traceErr)
			}
			selected := map[string]providerQuery{}
			for _, q := range queries {
				switch {
				case strings.HasPrefix(q.sql, "SELECT p.issuer_digest,") && strings.Contains(q.sql, "p.protocol='saml'"):
					selected["profile"] = q
				case strings.HasPrefix(q.sql, "WITH eligible_provider AS MATERIALIZED") && strings.Contains(q.sql, "p.protocol='saml'"):
					selected["fence"] = q
				case strings.Contains(q.sql, "SELECT binding_envelope") && strings.Contains(q.sql, "protocol='saml'") && strings.Contains(q.sql, "start_command_id=$1"):
					selected["redirect"] = q
				case strings.HasPrefix(q.sql, "INSERT INTO sso_providers.login_transactions") && strings.Contains(q.sql, "'saml'"):
					selected["insert"] = q
				}
			}
			if len(selected) != 4 || len(selected["fence"].oids) != 7 || len(selected["insert"].oids) != 14 {
				t.Fatal("missing exact SAML profile/fence/redirect/insert and Work wire types")
			}
			recovery := selected["redirect"]
			recovery.sql = ssopg.SAMLSigninStartRecoverySQLForTest
			selected["recovery"] = recovery
			t.Logf("PostgreSQL=%s scale=%s providers=%d hot-tenant-providers=%d retained-history=%d active-hot=%d; original native start elapsed=%s provider-statements=%d at committed tiny cardinality; scaled exact-statement replay is separate, rollback-only, isolated, no concurrent load; normal planner, first sample may be cold", engine, scale, providers, hot, history, active, elapsed, len(queries))
			for sample := range 2 {
				startedAt := time.Now()
				replayed, err := service.SigninStartSAML(f.ctx, x.request, browser)
				if err != nil || replayed.TransactionID != started.TransactionID || replayed.RedirectURI != started.RedirectURI || len(x.inputs) != 2 {
					t.Fatal("original native replay changed redirect or signed again", err)
				}
				trace.mu.Lock()
				count, traceErr := len(trace.queries), trace.err
				trace.queries = nil
				trace.mu.Unlock()
				if traceErr != nil || count > len(queries) {
					t.Fatal("native SAML retry amplified provider queries", count, traceErr)
				}
				t.Logf("native original retry sample=%d elapsed=%s provider-statements=%d; committed tiny cardinality", sample, time.Since(startedAt), count)
			}
			for _, name := range []string{"profile", "fence", "redirect", "recovery", "insert"} {
				partitions := []string{"hit", "miss"}
				if name == "redirect" || name == "recovery" {
					partitions = append(partitions, "retained")
				}
				for _, partition := range partitions {
					q := selected[name]
					q.args, q.values = append([]any(nil), q.args...), append([][]byte(nil), q.values...)
					if partition == "miss" {
						index, value := 0, any("saml-cost-missing-command")
						switch name {
						case "profile":
							index, value = 2, "saml-cost-missing-provider"
						case "fence":
							index, value = 6, time.Now().UTC().Add(-time.Hour)
						case "insert":
							index, value = 13, time.Now().UTC().Add(-time.Hour)
						}
						q.args[index] = value
						if len(q.oids) != 0 {
							format := int16(0)
							if len(q.formats) == 1 {
								format = q.formats[0]
							} else if len(q.formats) == len(q.oids) {
								format = q.formats[index]
							}
							q.values[index], err = pgtype.NewMap().Encode(q.oids[index], format, value, nil)
							if err != nil {
								t.Fatal("preserve native binding codec for negative case", err)
							}
						}
					}
					types := make([]string, len(q.args))
					for i, arg := range q.args {
						types[i] = fmt.Sprintf("%T", arg)
					}
					for sample := range 2 {
						if _, err := tx.Exec(f.ctx, "SAVEPOINT saml_cost_sample"); err != nil {
							t.Fatal(err)
						}
						if name == "insert" {
							if _, err := tx.Exec(f.ctx, `DELETE FROM sso_providers.login_transactions WHERE start_command_id=$1`, started.TransactionID); err != nil {
								t.Fatal(err)
							}
						} else if partition == "retained" {
							if _, err := tx.Exec(f.ctx, `UPDATE sso_providers.login_transactions SET completed_at=expires_at WHERE start_command_id=$1`, started.TransactionID); err != nil {
								t.Fatal(err)
							}
						}
						var wire []byte
						if len(q.oids) > 0 {
							result := tx.Conn().PgConn().ExecParams(f.ctx, "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) "+q.sql, q.values, q.oids, q.formats, nil).Read()
							if result.Err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
								t.Fatal("exact native SAML wire plan", name, partition, result.Err)
							}
							wire = result.Rows[0][0]
						} else if err := tx.QueryRow(f.ctx, "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) "+q.sql, q.args...).Scan(&wire); err != nil {
							t.Fatal(name, partition, err)
						}
						var plans []struct {
							Plan          protocolRouteQueryPlan
							ExecutionTime float64 `json:"Execution Time"`
						}
						if err := json.Unmarshal(wire, &plans); err != nil || len(plans) != 1 {
							t.Fatal("decode native SAML plan", name, partition, err)
						}
						t.Logf("%s partition=%s sample=%d SQL=%s Go-types=%v native-OIDs=%v formats=%v plan=%s", name, partition, sample, q.sql, types, q.oids, q.formats, wire)
						wantRows := float64(1)
						retainedRedirect := name == "redirect" && partition == "retained"
						if partition == "miss" || retainedRedirect || name == "insert" {
							wantRows = 0
						}
						if plans[0].ExecutionTime > 100 || plans[0].Plan.ActualRows != wantRows {
							t.Fatal("SAML statement exceeded bounded execution or returned wrong partition", name, partition, plans[0].ExecutionTime, plans[0].Plan.ActualRows)
						}
						if name == "insert" {
							var inserted bool
							if err := tx.QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM sso_providers.login_transactions WHERE start_command_id=$1 AND protocol='saml' AND pkce_key_version IS NULL AND pkce_commitment IS NULL AND verifier_envelope IS NULL)`, started.TransactionID).Scan(&inserted); err != nil || inserted != (partition == "hit") {
								t.Fatal("measured SAML write did not preserve its one-row or rejected outcome", partition, err)
							}
						}
						if scale == "hot" {
							indexes := map[string]bool{}
							var inspect func(protocolRouteQueryPlan)
							inspect = func(n protocolRouteQueryPlan) {
								if n.ActualRows > 1 || n.ActualLoops > 1 || n.FilteredRows > 1 || n.NodeType == "Seq Scan" || n.NodeType == "Sort" {
									t.Fatal("SAML query examined unbounded work", name, partition, n.NodeType, n.IndexName, n.ActualRows, n.ActualLoops, n.FilteredRows)
								}
								indexes[n.IndexName] = true
								for _, child := range n.ChildPlans {
									inspect(child)
								}
							}
							inspect(plans[0].Plan)
							providerRead := name == "profile" || name == "fence" && partition == "hit"
							originalCommandRead := name == "redirect" || name == "recovery"
							missingProviderIndex := !indexes["providers_pkey"] || !indexes["credentials_pkey"]
							if providerRead && missingProviderIndex || originalCommandRead && !indexes["login_transactions_start_command_id_key"] {
								t.Fatal("SAML query lost exact indexed access; redirect/recovery must resolve unique original command before provider/expiry filtering", name, partition, indexes)
							}
						}
						if _, err := tx.Exec(f.ctx, "ROLLBACK TO SAVEPOINT saml_cost_sample"); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			if err := tx.Rollback(f.ctx); err != nil {
				t.Fatal("rollback SAML scale population and all measured writes", err)
			}
			t.Log("recovery uses exact exported statement with the observed original redirect arguments and binding types; recovery lifecycle is not exercised; original admission/insertion deadlines are never renewed")
		})
	}
}
