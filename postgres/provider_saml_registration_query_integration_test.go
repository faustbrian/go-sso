//go:build integration

package postgres_test

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-sso"
)

// This measures the new INSERT's incremental cost, not an invented predecessor
// or production latency. Synthetic ciphertext is only scale data and never
// supplies accepted configuration or a native command outcome.
func TestNativeSAMLProviderRegistrationQueryScale(t *testing.T) {
	f, service, config := newProviderFixture(t)
	seedRequest := providerRequest(t, "https://saml-query-seed.example.com", "saml-query-seed")
	seed, err := service.ProviderRegisterOidc(f.ctx, seedRequest)
	if err != nil || seed.Provider.ID == "" {
		t.Fatal("seed native provider for query scale", err)
	}
	populateProviderQueryRows(t, f, seed.Provider.ID)
	installProviderProtocolHistory(t, f)
	installSAMLProviderRegistrationHistory(t, f)

	var providers, hot, effects int
	var version, columns, indexes string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*),count(*) FILTER(WHERE tenant_id='org-test-basic'),(SELECT count(*) FROM sso_providers.command_effects),current_setting('server_version') FROM sso_providers.providers`).Scan(&providers, &hot, &effects, &version); err != nil || providers != 100001 || hot != 10001 || effects != 100001 {
		t.Fatal("representative SAML registration scale mismatch", providers, hot, effects, err)
	}
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT string_agg(attname||'='||format_type(atttypid,atttypmod),', ' ORDER BY attnum) FROM pg_attribute WHERE attrelid='sso_providers.providers'::regclass AND attnum>0 AND NOT attisdropped),
 (SELECT string_agg(pg_get_indexdef(indexrelid),'; ' ORDER BY indexrelid) FROM pg_index WHERE indrelid='sso_providers.providers'::regclass AND indisvalid AND indisready)`).Scan(&columns, &indexes); err != nil {
		t.Fatal("inspect actual registration columns and usable indexes", err)
	}
	t.Logf("isolated PostgreSQL %s; providers=%d hot organization=%d effects=%d; columns=%s; usable indexes=%s; synthetic 100k-row fixture, no concurrent load; cold cache, production distribution and contention unmeasured", version, providers, hot, effects, columns, indexes)

	trace := new(providerTrace)
	service = tracedProviderService(t, f, config, trace)
	service, err = service.WithOAuthRegistration()
	if err != nil {
		t.Fatal("select protocol-aware provider reader", err)
	}
	service, err = service.WithSAMLRegistration("https://sso.example.com", validateSAMLRegistrationFixture)
	if err != nil {
		t.Fatal("select native SAML registration", err)
	}
	request := providerSAMLRegistrationRequest(t, seedRequest.OrganizationID)
	spec, err := request.Configuration.Spec()
	if err != nil {
		t.Fatal(err)
	}

	const insertSQL = `INSERT INTO sso_providers.providers(tenant_id,organization_id,provider_id,issuer_digest,configuration_envelope,mapping_version,pending_domains,protocol) VALUES($1,$2,$3,$4,$5,$6::numeric,$7,'saml') ON CONFLICT DO NOTHING`
	var captured providerQuery
	var registrationTimes, retryTimes []time.Duration
	// The first genuine registration/retry warms the same native coordinator
	// and traced pool; only the following three calls enter timing summaries.
	for sample := range 4 {
		spec.EntityID = fmt.Sprintf("urn:example:saml-query:%d", sample)
		request.Configuration, err = sso.NewSAMLConfiguration(spec)
		if err != nil {
			t.Fatal(err)
		}
		request.CommandID = commandID(t)
		request.IdempotencyKey, err = identity.NewIdempotencyKey([]byte(fmt.Sprintf("saml-query-%d", sample)))
		if err != nil {
			t.Fatal(err)
		}
		trace.mu.Lock()
		trace.queries = nil
		trace.err = nil
		trace.mu.Unlock()

		started := time.Now()
		registered, err := service.ProviderRegisterSaml(f.ctx, request)
		registrationTime := time.Since(started)
		if err != nil || registered.Completion.Outcome != identity.CommitOutcomeCommitted || registered.Provider.ID == "" || registered.Provider.Protocol != "saml" || registered.Provider.Enabled {
			t.Fatal("native scaled SAML registration did not commit disabled metadata", err)
		}
		trace.mu.Lock()
		queries := append([]providerQuery(nil), trace.queries...)
		traceErr := trace.err
		trace.queries = nil
		trace.mu.Unlock()
		if traceErr != nil {
			t.Fatal(traceErr)
		}
		var inserts []providerQuery
		for _, query := range queries {
			if strings.HasPrefix(query.sql, "INSERT INTO sso_providers.providers") {
				inserts = append(inserts, query)
			}
		}
		if len(inserts) != 1 || inserts[0].sql != insertSQL {
			t.Fatal("native registration did not execute one parameterized SAML single-row INSERT", len(inserts))
		}
		query := inserts[0]
		if len(query.args) != 7 || len(query.values) != 7 || !reflect.DeepEqual(query.oids, []uint32{25, 25, 25, 17, 17, 25, 23}) ||
			(len(query.formats) != 0 && len(query.formats) != 1 && len(query.formats) != 7) {
			t.Fatal("native SAML INSERT lost explicit text/bytea/integer parameter identity")
		}
		if query.args[0] != "org-test-basic" || query.args[1] != request.OrganizationID || query.args[2] != registered.Provider.ID {
			t.Fatal("captured SAML INSERT differs from the native registered scope")
		}
		if sample == 1 {
			captured = query
		}

		started = time.Now()
		retried, err := service.ProviderRegisterSaml(f.ctx, request)
		retryTime := time.Since(started)
		if err != nil || !reflect.DeepEqual(retried, registered) {
			t.Fatal("native scaled original retry changed SAML registration", err)
		}
		trace.mu.Lock()
		retryQueries := append([]providerQuery(nil), trace.queries...)
		traceErr = trace.err
		trace.mu.Unlock()
		if traceErr != nil {
			t.Fatal(traceErr)
		}
		for _, query := range retryQueries {
			if strings.HasPrefix(query.sql, "INSERT INTO sso_providers.providers") {
				t.Fatal("original SAML retry amplified provider INSERTs")
			}
		}
		if sample > 0 {
			registrationTimes = append(registrationTimes, registrationTime)
			retryTimes = append(retryTimes, retryTime)
			t.Logf("native warmed sample=%d registration=%s provider-statements=%d provider-inserts=1 original-retry=%s provider-statements=%d provider-inserts=0; elapsed includes coordinator/session/org/policy/protected effects and pool/client overhead; statement counts cover provider schema only", sample, registrationTime, len(queries), retryTime, len(retryQueries))
		}
	}
	for _, operation := range []struct {
		name    string
		samples []time.Duration
	}{{"fresh registration", registrationTimes}, {"original retry", retryTimes}} {
		sort.Slice(operation.samples, func(i, j int) bool { return operation.samples[i] < operation.samples[j] })
		t.Logf("native SAML %s: 3 warmed calls median=%s max=%s", operation.name, operation.samples[1], operation.samples[2])
	}

	types := make([]string, len(captured.args))
	for i, arg := range captured.args {
		types[i] = fmt.Sprintf("%T", arg)
	}
	t.Logf("actual SQL=%s; binding types=%v native-OIDs=%v native-formats=%v; text mapping version uses explicit numeric cast, pending domains uses native int4; parameter values retained only in memory", captured.sql, types, captured.oids, captured.formats)
	for _, partition := range []string{"fresh", "exact-conflict"} {
		for sample := range 3 {
			tx, err := f.pool.Raw().Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			if partition == "fresh" {
				// Remove only the captured committed fixture's effect and row
				// inside this rollback. Journals remain untouched, and the
				// duplicate partition retains the exact scope and both keys.
				tag, deleteErr := tx.Exec(f.ctx, `DELETE FROM sso_providers.command_effects WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`, captured.args[0], captured.args[1], captured.args[2])
				err = deleteErr
				if err == nil && tag.RowsAffected() != 1 {
					err = fmt.Errorf("fresh replay must remove exactly one fixture effect")
				}
				if err == nil {
					tag, err = tx.Exec(f.ctx, `DELETE FROM sso_providers.providers WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`, captured.args[0], captured.args[1], captured.args[2])
					if err == nil && tag.RowsAffected() != 1 {
						err = fmt.Errorf("fresh replay must remove exactly one fixture provider")
					}
				}
			}
			var plan []byte
			if err == nil {
				result := tx.Conn().PgConn().ExecParams(f.ctx, "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) "+captured.sql, captured.values, captured.oids, captured.formats, nil).Read()
				err = result.Err
				if err == nil {
					if len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
						err = fmt.Errorf("unexpected native SAML INSERT plan result")
					} else {
						plan = result.Rows[0][0]
					}
				}
			}
			rollbackErr := tx.Rollback(f.ctx)
			if err != nil || rollbackErr != nil {
				t.Fatal("native typed SAML INSERT plan replay", partition, err, rollbackErr)
			}
			var decoded []struct {
				Plan struct {
					NodeType          string `json:"Node Type"`
					Operation         string
					RelationName      string `json:"Relation Name"`
					TuplesInserted    int    `json:"Tuples Inserted"`
					ConflictingTuples int    `json:"Conflicting Tuples"`
					Plans             []struct {
						NodeType    string  `json:"Node Type"`
						ActualRows  float64 `json:"Actual Rows"`
						ActualLoops int     `json:"Actual Loops"`
					}
				}
			}
			if err := json.Unmarshal(plan, &decoded); err != nil || len(decoded) != 1 {
				t.Fatal("decode native SAML INSERT plan", err)
			}
			root := decoded[0].Plan
			wantInserted, wantConflicts := 1, 0
			if partition == "exact-conflict" {
				wantInserted, wantConflicts = 0, 1
			}
			if root.NodeType != "ModifyTable" || root.Operation != "Insert" || root.RelationName != "providers" || root.TuplesInserted != wantInserted || root.ConflictingTuples != wantConflicts ||
				len(root.Plans) != 1 || root.Plans[0].NodeType != "Result" || root.Plans[0].ActualRows != 1 || root.Plans[0].ActualLoops != 1 {
				t.Fatal("SAML INSERT plan lost its bounded single-row insertion/conflict shape", partition)
			}
			t.Logf("native SAML INSERT partition=%s sample=%d; exact captured bindings; rollback-only fixture replay, setup deletes excluded from plan timing; plan=%s", partition, sample, string(plan))
		}
	}
	assertSAMLRegistrationEffects(t, f, 100005, 100005, 4, 5)
}
