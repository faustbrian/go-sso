//go:build integration

package postgres_test

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/jackc/pgx/v5/pgtype"
)

type providerTrace struct {
	mu      sync.Mutex
	queries []providerQuery
	err     error
}

type providerQuery struct {
	tracedQuery
	oids    []uint32
	formats []int16
	values  [][]byte
}

// Work deliberately uses fixed-codec ExecParams instead of pgx.QueryTracer.
// Observe only its explicit-OID Parse/Bind messages in this isolated fixture;
// retain parameters in memory for measurements, never print their values.
type providerWireConn struct {
	net.Conn
	trace      *providerTrace
	started    bool
	pending    []byte
	statements map[string]pgproto3.Parse
}

func (c *providerWireConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.pending = append(c.pending, p[:n]...)
	for {
		if !c.started {
			if len(c.pending) < 4 {
				break
			}
			size := int(binary.BigEndian.Uint32(c.pending[:4]))
			if size < 8 || size > 16<<20 {
				c.failed(fmt.Errorf("invalid fixture startup frame"))
				break
			}
			if len(c.pending) < size {
				break
			}
			c.pending = c.pending[size:]
			c.started = true
			continue
		}
		if len(c.pending) < 5 {
			break
		}
		size := int(binary.BigEndian.Uint32(c.pending[1:5])) + 1
		if size < 5 || size > 16<<20 {
			c.failed(fmt.Errorf("invalid fixture query frame"))
			break
		}
		if len(c.pending) < size {
			break
		}
		frame := c.pending[:size]
		switch frame[0] {
		case 'P':
			var parse pgproto3.Parse
			if parse.Decode(frame[5:]) != nil {
				c.failed(fmt.Errorf("invalid fixture parse"))
				break
			}
			if c.statements == nil {
				c.statements = map[string]pgproto3.Parse{}
			}
			c.statements[parse.Name] = parse
		case 'B':
			var bind pgproto3.Bind
			if bind.Decode(frame[5:]) != nil {
				c.failed(fmt.Errorf("invalid fixture bind"))
				break
			}
			parse, ok := c.statements[bind.PreparedStatement]
			if !ok || !strings.Contains(parse.Query, "sso_providers.") || len(parse.ParameterOIDs) == 0 {
				break
			}
			if len(parse.ParameterOIDs) != len(bind.Parameters) {
				c.failed(fmt.Errorf("fixture parameter identity mismatch"))
				break
			}
			codecs := pgtype.NewMap()
			args := make([]any, len(bind.Parameters))
			values := make([][]byte, len(bind.Parameters))
			for i, parameter := range bind.Parameters {
				values[i] = append([]byte(nil), parameter...)
				format := int16(0)
				if len(bind.ParameterFormatCodes) == 1 {
					format = bind.ParameterFormatCodes[0]
				} else if len(bind.ParameterFormatCodes) == len(bind.Parameters) {
					format = bind.ParameterFormatCodes[i]
				}
				dataType, known := codecs.TypeForOID(parse.ParameterOIDs[i])
				if !known {
					c.failed(fmt.Errorf("unknown fixture parameter OID"))
					continue
				}
				value, decodeErr := dataType.Codec.DecodeValue(codecs, parse.ParameterOIDs[i], format, parameter)
				if decodeErr != nil {
					c.failed(fmt.Errorf("fixture parameter decode failed"))
					continue
				}
				if valueBytes, ok := value.([]byte); ok {
					value = append([]byte(nil), valueBytes...)
				}
				args[i] = value
			}
			c.trace.mu.Lock()
			c.trace.queries = append(c.trace.queries, providerQuery{tracedQuery: tracedQuery{sql: parse.Query, args: args}, oids: append([]uint32(nil), parse.ParameterOIDs...), formats: append([]int16(nil), bind.ParameterFormatCodes...), values: values})
			c.trace.mu.Unlock()
		}
		c.pending = c.pending[size:]
	}
	return n, err
}
func (c *providerWireConn) failed(err error) {
	c.trace.mu.Lock()
	if c.trace.err == nil {
		c.trace.err = err
	}
	c.trace.mu.Unlock()
}

func (q *providerTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	if strings.Contains(d.SQL, "sso_providers.") {
		q.mu.Lock()
		q.queries = append(q.queries, providerQuery{tracedQuery: tracedQuery{sql: d.SQL, args: append([]any(nil), d.Args...)}})
		q.mu.Unlock()
	}
	return ctx
}
func (*providerTrace) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func populateProviderQueryRows(t *testing.T, f *orgFixture, providerID string) {
	t.Helper()
	_, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO sso_providers.providers(tenant_id,organization_id,provider_id,issuer_digest,configuration_envelope,mapping_version,pending_domains)
SELECT CASE WHEN n<=10000 THEN 'org-test-basic' ELSE 'scale-'||(n%1000)::text END,
CASE WHEN n<=10000 THEN '01ARZ3NDEKTSV4RRFFQ69G5FAV' ELSE 'scale-org-'||(n%100)::text END,
'scale-'||lpad(n::text,8,'0'),decode(md5(n::text)||md5('issuer-'||n::text),'hex'),configuration_envelope,mapping_version,pending_domains
FROM sso_providers.providers CROSS JOIN generate_series(1,100000) n WHERE provider_id=$1`, providerID)
	if err != nil {
		t.Fatal("representative provider population", err)
	}
	_, err = f.pool.Raw().Exec(f.ctx, `INSERT INTO sso_providers.command_effects(command_id,tenant_id,organization_id,provider_id,binding,fingerprint,generation)
SELECT 'scale-command-'||n::text,p.tenant_id,p.organization_id,p.provider_id,e.binding,e.fingerprint,1
FROM generate_series(1,100000) n JOIN sso_providers.providers p ON p.provider_id='scale-'||lpad(n::text,8,'0')
CROSS JOIN sso_providers.command_effects e WHERE e.provider_id=$1`, providerID)
	if err != nil {
		t.Fatal("representative effect population", err)
	}
	if _, err = f.pool.Raw().Exec(f.ctx, `ANALYZE sso_providers.providers;ANALYZE sso_providers.command_effects`); err != nil {
		t.Fatal(err)
	}
}

func tracedProviderService(t *testing.T, f *orgFixture, config ssopg.ProviderServiceConfig, trace *providerTrace) *ssopg.ProviderService {
	t.Helper()
	pool, err := database.Connect(f.ctx, database.Config{DSN: f.dsn, MaxConns: 2, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database = f.database
		c.ConnConfig.Tracer = trace
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
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if pool.Close(ctx) != nil {
			t.Error("provider trace pool cleanup")
		}
	})
	service, err := ssopg.NewProviderService(pool, config, f.auth("org-test-basic", "owner"), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	return service
}

// Query scale is a bounded isolated cost proof, not production latency or
// authority for synthetic rows. Copied ciphertext is never decrypted/accepted
// as provider configuration or used to manufacture a command outcome.
func TestNativeProviderQueryScale(t *testing.T) {
	f, service, config := newProviderFixture(t)
	request := providerRequest(t, "https://query.example.com", "query-seed")
	created, err := service.ProviderRegisterOidc(f.ctx, request)
	if err != nil || created.Provider.ID == "" {
		t.Fatal(err)
	}
	populateProviderQueryRows(t, f, created.Provider.ID)
	trace := new(providerTrace)
	service = tracedProviderService(t, f, config, trace)
	var rows, hot, effects int
	var version string
	if err = f.pool.Raw().QueryRow(f.ctx, `SELECT count(*),count(*) FILTER(WHERE tenant_id='org-test-basic'),(SELECT count(*) FROM sso_providers.command_effects),current_setting('server_version') FROM sso_providers.providers`).Scan(&rows, &hot, &effects, &version); err != nil || rows != 100001 || hot != 10001 || effects != 100001 {
		t.Fatal("provider scale mismatch", rows, hot, err)
	}
	t.Logf("isolated PostgreSQL %s; providers=%d hot organization=%d effects=%d; C-collated tenant/organization/provider primary key, scoped issuer digest unique index and exact command primary key; no concurrent load", version, rows, hot, effects)
	operations := []struct {
		name string
		run  func() error
	}{
		{"exact-get", func() error {
			_, err := service.ProviderGet(f.ctx, sso.ProviderGetRequest{OrganizationID: request.OrganizationID, ProviderID: sso.ProviderID(created.Provider.ID)})
			return err
		}},
		{"missing-get", func() error {
			_, err := service.ProviderGet(f.ctx, sso.ProviderGetRequest{OrganizationID: request.OrganizationID, ProviderID: "missing"})
			if err == nil {
				return fmt.Errorf("missing provider disclosed")
			}
			return nil
		}},
		{"dense-first", func() error {
			_, err := service.ProviderList(f.ctx, sso.ProviderListRequest{OrganizationID: request.OrganizationID, Limit: 100})
			return err
		}},
		{"dense-deep", func() error {
			_, err := service.ProviderList(f.ctx, sso.ProviderListRequest{OrganizationID: request.OrganizationID, Cursor: "scale-00009000", Limit: 100})
			return err
		}},
		{"sparse-tail", func() error {
			out, err := service.ProviderList(f.ctx, sso.ProviderListRequest{OrganizationID: request.OrganizationID, Cursor: "scale-00009999", Limit: 100})
			if err == nil && (len(out.Providers) < 1 || len(out.Providers) > 2) {
				return fmt.Errorf("sparse tail cardinality changed")
			}
			return err
		}},
		{"empty-tail", func() error {
			out, err := service.ProviderList(f.ctx, sso.ProviderListRequest{OrganizationID: request.OrganizationID, Cursor: "zzzz", Limit: 1})
			if err == nil && len(out.Providers) != 0 {
				return fmt.Errorf("tail not empty")
			}
			return err
		}},
	}
	for _, operation := range operations {
		var elapsed []time.Duration
		for range 7 {
			start := time.Now()
			if err = operation.run(); err != nil {
				t.Fatal(operation.name, err)
			}
			elapsed = append(elapsed, time.Since(start))
		}
		sort.Slice(elapsed, func(i, j int) bool { return elapsed[i] < elapsed[j] })
		t.Logf("native %s: 7 warmed calls median=%s max=%s (includes current session/org/policy checks and pool/client overhead)", operation.name, elapsed[3], elapsed[6])
	}
	fresh := providerRequest(t, "https://query-new.example.com", "query-fresh")
	if out, err := service.ProviderRegisterOidc(f.ctx, fresh); err != nil || out.Provider.ID == "" {
		t.Fatal("native scaled insertion", err)
	}
	if out, err := service.ProviderRegisterOidc(f.ctx, fresh); err != nil || out.Provider.ID == "" {
		t.Fatal("native scaled original recovery", err)
	}
	trace.mu.Lock()
	queries := append([]providerQuery(nil), trace.queries...)
	traceError := trace.err
	trace.mu.Unlock()
	if traceError != nil {
		t.Fatal(traceError)
	}
	seen := map[string]bool{}
	for _, query := range queries {
		partition := query.sql
		if strings.HasPrefix(query.sql, "SELECT") && len(query.args) > 2 {
			partition += fmt.Sprint(query.args[2])
		}
		if seen[partition] {
			continue
		}
		seen[partition] = true
		types := make([]string, len(query.args))
		for i, arg := range query.args {
			types[i] = fmt.Sprintf("%T", arg)
		}
		var plan []byte
		for range 3 {
			tx, beginErr := f.pool.Raw().Begin(f.ctx)
			if beginErr != nil {
				t.Fatal(beginErr)
			}
			// Reproduce the captured fresh insert in a rollback-only fixture
			// transaction. Never mutate journals or bypass their immutability.
			if strings.HasPrefix(query.sql, "INSERT INTO sso_providers.providers") {
				_, err = tx.Exec(f.ctx, `DELETE FROM sso_providers.command_effects WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`, query.args[0], query.args[1], query.args[2])
				if err == nil {
					_, err = tx.Exec(f.ctx, `DELETE FROM sso_providers.providers WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`, query.args[0], query.args[1], query.args[2])
				}
			} else if strings.HasPrefix(query.sql, "INSERT INTO sso_providers.command_effects") {
				_, err = tx.Exec(f.ctx, `DELETE FROM sso_providers.command_effects WHERE command_id=$1`, query.args[0])
			}
			if err == nil {
				if len(query.oids) > 0 {
					// Preserve Work's actual explicit parameter OIDs and formats.
					// Inferring numeric parameters from casts would measure a
					// different driver path from Work's original text arguments.
					result := tx.Conn().PgConn().ExecParams(f.ctx, "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) "+query.sql, query.values, query.oids, query.formats, nil).Read()
					err = result.Err
					if err == nil {
						if len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
							err = fmt.Errorf("unexpected encoded query plan result")
						} else {
							plan = result.Rows[0][0]
						}
					}
				} else {
					err = tx.QueryRow(f.ctx, "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) "+query.sql, query.args...).Scan(&plan)
				}
			}
			rollbackErr := tx.Rollback(f.ctx)
			if err != nil || rollbackErr != nil {
				t.Fatal("actual typed provider plan", err, rollbackErr)
			}
			t.Logf("actual SQL=%s; binding types=%v native-OIDs=%v native-formats=%v; plan=%s", query.sql, types, query.oids, query.formats, string(plan))
		}
	}
	if len(seen) < 7 {
		t.Fatal("missing exact/paginated/mutation provider plans", len(seen))
	}
}

func TestNativeProviderPendingRecoveryQueryScale(t *testing.T) {
	f, service, config := newProviderFixture(t)
	seed, err := service.ProviderRegisterOidc(f.ctx, providerRequest(t, "https://recovery-scale.example.com", "recovery-scale-seed"))
	if err != nil || seed.Provider.ID == "" {
		t.Fatal(err)
	}
	populateProviderQueryRows(t, f, seed.Provider.ID)
	var rows, hot, effects int
	var version string
	if err = f.pool.Raw().QueryRow(f.ctx, `SELECT count(*),count(*) FILTER(WHERE tenant_id='org-test-basic'),(SELECT count(*) FROM sso_providers.command_effects),current_setting('server_version') FROM sso_providers.providers`).Scan(&rows, &hot, &effects, &version); err != nil || rows != 100001 || hot != 10001 || effects != 100001 {
		t.Fatal("reconciliation scale mismatch", rows, hot, effects, err)
	}
	t.Logf("isolated PostgreSQL %s; actual pending reconciliation with providers=%d hot organization=%d effects=%d; exact command primary key; no concurrent load", version, rows, hot, effects)
	trace := new(providerTrace)
	service = tracedProviderService(t, f, config, trace)
	lossy, fault := providerLossService(t, f, config, "INSERT INTO sso_providers.providers")
	fault.beforeCommit.Store(true)
	const recoverySQL = `SELECT binding,organization_id,provider_id FROM sso_providers.command_effects WHERE command_id=$1 AND tenant_id=$2`
	for sample := range 3 {
		fault.seen.Store(false)
		fault.lost.Store(false)
		request := providerRequest(t, fmt.Sprintf("https://pending-%d.example.com", sample), fmt.Sprintf("pending-original-%d", sample))
		original, originalErr := lossy.ProviderRegisterOidc(f.ctx, request)
		if !fault.lost.Load() || originalErr == nil || original.Completion.Outcome != identity.CommitOutcomeUnknown || original.Provider.ID != "" {
			t.Fatal("real final-commit loss did not leave an unknown original", original.Completion.Outcome, originalErr)
		}
		expirePendingProviderOriginal(t, f, original.Completion)
		trace.mu.Lock()
		trace.queries = nil
		trace.err = nil
		trace.mu.Unlock()
		started := time.Now()
		recovered, recoveryErr := service.ProviderRegisterOidc(f.ctx, request)
		elapsed := time.Since(started)
		if !errors.Is(recoveryErr, sso.ErrUnavailable) || recovered.Completion.Outcome != identity.CommitOutcomeNotCommitted || recovered.Completion.Binding != original.Completion.Binding || recovered.Provider.ID != "" {
			t.Fatal("attached original did not reconcile exact no-effect history", recovered.Completion.Outcome, recoveryErr)
		}
		trace.mu.Lock()
		queries := append([]providerQuery(nil), trace.queries...)
		traceErr := trace.err
		trace.mu.Unlock()
		if traceErr != nil {
			t.Fatal(traceErr)
		}
		var selected []providerQuery
		for _, query := range queries {
			if query.sql == recoverySQL {
				selected = append(selected, query)
			}
		}
		if len(selected) != 1 {
			t.Fatal("actual attached-original contributor read missing", len(selected))
		}
		query := selected[0]
		if len(query.args) != 2 || query.args[0] != string(original.Completion.Binding.CommandID) || query.args[1] != string(original.Completion.Binding.TenantID) || len(query.oids) != 2 || query.oids[0] != 25 || query.oids[1] != 25 {
			t.Fatal("recovery read lost original native scope/types")
		}
		t.Logf("actual public pending-reconciliation sample=%d elapsed=%s; original request/binding unchanged; outcome=not-committed; success effects absent", sample, elapsed)
		for range 3 {
			tx, beginErr := f.pool.Raw().Begin(f.ctx)
			if beginErr != nil {
				t.Fatal(beginErr)
			}
			plan := tx.Conn().PgConn().ExecParams(f.ctx, "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) "+query.sql, query.values, query.oids, query.formats, nil).Read()
			rollbackErr := tx.Rollback(f.ctx)
			if plan.Err != nil || rollbackErr != nil || len(plan.Rows) != 1 || len(plan.Rows[0]) != 1 {
				t.Fatal("actual original recovery read plan failed", plan.Err, rollbackErr)
			}
			t.Logf("actual SQL=%s; binding types=[string string] native-OIDs=%v native-formats=%v; plan=%s", query.sql, query.oids, query.formats, string(plan.Rows[0][0]))
		}
	}
	var committed, successAudits, outbox int
	if err = f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM sso_providers.providers),(SELECT count(*) FROM sso_providers.command_effects),(SELECT count(*) FROM audit.records WHERE action='identity.sso.provider.register-oidc' AND outcome=1),(SELECT count(*) FROM outbox_messages WHERE topic='sso.provider_registered.v1')`).Scan(&rows, &effects, &successAudits, &outbox); err != nil || rows != 100001 || effects != 100001 || successAudits != 1 || outbox != 1 {
		t.Fatal("pending reconciliation repeated success effects", rows, effects, successAudits, outbox, err)
	}
	if err = f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM identity.commands WHERE purpose='identity.sso.provider.register-oidc' AND state='committed'`).Scan(&committed); err != nil || committed != 1 {
		t.Fatal("reconciliation manufactured committed history", committed, err)
	}
}
