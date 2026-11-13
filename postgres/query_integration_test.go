//go:build integration

package postgres_test

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	database "github.com/faustbrian/go-postgres"
	sso "github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/jackc/pgx/v5"
)

type tracedQuery struct {
	sql  string
	args []any
}
type challengeTrace struct {
	mu      sync.Mutex
	queries []tracedQuery
}

func (q *challengeTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	if strings.Contains(d.SQL, "sso.domain_challenges") {
		q.mu.Lock()
		q.queries = append(q.queries, tracedQuery{sql: d.SQL, args: append([]any(nil), d.Args...)})
		q.mu.Unlock()
	}
	return ctx
}
func (*challengeTrace) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

// This is a bounded local cost proof, not a production-latency claim. Synthetic
// rows model challenge metadata/ciphertext size and a 10,000-row hot tenant;
// their copied ciphertext is intentionally never accepted as domain authority.
func TestDomainChallengeQueryScale(t *testing.T) {
	f := nativeDomainFixture(t)
	issued := f.issue(t, "query", "example.com", 1)
	owner, value := issued.DNSTXT()
	f.zone.publish(owner, value)
	committed, e := f.service.VerifyDomain(f.org.ctx, issued.Request())
	if e != nil || committed.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal(e)
	}
	_, e = f.org.pool.Raw().Exec(f.org.ctx, `INSERT INTO sso.domain_challenges SELECT CASE WHEN n<=10000 THEN 'org-test-basic' ELSE 'scale-'||(n%1000)::text END,'scale-org-'||((n-1)/10%1000)::text,'scale-claim-'||n::text,actor_id,substr(md5(n::text),1,22),canonical_domain,challenge_digest,capability_envelope,network_digest,correlation_id,issued_at,expires_at,NULL FROM sso.domain_challenges CROSS JOIN generate_series(1,100000) AS n WHERE claim_id='query'`)
	if e != nil {
		t.Fatal("representative challenge population failed", e)
	}
	if _, e = f.org.pool.Raw().Exec(f.org.ctx, `ANALYZE sso.domain_challenges`); e != nil {
		t.Fatal(e)
	}
	var rows, hot int
	var version string
	if e = f.org.pool.Raw().QueryRow(f.org.ctx, `SELECT count(*),count(*) FILTER(WHERE tenant_id='org-test-basic'),current_setting('server_version') FROM sso.domain_challenges`).Scan(&rows, &hot, &version); e != nil || rows != 100001 || hot != 10001 {
		t.Fatal("representative population mismatch", rows, hot, e)
	}
	trace := new(challengeTrace)
	pool, e := database.Connect(f.org.ctx, database.Config{DSN: f.org.dsn, MaxConns: 2, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database = f.org.database
		c.ConnConfig.Tracer = trace
		return nil
	}})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if pool.Close(ctx) != nil {
			t.Error("query fixture pool cleanup failed")
		}
	})
	store, e := ssopg.NewStore(pool, f.custody)
	if e != nil {
		t.Fatal(e)
	}
	key := sso.DomainChallengeKey{TenantID: "org-test-basic", OrganizationID: issued.Request().Claim().OrganizationID, ClaimID: issued.Request().Claim().ID}
	state, e := store.LoadDomainChallenge(f.org.ctx, key)
	if e != nil {
		t.Fatal(e)
	}
	operations := []struct {
		name string
		call func() error
	}{
		{"load-hot-tenant", func() error { _, e := store.LoadDomainChallenge(f.org.ctx, key); return e }},
		{"load-no-match", func() error {
			_, e := store.LoadDomainChallenge(f.org.ctx, sso.DomainChallengeKey{TenantID: "absent", OrganizationID: "absent", ClaimID: "absent"})
			if e == nil {
				return fmt.Errorf("missing challenge disclosed")
			}
			return nil
		}},
		{"create-idempotent-conflict", func() error { _, e := store.CreateDomainChallenge(f.org.ctx, state.Challenge); return e }},
		{"save-original-recovery", func() error { return store.SaveDomainRecovery(f.org.ctx, key, state.Recovery) }},
	}
	t.Logf("isolated PostgreSQL %s; challenge rows=%d hot-tenant=%d; text/C-collated tenant/org/claim composite primary key and global command unique index", version, rows, hot)
	for _, operation := range operations {
		var elapsed []time.Duration
		for range 7 {
			start := time.Now()
			if e = operation.call(); e != nil {
				t.Fatal(operation.name, e)
			}
			elapsed = append(elapsed, time.Since(start))
		}
		sort.Slice(elapsed, func(i, j int) bool { return elapsed[i] < elapsed[j] })
		t.Logf("native %s: 7 repeated warmed calls, median=%s max=%s, configured deadline=1s", operation.name, elapsed[3], elapsed[6])
	}
	// Capture actual pgx arguments and SQL, never their secret-bearing values.
	// EXPLAIN executes these same idempotent/missing-key statements in this
	// disposable fixture; unrelated user tables and services are not accessed.
	trace.mu.Lock()
	queries := append([]tracedQuery(nil), trace.queries...)
	trace.mu.Unlock()
	seen := map[string]bool{}
	for _, query := range queries {
		partition := query.sql
		if strings.HasPrefix(query.sql, "SELECT") && len(query.args) > 0 && query.args[0] == "absent" {
			partition += ":no-match"
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
		if e = f.org.pool.Raw().QueryRow(f.org.ctx, "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) "+query.sql, query.args...).Scan(&plan); e != nil {
			t.Fatal("actual typed query plan failed", e)
		}
		var decoded []map[string]any
		if json.Unmarshal(plan, &decoded) != nil || len(decoded) != 1 {
			t.Fatal("invalid plan output")
		}
		t.Logf("actual SQL=%s; pgx binding types=%v; plan=%s", query.sql, types, string(plan))
	}
	if len(seen) != 4 {
		t.Fatal("missing actual native query coverage", len(seen))
	}
	// Cover a real fresh insertion rather than only the conflict path. The
	// organization owner reserves this new claim; SSO alone signs its challenge.
	prepared, e := f.org.service.PrepareReserveDomain(f.org.ctx, organization.DomainClaimRequest{Authentication: f.org.auth("org-test-basic", "owner"), CommandID: commandID(t), OrganizationID: key.OrganizationID, ClaimID: "fresh-query", Domain: "fresh.example.com", OrganizationVersion: 3, CorrelationID: "fresh-query"}, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	if r, e := f.org.service.Execute(f.org.ctx, prepared); e != nil || r.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal(e)
	}
	factory, _ := ssopg.NewDomainEvidenceFactory(f.org.service)
	service, e := sso.NewService(f.config, f.org.service, factory, store, f.org.auth("org-test-basic", "owner"), "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	start := time.Now()
	_, e = service.ChallengeDomain(f.org.ctx, sso.DomainChallengeRequest{OrganizationID: key.OrganizationID, ClaimID: "fresh-query", CommandID: commandID(t), CorrelationID: "fresh-query"})
	if e != nil {
		t.Fatal(e)
	}
	t.Logf("fresh authorized challenge issue through native store, including current org/policy reads, signing/envelope/insert/readback: %s", time.Since(start))
}
