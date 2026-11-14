//go:build integration

package postgres_test

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	database "github.com/faustbrian/go-postgres"
	sso "github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestDomainMethodMigrationPreservesPopulatedDNSAndMixedReaders(t *testing.T) {
	f := nativeDomainFixture(t)
	issued := f.issue(t, "historical-dns", "example.com", 1)
	key := sso.DomainChallengeKey{TenantID: issued.Request().Claim().TenantID, OrganizationID: issued.Request().Claim().OrganizationID, ClaimID: issued.Request().Claim().ID}
	before, err := f.store.LoadDomainChallenge(f.org.ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	config, err := pgx.ParseConfig(f.org.dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.Database = f.org.database
	db := stdlib.OpenDB(*config)
	defer db.Close()
	backend, err := migrationpg.New(db)
	if err != nil {
		t.Fatal(err)
	}
	more, err := (ssopg.DomainChallengeMethodMigrationSource{Version: 313}).Load(f.org.ctx)
	if err != nil {
		t.Fatal(err)
	}
	history := append(append(migrationList{}, f.org.history...), more...)
	runner, err := migrations.NewRunner(history, backend)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err = runner.Up(f.org.ctx); err != nil {
			t.Fatal("populated additive migration/replay failed", err)
		}
	}
	methodAware, err := ssopg.NewHTTPSStore(f.org.pool, f.custody)
	if err != nil {
		t.Fatal(err)
	}
	for _, store := range []*ssopg.Store{f.store, methodAware} {
		after, err := store.LoadDomainChallenge(f.org.ctx, key)
		if err != nil || after != before {
			t.Fatal("historical DNS custody/AAD changed", err)
		}
		if got, err := store.CreateDomainChallenge(f.org.ctx, before.Challenge); err != nil || got != before.Challenge {
			t.Fatal("mixed DNS writer changed original", err)
		}
	}
	// One primary key still owns both methods: switching methods cannot create
	// another original challenge or recovery binding for this immutable claim.
	changed := before.Challenge
	changed.Method = sso.DomainProofHTTPS
	if _, err = methodAware.CreateDomainChallenge(f.org.ctx, changed); err == nil {
		t.Fatal("method switch replaced immutable original custody")
	}
	var rows int
	if err = f.org.pool.Raw().QueryRow(f.org.ctx, `SELECT count(*) FROM sso.domain_challenges`).Scan(&rows); err != nil || rows != 1 {
		t.Fatal("method switch created another original", err)
	}
}

// Synthetic ciphertext copies are used only for planner cardinality, never as
// valid authority. 100k rows and a 10k hot tenant match the retained DNS query
// proof; the changed method-aware projection and int16 insertion are traced.
func TestDomainHTTPSMethodQueriesAtScale(t *testing.T) {
	f := nativeDomainFixtureMethod(t, true)
	issued := f.issue(t, "https-query", "example.com", 1)
	_, body := issued.HTTPSWellKnown()
	f.zone.publish("https-body", body)
	if _, err := f.service.VerifyDomain(f.org.ctx, issued.Request()); err != nil {
		t.Fatal(err)
	}
	_, err := f.org.pool.Raw().Exec(f.org.ctx, `INSERT INTO sso.domain_challenges(tenant_id,organization_id,claim_id,actor_id,command_id,canonical_domain,challenge_digest,capability_envelope,network_digest,correlation_id,issued_at,expires_at,recovery,method) SELECT CASE WHEN n<=10000 THEN 'org-test-basic' ELSE 'scale-'||(n%1000)::text END,'scale-org-'||((n-1)/10%1000)::text,'scale-claim-'||n::text,actor_id,substr(md5(n::text),1,22),canonical_domain,challenge_digest,capability_envelope,network_digest,correlation_id,issued_at,expires_at,NULL,method FROM sso.domain_challenges CROSS JOIN generate_series(1,100000) AS n WHERE claim_id='https-query'`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.org.pool.Raw().Exec(f.org.ctx, `ANALYZE sso.domain_challenges`); err != nil {
		t.Fatal(err)
	}
	trace := new(challengeTrace)
	pool, err := database.Connect(f.org.ctx, database.Config{DSN: f.org.dsn, MaxConns: 2, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database = f.org.database
		c.ConnConfig.Tracer = trace
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if pool.Close(ctx) != nil {
			t.Error("query pool cleanup failed")
		}
	})
	store, err := ssopg.NewHTTPSStore(pool, f.custody)
	if err != nil {
		t.Fatal(err)
	}
	key := sso.DomainChallengeKey{TenantID: issued.Request().Claim().TenantID, OrganizationID: issued.Request().Claim().OrganizationID, ClaimID: issued.Request().Claim().ID}
	state, err := store.LoadDomainChallenge(f.org.ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	operations := []struct {
		name string
		call func() error
	}{
		{"method-load-hot", func() error { _, err := store.LoadDomainChallenge(f.org.ctx, key); return err }},
		{"method-load-absent", func() error {
			_, err := store.LoadDomainChallenge(f.org.ctx, sso.DomainChallengeKey{TenantID: "absent", OrganizationID: "absent", ClaimID: "absent"})
			if err == nil {
				return fmt.Errorf("absent disclosed")
			}
			return nil
		}},
		{"method-insert-conflict", func() error { _, err := store.CreateDomainChallenge(f.org.ctx, state.Challenge); return err }},
	}
	for _, op := range operations {
		var elapsed []time.Duration
		for range 7 {
			start := time.Now()
			if err := op.call(); err != nil {
				t.Fatal(op.name, err)
			}
			elapsed = append(elapsed, time.Since(start))
		}
		sort.Slice(elapsed, func(i, j int) bool { return elapsed[i] < elapsed[j] })
		t.Logf("100001 rows/10001 hot tenant, 7 warmed native %s calls: median=%s max=%s", op.name, elapsed[3], elapsed[6])
	}
	trace.mu.Lock()
	queries := append([]tracedQuery(nil), trace.queries...)
	trace.mu.Unlock()
	seen := map[string]bool{}
	for _, query := range queries {
		partition := query.sql
		if len(query.args) > 0 && query.args[0] == "absent" {
			partition += ":absent"
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
		if err = f.org.pool.Raw().QueryRow(f.org.ctx, "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) "+query.sql, query.args...).Scan(&plan); err != nil {
			t.Fatal(err)
		}
		var decoded []map[string]any
		if json.Unmarshal(plan, &decoded) != nil || len(decoded) != 1 {
			t.Fatal("plan malformed")
		}
		if strings.HasPrefix(query.sql, "SELECT") && !strings.Contains(string(plan), "domain_challenges_pkey") {
			t.Fatal("exact method read lost primary-key access")
		}
		t.Logf("actual SQL=%s; native binding types=%v; plan=%s", query.sql, types, string(plan))
	}
	if len(seen) != 3 {
		t.Fatal("missing method-aware query partitions", len(seen))
	}
}
