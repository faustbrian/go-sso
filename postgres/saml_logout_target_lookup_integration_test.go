//go:build integration

package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	"github.com/faustbrian/go-sso/saml"
	"github.com/jackc/pgx/v5"
)

func TestSAMLLogoutTargetLookupExactAndIndexless(t *testing.T) {
	f := newSAMLLogoutTargetFixture(t)
	want := []samlLogoutIssuanceAnchor{}
	for _, test := range []struct {
		session, index string
		version        uint32
	}{
		{"session-z", "original-index", 1}, {"session-a", "original-index", 2},
		{"session-m", "another-index", 1}, {"session-n", "", 2},
	} {
		a, s := f.anchor(test.session), f.subject
		s.SessionIndex = test.index
		f.insert(t, a, f.scope, s, test.version, nil)
		want = append(want, a)
	}
	slices.SortFunc(want, func(a, b samlLogoutIssuanceAnchor) int { return bytes.Compare([]byte(a.Session), []byte(b.Session)) })
	for _, test := range []struct {
		name string
		edit func(*samlLogoutIssuanceAnchor, *samlLogoutIssuerScope, *samlStoredLogoutSubject)
	}{
		{"tenant", func(a *samlLogoutIssuanceAnchor, _ *samlLogoutIssuerScope, _ *samlStoredLogoutSubject) {
			a.Tenant = "other-tenant"
		}},
		{"organization", func(a *samlLogoutIssuanceAnchor, sc *samlLogoutIssuerScope, _ *samlStoredLogoutSubject) {
			a.Organization = "other-organization"
			sc.organization = a.Organization
		}},
		{"provider", func(a *samlLogoutIssuanceAnchor, sc *samlLogoutIssuerScope, _ *samlStoredLogoutSubject) {
			a.Provider = "other-provider"
			sc.provider = a.Provider
		}},
		{"issuer", func(_ *samlLogoutIssuanceAnchor, sc *samlLogoutIssuerScope, s *samlStoredLogoutSubject) {
			sc.issuer = "urn:other:idp"
			s.NameQualifier = sc.issuer
		}},
		{"subject", func(_ *samlLogoutIssuanceAnchor, _ *samlLogoutIssuerScope, s *samlStoredLogoutSubject) {
			s.ProviderSubject = "other-subject"
		}},
		{"format", func(_ *samlLogoutIssuanceAnchor, _ *samlLogoutIssuerScope, s *samlStoredLogoutSubject) {
			s.SubjectFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
		}},
		{"absent-name-qualifier", func(_ *samlLogoutIssuanceAnchor, _ *samlLogoutIssuerScope, s *samlStoredLogoutSubject) {
			s.NameQualifier = ""
		}},
		{"sp-qualifier", func(_ *samlLogoutIssuanceAnchor, _ *samlLogoutIssuerScope, s *samlStoredLogoutSubject) {
			s.SPNameQualifier = "https://other.example/sp"
		}},
		{"absent-sp-qualifier", func(_ *samlLogoutIssuanceAnchor, _ *samlLogoutIssuerScope, s *samlStoredLogoutSubject) {
			s.SPNameQualifier = ""
		}},
		{"expired", func(a *samlLogoutIssuanceAnchor, _ *samlLogoutIssuerScope, _ *samlStoredLogoutSubject) {
			a.ExpiresAt = f.now
		}},
		{"future", func(a *samlLogoutIssuanceAnchor, _ *samlLogoutIssuerScope, _ *samlStoredLogoutSubject) {
			a.IssuedAt = f.now.Add(time.Minute)
		}},
	} {
		a, sc, s := f.anchor("isolated-"+test.name), f.scope, f.subject
		test.edit(&a, &sc, &s)
		f.insert(t, a, sc, s, 1, nil)
	}
	for _, index := range []string{"original-index", "", "missing-index"} {
		request := f.request()
		request.SessionIndex = index
		var expected []samlLogoutIssuanceAnchor
		if index == "" {
			expected = want
		} else if index == "original-index" {
			expected = []samlLogoutIssuanceAnchor{want[0], want[3]}
		}
		for range 3 {
			got, err := f.custody.lookupTargets(f.ctx, f.pool, f.payload.Envelope, "tenant", f.scope, request, f.now)
			if err != nil || !slices.Equal(got, expected) {
				t.Fatal("exact signed target set or stable ordering changed", index, len(got), len(expected), err)
			}
		}
	}
	// Retiring a no-longer-retained key does not let it masquerade as a current
	// match. Deployments must retain keys for every still-live correlation.
	delete(f.custody.config.MatchKeys, 1)
	request := f.request()
	request.SessionIndex = ""
	got, err := f.custody.lookupTargets(f.ctx, f.pool, f.payload.Envelope, "tenant", f.scope, request, f.now)
	if err != nil || !slices.Equal(got, []samlLogoutIssuanceAnchor{want[0], want[2]}) {
		t.Fatal("retired match key was used or retained rows disappeared", err)
	}
}

func TestSAMLLogoutTargetLookupRejectsWholeContradictorySet(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*samlLogoutIssuanceAnchor, *samlStoredLogoutSubject, *samlPreparedLogoutSubject)
	}{
		{"conflicting-user", func(a *samlLogoutIssuanceAnchor, _ *samlStoredLogoutSubject, _ *samlPreparedLogoutSubject) {
			a.User = "different-user"
		}},
		{"bad-envelope", func(_ *samlLogoutIssuanceAnchor, _ *samlStoredLogoutSubject, p *samlPreparedLogoutSubject) {
			p.Envelope[len(p.Envelope)-1] ^= 1
		}},
		{"anchor-tamper", func(a *samlLogoutIssuanceAnchor, _ *samlStoredLogoutSubject, _ *samlPreparedLogoutSubject) {
			a.Family = "changed-family"
		}},
		{"noncanonical-anchor", func(a *samlLogoutIssuanceAnchor, _ *samlStoredLogoutSubject, _ *samlPreparedLogoutSubject) {
			a.Family = " padded"
		}},
		{"index-tamper", func(_ *samlLogoutIssuanceAnchor, _ *samlStoredLogoutSubject, p *samlPreparedLogoutSubject) {
			p.Index = nil
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newSAMLLogoutTargetFixture(t)
			f.insert(t, f.anchor("session-a-valid"), f.scope, f.subject, 1, nil)
			a := f.anchor("session-z-contradiction")
			if test.name == "conflicting-user" {
				a.User = "different-user"
			}
			f.insert(t, a, f.scope, f.subject, 2, func(a *samlLogoutIssuanceAnchor, s *samlStoredLogoutSubject, p *samlPreparedLogoutSubject) {
				if test.name != "conflicting-user" {
					test.edit(a, s, p)
				}
			})
			request := f.request()
			request.SessionIndex = ""
			got, err := f.custody.lookupTargets(f.ctx, f.pool, f.payload.Envelope, "tenant", f.scope, request, f.now)
			if err == nil || got != nil {
				t.Fatal("contradictory set released partial anchors", len(got), err)
			}
		})
	}
}

func TestSAMLLogoutTargetLookupBoundsCompleteSet(t *testing.T) {
	f := newSAMLLogoutTargetFixture(t)
	for n := range 128 {
		a, s := f.anchor(fmt.Sprintf("session-%03d", n)), f.subject
		if n%2 == 0 {
			s.SessionIndex = ""
		}
		f.insert(t, a, f.scope, s, uint32(1+n%2), nil)
	}
	request := f.request()
	request.SessionIndex = ""
	got, err := f.custody.lookupTargets(f.ctx, f.pool, f.payload.Envelope, "tenant", f.scope, request, f.now)
	if err != nil || len(got) != 128 {
		t.Fatal("maximum complete target set rejected", len(got), err)
	}
	f.insert(t, f.anchor("overflow-session"), f.scope, f.subject, 2, nil)
	got, err = f.custody.lookupTargets(f.ctx, f.pool, f.payload.Envelope, "tenant", f.scope, request, f.now)
	if err == nil || got != nil {
		t.Fatal("overflow released partial anchors", len(got), err)
	}
}

func TestSAMLLogoutTargetLookupReleasesConnectionBeforeOpening(t *testing.T) {
	f := newSAMLLogoutTargetFixture(t)
	f.insert(t, f.anchor("session"), f.scope, f.subject, 1, nil)
	keys, err := keyring.New(map[string][]byte{f.payload.KeyReference: bytes.Repeat([]byte{4}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	provider := &samlLogoutTargetConnectionCheckingKeys{KeyProvider: keys, pool: f.pool}
	crypto, err := envelope.NewService(provider)
	if err != nil {
		t.Fatal(err)
	}
	got, err := f.custody.lookupTargets(f.ctx, f.pool, crypto, "tenant", f.scope, f.request(), f.now)
	if err != nil || len(got) != 1 || provider.opened != 1 {
		t.Fatal("custody opening retained a database connection", len(got), provider.opened, err)
	}
	for n := range 128 {
		f.insert(t, f.anchor(fmt.Sprintf("overflow-%03d", n)), f.scope, f.subject, uint32(1+n%2), nil)
	}
	got, err = f.custody.lookupTargets(f.ctx, f.pool, crypto, "tenant", f.scope, f.request(), f.now)
	if err == nil || got != nil || provider.opened != 1 {
		t.Fatal("overflow opened custody or released a partial result", provider.opened, err)
	}
}

type samlLogoutTargetConnectionCheckingKeys struct {
	envelope.KeyProvider
	pool   *database.Pool
	opened int
}

func (p *samlLogoutTargetConnectionCheckingKeys) DecryptDataKey(ctx context.Context, reference string, ciphertext []byte, aad envelope.Context) ([]byte, error) {
	p.opened++
	if p.pool.Raw().Stat().AcquiredConns() != 0 {
		return nil, identity.UnavailableError{}
	}
	return p.KeyProvider.DecryptDataKey(ctx, reference, ciphertext, aad)
}

func TestSAMLLogoutTargetLookupRejectsInvalidInput(t *testing.T) {
	f := newSAMLLogoutTargetFixture(t)
	f.insert(t, f.anchor("session"), f.scope, f.subject, 1, nil)
	for _, test := range []struct {
		name string
		edit func(*context.Context, **database.Pool, *identity.TenantID, *samlLogoutIssuerScope, *saml.LogoutPOSTRequestEvidence, *time.Time)
	}{
		{"nil-context", func(c *context.Context, _ **database.Pool, _ *identity.TenantID, _ *samlLogoutIssuerScope, _ *saml.LogoutPOSTRequestEvidence, _ *time.Time) {
			*c = nil
		}},
		{"cancelled", func(c *context.Context, _ **database.Pool, _ *identity.TenantID, _ *samlLogoutIssuerScope, _ *saml.LogoutPOSTRequestEvidence, _ *time.Time) {
			cancelled, cancel := context.WithCancel(f.ctx)
			cancel()
			*c = cancelled
		}},
		{"nil-pool", func(_ *context.Context, p **database.Pool, _ *identity.TenantID, _ *samlLogoutIssuerScope, _ *saml.LogoutPOSTRequestEvidence, _ *time.Time) {
			*p = nil
		}},
		{"tenant", func(_ *context.Context, _ **database.Pool, tenant *identity.TenantID, _ *samlLogoutIssuerScope, _ *saml.LogoutPOSTRequestEvidence, _ *time.Time) {
			*tenant = " padded"
		}},
		{"scope", func(_ *context.Context, _ **database.Pool, _ *identity.TenantID, sc *samlLogoutIssuerScope, _ *saml.LogoutPOSTRequestEvidence, _ *time.Time) {
			sc.provider = " padded"
		}},
		{"issuer", func(_ *context.Context, _ **database.Pool, _ *identity.TenantID, sc *samlLogoutIssuerScope, _ *saml.LogoutPOSTRequestEvidence, _ *time.Time) {
			sc.issuer = ""
		}},
		{"subject", func(_ *context.Context, _ **database.Pool, _ *identity.TenantID, _ *samlLogoutIssuerScope, r *saml.LogoutPOSTRequestEvidence, _ *time.Time) {
			r.ProviderSubject = ""
		}},
		{"qualifier", func(_ *context.Context, _ **database.Pool, _ *identity.TenantID, _ *samlLogoutIssuerScope, r *saml.LogoutPOSTRequestEvidence, _ *time.Time) {
			r.NameQualifier = "urn:other:idp"
		}},
		{"clock", func(_ *context.Context, _ **database.Pool, _ *identity.TenantID, _ *samlLogoutIssuerScope, _ *saml.LogoutPOSTRequestEvidence, n *time.Time) {
			*n = time.Time{}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, pool, tenant, sc, request, now := f.ctx, f.pool, identity.TenantID("tenant"), f.scope, f.request(), f.now
			test.edit(&ctx, &pool, &tenant, &sc, &request, &now)
			got, err := f.custody.lookupTargets(ctx, pool, f.payload.Envelope, tenant, sc, request, now)
			if err == nil || got != nil {
				t.Fatal("invalid input released anchors", err)
			}
		})
	}
}

// Measurements use the production statements and inferred pgx bindings. The
// synthetic population models retained correlations, not signing, decryption,
// coordinator/session authorization, concurrent load or production latency.
func TestSAMLLogoutTargetLookupQueryScale(t *testing.T) {
	f := newSAMLLogoutTargetFixture(t)
	pool := f.pool.Raw()
	if _, err := pool.Exec(f.ctx, `INSERT INTO sso_providers.providers
 (tenant_id,organization_id,provider_id,issuer_digest,configuration_envelope,mapping_version,pending_domains)
 SELECT CASE WHEN n=0 THEN 'tenant' ELSE 'cold-tenant-'||n::text END,'organization','provider',
 sha256(convert_to('synthetic-issuer','UTF8')),decode('01','hex'),1,1 FROM generate_series(0,100) n`); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields)
 SELECT decode(md5('target-scale-'||n::text),'hex'),CASE WHEN n<=16000 THEN 'tenant' ELSE 'cold-tenant-'||(1+n%100)::text END,
 'identity.sso.saml-acs',sha256(convert_to('target-scale-'||n::text,'UTF8')),1,decode('01','hex') FROM generate_series(1,20000) n`,
		`INSERT INTO identity.commands(command_id,tenant_id,purpose) SELECT command_id,tenant_id,purpose FROM identity.identity_command_id_claims`,
		`ANALYZE identity.commands; ANALYZE sso_providers.providers`,
		`INSERT INTO sso_providers.saml_logout_subjects
 (tenant_id,organization_id,provider_id,user_id,session_id,family_id,issuance_command_id,issuance_purpose,
 issued_at,expires_at,match_key_version,subject_digest,session_index_digest,subject_envelope)
 SELECT CASE WHEN n<=16000 THEN 'tenant' ELSE 'cold-tenant-'||(1+n%100)::text END,'organization','provider','user',
 'scale-session-'||n::text,'scale-family-'||n::text,decode(md5('target-scale-'||n::text),'hex'),'identity.sso.saml-acs',
 $1::timestamptz-interval '1 day',$1::timestamptz+interval '1 day',1+n%3,
 sha256(convert_to('scale-subject-'||(n%200)::text,'UTF8')),
 CASE WHEN n%4=0 THEN NULL ELSE sha256(convert_to('scale-index-'||n::text,'UTF8')) END,
 convert_to(repeat('x',2048),'UTF8') FROM generate_series(1,20000) n`,
		`ANALYZE sso_providers.saml_logout_subjects`,
	} {
		var args []any
		if bytes.Contains([]byte(statement), []byte("$1")) {
			args = []any{f.now}
		}
		if _, err := pool.Exec(f.ctx, statement, args...); err != nil {
			t.Fatal("populate representative target rows", err)
		}
	}
	var engine string
	var count, hot, absent int
	var types, indexes []byte
	if err := pool.QueryRow(f.ctx, `SELECT current_setting('server_version'),count(*),count(*) FILTER(WHERE tenant_id='tenant'),
 count(*) FILTER(WHERE session_index_digest IS NULL),
 (SELECT jsonb_agg(jsonb_build_object('column',attname,'type',format_type(atttypid,atttypmod)) ORDER BY attnum)
 FROM pg_attribute WHERE attrelid='sso_providers.saml_logout_subjects'::regclass AND attnum>0 AND NOT attisdropped),
 (SELECT jsonb_agg(jsonb_build_object('definition',pg_get_indexdef(indexrelid),'valid',indisvalid) ORDER BY indexrelid)
 FROM pg_index WHERE indrelid='sso_providers.saml_logout_subjects'::regclass)
 FROM sso_providers.saml_logout_subjects`).Scan(&engine, &count, &hot, &absent, &types, &indexes); err != nil || count != 20000 || hot != 16000 || absent != 5000 {
		t.Fatal("inspect target scale distribution", count, hot, absent, err)
	}
	t.Logf("PostgreSQL=%s rows=%d hot-tenant/provider=%d absent-index=%d; 100 cold tenants, 200 recurring subjects, 3 match versions, 2048-byte synthetic envelopes; actual-types=%s installed-indexes=%s; normal planner, ANALYZE, no concurrent load", engine, count, hot, absent, types, indexes)
	for _, test := range []struct {
		name, tenant, subject, index string
		exact                        bool
		want, limit                  int
	}{
		{"indexless-hot", "tenant", "scale-subject-1", "", false, 80, 129},
		{"indexless-absent-stored-index", "tenant", "scale-subject-0", "", false, 80, 129},
		{"indexless-cold", "cold-tenant-2", "scale-subject-1", "", false, 20, 129},
		{"indexless-miss", "tenant", "missing-subject", "", false, 0, 129},
		{"exact-hit", "tenant", "scale-subject-1", "scale-index-1", true, 1, 129},
		{"exact-miss", "tenant", "scale-subject-1", "missing-index", true, 0, 129},
		{"exact-absent-stored-index", "tenant", "scale-subject-0", "scale-index-200", true, 0, 129},
	} {
		digest, index := sha256.Sum256([]byte(test.subject)), sha256.Sum256([]byte(test.index))
		args := samlLogoutTargetQueryBindings(test.tenant, digest, index, test.exact, f.now, test.limit)
		sql := lookupSAMLLogoutTargetsSQL
		fenceSQL := fenceSAMLLogoutTargetsSQL
		if test.exact {
			sql = lookupSAMLLogoutTargetsWithIndexSQL
			fenceSQL = fenceSAMLLogoutTargetsWithIndexSQL
		}
		measureSAMLLogoutTargetQuery(t, f.ctx, pool, test.name, sql, args, test.want)
		measureSAMLLogoutTargetQuery(t, f.ctx, pool, "fence-"+test.name, fenceSQL, args, test.want)
	}
	if _, err := pool.Exec(f.ctx, `UPDATE sso_providers.saml_logout_subjects
 SET subject_digest=sha256(convert_to('scale-subject-1','UTF8'))
 WHERE tenant_id='tenant' AND subject_digest=sha256(convert_to('scale-subject-2','UTF8'))`); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("scale-subject-1"))
	overflowArgs := samlLogoutTargetQueryBindings("tenant", digest, [32]byte{}, false, f.now, 129)
	measureSAMLLogoutTargetQuery(t, f.ctx, pool, "indexless-overflow", lookupSAMLLogoutTargetsSQL, overflowArgs, 129)
	measureSAMLLogoutTargetQuery(t, f.ctx, pool, "fence-indexless-overflow", fenceSAMLLogoutTargetsSQL, overflowArgs, 129)
	// Expired history is deliberately measured rather than assuming LIMIT bounds
	// the number of filtered heap rows under the installed non-expiry index.
	if _, err := pool.Exec(f.ctx, `UPDATE sso_providers.saml_logout_subjects SET expires_at=$1 WHERE tenant_id='tenant' AND subject_digest=sha256(convert_to('scale-subject-1','UTF8'))`, f.now); err != nil {
		t.Fatal(err)
	}
	measureSAMLLogoutTargetQuery(t, f.ctx, pool, "indexless-expired-history", lookupSAMLLogoutTargetsSQL, overflowArgs, 0)
	measureSAMLLogoutTargetQuery(t, f.ctx, pool, "fence-indexless-expired-history", fenceSAMLLogoutTargetsSQL, overflowArgs, 0)
}

func samlLogoutTargetQueryBindings(tenant string, subject, index [32]byte, exact bool, now time.Time, limit int) []any {
	macs := make([]samlIDPLogoutProbeMAC, 0, 3)
	for version := int64(1); version <= 3; version++ {
		mac := samlIDPLogoutProbeMAC{Version: version, Subject: hex.EncodeToString(subject[:])}
		if exact {
			mac.Index = hex.EncodeToString(index[:])
		}
		macs = append(macs, mac)
	}
	// These concrete scalar bindings match Work's closed parameter profile.
	wire, _ := json.Marshal(macs)
	return []any{tenant, "organization", "provider", string(wire), now, int64(limit)}
}

func measureSAMLLogoutTargetQuery(t *testing.T, ctx context.Context, pool interface {
	Begin(context.Context) (pgx.Tx, error)
}, name, sql string, args []any, want int) {
	t.Helper()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := tx.Rollback(cleanup); err != nil && err != pgx.ErrTxClosed {
			t.Error(err)
		}
	}()
	if _, err := tx.Exec(ctx, "SET LOCAL statement_timeout='1s'; SET LOCAL lock_timeout='1s'"); err != nil {
		t.Fatal(err)
	}
	description, err := tx.Conn().Prepare(ctx, "", sql)
	if err != nil {
		t.Fatal("describe exact target bindings", name, err)
	}
	var elapsed []time.Duration
	for sample := range 6 {
		var wire []byte
		if err := tx.QueryRow(ctx, "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) "+sql, args...).Scan(&wire); err != nil {
			t.Fatal("explain target query", name, err)
		}
		var plans []struct {
			Plan      samlSubjectQueryPlan `json:"Plan"`
			Execution float64              `json:"Execution Time"`
		}
		if err := json.Unmarshal(wire, &plans); err != nil || len(plans) != 1 {
			t.Fatal("decode target plan", err)
		}
		clear(wire)
		lookups := 0
		heapOutput, heapFiltered := float64(0), float64(0)
		var hasMatchBitmapIndex func(samlSubjectQueryPlan) bool
		hasMatchBitmapIndex = func(p samlSubjectQueryPlan) bool {
			if p.NodeType == "Bitmap Index Scan" && p.Index == "saml_logout_subject_match" {
				return true
			}
			for _, child := range p.Plans {
				if hasMatchBitmapIndex(child) {
					return true
				}
			}
			return false
		}
		var inspect func(samlSubjectQueryPlan)
		inspect = func(p samlSubjectQueryPlan) {
			if p.Relation == "saml_logout_subjects" {
				indexed := (p.NodeType == "Index Scan" || p.NodeType == "Index Only Scan") && p.Index == "saml_logout_subject_match"
				bitmapIndexed := p.NodeType == "Bitmap Heap Scan" && hasMatchBitmapIndex(p)
				if !indexed && !bitmapIndexed {
					t.Fatal("target query did not use installed scoped match index", name, p.NodeType, p.Index)
				}
				lookups++
				heapOutput += p.Rows * p.Loops
				heapFiltered += p.Filtered * p.Loops
			}
			for _, child := range p.Plans {
				inspect(child)
			}
		}
		inspect(plans[0].Plan)
		if lookups != 1 {
			t.Fatal("unexpected match lookup plan count", name, lookups)
		}
		if sample == 0 {
			safe, err := json.Marshal(plans)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("query=%s relation-output=%g rows-removed-by-filter=%g (rows times loops, not summed across parent/index nodes); first-sanitized-plan=%s", name, heapOutput, heapFiltered, safe)
		}
		started := time.Now()
		rows, err := tx.Query(ctx, sql, args...)
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		for rows.Next() {
			if _, err := rows.Values(); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			count++
		}
		rows.Close()
		if rows.Err() != nil || count != want {
			t.Fatal("target query result count", name, count, want, rows.Err())
		}
		if sample > 0 {
			elapsed = append(elapsed, time.Since(started))
		}
	}
	slices.Sort(elapsed)
	goTypes := make([]string, len(args))
	for n, arg := range args {
		goTypes[n] = fmt.Sprintf("%T", arg)
	}
	t.Logf("query=%s SQL=%s Go-types=%v inferred-OIDs=%v returned=%d; five warmed statement executions after one warmup: min=%s median=%s max=%s; statement timeout=1s; excludes pool acquisition, signature/decryption, coordinator/session work and commit", name, sql, goTypes, description.ParamOIDs, want, elapsed[0], elapsed[2], elapsed[4])
}

type samlLogoutTargetFixture struct {
	ctx     context.Context
	pool    *database.Pool
	payload providerLoginPayloadConfig
	custody *SAMLLogoutSubjectCustody
	now     time.Time
	scope   samlLogoutIssuerScope
	subject samlStoredLogoutSubject
}

func newSAMLLogoutTargetFixture(t *testing.T) *samlLogoutTargetFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	t.Cleanup(cancel)
	conn := samlSubjectQueryDatabase(t, ctx)
	for _, source := range []migrations.Source{kernel.MigrationSource{}, ProviderMigrationSource{Version: 320}, SAMLLogoutSubjectMigrationSource{Version: 394}} {
		history, err := source.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, step := range history {
			if _, err := conn.Exec(ctx, step.UpSQL()); err != nil {
				t.Fatal("install target fixture", err)
			}
		}
	}
	pool, err := database.New(ctx, database.Config{DSN: conn.Config().ConnString(), MaxConns: 2, Configure: func(config *database.PoolConfig) error {
		// ConnString retains the original administrator DSN even after the
		// fixture helper selects its newly created disposable database.
		config.ConnConfig.Database = conn.Config().Database
		return nil
	}})
	if err != nil {
		t.Fatal("open target pool", err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := pool.Close(cleanup); err != nil {
			t.Error(err)
		}
	})
	payload, _, now, _ := providerLoginPayloadFixture(t)
	custody, _, subject := samlLogoutSubjectReadFixture(t, payload, *now, "original-index")
	custody.config.CurrentMatchKey = 2
	return &samlLogoutTargetFixture{ctx: ctx, pool: pool, payload: payload, custody: custody, now: *now, scope: samlLogoutIssuerScope{"organization", "provider", "urn:example:original-idp"}, subject: subject}
}

func (f *samlLogoutTargetFixture) anchor(session string) samlLogoutIssuanceAnchor {
	command := sha256.Sum256([]byte(session))
	return samlLogoutIssuanceAnchor{Tenant: "tenant", Organization: f.scope.organization, Provider: f.scope.provider, User: "user", Session: session, Family: "family-" + session, Purpose: "identity.sso.saml-acs", Command: base64.RawURLEncoding.EncodeToString(command[:16]), IssuedAt: f.now.Add(-time.Minute), ExpiresAt: f.now.Add(time.Hour)}
}

func (f *samlLogoutTargetFixture) request() saml.LogoutPOSTRequestEvidence {
	s := f.subject
	return saml.LogoutPOSTRequestEvidence{ID: "_synthetic-signed-request", IssuedAt: f.now, ValidUntil: f.now.Add(time.Minute), ProviderSubject: s.ProviderSubject, SubjectFormat: s.SubjectFormat, NameQualifier: s.NameQualifier, SPNameQualifier: s.SPNameQualifier, SessionIndex: s.SessionIndex}
}

func (f *samlLogoutTargetFixture) insert(t *testing.T, a samlLogoutIssuanceAnchor, sc samlLogoutIssuerScope, s samlStoredLogoutSubject, version uint32, edit func(*samlLogoutIssuanceAnchor, *samlStoredLogoutSubject, *samlPreparedLogoutSubject)) {
	t.Helper()
	writer := *f.custody
	writer.config = f.custody.config
	writer.config.CurrentMatchKey = version
	p, err := writer.prepare(f.ctx, f.payload.Envelope, a, sc, &s)
	if err != nil {
		t.Fatal("seal synthetic signed subject", err)
	}
	defer clear(p.Envelope)
	if edit != nil {
		edit(&a, &s, p)
	}
	// Distinct synthetic provider tuples need distinct issuer digests within an
	// organization; a generic conflict handler would silently omit that FK owner.
	issuerDigest := sha256.Sum256([]byte(a.Provider))
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO sso_providers.providers(tenant_id,organization_id,provider_id,issuer_digest,configuration_envelope,mapping_version,pending_domains)
 VALUES($1,$2,$3,$4,decode('01','hex'),1,1)
 ON CONFLICT(tenant_id,organization_id,provider_id) DO NOTHING`, a.Tenant, a.Organization, a.Provider, issuerDigest[:]); err != nil {
		t.Fatal(err)
	}
	command, err := base64.RawURLEncoding.Strict().DecodeString(a.Command)
	if err != nil {
		t.Fatal(err)
	}
	for _, sql := range []string{
		`INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,$2,$3,sha256($1),1,decode('01','hex'))`,
		`INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,$2,$3)`,
	} {
		if _, err := f.pool.Raw().Exec(f.ctx, sql, command, a.Tenant, a.Purpose); err != nil {
			t.Fatal(err)
		}
	}
	var index []byte
	if p.Index != nil {
		index = p.Index[:]
	}
	if _, err := f.pool.Raw().Exec(f.ctx, insertSAMLLogoutSubjectSQL, a.Tenant, a.Organization, a.Provider, a.User, a.Session, a.Family, command, a.Purpose, a.IssuedAt, a.ExpiresAt, int64(p.KeyVersion), p.Subject[:], index, p.Envelope); err != nil {
		t.Fatal("insert sealed synthetic target", err)
	}
}
