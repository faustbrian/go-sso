//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/jackc/pgx/v5"
)

func TestNativeSAMLIDPPendingQueryScale(t *testing.T) {
	x := newNativeSAMLIDPAdmissionFixture(t)
	f := x.enable.f
	installSAMLIDPStorage(t, f, ssopg.SAMLIDPConfirmationMigrationSource{Version: 394})
	tenant, org, provider := string(x.enable.proof.TenantID), string(x.profile.OrganizationID), string(x.profile.ProviderID)
	command := samlIDPMigrationCommandBytes(t, f, x.enable.proof.TenantID, "identity.sso.saml-idp-prepare")
	expiredCommand := samlIDPMigrationCommandBytes(t, f, x.enable.proof.TenantID, "identity.sso.saml-idp-prepare")
	completion := samlIDPMigrationCommandBytes(t, f, x.enable.proof.TenantID, "identity.sso.saml-idp-init")
	const n = 20000
	tx, err := f.pool.Raw().Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = tx.Rollback(ctx)
	}()
	for _, statement := range []string{
		`INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields)
 SELECT decode(md5('pending-cost-'||n::text),'hex'),$1,'identity.sso.saml-idp-prepare',sha256(convert_to('pending-cost-'||n::text,'UTF8')),1,decode('01','hex')
 FROM generate_series(1,$2::int) n`,
		`INSERT INTO identity.commands(command_id,tenant_id,purpose)
 SELECT decode(md5('pending-cost-'||n::text),'hex'),$1,'identity.sso.saml-idp-prepare' FROM generate_series(1,$2::int) n`,
	} {
		if tag, err := tx.Exec(f.ctx, statement, tenant, n); err != nil || tag.RowsAffected() != n {
			t.Fatal("seed retained fixture command scope", err)
		}
	}
	if _, err := tx.Exec(f.ctx, `ANALYZE identity.commands; ANALYZE sso_providers.providers`); err != nil {
		t.Fatal(err)
	}
	if tag, err := tx.Exec(f.ctx, `INSERT INTO sso_providers.saml_idp_confirmations
 (tenant_id,confirmation_id,organization_id,provider_id,user_id,binding_envelope,confirmation_key_version,browser_digest,form_digest,issued_at,expires_at)
 SELECT $1,decode(md5('pending-cost-'||n::text),'hex'),$2,$3,'owner',decode('01','hex'),1,
 sha256(convert_to('browser-'||n::text,'UTF8')),sha256(convert_to('form-'||n::text,'UTF8')),statement_timestamp()-interval '15 seconds',statement_timestamp()+interval '20 seconds'
 FROM generate_series(1,$4::int) n`, tenant, org, provider, n); err != nil || tag.RowsAffected() != n {
		t.Fatal("seed bounded pending rows under installed constraints", err)
	}
	if _, err := tx.Exec(f.ctx, `ANALYZE sso_providers.saml_idp_confirmations`); err != nil {
		t.Fatal(err)
	}
	issued := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Second)
	insert := []any{tenant, command, org, provider, "owner", bytes.Repeat([]byte{3}, 2000), int64(1), bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), issued, issued.Add(time.Minute)}
	measureSAMLIDPPendingStatement(t, f, tx, "insert", ssopg.SAMLIDPInsertPendingForTest, insert, 1, false)
	if tag, err := tx.Exec(f.ctx, ssopg.SAMLIDPInsertPendingForTest, insert...); err != nil || tag.RowsAffected() != 1 {
		t.Fatal("insert exact recovery fixture target", err)
	}
	measureSAMLIDPPendingStatement(t, f, tx, "recovery-hit", ssopg.SAMLIDPObservePendingForTest, insert[:2], 1, true)
	missing := append(bytes.Clone(command[:15]), command[15]^1)
	measureSAMLIDPPendingStatement(t, f, tx, "recovery-miss", ssopg.SAMLIDPObservePendingForTest, []any{tenant, missing}, 0, true)
	measureSAMLIDPPendingStatement(t, f, tx, "confirmation-read", ssopg.SAMLIDPReadPendingForTest, insert[:2], 1, true)
	measureSAMLIDPPendingStatement(t, f, tx, "confirmation-read-miss", ssopg.SAMLIDPReadPendingForTest, []any{tenant, missing}, 0, true)
	confirmed := append(insert, completion)
	measureSAMLIDPPendingStatement(t, f, tx, "confirmation-write", ssopg.SAMLIDPCompletePendingForTest, confirmed, 1, true)
	unmatched := slices.Clone(confirmed)
	unmatched[1] = missing
	measureSAMLIDPPendingStatement(t, f, tx, "confirmation-write-miss", ssopg.SAMLIDPCompletePendingForTest, unmatched, 0, true)
	expired := slices.Clone(confirmed)
	expired[1], expired[9], expired[10] = expiredCommand, issued.Add(-time.Second), issued
	if tag, err := tx.Exec(f.ctx, `INSERT INTO sso_providers.saml_idp_confirmations
 (tenant_id,confirmation_id,organization_id,provider_id,user_id,binding_envelope,confirmation_key_version,browser_digest,form_digest,issued_at,expires_at)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, expired[:11]...); err != nil || tag.RowsAffected() != 1 {
		t.Fatal("seed the already expired original pending row", err)
	}
	measureSAMLIDPPendingStatement(t, f, tx, "confirmation-read-expired", ssopg.SAMLIDPReadPendingForTest, expired[:2], 0, true)
	measureSAMLIDPPendingStatement(t, f, tx, "confirmation-write-expired", ssopg.SAMLIDPCompletePendingForTest, expired, 0, true)
	measureSAMLIDPPendingStatement(t, f, tx, "confirmation-recovery-hit", ssopg.SAMLIDPRecoverConfirmationPendingForTest, []any{tenant, command, "owner"}, 1, true)
	measureSAMLIDPPendingStatement(t, f, tx, "confirmation-recovery-miss", ssopg.SAMLIDPRecoverConfirmationPendingForTest, []any{tenant, missing, "owner"}, 0, true)
}

func measureSAMLIDPPendingStatement(t *testing.T, f *orgFixture, tx pgx.Tx, name, query string, args []any, rows int64, index bool) {
	t.Helper()
	description, err := tx.Conn().Prepare(f.ctx, "", query)
	if err != nil || len(description.ParamOIDs) != len(args) {
		t.Fatal("describe exact production query parameters", name, err)
	}
	var elapsed []time.Duration
	for sample := range 5 {
		if _, err := tx.Exec(f.ctx, "SAVEPOINT sample_pending"); err != nil {
			t.Fatal(err)
		}
		var raw []byte
		if err := tx.QueryRow(f.ctx, "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) "+query, args...).Scan(&raw); err != nil {
			t.Fatal("explain exact production query", name, err)
		}
		var plans []struct {
			Plan          nativeOAuth2CallbackPlan `json:"Plan"`
			ExecutionTime float64                  `json:"Execution Time"`
		}
		err := json.Unmarshal(raw, &plans)
		clear(raw)
		if err != nil || len(plans) != 1 {
			t.Fatal("decode structural plan", name, err)
		}
		p := plans[0].Plan
		if indexes, bounded := samlIDPPendingQueryIndexes(p); index && (!bounded || indexes == 0) {
			t.Fatal("pending custody query performed an unbounded or non-primary-key lookup", name, indexes)
		}
		if _, err := tx.Exec(f.ctx, "ROLLBACK TO SAVEPOINT sample_pending"); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		tag, err := tx.Exec(f.ctx, query, args...)
		took := time.Since(start)
		if err != nil || tag.RowsAffected() != rows {
			t.Fatal("execute exact production query", name, tag.RowsAffected(), err)
		}
		if sample > 0 {
			elapsed = append(elapsed, took)
		}
		if sample == 0 {
			t.Logf("%s: rows=%d node=%s index=%s OIDs=%v execution=%.3fms", name, rows, p.NodeType, p.IndexName, description.ParamOIDs, plans[0].ExecutionTime)
		}
		if _, err := tx.Exec(f.ctx, "ROLLBACK TO SAVEPOINT sample_pending; RELEASE SAVEPOINT sample_pending"); err != nil {
			t.Fatal(err)
		}
	}
	slices.Sort(elapsed)
	t.Logf("%s: median %s over 4 warmed client executions (20000 retained rows)", name, elapsed[len(elapsed)/2])
}

func samlIDPPendingQueryIndexes(plan nativeOAuth2CallbackPlan) (indexes int, bounded bool) {
	bounded = true
	if plan.RelationName == "saml_idp_confirmations" && plan.NodeType != "ModifyTable" {
		if plan.IndexName != "saml_idp_confirmations_pkey" || plan.ActualRows > 1 || plan.FilteredRows > 1 {
			return 0, false
		}
		indexes++
	}
	for _, child := range plan.ChildPlans {
		n, ok := samlIDPPendingQueryIndexes(child)
		indexes += n
		bounded = bounded && ok
	}
	return indexes, bounded
}
