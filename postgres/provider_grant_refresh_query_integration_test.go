//go:build integration

package postgres_test

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/jackc/pgx/v5"
)

// Genuine refused and rotated operations supply their distinct native binding
// profiles. Copied ciphertext below is rollback-only storage cardinality, never
// authenticated grant authority or a reason to contact a provider again.
func TestNativeProviderGrantRefreshQueryScale(t *testing.T) {
	var successful map[string]providerQuery
	if !t.Run("capture-rotated-native-bindings", func(t *testing.T) {
		_, successful = nativeProviderGrantRefreshQueryFixture(t, "restorable-vault-refresh", "rotated")
	}) {
		t.Fatal("capture successful native refresh before its fixture cleanup")
	}
	x, selected := nativeProviderGrantRefreshQueryFixture(t, "restorable-vault-refresh-refused", "refused")
	f := x.start.enable.f
	if selected["settlement"].sql != successful["settlement"].sql {
		t.Fatal("refused and successful refresh did not execute the same settlement SQL")
	}
	predecessorBindings := map[int]any{}
	for index := range 9 {
		predecessorBindings[index] = selected["settlement"].args[index]
	}
	successfulSettlement := nativeProviderLogoutQueryBindings(t, successful["settlement"], predecessorBindings)
	tx, err := f.pool.Raw().Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.ctx)
	if _, err := tx.Exec(f.ctx, "SET LOCAL statement_timeout='15s'; SET LOCAL lock_timeout='1s'"); err != nil {
		t.Fatal(err)
	}
	selected["receipt"] = nativeProviderGrantRevocationWireBindings(t, f, tx, selected["receipt"])
	measureNativeProviderGrantFenceQuery(t, f, tx, "refresh-before-scale-receipt", selected["receipt"], 1)
	measureNativeProviderGrantRefreshSettlement(t, f, tx, "before-scale-retain-generation", selected["settlement"], 1)
	measureNativeProviderGrantRefreshSettlement(t, f, tx, "before-scale-rotated-cas", successfulSettlement, 1)
	populateNativeProviderGrantFenceScale(t, f, tx, selected["fence"])
	if _, err := tx.Exec(f.ctx, `INSERT INTO sso_providers.provider_grant_refresh_receipts
 (tenant_id,user_id,callback_command_id,token_version,attempt_command_id,attempt_generation,intent_digest,outcome,successor_version)
SELECT r.tenant_id,$1,r.grant_command_id,f.token_version,f.attempt_command_id,f.attempt_generation,$2,'refused',NULL
FROM grant_fence_cost_rows r JOIN sso_providers.provider_grant_fences f
 ON (f.tenant_id,f.grant_command_id)=(r.tenant_id,r.grant_command_id)
WHERE f.attempt_purpose='identity.sso.provider-token.refresh'`, selected["settlement"].args[1], selected["settlement"].args[8]); err != nil {
		t.Fatal("populate receipts only for existing native-shaped refresh fences", err)
	}
	if _, err := tx.Exec(f.ctx, "ANALYZE sso_providers.provider_grant_refresh_receipts"); err != nil {
		t.Fatal(err)
	}
	var engine string
	var grants, fences, receipts, hotReceipts int
	if err := tx.QueryRow(f.ctx, `SELECT current_setting('server_version'),
 (SELECT count(*) FROM sso_providers.provider_login_token_sets),
 (SELECT count(*) FROM sso_providers.provider_grant_fences),
 (SELECT count(*) FROM sso_providers.provider_grant_refresh_receipts),
 (SELECT count(*) FROM sso_providers.provider_grant_refresh_receipts WHERE tenant_id=$1)`, selected["settlement"].args[0]).Scan(&engine, &grants, &fences, &receipts, &hotReceipts); err != nil || grants != 40001 || fences != 39999 || receipts != 20001 || hotReceipts != 2001 {
		t.Fatal("representative refresh storage population mismatch", grants, fences, receipts, hotReceipts, err)
	}
	var columns, indexes []byte
	if err := tx.QueryRow(f.ctx, `SELECT
 (SELECT jsonb_agg(jsonb_build_object('table',c.relname,'column',a.attname,'type',format_type(a.atttypid,a.atttypmod)) ORDER BY c.relname,a.attnum)
 FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='sso_providers' AND c.relname IN ('provider_login_token_sets','provider_grant_fences','provider_grant_refresh_receipts') AND a.attnum>0 AND NOT a.attisdropped),
 (SELECT jsonb_agg(jsonb_build_object('table',tablename,'definition',indexdef) ORDER BY tablename,indexname)
 FROM pg_indexes WHERE schemaname='sso_providers' AND tablename IN ('provider_login_token_sets','provider_grant_fences','provider_grant_refresh_receipts'))`).Scan(&columns, &indexes); err != nil {
		t.Fatal("inspect installed refresh column types/indexes", err)
	}
	t.Logf("PostgreSQL=%s rollback-only grants=%d fences=%d receipts=%d hot-receipts=%d; 400 colder tenants, 90 grants each; isolated, no concurrent load or forced planner settings, first sample may be cold", engine, grants, fences, receipts, hotReceipts)
	t.Logf("actual-column-types=%s actual-indexes=%s", columns, indexes)
	for _, fixture := range []struct {
		name string
		n    int
	}{{"hot", 2}, {"cold", 4002}} {
		var tenant, callback string
		var command, attempt []byte
		if err := tx.QueryRow(f.ctx, `SELECT tenant_id,callback_command_id,grant_command_id,attempt_command_id
FROM grant_fence_cost_rows WHERE n=$1`, fixture.n).Scan(&tenant, &callback, &command, &attempt); err != nil {
			t.Fatal("select rollback-only refresh population", err)
		}
		receipt := nativeProviderLogoutQueryBindings(t, selected["receipt"], map[int]any{0: tenant, 2: attempt})
		measureNativeProviderGrantFenceQuery(t, f, tx, "refresh-"+fixture.name+"-receipt", receipt, 1)
		measureNativeProviderGrantFenceQuery(t, f, tx, "refresh-"+fixture.name+"-missing-receipt",
			nativeProviderLogoutQueryBindings(t, receipt, map[int]any{1: "refresh-cost-missing-user"}), 0)
		retained := nativeProviderLogoutQueryBindings(t, selected["settlement"], map[int]any{0: tenant, 2: command, 3: callback, 5: attempt})
		measureNativeProviderGrantRefreshSettlement(t, f, tx, fixture.name+"-retain-generation", retained, 1)
		rotated := nativeProviderLogoutQueryBindings(t, successfulSettlement, map[int]any{0: tenant, 2: command, 3: callback, 5: attempt})
		measureNativeProviderGrantRefreshSettlement(t, f, tx, fixture.name+"-rotated-cas", rotated, 1)
		measureNativeProviderGrantRefreshSettlement(t, f, tx, fixture.name+"-retained-token-cas",
			nativeProviderLogoutQueryBindings(t, rotated, map[int]any{9: "retained"}), 1)
		for _, stale := range []struct {
			name    string
			changes map[int]any
		}{{"absent", map[int]any{3: "refresh-cost-missing-callback"}},
			{"stale-version", map[int]any{4: "18446744073709551615"}},
			{"stale-generation", map[int]any{6: "18446744073709551615"}},
			{"stale-ciphertext", map[int]any{7: make([]byte, 32)}},
			{"non-successor-version", map[int]any{10: "3"}}} {
			measureNativeProviderGrantRefreshSettlement(t, f, tx, fixture.name+"-"+stale.name,
				nativeProviderLogoutQueryBindings(t, rotated, stale.changes), 0)
		}
	}
	if err := tx.Rollback(f.ctx); err != nil {
		t.Fatal("rollback representative refresh population and measured writes", err)
	}
}

func nativeProviderGrantRefreshQueryFixture(t *testing.T, mode, outcome string) (nativeOAuth2JourneyFixture, map[string]providerQuery) {
	t.Helper()
	trace := new(providerTrace)
	x := newNativeOAuth2JourneyFixture(t, mode, trace)
	f := x.start.enable.f
	erasure, err := (kernel.SSOEnterpriseGrantRefreshPreparationErasureMigrationSource{Base: f.history, Version: 355}).Load(f.ctx)
	if err != nil || len(erasure) != len(f.history)+1 {
		t.Fatal("load native refresh query erasure prerequisite", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, erasure[len(erasure)-1].UpSQL()); err != nil {
		t.Fatal("install native refresh query erasure prerequisite", err)
	}
	for _, source := range []migrations.Source{
		ssopg.ProviderGrantFenceMigrationSource{Version: 356},
		ssopg.ProviderGrantRefreshMigrationSource{Version: 357, ValidationVersion: 358, ReceiptVersion: 359},
	} {
		history, err := source.Load(f.ctx)
		if err != nil || len(history) == 0 {
			t.Fatal("load native refresh query prerequisites", err)
		}
		for _, step := range history {
			if _, err := f.pool.Raw().Exec(f.ctx, step.UpSQL()); err != nil {
				t.Fatal("install native refresh query prerequisites", err)
			}
		}
	}
	login, err := x.completion.SigninCallbackOAuth2(f.ctx, x.request)
	if err != nil || login.Completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("establish native grant and session for refresh query", err)
	}
	spec, err := login.Issuance.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	wire, err := login.Issuance.Token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	grant, err := sso.NewTokenVersion(sso.TokenVersionSpec{TenantID: spec.TenantID,
		OrganizationID: x.start.profile.OrganizationID, ProviderID: x.start.profile.ProviderID,
		ProviderSubject: nativeOAuth2JourneySubject, CommandID: login.Completion.Binding.CommandID,
		CredentialGeneration: x.start.profile.CredentialGeneration, Version: 1, Purpose: sso.EnterpriseTokenPurpose})
	if err != nil {
		t.Fatal(err)
	}
	key, err := identity.NewIdempotencyKey([]byte("native-refresh-query-scale"))
	if err != nil {
		t.Fatal(err)
	}
	request, err := sso.NewRefreshEnterpriseToken(grant, key)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := ssopg.NewProviderGrantRefreshService(x.completion, ssopg.ProviderGrantRefreshConfig{
		Session: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: spec.Audience,
			Clock: clock.System{}, MaximumDuration: time.Second, ClockUncertainty: time.Millisecond,
			LookupKeys: []session.DigestKey{x.lookup}},
		Providers: []ssopg.ProviderGrantRefreshProvider{{OrganizationID: x.start.profile.OrganizationID, ProviderID: x.start.profile.ProviderID}},
	})
	if err != nil {
		t.Fatal("compose native refresh query fixture", err)
	}
	browser := ssopg.ProviderGrantRefreshBrowser{Origin: x.start.config.Origin,
		Session: authentication.NewBearerCredential(wire), CSRF: login.CSRF}
	trace.mu.Lock()
	trace.queries = nil
	trace.mu.Unlock()
	started := time.Now()
	got, err := svc.Refresh(f.ctx, request, browser)
	elapsed := time.Since(started)
	if err != nil || got.Completion.Outcome != identity.CommitOutcomeCommitted || string(got.ProviderOutcome) != outcome || x.refreshes.Load() != 1 {
		t.Fatal("native refresh did not commit the expected provider outcome", mode, err)
	}
	trace.mu.Lock()
	queries, traceErr := append([]providerQuery(nil), trace.queries...), trace.err
	trace.mu.Unlock()
	if traceErr != nil {
		t.Fatal(traceErr)
	}
	selected := map[string]providerQuery{}
	for _, query := range queries {
		name := ""
		switch {
		case strings.HasPrefix(query.sql, "WITH original AS MATERIALIZED ("):
			name = "settlement"
		case strings.HasPrefix(query.sql, "SELECT tenant_id,user_id,callback_command_id,attempt_command_id,"):
			name = "receipt"
		case strings.HasPrefix(query.sql, "INSERT INTO sso_providers.provider_grant_fences"):
			name = "fence"
		}
		if name != "" {
			if previous, ok := selected[name]; !ok || len(query.oids) > len(previous.oids) {
				selected[name] = query
			}
		}
	}
	if len(selected) != 3 || len(selected["settlement"].oids) != 18 || len(selected["fence"].args) != 7 {
		t.Fatal("native refresh did not capture settlement, receipt and fence with actual Work bindings", mode, len(selected))
	}
	t.Logf("native-refresh outcome=%s first-operation-elapsed=%s provider-trace-records=%d; committed fixture cardinality, includes session/coordinator/client/provider work", outcome, elapsed, len(queries))
	for sample := range 2 {
		started := time.Now()
		replayed, err := svc.Refresh(f.ctx, request, browser)
		if err != nil || replayed.Completion.Binding != got.Completion.Binding || replayed.ProviderOutcome != got.ProviderOutcome || replayed.Successor != got.Successor || x.refreshes.Load() != 1 {
			t.Fatal("native refresh receipt recovery resent or changed the result", mode, err)
		}
		t.Logf("native-refresh outcome=%s recovery-sample=%d operation-elapsed=%s; no additional provider send", outcome, sample, time.Since(started))
	}
	return x, selected
}

func measureNativeProviderGrantRefreshSettlement(t *testing.T, f *orgFixture, tx pgx.Tx, scope string, query providerQuery, want int64) {
	t.Helper()
	if _, err := tx.Exec(f.ctx, "SAVEPOINT refresh_receipt"); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(f.ctx, `DELETE FROM sso_providers.provider_grant_refresh_receipts
WHERE tenant_id=$1 AND user_id=$2 AND attempt_command_id=$3`, query.args[0], query.args[1], query.args[5]); err != nil {
		t.Fatal("isolate original/synthetic refresh receipt inside rollback savepoint", err)
	}
	var beforeVersion string
	var beforeDigest []byte
	if err := tx.QueryRow(f.ctx, `SELECT token_version::text,sha256(token_ciphertext)
FROM sso_providers.provider_login_token_sets WHERE tenant_id=$1 AND origin_command_id=$2`, query.args[0], query.args[2]).Scan(&beforeVersion, &beforeDigest); err != nil {
		t.Fatal("read settlement predecessor before native replay", err)
	}
	measureNativeProviderGrantFenceQuery(t, f, tx, "refresh-settlement-"+scope, query, want)
	result := tx.Conn().PgConn().ExecParams(f.ctx, query.sql, query.values, query.oids, query.formats, nil).Read()
	if result.Err != nil || result.CommandTag.RowsAffected() != want {
		t.Fatal("refresh settlement semantic replay affected cardinality", scope, result.Err)
	}
	var version string
	var digest []byte
	var outcome, successor *string
	if err := tx.QueryRow(f.ctx, `SELECT v.token_version::text,sha256(v.token_ciphertext),r.outcome,r.successor_version::text
FROM sso_providers.provider_login_token_sets v
LEFT JOIN sso_providers.provider_grant_refresh_receipts r ON r.tenant_id=v.tenant_id AND r.attempt_command_id=$3
WHERE v.tenant_id=$1 AND v.origin_command_id=$2`, query.args[0], query.args[2], query.args[5]).Scan(&version, &digest, &outcome, &successor); err != nil {
		t.Fatal("inspect atomic successor/receipt result", scope, err)
	}
	wantVersion, wantDigest := beforeVersion, beforeDigest
	if want == 1 && query.args[10] != nil {
		wantVersion = query.args[10].(string)
		nextDigest := sha256.Sum256(query.args[17].([]byte))
		wantDigest = nextDigest[:]
	}
	if version != wantVersion || !bytes.Equal(digest, wantDigest) || (outcome != nil) != (want == 1) {
		t.Fatal("refresh settlement changed vault generation, ciphertext or receipt semantics", scope)
	}
	if want == 1 && (*outcome != query.args[9].(string) || (successor != nil) != (query.args[10] != nil)) {
		t.Fatal("refresh settlement receipt changed the provider outcome or successor presence", scope)
	}
	if successor != nil && *successor != wantVersion {
		t.Fatal("refresh settlement receipt did not identify the atomic successor", scope)
	}
	if _, err := tx.Exec(f.ctx, "ROLLBACK TO SAVEPOINT refresh_receipt; RELEASE SAVEPOINT refresh_receipt"); err != nil {
		t.Fatal(err)
	}
}
