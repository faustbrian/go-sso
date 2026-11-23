//go:build integration

package postgres_test

import (
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/jackc/pgx/v5"
)

// The authorized native refusal leaves the original grant available as a storage
// template. All synthetic credentials, grants and receipts are rollback-only
// cardinality; exact SQL replay never opens an envelope or contacts a provider.
func TestNativeProviderGrantRevocationQueryScale(t *testing.T) {
	trace := new(providerTrace)
	x := newNativeOAuth2JourneyFixture(t, "restorable-vault-revoke-refused", trace)
	f := x.start.enable.f
	for _, source := range []migrations.Source{
		ssopg.ProviderGrantFenceMigrationSource{Version: 355},
		ssopg.ProviderGrantRevocationReceiptMigrationSource{Version: 356},
	} {
		history, err := source.Load(f.ctx)
		if err != nil || len(history) != 1 {
			t.Fatal("load revocation query prerequisites", err)
		}
		if _, err := f.pool.Raw().Exec(f.ctx, history[0].UpSQL()); err != nil {
			t.Fatal("install revocation query prerequisites", err)
		}
	}
	login, err := x.completion.SigninCallbackOAuth2(f.ctx, x.request)
	if err != nil || login.Completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("establish native grant and session", err)
	}
	spec, err := login.Issuance.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	wire, err := login.Issuance.Token.Reveal()
	if err != nil {
		t.Fatal("use actual native session only", err)
	}
	grant, err := sso.NewTokenVersion(sso.TokenVersionSpec{TenantID: spec.TenantID,
		OrganizationID: x.start.profile.OrganizationID, ProviderID: x.start.profile.ProviderID,
		ProviderSubject: nativeOAuth2JourneySubject, CommandID: login.Completion.Binding.CommandID,
		CredentialGeneration: x.start.profile.CredentialGeneration, Version: 1, Purpose: sso.EnterpriseTokenPurpose})
	if err != nil {
		t.Fatal(err)
	}
	key, err := identity.NewIdempotencyKey([]byte("native-revocation-query-scale"))
	if err != nil {
		t.Fatal(err)
	}
	request, err := sso.NewRevokeEnterpriseToken(grant, key)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := ssopg.NewProviderGrantRevocationService(x.completion, ssopg.ProviderGrantRevocationConfig{
		Session: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: spec.Audience,
			Clock: clock.System{}, MaximumDuration: time.Second, ClockUncertainty: time.Millisecond,
			LookupKeys: []session.DigestKey{x.lookup}},
		Endpoints: []ssopg.ProviderGrantRevocationEndpoint{{OrganizationID: x.start.profile.OrganizationID,
			ProviderID: x.start.profile.ProviderID, URL: "https://provider.example.com/revoke"}},
	})
	if err != nil {
		t.Fatal("compose authorized native revocation query fixture", err)
	}
	browser := ssopg.ProviderGrantRevocationBrowser{Origin: x.start.config.Origin,
		Session: authentication.NewBearerCredential(wire), CSRF: login.CSRF}
	trace.mu.Lock()
	trace.queries = nil
	trace.mu.Unlock()
	started := time.Now()
	got, err := svc.Revoke(f.ctx, request, browser)
	elapsed := time.Since(started)
	if err != nil || got.Completion.Outcome != identity.CommitOutcomeCommitted || string(got.ProviderOutcome) != "refused" || got.LocalErased || x.revokes.Load() != 1 {
		t.Fatal("native refused revocation did not retain the grant", err)
	}
	trace.mu.Lock()
	queries, traceErr := append([]providerQuery(nil), trace.queries...), trace.err
	trace.mu.Unlock()
	if traceErr != nil {
		t.Fatal(traceErr)
	}
	t.Logf("native-revocation first-operation-elapsed=%s provider-trace-records=%d; committed fixture cardinality, includes session/coordinator/client/provider work", elapsed, len(queries))
	selected := map[string]providerQuery{}
	for _, query := range queries {
		name := ""
		switch {
		case strings.HasPrefix(query.sql, "SELECT organization_id,provider_id,start_command_id,callback_command_id,callback_generation::text"):
			name = "vault"
		case strings.HasPrefix(query.sql, "SELECT p.metadata_version::text") && strings.Contains(query.sql, "AND p.protocol='oauth2' AND p.enabled"):
			name = "material"
		case strings.HasPrefix(query.sql, "SELECT true") && strings.Contains(query.sql, "FOR UPDATE OF p,c"):
			name = "epoch"
		case strings.HasPrefix(query.sql, "SELECT tenant_id,user_id,callback_command_id,attempt_command_id,"):
			name = "receipt"
		case strings.HasPrefix(query.sql, "WITH original AS MATERIALIZED ("):
			name = "settlement"
		case strings.HasPrefix(query.sql, "INSERT INTO sso_providers.provider_grant_fences"):
			name = "fence"
		}
		if name != "" {
			if previous, ok := selected[name]; !ok || len(query.oids) > len(previous.oids) {
				selected[name] = query
			}
		}
	}
	if len(selected) != 6 || len(selected["epoch"].oids) != 7 || len(selected["settlement"].oids) != 11 {
		t.Fatal("native revocation did not capture all storage queries and Work bindings", len(selected))
	}
	for sample := range 2 {
		started := time.Now()
		replayed, err := svc.Revoke(f.ctx, request, browser)
		if err != nil || replayed.Completion.Binding != got.Completion.Binding || replayed.ProviderOutcome != got.ProviderOutcome || x.revokes.Load() != 1 {
			t.Fatal("native receipt recovery resent or changed the outcome", err)
		}
		t.Logf("native-revocation recovery-sample=%d operation-elapsed=%s; no additional provider send", sample, time.Since(started))
	}
	tx, err := f.pool.Raw().Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.ctx)
	if _, err := tx.Exec(f.ctx, "SET LOCAL statement_timeout='15s'; SET LOCAL lock_timeout='1s'"); err != nil {
		t.Fatal(err)
	}
	for name, query := range selected {
		selected[name] = nativeProviderGrantRevocationWireBindings(t, f, tx, query)
	}
	for _, name := range []string{"vault", "material", "epoch", "receipt"} {
		measureNativeProviderGrantFenceQuery(t, f, tx, "revocation-before-scale-"+name, selected[name], 1)
	}
	measureNativeProviderGrantRevocationSettlement(t, f, tx, "before-scale-retain", selected["settlement"], 1, false)
	populateNativeProviderGrantFenceScale(t, f, tx, selected["fence"])
	populateNativeProviderGrantRevocationScale(t, f, tx, selected["settlement"], selected["material"])
	var engine string
	var grants, fences, receipts, hotReceipts, credentials int
	if err := tx.QueryRow(f.ctx, `SELECT current_setting('server_version'),
 (SELECT count(*) FROM sso_providers.provider_login_token_sets),
 (SELECT count(*) FROM sso_providers.provider_grant_fences),
 (SELECT count(*) FROM sso_providers.provider_grant_revocation_receipts),
 (SELECT count(*) FROM sso_providers.provider_grant_revocation_receipts WHERE tenant_id=$1),
 (SELECT count(*) FROM sso_providers.credentials)`, selected["settlement"].args[0]).Scan(&engine, &grants, &fences, &receipts, &hotReceipts, &credentials); err != nil || grants != 40001 || fences != 39999 || receipts != 19999 || hotReceipts != 2000 || credentials < 40001 {
		t.Fatal("representative revocation storage population mismatch", grants, fences, receipts, hotReceipts, credentials, err)
	}
	var columns, indexes []byte
	if err := tx.QueryRow(f.ctx, `SELECT
 (SELECT jsonb_agg(jsonb_build_object('table',c.relname,'column',a.attname,'type',format_type(a.atttypid,a.atttypmod)) ORDER BY c.relname,a.attnum)
 FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='sso_providers' AND c.relname IN ('providers','credentials','provider_login_token_sets','provider_grant_fences','provider_grant_revocation_receipts') AND a.attnum>0 AND NOT a.attisdropped),
 (SELECT jsonb_agg(jsonb_build_object('table',tablename,'definition',indexdef) ORDER BY tablename,indexname)
 FROM pg_indexes WHERE schemaname='sso_providers' AND tablename IN ('providers','credentials','provider_login_token_sets','provider_grant_fences','provider_grant_revocation_receipts'))`).Scan(&columns, &indexes); err != nil {
		t.Fatal("inspect installed revocation column types/indexes", err)
	}
	t.Logf("PostgreSQL=%s rollback-only grants=%d fences=%d receipts=%d hot-receipts=%d credentials=%d; 400 colder grant tenants, revoke receipts only on valid revoke fences; isolated, no concurrent load, first sample may be cold", engine, grants, fences, receipts, hotReceipts, credentials)
	t.Logf("actual-column-types=%s actual-indexes=%s", columns, indexes)
	for _, fixture := range []struct {
		name string
		n    int
	}{{"hot", 3}, {"cold", 4003}} {
		var tenant, provider, callback string
		var command, attempt []byte
		if err := tx.QueryRow(f.ctx, `SELECT tenant_id,provider_id,callback_command_id,grant_command_id,attempt_command_id FROM grant_fence_cost_rows WHERE n=$1`, fixture.n).Scan(&tenant, &provider, &callback, &command, &attempt); err != nil {
			t.Fatal("select rollback-only revocation population", err)
		}
		variants := map[string]providerQuery{
			"vault":   nativeProviderLogoutQueryBindings(t, selected["vault"], map[int]any{0: tenant, 1: callback}),
			"receipt": nativeProviderLogoutQueryBindings(t, selected["receipt"], map[int]any{0: tenant, 2: attempt}),
		}
		issuer := sha256.Sum256([]byte(provider))
		for _, name := range []string{"material", "epoch"} {
			variants[name] = nativeProviderLogoutQueryBindings(t, selected[name], map[int]any{0: tenant, 2: provider, 6: issuer[:]})
		}
		for _, name := range []string{"vault", "material", "epoch", "receipt"} {
			query := variants[name]
			measureNativeProviderGrantFenceQuery(t, f, tx, "revocation-"+fixture.name+"-"+name, query, 1)
			changes := map[int]any{1: "grant-revoke-cost-missing"}
			if name == "material" || name == "epoch" {
				changes = map[int]any{2: "grant-revoke-cost-missing"}
			}
			measureNativeProviderGrantFenceQuery(t, f, tx, "revocation-"+fixture.name+"-missing-"+name, nativeProviderLogoutQueryBindings(t, query, changes), 0)
		}
		for _, name := range []string{"material", "epoch"} {
			measureNativeProviderGrantFenceQuery(t, f, tx, "revocation-"+fixture.name+"-stale-credential-"+name,
				nativeProviderLogoutQueryBindings(t, variants[name], map[int]any{4: "18446744073709551615"}), 0)
		}
		settlement := nativeProviderLogoutQueryBindings(t, selected["settlement"], map[int]any{0: tenant, 2: command, 3: callback, 5: attempt})
		measureNativeProviderGrantRevocationSettlement(t, f, tx, fixture.name+"-retain", settlement, 1, false)
		acknowledged := nativeProviderLogoutQueryBindings(t, settlement, map[int]any{9: "acknowledged", 10: true})
		measureNativeProviderGrantRevocationSettlement(t, f, tx, fixture.name+"-acknowledged-erasure", acknowledged, 1, true)
		for _, stale := range []struct {
			name    string
			changes map[int]any
		}{{"absent", map[int]any{3: "grant-revoke-cost-missing"}},
			{"stale-version", map[int]any{4: "18446744073709551615"}},
			{"stale-generation", map[int]any{6: "18446744073709551615"}},
			{"stale-ciphertext", map[int]any{7: make([]byte, 32)}}} {
			measureNativeProviderGrantRevocationSettlement(t, f, tx, fixture.name+"-"+stale.name,
				nativeProviderLogoutQueryBindings(t, acknowledged, stale.changes), 0, false)
		}
	}
	if err := tx.Rollback(f.ctx); err != nil {
		t.Fatal("rollback representative revocation population and measured writes", err)
	}
}

// Direct pool calls expose Go arguments through pgx's query tracer. Reconstruct
// their wire encoding with the same backend description and ExtendedQueryBuilder
// used by pgx cached statements; Work's captured explicit OIDs stay unchanged.
func nativeProviderGrantRevocationWireBindings(t *testing.T, f *orgFixture, tx pgx.Tx, query providerQuery) providerQuery {
	t.Helper()
	if len(query.oids) > 0 {
		return query
	}
	description, err := tx.Conn().Prepare(f.ctx, "", query.sql)
	if err != nil {
		t.Fatal("describe executed native revocation query", err)
	}
	var builder pgx.ExtendedQueryBuilder
	if err := builder.Build(tx.Conn().TypeMap(), description, query.args); err != nil {
		t.Fatal("encode captured native revocation Go arguments", err)
	}
	query.oids, query.formats, query.values = description.ParamOIDs, builder.ParamFormats, builder.ParamValues
	return query
}

func populateNativeProviderGrantRevocationScale(t *testing.T, f *orgFixture, tx pgx.Tx, settlement, material providerQuery) {
	t.Helper()
	if _, err := tx.Exec(f.ctx, `INSERT INTO sso_providers.credentials(tenant_id,organization_id,provider_id,generation,provider_version,envelope,credential_context)
SELECT r.tenant_id,c.organization_id,r.provider_id,c.generation,c.provider_version,c.envelope,c.credential_context
FROM grant_fence_cost_rows r CROSS JOIN sso_providers.credentials c
WHERE c.tenant_id=$1 AND c.organization_id=$2 AND c.provider_id=$3`, material.args[:3]...); err != nil {
		t.Fatal("populate rollback-only installed credential cardinality", err)
	}
	if _, err := tx.Exec(f.ctx, `UPDATE sso_providers.providers p SET
 enabled=original.enabled,enablement_proof=original.enablement_proof,enablement_credential_generation=original.enablement_credential_generation,
 metadata_version=original.metadata_version,metadata_configuration_envelope=original.metadata_configuration_envelope,metadata_mapping_version=original.metadata_mapping_version
FROM grant_fence_cost_rows r,sso_providers.providers original
WHERE p.tenant_id=r.tenant_id AND p.provider_id=r.provider_id AND original.tenant_id=$1 AND original.organization_id=$2 AND original.provider_id=$3`, material.args[:3]...); err != nil {
		t.Fatal("populate rollback-only enabled installation projections", err)
	}
	if _, err := tx.Exec(f.ctx, `INSERT INTO sso_providers.provider_grant_revocation_receipts
 (tenant_id,user_id,callback_command_id,token_version,attempt_command_id,attempt_generation,intent_digest,outcome,local_erased)
SELECT r.tenant_id,$1,r.grant_command_id,f.token_version,f.attempt_command_id,f.attempt_generation,$2,'refused',false
FROM grant_fence_cost_rows r JOIN sso_providers.provider_grant_fences f
 ON (f.tenant_id,f.grant_command_id)=(r.tenant_id,r.grant_command_id)
WHERE f.attempt_purpose='identity.sso.provider-token.revoke'`, settlement.args[1], settlement.args[8]); err != nil {
		t.Fatal("populate receipts only for existing native-shaped revoke fences", err)
	}
	if _, err := tx.Exec(f.ctx, `ANALYZE sso_providers.providers; ANALYZE sso_providers.credentials; ANALYZE sso_providers.provider_grant_revocation_receipts`); err != nil {
		t.Fatal(err)
	}
}

func measureNativeProviderGrantRevocationSettlement(t *testing.T, f *orgFixture, tx pgx.Tx, scope string, query providerQuery, want int64, erased bool) {
	t.Helper()
	if _, err := tx.Exec(f.ctx, "SAVEPOINT revoke_receipt"); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(f.ctx, `DELETE FROM sso_providers.provider_grant_revocation_receipts WHERE tenant_id=$1 AND user_id=$2 AND attempt_command_id=$3`, query.args[0], query.args[1], query.args[5]); err != nil {
		t.Fatal("isolate original/synthetic receipt only inside rollback savepoint", err)
	}
	measureNativeProviderGrantFenceQuery(t, f, tx, "revocation-settlement-"+scope, query, want)
	result := tx.Conn().PgConn().ExecParams(f.ctx, query.sql, query.values, query.oids, query.formats, nil).Read()
	if result.Err != nil || result.CommandTag.RowsAffected() != want {
		t.Fatal("settlement semantic replay affected cardinality", scope, result.Err)
	}
	var present, receipt bool
	if err := tx.QueryRow(f.ctx, `SELECT
 EXISTS(SELECT 1 FROM sso_providers.provider_login_token_sets WHERE tenant_id=$1 AND origin_command_id=$2),
 EXISTS(SELECT 1 FROM sso_providers.provider_grant_revocation_receipts WHERE tenant_id=$1 AND attempt_command_id=$3)`, query.args[0], query.args[2], query.args[5]).Scan(&present, &receipt); err != nil || present == erased || receipt != (want == 1) {
		t.Fatal("settlement changed erasure or receipt semantics", scope, present, receipt, err)
	}
	if _, err := tx.Exec(f.ctx, "ROLLBACK TO SAVEPOINT revoke_receipt; RELEASE SAVEPOINT revoke_receipt"); err != nil {
		t.Fatal(err)
	}
}
