//go:build integration

package postgres_test

import (
	"strconv"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestNativeProviderDisableInvalidatesManagedRolePolicyOnce(t *testing.T) {
	x := newNativeCallbackJourneyFixture(t, "role-grant")
	f, profile := x.start.enable.f, x.start.config.Profiles[0]
	tenant, org, provider := string(x.start.config.TenantID), string(profile.OrganizationID), string(profile.ProviderID)
	issued, err := x.completion.SigninCallback(f.ctx, x.request)
	if err != nil || issued.Completion.Outcome != identity.CommitOutcomeCommitted || issued.Issuance.CommitOutcome != identity.CommitOutcomeCommitted {
		t.Fatal("establish an actual managed provider grant and native session", err)
	}
	spec, err := issued.Issuance.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	reader, _ := nativeCallbackJourneySessionReader(t, x, spec.Audience)
	credential, err := session.NewCredential(session.CredentialCookie, issued.Issuance.Token)
	if err != nil {
		t.Fatal(err)
	}
	access := session.GetRequest{TenantID: spec.TenantID, Credential: credential}
	assertSession := func(want bool) {
		t.Helper()
		got, err := reader.Get(f.ctx, access)
		if err != nil || got.Authenticated != want || (!want && got.Session != (session.Session{})) {
			t.Fatalf("original native session authenticated=%v, want %v: %v", got.Authenticated, want, err)
		}
	}
	assertSession(true)
	type policyState struct {
		version, credential, generation, grant string
		active                                 bool
	}
	read := func() policyState {
		t.Helper()
		var got policyState
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT o.version::text,o.credential_version::text,s.generation::text,s.active,to_jsonb(g)::text
FROM organization.organizations o
JOIN organization.provider_role_sources s USING(tenant_id,organization_id)
JOIN organization.provider_role_grants g USING(tenant_id,organization_id,provider_id)
WHERE o.tenant_id=$1 AND o.organization_id=$2 AND s.provider_id=$3 AND g.user_id='owner' AND cardinality(g.role_ids)>0`,
			tenant, org, provider).Scan(&got.version, &got.credential, &got.generation, &got.active, &got.grant); err != nil {
			t.Fatal("observe retained managed grants and the organization's two independent epochs", err)
		}
		return got
	}
	before := read()
	if !before.active || before.generation != "3" {
		t.Fatal("native role fixture did not retain its exact enabled provider generation")
	}
	beforeVersion, err := strconv.ParseUint(before.version, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	service := nativeProviderDisableService(t, x.start, providerDisablePolicy{})
	disable := nativeProviderDisableRequest(t, x.start, sso.ActiveTransactionRevoke)
	if _, err := f.pool.Raw().Exec(f.ctx, `CREATE SEQUENCE sso_providers.managed_role_disable_fault;
CREATE FUNCTION sso_providers.reject_managed_role_disable_outbox() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN
 IF NEW.topic='enterprise_provider.disabled.v1' THEN
   PERFORM nextval('sso_providers.managed_role_disable_fault');
   RAISE EXCEPTION 'controlled managed role disable rollback';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER reject_managed_role_disable_outbox BEFORE INSERT ON outbox_messages
FOR EACH ROW EXECUTE FUNCTION sso_providers.reject_managed_role_disable_outbox()`); err != nil {
		t.Fatal("install isolated native disable outbox fault", err)
	}
	failed, err := service.ProviderDisable(f.ctx, disable)
	if err == nil || failed.Disabled || failed.Completion.Outcome != identity.CommitOutcomeNotCommitted || failed.Completion.Binding.CommandID == "" {
		t.Fatal("failed native disable did not roll back its provider and managed policy transition", err)
	}
	var reached bool
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT is_called FROM sso_providers.managed_role_disable_fault`).Scan(&reached); err != nil || !reached {
		t.Fatal("disable did not reach the controlled outbox fault", err)
	}
	if read() != before {
		t.Fatal("failed native disable changed the policy epoch, credential epoch, source or retained grant")
	}
	assertSession(true)
	assertProviderDisableState(t, x.start, true, "3")
	if _, err := f.pool.Raw().Exec(f.ctx, `DROP TRIGGER reject_managed_role_disable_outbox ON outbox_messages;
DROP FUNCTION sso_providers.reject_managed_role_disable_outbox()`); err != nil {
		t.Fatal("remove isolated native disable outbox fault", err)
	}
	result, err := service.RetryProviderDisable(f.ctx, disable, failed.Completion.Binding.CommandID)
	if err != nil || !result.Disabled || result.Completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("native provider disable with retained managed grants did not commit", err)
	}
	after := read()
	if after.version != strconv.FormatUint(beforeVersion+1, 10) || after.credential != before.credential ||
		after.generation != "4" || after.active || after.grant != before.grant {
		t.Fatal("native disable did not invalidate policy once while preserving credential epoch and retained grants")
	}
	assertSession(false)
	if replay, err := service.RetryProviderDisable(f.ctx, disable, failed.Completion.Binding.CommandID); err != nil || replay.Completion.Binding != result.Completion.Binding {
		t.Fatal("native disable replay did not recover its original committed result", err)
	}
	if read() != after {
		t.Fatal("native disable replay advanced policy again or changed retained grants")
	}
}

func TestNativeProviderRoleSourceProjectionFollowsLifecycle(t *testing.T) {
	x := newProviderLoginStartFixture(t)
	f := x.enable.f
	installProviderRoleSourceProjection(t, f)
	tenant, org, provider := string(x.enable.proof.TenantID), string(x.enable.proof.OrganizationID), x.request.ProviderID

	const findSource = `SELECT generation::text,mapping_version::text,active FROM organization.provider_role_sources
WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`
	assertSource := func(version string, active bool) {
		t.Helper()
		var gotVersion, mapping string
		var gotActive bool
		if err := f.pool.Raw().QueryRow(f.ctx, findSource, tenant, org, provider).Scan(&gotVersion, &mapping, &gotActive); err != nil ||
			gotVersion != version || mapping != "1" || gotActive != active {
			t.Fatalf("source state: want generation %s active=%v, got %s/%s active=%v: %v", version, active, gotVersion, mapping, gotActive, err)
		}
	}
	var dormant int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM organization.provider_role_sources
WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`, tenant, org, provider).Scan(&dormant); err != nil || dormant != 0 {
		t.Fatal("additive migration inferred active grant authority for existing provider", err)
	}
	service := nativeProviderDisableService(t, x, providerDisablePolicy{})
	disable := nativeProviderDisableRequest(t, x, sso.ActiveTransactionRevoke)
	result, err := service.ProviderDisable(f.ctx, disable)
	if err != nil || !result.Disabled || result.Completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("native provider disable did not commit", err)
	}
	assertSource("4", false)
	if replay, err := service.ProviderDisable(f.ctx, disable); err != nil || replay.Completion.Binding != result.Completion.Binding {
		t.Fatal("native disable replay did not return the original result", err)
	}
	assertSource("4", false)

	credential, err := x.enable.service.ObserveProviderCredentialCheckpoint(f.ctx, provider, 4)
	if err != nil {
		t.Fatal("selected original provider credential", err)
	}
	key, err := identity.NewIdempotencyKey([]byte("provider-role-native-re-enable"))
	if err != nil {
		t.Fatal(err)
	}
	enable := x.enable.request
	enable.ExpectedVersion, enable.CredentialCheckpoint, enable.IdempotencyKey = 4, credential, key
	current, err := x.enable.service.ProviderEnable(f.ctx, enable)
	if err != nil || !current.Provider.Enabled || current.Provider.Version != 5 || current.Completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("native provider re-enable did not commit at a new generation", err)
	}
	assertSource("5", true)

	// Fail after the provider mutation and its projection have both run. Neither
	// can escape an existing owner transaction when mandatory effects fail.
	if _, err := f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION sso_providers.reject_role_projection_outbox() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN
 IF NEW.topic='enterprise_provider.disabled.v1' THEN RAISE EXCEPTION 'controlled outbox failure'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER reject_role_projection_outbox BEFORE INSERT ON outbox_messages
FOR EACH ROW EXECUTE FUNCTION sso_providers.reject_role_projection_outbox()`); err != nil {
		t.Fatal("install isolated outbox fault", err)
	}
	disposition, err := sso.NewActiveTransactionDisposition(sso.ProviderID(provider), 5, sso.ActiveTransactionRevoke)
	if err != nil {
		t.Fatal(err)
	}
	disable.ExpectedVersion, disable.ActiveTransactionDisposition = 5, disposition
	if failed, err := service.ProviderDisable(f.ctx, disable); err == nil || failed.Completion.Outcome != identity.CommitOutcomeNotCommitted || failed.Disabled {
		t.Fatal("outbox failure did not report rolled-back native disable", err)
	}
	assertProviderDisableState(t, x, true, "5")
	assertSource("5", true)
}

func installProviderRoleSourceProjection(t *testing.T, f *orgFixture) {
	t.Helper()
	config, err := pgx.ParseConfig(f.dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.Database = f.database
	db := stdlib.OpenDB(*config)
	defer db.Close()
	backend, err := migrationpg.New(db)
	if err != nil {
		t.Fatal(err)
	}
	history := append(migrationList(nil), f.history...)
	for _, source := range []migrations.Source{
		organizationpg.DynamicRoleMigrationSource{Version: 350},
		organizationpg.ProviderRoleGrantMigrationSource{Version: 351},
		organizationpg.ProviderRoleSourceProjectionMigrationSource{Version: 352},
		ssopg.ProviderRoleSourceMigrationSource{Version: 353},
	} {
		steps, err := source.Load(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		history = append(history, steps...)
	}
	runner, err := migrations.NewRunner(history, backend)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := runner.Up(f.ctx); err != nil {
			t.Fatal("install or replay optional native provider-role source projection", err)
		}
	}
}
