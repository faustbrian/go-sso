//go:build integration

package postgres_test

import (
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	"github.com/faustbrian/go-sso"
)

func prepareNativeCallbackRole(t *testing.T, x providerLoginStartFixture, role organization.ID) {
	t.Helper()
	f := x.enable.f
	f.dynamicRoles = organization.DynamicRoleConfig{Version: 1, MaximumRoles: 2,
		Catalog: []organization.Permission{{ID: "project-view", Action: "project.view", ResourceType: "project"}}}
	f.compose(t)
	auth := f.auth(string(x.config.TenantID), "owner")
	view, err := f.service.Get(f.ctx, organization.ReadRequest{Authentication: auth,
		OrganizationID: x.config.Profiles[0].OrganizationID, CorrelationID: "enterprise-role-fixture"})
	if err != nil {
		t.Fatal("observe organization before configuring an application role", err)
	}
	prepared, err := f.service.PrepareCreateDynamicRole(f.ctx, organization.DynamicRoleRequest{
		Authentication: auth, CommandID: commandID(t), OrganizationID: view.Organization.ID, OrganizationVersion: view.Organization.Version,
		RoleID: role, Name: "Project reader", CorrelationID: "enterprise-role-fixture",
		Statements: []organization.RoleStatement{{PermissionID: "project-view", ResourceID: "one", Effect: authorization.Allow}},
	}, "127.0.0.1")
	if err != nil {
		t.Fatal("prepare actual organization custom role", err)
	}
	if got, err := f.service.Execute(f.ctx, prepared); err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("commit actual organization custom role", err)
	}
}

func TestNativeProviderRoleRepeatLoginCommitsWithdrawalAndRollsBack(t *testing.T) {
	x := newNativeCallbackJourneyFixture(t, "role-grant")
	f, profile := x.start.enable.f, x.start.config.Profiles[0]
	reader, err := organizationpg.NewRepositoryWithProviderRoleGrants(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	service, err := organization.NewService(f.sessions, reader, fixturePolicy{}, f.configuration.Core)
	if err != nil {
		t.Fatal(err)
	}
	auth := f.auth(string(x.start.config.TenantID), "owner")
	readOrganization := func() organization.View {
		t.Helper()
		view, err := f.service.Get(f.ctx, organization.ReadRequest{Authentication: auth, OrganizationID: profile.OrganizationID, CorrelationID: "enterprise-role-check"})
		if err != nil {
			t.Fatal(err)
		}
		return view
	}
	assertPermission := func(want authorization.Outcome) {
		t.Helper()
		check := organization.PermissionCheckRequest{Authentication: auth, OrganizationID: profile.OrganizationID, OrganizationVersion: readOrganization().Organization.Version,
			Action: "project.view", ResourceType: "project", ResourceID: "one", CorrelationID: "enterprise-role-check"}
		if got, err := service.CheckPermission(f.ctx, check); err != nil || got.Outcome != want {
			t.Fatalf("organization permission=%v, want=%v: %v", got.Outcome, want, err)
		}
	}
	assertPermission(authorization.Deny)
	beforeGrantVersion := readOrganization().Organization.Version
	reply, err := x.completion.SigninCallback(f.ctx, x.request)
	if err != nil || reply.Completion.Outcome != identity.CommitOutcomeCommitted || reply.Issuance.CommitOutcome != identity.CommitOutcomeCommitted || x.posts.Load() != 1 {
		t.Fatal("verified provider grant and actual session did not commit", err)
	}
	if got := readOrganization().Organization.Version; got != beforeGrantVersion+1 {
		t.Fatalf("provider grant policy revision=%d, want %d", got, beforeGrantVersion+1)
	}
	assertPermission(authorization.Allow)

	const selectGrant = `SELECT to_jsonb(g)::text FROM organization.provider_role_grants g
WHERE tenant_id=$1 AND organization_id=$2 AND user_id='owner' AND provider_id=$3`
	snapshot := func() string {
		t.Helper()
		var wire string
		if err := f.pool.Raw().QueryRow(f.ctx, selectGrant, string(x.start.config.TenantID), string(profile.OrganizationID), string(profile.ProviderID)).Scan(&wire); err != nil {
			t.Fatal("native callback omitted exact durable provider grant", err)
		}
		return wire
	}
	committed := snapshot()
	result, _ := x.completion.SigninCallback(f.ctx, x.request)
	if result.Issuance.Token != (session.Token{}) || result.CSRF != (session.CSRFToken{}) || snapshot() != committed || x.posts.Load() != 1 {
		t.Fatal("terminal replay changed role state, repeated exchange or disclosed browser custody")
	}
	bearer, err := reply.Issuance.Token.Reveal()
	if err != nil {
		t.Fatal("deliver committed session bearer", err)
	}
	csrf, err := reply.CSRF.Reveal()
	if err != nil {
		t.Fatal("deliver committed session CSRF token", err)
	}
	assertNativeCallbackJourneyLocalSessionAndLogout(t, x, reply, bearer, csrf)

	// Give the same role independently through the real application admin. A
	// second provider sign-in explicitly withdraws only the provider-owned set.
	tenant := string(x.start.config.TenantID)
	f.seedUser(t, x.start.config.TenantID, "second")
	f.add(t, tenant, "second", organization.RoleAdministrator, readOrganization().Organization.Version)
	applyAdminBinding := func(assign bool) {
		t.Helper()
		admin := f.auth(tenant, "second")
		const role = "native-enterprise-reader"
		view, err := f.service.GetDynamicRole(f.ctx, organization.DynamicRoleReadRequest{Authentication: admin, OrganizationID: profile.OrganizationID,
			RoleID: role, TargetUserID: "owner", CorrelationID: "separate-app-role"})
		if err != nil {
			t.Fatal("read independent application grant", err)
		}
		request := organization.RoleBindingRequest{Authentication: admin, CommandID: commandID(t), OrganizationID: profile.OrganizationID,
			RoleID: role, UserID: "owner", OrganizationVersion: view.Organization.Version, RoleVersion: view.DynamicRole.Version,
			OrganizationMemberVersion: view.Target.Version, BindingVersion: view.RoleBinding.Version, CorrelationID: "separate-app-role"}
		var prepared organizationpg.PreparedCommand
		if assign {
			prepared, err = f.service.PrepareAssignDynamicRole(f.ctx, request, "127.0.0.1")
		} else {
			prepared, err = f.service.PrepareRevokeDynamicRole(f.ctx, request, "127.0.0.1")
		}
		if err != nil {
			t.Fatal("prepare independent application grant transition", err)
		}
		if changed, err := f.service.Execute(f.ctx, prepared); err != nil || changed.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("commit independent application grant transition", err)
		}
	}
	applyAdminBinding(true)
	beforeWithdrawalVersion := readOrganization().Organization.Version
	retain := true
	unchanged := x.newAttempt(t, "native-enterprise-role-retained", &retain, time.Time{})
	kept, err := x.completion.SigninCallback(f.ctx, unchanged)
	if err != nil || kept.Issuance.CommitOutcome != identity.CommitOutcomeCommitted || readOrganization().Organization.Version != beforeWithdrawalVersion {
		t.Fatal("unchanged provider grants did not preserve organization policy revision", err)
	}
	spec, err := kept.Issuance.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	sessionReader, _ := nativeCallbackJourneySessionReader(t, x, spec.Audience)
	assertSessionAdmission := func(token session.Token, want bool) {
		t.Helper()
		credential, err := session.NewCredential(session.CredentialCookie, token)
		if err != nil {
			t.Fatal(err)
		}
		got, err := sessionReader.Get(f.ctx, session.GetRequest{TenantID: spec.TenantID, Credential: credential})
		if err != nil || got.Authenticated != want {
			t.Fatalf("enterprise session current admission=%t, want %t: %v", got.Authenticated, want, err)
		}
	}
	assertSessionAdmission(kept.Issuance.Token, true)
	withdraw := false
	second := x.newAttempt(t, "native-enterprise-role-withdrawal", &withdraw, time.Time{})
	withdrawn, err := x.completion.SigninCallback(f.ctx, second)
	if err != nil || withdrawn.Issuance.CommitOutcome != identity.CommitOutcomeCommitted || x.posts.Load() != 3 {
		t.Fatalf("signed false did not commit role withdrawal and a new session: outcome=%v provider exchanges=%d err=%v", withdrawn.Completion.Outcome, x.posts.Load(), err)
	}
	if got := readOrganization().Organization.Version; got != beforeWithdrawalVersion+1 {
		t.Fatalf("provider withdrawal policy revision=%d, want %d", got, beforeWithdrawalVersion+1)
	}
	assertSessionAdmission(kept.Issuance.Token, false)
	assertSessionAdmission(withdrawn.Issuance.Token, true)
	var roleCount int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT cardinality(role_ids) FROM organization.provider_role_grants
WHERE tenant_id=$1 AND organization_id=$2 AND user_id='owner' AND provider_id=$3`, tenant, string(profile.OrganizationID), string(profile.ProviderID)).Scan(&roleCount); err != nil || roleCount != 0 {
		t.Fatalf("provider withdrawal retained grants or erased the durable checkpoint: %d, %v", roleCount, err)
	}
	assertPermission(authorization.Allow) // Independent administrator grant survived.
	applyAdminBinding(false)
	assertPermission(authorization.Deny)
	beforeRollback := snapshot()

	// Force a later required effect to fail after the attempted role change.
	grant := true
	third := x.newAttempt(t, "native-enterprise-role-rollback", &grant, time.Time{})
	type durableEffects struct {
		sessions             int
		authorizationVersion string
		organizationVersion  string
	}
	readEffects := func() durableEffects {
		t.Helper()
		var got durableEffects
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT
(SELECT count(*) FROM organization_sessions.sessions WHERE tenant_id=$1 AND user_id='owner'),
m.authorization_version::text,o.version::text FROM organization.memberships m
JOIN organization.organizations o USING (tenant_id,organization_id) WHERE m.tenant_id=$1 AND m.organization_id=$2 AND m.user_id='owner'`,
			tenant, string(profile.OrganizationID)).Scan(&got.sessions, &got.authorizationVersion, &got.organizationVersion); err != nil {
			t.Fatal("observe durable native session and authorization effects", err)
		}
		return got
	}
	beforeEffects := readEffects()
	if _, err := f.pool.Raw().Exec(f.ctx, `CREATE SEQUENCE sso_providers.role_session_outbox_attempt;
CREATE FUNCTION sso_providers.reject_role_session_outbox() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN
 IF NEW.topic='session.created.v1' THEN
   PERFORM nextval('sso_providers.role_session_outbox_attempt');
   RAISE EXCEPTION 'controlled role callback rollback';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER reject_role_session_outbox BEFORE INSERT ON outbox_messages
FOR EACH ROW EXECUTE FUNCTION sso_providers.reject_role_session_outbox()`); err != nil {
		t.Fatal("install isolated callback outbox fault", err)
	}
	failed, err := x.completion.SigninCallback(f.ctx, third)
	if err == nil || failed.Completion.Outcome != identity.CommitOutcomeNotCommitted || x.posts.Load() != 4 ||
		failed.Issuance.Token != (session.Token{}) || failed.CSRF != (session.CSRFToken{}) || snapshot() != beforeRollback || readEffects() != beforeEffects {
		t.Fatal("failed transaction escaped with a grant, a session or wrong outcome", err)
	}
	// A sequence increment survives rollback, so an earlier failure cannot
	// make the outbox rollback assertions pass without reaching this fault.
	var caught bool
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT is_called FROM sso_providers.role_session_outbox_attempt`).Scan(&caught); err != nil || !caught {
		t.Fatal("callback did not reach the controlled session outbox fault", err)
	}
	assertPermission(authorization.Deny)
}

func TestNativeProviderRoleMissingClaimPreservesGrant(t *testing.T) {
	x := newNativeCallbackJourneyFixture(t, "role-grant")
	f, profile := x.start.enable.f, x.start.config.Profiles[0]
	tenant := string(x.start.config.TenantID)
	reply, err := x.completion.SigninCallback(f.ctx, x.request)
	if err != nil || reply.Issuance.CommitOutcome != identity.CommitOutcomeCommitted || x.posts.Load() != 1 {
		t.Fatal("establish an existing provider role and session", err)
	}
	type state struct {
		grant            string
		sessions, tokens int
	}
	read := func() state {
		t.Helper()
		var got state
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT to_jsonb(g)::text,
(SELECT count(*) FROM organization_sessions.sessions WHERE tenant_id=$1 AND user_id='owner'),
(SELECT count(*) FROM sso_providers.provider_login_token_sets WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3)
FROM organization.provider_role_grants g
WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND user_id='owner'`, tenant, string(profile.OrganizationID), string(profile.ProviderID)).Scan(&got.grant, &got.sessions, &got.tokens); err != nil {
			t.Fatal("observe the exact provider grant, session and vault effects", err)
		}
		return got
	}
	before := read()
	missing := x.newAttempt(t, "native-enterprise-missing-role-claim", nil, time.Time{})
	denied, err := x.completion.SigninCallback(f.ctx, missing)
	if !errors.Is(err, sso.ErrForbidden) || denied.Issuance.Token != (session.Token{}) || denied.CSRF != (session.CSRFToken{}) || x.posts.Load() != 2 {
		t.Fatal("a signed response missing its mapped claim did not fail closed", err)
	}
	if read() != before {
		t.Fatal("incomplete role claims changed the retained grant, issued a session or deposited new tokens")
	}
}
