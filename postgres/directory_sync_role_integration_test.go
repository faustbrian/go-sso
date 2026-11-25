//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	scim "github.com/faustbrian/go-scim"
	scimorganization "github.com/faustbrian/go-scim/organization"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

const directoryRoleReader = "directory-role-reader"

type directoryRolePolicy func(context.Context, authorization.DecisionContext, uint64) (ssopg.ProviderUpdateAuthorizationEvidence, error)

func (p directoryRolePolicy) ObserveDirectoryRoleAuthorization(ctx context.Context, d authorization.DecisionContext, version uint64) (ssopg.ProviderUpdateAuthorizationEvidence, error) {
	return p(ctx, d, version)
}

func TestNativeDirectorySyncRoleRequiresExactOriginalProfileAndCurrentSource(t *testing.T) {
	x, config, ordinary := newDirectoryRoleJourney(t)
	f, ctx := x.provider.f, x.provider.f.ctx
	generation := x.start(t)
	worker, err := x.sync.WithGroupRoles(config)
	if err != nil {
		t.Fatal("select explicit native role synchronization", err)
	}
	membership, err := x.sync.WithGroupEdges(ordinary)
	if err != nil {
		t.Fatal("select the separate membership-only profile", err)
	}
	reader, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	selected, err := reader.WithDirectoryTeamRoles(worker.CurrentRoleSources)
	if err != nil {
		t.Fatal("opt into current directory-role authority", err)
	}
	plainPermissions, err := organization.NewService(f.configuration.Sessions, reader, f.configuration.Authorization, f.configuration.Core)
	if err != nil {
		t.Fatal(err)
	}
	rolePermissions, err := organization.NewService(f.configuration.Sessions, selected, f.configuration.Authorization, f.configuration.Core)
	if err != nil {
		t.Fatal(err)
	}
	check := func(service *organization.Service, user string, want authorization.Outcome) {
		t.Helper()
		authority, err := reader.ObserveCredentialAuthority(ctx, organization.CredentialAuthorityQuery{TenantID: x.scope.TenantID, OrganizationID: x.scope.OrganizationID})
		if err != nil {
			t.Fatal("observe current organization permission fence", err)
		}
		decision, err := service.CheckPermission(ctx, organization.PermissionCheckRequest{
			Authentication: f.auth(directoryTestTenant, user), OrganizationID: x.scope.OrganizationID,
			OrganizationVersion: authority.Version, Action: "document.read", ResourceType: "document", ResourceID: "one", CorrelationID: "directory-role-permission",
		})
		if err != nil || decision.Outcome != want {
			t.Fatal("wrong effective native permission", user, decision.Outcome, want, err)
		}
	}
	request := func(batch sso.DirectoryDeltaBatch) ssopg.DirectoryGroupRoleApplyRequest {
		return ssopg.DirectoryGroupRoleApplyRequest{GenerationID: generation.ID, ProviderID: generation.Provider,
			MappingVersion: generation.MappingVersion, PredecessorCheckpoint: batch.PredecessorCheckpoint, Delta: batch.Deltas[0]}
	}
	status := func() ssopg.DirectorySyncGeneration {
		t.Helper()
		at, err := x.sync.Status(ctx, generation.ID)
		if err != nil {
			t.Fatal("read committed role cursor", err)
		}
		return at
	}
	check(plainPermissions, directoryRoleReader, authorization.Deny)
	check(rolePermissions, directoryRoleReader, authorization.Deny)
	check(rolePermissions, "directory-local-reader", authorization.Allow)

	ordinaryBatch := x.batch(t, generation, sso.DirectoryMembershipAdd)
	ordinaryResult, err := membership.Apply(ctx, generation.ID, ordinaryBatch)
	if err != nil || len(ordinaryResult.ChildOutcomes) != 1 || ordinaryResult.ChildOutcomes[0].Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("commit native membership-only original", err)
	}
	afterOrdinary := status()
	check(rolePermissions, directoryRoleReader, authorization.Deny)
	if rejected, err := worker.ApplyGeneration(ctx, request(ordinaryBatch)); err == nil || rejected.Checkpoint != ([32]byte{}) || len(rejected.ChildOutcomes) != 0 {
		t.Fatal("ordinary membership receipt satisfied the exact role profile", err)
	}
	if actual := status(); actual != afterOrdinary {
		t.Fatal("rejected profile substitution changed the generation")
	}

	roleBatch := x.batch(t, afterOrdinary, sso.DirectoryMembershipAdd)
	roleRequest := request(roleBatch)
	roleResult, err := worker.ApplyGeneration(ctx, roleRequest)
	if err != nil || len(roleResult.ChildOutcomes) != 1 || roleResult.ChildOutcomes[0].Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("genuine Group edge did not commit its exact selected role", err)
	}
	afterRole := status()
	if expected, err := roleResult.NextCheckpoint(roleBatch); err != nil || expected != afterRole.Checkpoint || expected == afterOrdinary.Checkpoint || afterRole.AppliedCount != 2 {
		t.Fatal("role child was not finalized before the durable successor", err)
	}
	check(plainPermissions, directoryRoleReader, authorization.Deny)
	check(rolePermissions, directoryRoleReader, authorization.Allow)
	if rejected, err := membership.Apply(ctx, generation.ID, roleBatch); err == nil || rejected.Checkpoint != ([32]byte{}) || len(rejected.ChildOutcomes) != 0 {
		t.Fatal("role receipt satisfied the exact membership-only profile", err)
	}
	if actual := status(); actual != afterRole {
		t.Fatal("reverse profile substitution changed the generation")
	}
	if replay, err := worker.ApplyGeneration(ctx, roleRequest); err != nil || !reflect.DeepEqual(replay, roleResult) {
		t.Fatal("original role apply did not replay its exact child and successor", err)
	}

	premature := x.batch(t, afterRole, sso.DirectoryMembershipRemove)
	if rejected, err := worker.ApplyGeneration(ctx, request(premature)); err == nil || rejected.Checkpoint != ([32]byte{}) {
		t.Fatal("role withdrawal succeeded while the real source edge still existed", err)
	}
	if actual := status(); actual != afterRole {
		t.Fatal("rejected role withdrawal changed the cursor")
	}
	check(rolePermissions, directoryRoleReader, authorization.Allow)
	x.withdrawSourceMember(t)
	check(rolePermissions, directoryRoleReader, authorization.Deny)
	check(rolePermissions, "directory-local-reader", authorization.Allow)
	if replay, err := worker.ApplyGeneration(ctx, roleRequest); err != nil || !reflect.DeepEqual(replay, roleResult) {
		t.Fatal("removed source prevented recovery of the original committed add", err)
	}
	if actual := status(); actual != afterRole {
		t.Fatal("removed-edge add recovery changed the installed original successor")
	}

	removeBatch := x.batch(t, afterRole, sso.DirectoryMembershipRemove)
	removeRequest := request(removeBatch)
	removed, err := worker.ApplyGeneration(ctx, removeRequest)
	if err != nil || len(removed.ChildOutcomes) != 1 || removed.ChildOutcomes[0].Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("real SCIM withdrawal did not commit the original role removal", err)
	}
	afterRemove := status()
	if expected, err := removed.NextCheckpoint(removeBatch); err != nil || expected != afterRemove.Checkpoint || expected == afterRole.Checkpoint || afterRemove.AppliedCount != 3 {
		t.Fatal("role withdrawal did not finalize exactly one durable successor", err)
	}
	if replay, err := worker.ApplyGeneration(ctx, removeRequest); err != nil || !reflect.DeepEqual(replay, removed) {
		t.Fatal("original role withdrawal lost its exact receipt", err)
	}
	if historical, err := worker.ApplyGeneration(ctx, roleRequest); !errors.Is(err, sso.ErrDirectoryReconciliation) || historical.Checkpoint != ([32]byte{}) {
		t.Fatal("historical add disclosed a stale successor after a different advancement", err)
	}
	if actual := status(); actual != afterRemove {
		t.Fatal("historical add replay rewound or advanced the durable cursor")
	}
	check(rolePermissions, directoryRoleReader, authorization.Deny)
	check(rolePermissions, "directory-local-reader", authorization.Allow)
	grant := organizationpg.DirectoryTeamGrantScope{TenantID: x.scope.TenantID, OrganizationID: x.scope.OrganizationID,
		ProviderID: organization.ID(x.scope.ProviderID), ConnectionID: organization.ID(x.scope.ConnectionID),
		GroupID: organization.ID(x.groupID), TeamID: directoryTestTeam, UserID: directoryRoleReader}
	if actual, err := reader.ObserveDirectoryTeamMembership(ctx, grant); err != nil || actual.Source || actual.Local || actual.Version != 3 {
		t.Fatal("role withdrawal lost its source tombstone or created local membership", err)
	}
	var projections, bindings int
	err = f.pool.Raw().QueryRow(ctx, `SELECT
 (SELECT count(*) FROM organization.directory_team_role_grants),
 (SELECT count(*) FROM organization.team_role_bindings WHERE state='active')`).Scan(&projections, &bindings)
	if err != nil || projections != 0 || bindings != 1 {
		t.Fatal("withdrawal retained directory-role authority or removed the native team-role binding", projections, bindings, err)
	}
}

func TestNativeDirectorySyncRoleRecoversCanceledOriginalAfterLostAcknowledgment(t *testing.T) {
	x, config, _ := newDirectoryRoleJourney(t)
	ctx := x.provider.f.ctx
	generation := x.start(t)
	batch := x.batch(t, generation, sso.DirectoryMembershipAdd)
	request := ssopg.DirectoryGroupRoleApplyRequest{GenerationID: generation.ID, ProviderID: generation.Provider, MappingVersion: generation.MappingVersion,
		PredecessorCheckpoint: generation.Checkpoint, Delta: batch.Deltas[0]}
	lossy, fault := providerLossService(t, x.provider.f, x.provider.config, "SET state='reconciling',pending_batch")
	lossy, err := lossy.ForOrganization(string(x.scope.OrganizationID))
	if err != nil {
		t.Fatal(err)
	}
	bound, err := lossy.DirectorySync(x.scope.ConnectionID, directoryAdminPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	losingWorker, err := bound.WithGroupRoles(config)
	if err != nil {
		t.Fatal(err)
	}
	unknown, err := losingWorker.ApplyGeneration(ctx, request)
	if !fault.seen.Load() || !fault.lost.Load() || !errors.Is(err, sso.ErrDirectoryReconciliation) || unknown.Checkpoint != ([32]byte{}) {
		t.Fatal("lost role acknowledgment disclosed a successor or lost reconciliation", err)
	}
	pending, err := x.sync.Status(ctx, generation.ID)
	if err != nil || pending.State != ssopg.DirectorySyncReconciling || pending.Checkpoint != generation.Checkpoint || pending.AppliedCount != 0 {
		t.Fatal("unresolved role child advanced the durable generation", err)
	}
	cancel, err := x.sync.CancelExact(ctx, generation.ID, pending.Version)
	if err != nil || cancel.Completion.Outcome != identity.CommitOutcomeCommitted || cancel.Generation.State != ssopg.DirectorySyncCanceling ||
		cancel.Generation.Checkpoint != pending.Checkpoint || cancel.Generation.AppliedCount != pending.AppliedCount {
		t.Fatal("cancellation did not hold the original unresolved role child", err)
	}
	x.withdrawSourceMember(t)
	healthy, err := x.sync.WithGroupRoles(config)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := healthy.ApplyGeneration(ctx, request)
	if err != nil || len(recovered.ChildOutcomes) != 1 || recovered.ChildOutcomes[0].Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("removed source prevented exact committed role-child recovery", err)
	}
	expected, err := recovered.NextCheckpoint(batch)
	if err != nil || expected == generation.Checkpoint {
		t.Fatal("recovered original role child did not authorize its successor", err)
	}
	settled, err := x.sync.Status(ctx, generation.ID)
	if err != nil || settled.State != ssopg.DirectorySyncCanceled || settled.Checkpoint != expected || settled.AppliedCount != 1 || settled.Version != cancel.Generation.Version+1 {
		t.Fatal("role recovery did not close cancellation at exactly one original successor", err)
	}
	if replay, err := healthy.ApplyGeneration(ctx, request); err != nil || !reflect.DeepEqual(replay, recovered) {
		t.Fatal("settled role original was not exactly recoverable", err)
	}
	future := x.batch(t, settled, sso.DirectoryMembershipRemove)
	if rejected, err := healthy.ApplyGeneration(ctx, ssopg.DirectoryGroupRoleApplyRequest{
		GenerationID: settled.ID, ProviderID: settled.Provider, MappingVersion: settled.MappingVersion,
		PredecessorCheckpoint: settled.Checkpoint, Delta: future.Deltas[0],
	}); err == nil || rejected.Checkpoint != ([32]byte{}) {
		t.Fatal("closed role generation admitted a fresh withdrawal", err)
	}
	var grants, projections, roleEvents, ordinaryEvents int
	err = x.provider.f.pool.Raw().QueryRow(ctx, `SELECT
 (SELECT count(*) FROM organization.directory_team_grants WHERE active),
 (SELECT count(*) FROM organization.directory_team_role_grants),
 (SELECT count(*) FROM outbox_messages WHERE topic='sso.directory_sync.team_role_changed.v1'),
 (SELECT count(*) FROM outbox_messages WHERE topic='sso.directory_sync.team_membership_changed.v1')`).Scan(&grants, &projections, &roleEvents, &ordinaryEvents)
	if err != nil || grants != 1 || projections != 1 || roleEvents != 1 || ordinaryEvents != 0 {
		t.Fatal("lost acknowledgment recovery duplicated or omitted role effects", grants, projections, roleEvents, ordinaryEvents, err)
	}
}

func TestNativeDirectorySyncRoleWithdrawalPreservesAnotherGroupSource(t *testing.T) {
	x, config, _ := newDirectoryRoleJourney(t)
	ctx := x.provider.f.ctx
	response, err := x.groups.Execute(ctx, scim.Request{Operation: scim.GroupCreate, Credential: x.bearer,
		IdempotencyKey: "directory-role-second-group", ContentType: "application/scim+json",
		Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Independent role source","members":[{"type":"User","value":"` + x.userID + `"}]}`)})
	if err != nil {
		t.Fatal("create second genuine Group source", err)
	}
	otherGroup := directoryFixtureSCIMID(t, response, 201)
	config.Mapping, err = scimorganization.NewDirectoryRoleMapper(scimorganization.DirectoryRoleMappingConfig{
		Directory: scimorganization.DirectoryMappingConfig{TenantID: x.scope.TenantID, OrganizationID: x.scope.OrganizationID,
			ProviderID: sso.ProviderID(x.scope.ProviderID), ConnectionID: x.scope.ConnectionID, MappingVersion: 1,
			Groups:  []scimorganization.DirectoryGroupTeamMapping{{GroupID: x.groupID, TeamID: directoryTestTeam}, {GroupID: otherGroup, TeamID: directoryTestTeam}},
			Members: []scimorganization.DirectoryMemberUserMapping{{MemberID: x.userID, UserID: directoryRoleReader}}},
		Roles: []scimorganization.DirectoryGroupRoleMapping{{GroupID: x.groupID, TeamID: directoryTestTeam, RoleID: "directory-reader"},
			{GroupID: otherGroup, TeamID: directoryTestTeam, RoleID: "directory-reader"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	worker, err := x.sync.WithGroupRoles(config)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := organizationpg.NewRepository(x.provider.f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	selected, err := reader.WithDirectoryTeamRoles(worker.CurrentRoleSources)
	if err != nil {
		t.Fatal(err)
	}
	permissions, err := organization.NewService(x.provider.f.configuration.Sessions, selected,
		x.provider.f.configuration.Authorization, x.provider.f.configuration.Core)
	if err != nil {
		t.Fatal(err)
	}
	check := func(want authorization.Outcome) {
		t.Helper()
		authority, err := reader.ObserveCredentialAuthority(ctx, organization.CredentialAuthorityQuery{TenantID: x.scope.TenantID, OrganizationID: x.scope.OrganizationID})
		if err != nil {
			t.Fatal(err)
		}
		decision, err := permissions.CheckPermission(ctx, organization.PermissionCheckRequest{
			Authentication: x.provider.f.auth(directoryTestTenant, directoryRoleReader), OrganizationID: x.scope.OrganizationID,
			OrganizationVersion: authority.Version, Action: "document.read", ResourceType: "document", ResourceID: "one", CorrelationID: "directory-role-isolation",
		})
		if err != nil || decision.Outcome != want {
			t.Fatal("wrong permission across independent Group sources", decision.Outcome, want, err)
		}
	}
	generation := x.start(t)
	apply := func(group string, action sso.DirectoryMembershipAction) sso.DirectoryApplyResult {
		t.Helper()
		at, err := x.sync.Status(ctx, generation.ID)
		if err != nil {
			t.Fatal(err)
		}
		delta, err := sso.NewDirectoryGroupMembershipDelta(commandID(t), group, x.userID, action)
		if err != nil {
			t.Fatal(err)
		}
		result, err := worker.ApplyGeneration(ctx, ssopg.DirectoryGroupRoleApplyRequest{
			GenerationID: generation.ID, ProviderID: at.Provider, MappingVersion: at.MappingVersion, PredecessorCheckpoint: at.Checkpoint, Delta: delta,
		})
		if err != nil || len(result.ChildOutcomes) != 1 || result.ChildOutcomes[0].Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("apply independent genuine Group role source", err)
		}
		return result
	}
	check(authorization.Deny)
	apply(x.groupID, sso.DirectoryMembershipAdd)
	apply(otherGroup, sso.DirectoryMembershipAdd)
	check(authorization.Allow)
	x.withdrawSourceMember(t)
	check(authorization.Allow)
	apply(x.groupID, sso.DirectoryMembershipRemove)
	check(authorization.Allow)
	grant := organizationpg.DirectoryTeamGrantScope{TenantID: x.scope.TenantID, OrganizationID: x.scope.OrganizationID,
		ProviderID: organization.ID(x.scope.ProviderID), ConnectionID: organization.ID(x.scope.ConnectionID),
		GroupID: organization.ID(otherGroup), TeamID: directoryTestTeam, UserID: directoryRoleReader}
	if actual, err := reader.ObserveDirectoryTeamMembership(ctx, grant); err != nil || !actual.Source || actual.Local || actual.Version != 1 {
		t.Fatal("first Group withdrawal changed the independent source grant", err)
	}
	response, err = x.groups.Execute(ctx, scim.Request{Operation: scim.GroupReplace, Credential: x.bearer, ResourceID: otherGroup,
		IfMatch: response.ETag, IdempotencyKey: "directory-role-remove-second-group", ContentType: "application/scim+json",
		Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Independent role source","members":[]}`)})
	if err != nil || response.Status != 200 {
		t.Fatal("withdraw independent source through native SCIM", err)
	}
	check(authorization.Deny)
	apply(otherGroup, sso.DirectoryMembershipRemove)
	check(authorization.Deny)
	if actual, err := reader.ObserveDirectoryTeamMembership(ctx, grant); err != nil || actual.Source || actual.Local || actual.Version != 2 {
		t.Fatal("independent Group did not retain its own withdrawal tombstone", err)
	}
}

func newDirectoryRoleJourney(t *testing.T) (directoryGroupApplyFixture, ssopg.DirectorySyncGroupRolesConfig, ssopg.DirectorySyncGroupEdgesConfig) {
	t.Helper()
	x := newDirectoryGroupApplyFixture(t, organizationpg.DynamicRoleMigrationSource{Version: 687},
		organizationpg.TeamRoleBindingMigrationSource{Version: 688}, organizationpg.DirectoryTeamRoleMigrationSource{Version: 689})
	f := x.provider.f
	f.teams = organization.TeamConfig{Version: 1, MaximumTeams: 10, MaximumMembers: 10, LifecycleVersion: 1}
	f.dynamicRoles = organization.DynamicRoleConfig{Version: 1, MaximumRoles: 10, TeamBindingsVersion: 1,
		Catalog: []organization.Permission{{ID: "read", Action: "document.read", ResourceType: "document"}}}
	f.compose(t)
	reader, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	organizationVersion := func() uint64 {
		t.Helper()
		observed, err := reader.ObserveCredentialAuthority(f.ctx, organization.CredentialAuthorityQuery{TenantID: x.scope.TenantID, OrganizationID: x.scope.OrganizationID})
		if err != nil {
			t.Fatal(err)
		}
		return observed.Version
	}
	for _, user := range []string{directoryRoleReader, "directory-local-reader"} {
		f.seedUser(t, x.scope.TenantID, identity.UserID(user))
		f.add(t, directoryTestTenant, user, organization.RoleMember, organizationVersion())
	}
	// The source owner checks its stored identity link, not just mapper output.
	// Establish that existing link as trusted setup; synchronization below must
	// still use the real SCIM edge and native organization command owners.
	linked, err := f.pool.Raw().Exec(f.ctx, `UPDATE scim.users SET user_id=$6
 WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4 AND resource_id=$5`,
		string(x.scope.TenantID), string(x.scope.OrganizationID), x.scope.ProviderID, x.scope.ConnectionID, x.userID, directoryRoleReader)
	if err != nil || linked.RowsAffected() != 1 {
		t.Fatal("establish the exact pre-existing SCIM-to-local identity link", err)
	}
	execute := func(prepared organizationpg.PreparedCommand, err error) {
		t.Helper()
		if err != nil {
			t.Fatal("prepare existing native role setup", err)
		}
		result, err := f.service.Execute(f.ctx, prepared)
		if err != nil || result.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("commit existing native role setup", err)
		}
	}
	execute(f.service.PrepareCreateDynamicRole(f.ctx, organization.DynamicRoleRequest{
		Authentication: f.auth(directoryTestTenant, "owner"), CommandID: commandID(t), OrganizationID: x.scope.OrganizationID,
		OrganizationVersion: organizationVersion(), RoleID: "directory-reader", Name: "Directory reader", CorrelationID: "directory-role-setup",
		Statements: []organization.RoleStatement{{PermissionID: "read", ResourceID: "one", Effect: authorization.Allow}},
	}, "127.0.0.1"))
	read := organization.DynamicRoleReadRequest{Authentication: f.auth(directoryTestTenant, "owner"), OrganizationID: x.scope.OrganizationID,
		RoleID: "directory-reader", TargetTeamID: directoryTestTeam, CorrelationID: "directory-role-setup"}
	view, err := f.service.GetDynamicRole(f.ctx, read)
	if err != nil {
		t.Fatal("discover native role and team binding versions", err)
	}
	execute(f.service.PrepareAssignTeamDynamicRole(f.ctx, organization.TeamRoleBindingRequest{
		Authentication: read.Authentication, CommandID: commandID(t), OrganizationID: read.OrganizationID, RoleID: read.RoleID, TeamID: read.TargetTeamID,
		OrganizationVersion: view.Organization.Version, RoleVersion: view.DynamicRole.Version, TeamVersion: view.Team.Version,
		BindingVersion: view.TeamRoleBinding.Version, CorrelationID: "directory-role-setup",
	}, "127.0.0.1"))
	view, err = f.service.GetDynamicRole(f.ctx, read)
	if err != nil {
		t.Fatal(err)
	}
	execute(f.service.PrepareAddTeamMember(f.ctx, organization.TeamMemberRequest{
		Authentication: read.Authentication, CommandID: commandID(t), OrganizationID: read.OrganizationID, OrganizationVersion: view.Organization.Version,
		TeamID: directoryTestTeam, TeamVersion: view.Team.Version, UserID: "directory-local-reader", OrganizationMemberVersion: 1, CorrelationID: "directory-role-setup",
	}, "127.0.0.1"))
	directory := scimorganization.DirectoryMappingConfig{TenantID: x.scope.TenantID, OrganizationID: x.scope.OrganizationID,
		ProviderID: sso.ProviderID(x.scope.ProviderID), ConnectionID: x.scope.ConnectionID, MappingVersion: 1,
		Groups:  []scimorganization.DirectoryGroupTeamMapping{{GroupID: x.groupID, TeamID: directoryTestTeam}},
		Members: []scimorganization.DirectoryMemberUserMapping{{MemberID: x.userID, UserID: directoryRoleReader}}}
	roleMapper, err := scimorganization.NewDirectoryRoleMapper(scimorganization.DirectoryRoleMappingConfig{
		Directory: directory, Roles: []scimorganization.DirectoryGroupRoleMapping{{GroupID: x.groupID, TeamID: directoryTestTeam, RoleID: "directory-reader"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := directoryServicePolicy(func(d authorization.DecisionContext) bool {
		return d.Request.Tenant == authorization.TenantID(x.scope.TenantID) && d.Request.Subject.Kind == authorization.SubjectServiceAccount &&
			d.Request.Subject.ID == directoryTestActor && (d.Request.Action == "identity.sso.directory-sync-apply-role" ||
			d.Request.Action == "identity.sso.directory-sync-apply" || d.Request.Action == authorization.Action(sso.DirectoryTeamMembershipOperation().OperationID))
	})
	roleConfig := ssopg.DirectorySyncGroupRolesConfig{Source: x.groups, Mapping: roleMapper, Authorization: policy, AuthorityNamespace: directoryTestAuthority,
		ApplyAuthorization: directoryRolePolicy(func(ctx context.Context, d authorization.DecisionContext, version uint64) (ssopg.ProviderUpdateAuthorizationEvidence, error) {
			decision, err := policy.Decide(ctx, d)
			return ssopg.ProviderUpdateAuthorizationEvidence{Context: d, Decision: decision, ActorAuthorizationVersion: version,
				ValidUntil: d.Request.Environment.Time.Add(5 * time.Second)}, err
		})}
	ordinary := x.workerConfig(t)
	ordinary.Mapping, err = scimorganization.NewDirectoryMapper(directory)
	if err != nil {
		t.Fatal(err)
	}
	return x, roleConfig, ordinary
}
