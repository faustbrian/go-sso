//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	scimpostgres "github.com/faustbrian/go-scim/postgres"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestNativeDirectoryRoleDriftInspectionAndOrdinaryApplyConverge(t *testing.T) {
	x, config, _ := newDirectoryRoleJourney(t)
	ctx := x.provider.f.ctx
	worker, inspector := directoryRoleDriftWorkers(t, x, config)
	generation := x.start(t)
	request := directoryRoleDriftRequest(generation, x.batch(t, generation, sso.DirectoryMembershipAdd))
	before := captureDirectoryRoleDriftState(t, x, generation.ID)
	if before.attribution.Membership.Source || before.attribution.Membership.Local || before.attribution.RetainedGrantVersion != 0 {
		t.Fatal("fixture must have a live source without a retained role or local team membership")
	}
	missing, err := inspector.ObserveDrift(ctx, request)
	if err != nil || missing != (ssopg.DirectoryGroupRoleDrift{
		Kind: ssopg.DirectoryGroupRoleDriftMissing, Source: scimpostgres.DirectoryGroupEdgePresent,
	}) {
		t.Fatal("live source without a retained role did not report missing drift", err)
	}
	assertDirectoryRoleDriftUnchanged(t, x, generation.ID, before)

	applied, err := worker.ApplyGeneration(ctx, request)
	if err != nil || len(applied.ChildOutcomes) != 1 || applied.ChildOutcomes[0].Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("ordinary role Apply did not settle the inspected missing role", err)
	}
	current, err := x.sync.Status(ctx, generation.ID)
	if err != nil || current.Checkpoint != applied.Checkpoint || current.Checkpoint == generation.Checkpoint || current.AppliedCount != 1 || current.ReadCount != 1 {
		t.Fatal("ordinary role Apply did not advance the real generation exactly once", err)
	}
	before = captureDirectoryRoleDriftState(t, x, generation.ID)
	if result, err := inspector.ObserveDrift(ctx, request); !errors.Is(err, sso.ErrDirectoryReconciliation) || result != (ssopg.DirectoryGroupRoleDrift{}) {
		t.Fatal("superseded checkpoint disclosed a role drift report", err)
	}
	assertDirectoryRoleDriftUnchanged(t, x, generation.ID, before)
	request.PredecessorCheckpoint = current.Checkpoint
	converged, err := inspector.ObserveDrift(ctx, request)
	if err != nil || converged != (ssopg.DirectoryGroupRoleDrift{
		Kind: ssopg.DirectoryGroupRoleDriftInSync, Source: scimpostgres.DirectoryGroupEdgePresent,
	}) || !before.attribution.Membership.Source || before.attribution.RetainedGrantVersion == 0 {
		t.Fatal("ordinary role Apply did not converge at the exact current checkpoint", err)
	}
	assertDirectoryRoleDriftUnchanged(t, x, generation.ID, before)

	x.withdrawSourceMember(t)
	request = directoryRoleDriftRequest(current, x.batch(t, current, sso.DirectoryMembershipRemove))
	before = captureDirectoryRoleDriftState(t, x, generation.ID)
	unexpected, err := inspector.ObserveDrift(ctx, request)
	if err != nil || unexpected != (ssopg.DirectoryGroupRoleDrift{
		Kind: ssopg.DirectoryGroupRoleDriftUnexpected, Source: scimpostgres.DirectoryGroupEdgeAbsent,
	}) || before.attribution.RetainedGrantVersion == 0 {
		t.Fatal("known absent source did not expose the independently retained role", err)
	}
	assertDirectoryRoleDriftUnchanged(t, x, generation.ID, before)
}

func TestNativeDirectoryRoleDriftRequiresIndependentInspectionAuthority(t *testing.T) {
	x, config, _ := newDirectoryRoleJourney(t)
	ctx := x.provider.f.ctx
	worker, inspector := directoryRoleDriftWorkers(t, x, config)
	generation := x.start(t)
	request := directoryRoleDriftRequest(generation, x.batch(t, generation, sso.DirectoryMembershipAdd))
	before := captureDirectoryRoleDriftState(t, x, generation.ID)
	if result, err := worker.ObserveDrift(ctx, request); !errors.Is(err, sso.ErrForbidden) || result != (ssopg.DirectoryGroupRoleDrift{}) {
		t.Fatal("ordinary role Apply authority authorized inspection or disclosed a report", err)
	}
	assertDirectoryRoleDriftUnchanged(t, x, generation.ID, before)
	if result, err := inspector.ApplyGeneration(ctx, request); !errors.Is(err, sso.ErrForbidden) || result.Checkpoint != ([32]byte{}) || len(result.ChildOutcomes) != 0 {
		t.Fatal("role inspection authority authorized Apply or disclosed protected outcomes", err)
	}
	assertDirectoryRoleDriftUnchanged(t, x, generation.ID, before)

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if result, err := inspector.ObserveDrift(canceled, request); err == nil || result != (ssopg.DirectoryGroupRoleDrift{}) {
		t.Fatal("canceled inspection disclosed a partial role drift report", err)
	}
	assertDirectoryRoleDriftUnchanged(t, x, generation.ID, before)
}

func TestNativeDirectoryRoleDriftReportsStaleRetainedEvidence(t *testing.T) {
	x, config, _ := newDirectoryRoleJourney(t)
	f, ctx := x.provider.f, x.provider.f.ctx
	worker, inspector := directoryRoleDriftWorkers(t, x, config)
	generation := x.start(t)
	request := directoryRoleDriftRequest(generation, x.batch(t, generation, sso.DirectoryMembershipAdd))
	if applied, err := worker.ApplyGeneration(ctx, request); err != nil || len(applied.ChildOutcomes) != 1 || applied.ChildOutcomes[0].Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("establish the exact retained role through ordinary Apply", err)
	}
	current, err := x.sync.Status(ctx, generation.ID)
	if err != nil {
		t.Fatal(err)
	}
	request.PredecessorCheckpoint = current.Checkpoint
	for _, column := range []string{"grant_version", "binding_version", "provider_version", "mapping_version", "connection_version"} {
		t.Run(column, func(t *testing.T) {
			changed, err := f.pool.Raw().Exec(ctx, `UPDATE organization.directory_team_role_grants SET `+column+`=`+column+`+1
 WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$3 AND provider_id=$4 AND connection_id=$5 AND group_id=$6 AND team_id=$7`,
				string(x.scope.TenantID), string(x.scope.OrganizationID), directoryRoleReader, x.scope.ProviderID, x.scope.ConnectionID, x.groupID, directoryTestTeam)
			if err != nil || changed.RowsAffected() != 1 {
				t.Fatal("change one isolated retained role evidence field", err)
			}
			t.Cleanup(func() {
				if restored, err := f.pool.Raw().Exec(ctx, `UPDATE organization.directory_team_role_grants SET `+column+`=`+column+`-1
 WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$3 AND provider_id=$4 AND connection_id=$5 AND group_id=$6 AND team_id=$7`,
					string(x.scope.TenantID), string(x.scope.OrganizationID), directoryRoleReader, x.scope.ProviderID, x.scope.ConnectionID, x.groupID, directoryTestTeam); err != nil || restored.RowsAffected() != 1 {
					t.Fatal("restore the isolated retained role evidence field", err)
				}
			})
			before := captureDirectoryRoleDriftState(t, x, generation.ID)
			result, err := inspector.ObserveDrift(ctx, request)
			if err != nil || result != (ssopg.DirectoryGroupRoleDrift{
				Kind: ssopg.DirectoryGroupRoleDriftStale, Source: scimpostgres.DirectoryGroupEdgePresent,
			}) {
				t.Fatal("present source concealed mismatched retained role evidence", err)
			}
			assertDirectoryRoleDriftUnchanged(t, x, generation.ID, before)
		})
	}
}

func TestNativeDirectoryRoleDriftLocalMembershipCannotSubstituteForRole(t *testing.T) {
	x, config, _ := newDirectoryRoleJourney(t)
	f, ctx := x.provider.f, x.provider.f.ctx
	_, inspector := directoryRoleDriftWorkers(t, x, config)
	generation := x.start(t)
	before := captureDirectoryRoleDriftState(t, x, generation.ID)
	prepared, err := f.service.PrepareAddTeamMember(ctx, organization.TeamMemberRequest{
		Authentication: f.auth(directoryTestTenant, "owner"), CommandID: commandID(t), OrganizationID: x.scope.OrganizationID,
		OrganizationVersion: before.attribution.Membership.OrganizationVersion, TeamID: directoryTestTeam,
		TeamVersion: before.attribution.Membership.TeamVersion, UserID: directoryRoleReader,
		OrganizationMemberVersion: before.attribution.Membership.MemberVersion, CorrelationID: "directory-role-drift-local",
	}, "127.0.0.1")
	if err != nil {
		t.Fatal("prepare independent local team membership", err)
	}
	if added, err := f.service.Execute(ctx, prepared); err != nil || added.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("establish independent local team membership", err)
	}
	before = captureDirectoryRoleDriftState(t, x, generation.ID)
	if !before.attribution.Membership.Local || before.attribution.RetainedGrantVersion != 0 {
		t.Fatal("fixture must have independent local membership without a retained role")
	}
	result, err := inspector.ObserveDrift(ctx, directoryRoleDriftRequest(generation, x.batch(t, generation, sso.DirectoryMembershipAdd)))
	if err != nil || result != (ssopg.DirectoryGroupRoleDrift{
		Kind: ssopg.DirectoryGroupRoleDriftMissing, Source: scimpostgres.DirectoryGroupEdgePresent, LocalMembership: true,
	}) {
		t.Fatal("independent local membership substituted for the missing exact source role", err)
	}
	assertDirectoryRoleDriftUnchanged(t, x, generation.ID, before)

	linked, err := f.pool.Raw().Exec(ctx, `UPDATE scim.users SET user_id=$6
 WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4 AND resource_id=$5`,
		string(x.scope.TenantID), string(x.scope.OrganizationID), x.scope.ProviderID, x.scope.ConnectionID, x.userID, "directory-local-reader")
	if err != nil || linked.RowsAffected() != 1 {
		t.Fatal("change the isolated SCIM-to-local identity link", err)
	}
	before = captureDirectoryRoleDriftState(t, x, generation.ID)
	result, err = inspector.ObserveDrift(ctx, directoryRoleDriftRequest(generation, x.batch(t, generation, sso.DirectoryMembershipAdd)))
	if err != nil || result != (ssopg.DirectoryGroupRoleDrift{
		Kind: ssopg.DirectoryGroupRoleDriftConflict, Source: scimpostgres.DirectoryGroupEdgeUnproven,
	}) || !before.attribution.Membership.Local {
		t.Fatal("unproven source link disclosed independent local membership", result, err)
	}
	assertDirectoryRoleDriftUnchanged(t, x, generation.ID, before)
}

func directoryRoleDriftWorkers(t *testing.T, x directoryGroupApplyFixture, config ssopg.DirectorySyncGroupRolesConfig) (*ssopg.DirectoryGroupRoleSyncService, *ssopg.DirectoryGroupRoleSyncService) {
	t.Helper()
	worker, err := x.sync.WithGroupRoles(config)
	if err != nil {
		t.Fatal("select ordinary native role Apply", err)
	}
	inspection := directoryServicePolicy(func(d authorization.DecisionContext) bool {
		return d.Request.Tenant == authorization.TenantID(x.scope.TenantID) &&
			d.Request.Subject.Kind == authorization.SubjectServiceAccount && d.Request.Subject.ID == directoryTestActor &&
			d.Request.Action == "identity.sso.directory-sync-inspect-role-drift"
	})
	config.ApplyAuthorization = directoryRolePolicy(func(ctx context.Context, d authorization.DecisionContext, epoch uint64) (ssopg.ProviderUpdateAuthorizationEvidence, error) {
		decision, err := inspection.Decide(ctx, d)
		return ssopg.ProviderUpdateAuthorizationEvidence{Context: d, Decision: decision, ActorAuthorizationVersion: epoch,
			ValidUntil: d.Request.Environment.Time.Add(5 * time.Second)}, err
	})
	inspector, err := x.sync.WithGroupRoles(config)
	if err != nil {
		t.Fatal("select separately authorized native role inspection", err)
	}
	return worker, inspector
}

func directoryRoleDriftRequest(generation ssopg.DirectorySyncGeneration, batch sso.DirectoryDeltaBatch) ssopg.DirectoryGroupRoleApplyRequest {
	return ssopg.DirectoryGroupRoleApplyRequest{GenerationID: generation.ID, ProviderID: generation.Provider,
		MappingVersion: generation.MappingVersion, PredecessorCheckpoint: generation.Checkpoint, Delta: batch.Deltas[0]}
}

type directoryRoleDriftState struct {
	generation                       ssopg.DirectorySyncGeneration
	attribution                      organizationpg.DirectoryTeamRoleAttribution
	organization                     string
	audits, events, commands, claims int
}

func captureDirectoryRoleDriftState(t *testing.T, x directoryGroupApplyFixture, generation identity.CommandID) directoryRoleDriftState {
	t.Helper()
	f := x.provider.f
	state := directoryRoleDriftState{}
	var err error
	state.generation, err = x.sync.Status(f.ctx, generation)
	if err != nil {
		t.Fatal("observe the exact role generation", err)
	}
	repository, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	state.attribution, err = repository.ObserveDirectoryTeamRoleAttribution(f.ctx, organizationpg.DirectoryTeamGrantScope{
		TenantID: x.scope.TenantID, OrganizationID: x.scope.OrganizationID,
		ProviderID: organization.ID(x.scope.ProviderID), ConnectionID: organization.ID(x.scope.ConnectionID),
		GroupID: organization.ID(x.groupID), TeamID: directoryTestTeam, UserID: directoryRoleReader,
	}, "directory-reader")
	if err != nil {
		t.Fatal("observe retained exact role and independent local membership", err)
	}
	err = f.pool.Raw().QueryRow(f.ctx, `SELECT jsonb_build_object(
 'organizations',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM organization.organizations r),
 'memberships',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM organization.memberships r),
 'teams',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM organization.teams r),
 'team_memberships',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM organization.team_memberships r),
 'grants',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM organization.directory_team_grants r),
 'roles',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM organization.custom_roles r),
 'bindings',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM organization.team_role_bindings r),
 'role_grants',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM organization.directory_team_role_grants r)
 )::text,
 (SELECT count(*) FROM audit.records),
 (SELECT count(*) FROM outbox_messages),
 (SELECT count(*) FROM identity.commands),
 (SELECT count(*) FROM identity.identity_command_id_claims)`).Scan(&state.organization, &state.audits, &state.events, &state.commands, &state.claims)
	if err != nil {
		t.Fatal("observe organization state and protected effect counts", err)
	}
	return state
}

func assertDirectoryRoleDriftUnchanged(t *testing.T, x directoryGroupApplyFixture, generation identity.CommandID, before directoryRoleDriftState) {
	t.Helper()
	if after := captureDirectoryRoleDriftState(t, x, generation); after != before {
		t.Fatal("role inspection changed the exact generation, organization state, attribution, or protected effects")
	}
}
