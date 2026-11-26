//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	scim "github.com/faustbrian/go-scim"
	scimorganization "github.com/faustbrian/go-scim/organization"
	scimpostgres "github.com/faustbrian/go-scim/postgres"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestNativeDirectoryMixedDriftPreservesTypedOrderWithoutPredictingApply(t *testing.T) {
	journey := newDirectoryMixedJourney(t)
	f := journey.fixture.provider.f
	worker := journey.worker(t, f.pool)
	inspector := directoryMixedDriftInspector(t, journey)
	request, source := directoryMixedDriftCurrentRequest(t, journey, journey.generation.Checkpoint)
	journey.request, journey.batch.Deltas = request, request.Deltas
	before := captureDirectoryMixedDriftState(t, journey)
	assertDirectoryMixedDriftAccess(t, journey, authorization.Deny)
	want := []ssopg.DirectoryMixedDrift{
		{Kind: ssopg.DirectoryMixedDriftUser, User: ssopg.DirectoryUserDrift{Kind: scimorganization.DirectoryMembershipDriftMissingSourceGrant, Source: source[0]}},
		{Kind: ssopg.DirectoryMixedDriftUser, User: ssopg.DirectoryUserDrift{Kind: scimorganization.DirectoryMembershipDriftMissingSourceGrant, Source: source[1]}},
		{Kind: ssopg.DirectoryMixedDriftGroup, Group: scimorganization.DirectoryMembershipDrift{Kind: scimorganization.DirectoryMembershipDriftConflict}},
		{Kind: ssopg.DirectoryMixedDriftRole, Role: ssopg.DirectoryGroupRoleDrift{Kind: ssopg.DirectoryGroupRoleDriftConflict, Source: scimpostgres.DirectoryGroupEdgePresent}},
	}
	for _, order := range [][]int{{0, 1, 2, 3}, {3, 1, 2, 0}, {0}, {2}, {3}} {
		ordered := request
		ordered.Deltas = make([]sso.DirectoryDelta, len(order))
		orderedWant := make([]ssopg.DirectoryMixedDrift, len(order))
		for i, index := range order {
			ordered.Deltas[i], orderedWant[i] = request.Deltas[index], want[index]
		}
		got, err := inspector.ObserveBatchDrift(f.ctx, ordered)
		if err != nil || !slices.Equal(got, orderedWant) {
			t.Fatal("mixed inspection regrouped candidates or predicted future admission for a Group or role", err)
		}
		assertDirectoryMixedDriftAccess(t, journey, authorization.Deny)
		assertDirectoryMixedDriftUnchanged(t, journey, before)
	}

	applied, err := worker.ApplyGeneration(f.ctx, request)
	if err != nil {
		t.Fatal("ordinary mixed Apply did not settle the inspected candidates", err)
	}
	journey.assertSettled(t, applied)
	assertDirectoryMixedDriftAccess(t, journey, authorization.Allow)
	before = captureDirectoryMixedDriftState(t, journey)
	if result, err := inspector.ObserveBatchDrift(f.ctx, request); !errors.Is(err, sso.ErrDirectoryReconciliation) || result != nil {
		t.Fatal("superseded mixed checkpoint disclosed a complete or partial report", err)
	}
	assertDirectoryMixedDriftUnchanged(t, journey, before)
	request, source = directoryMixedDriftCurrentRequest(t, journey, applied.Checkpoint)
	want = []ssopg.DirectoryMixedDrift{
		{Kind: ssopg.DirectoryMixedDriftUser, User: ssopg.DirectoryUserDrift{Kind: scimorganization.DirectoryMembershipDriftInSync, Source: source[0]}},
		{Kind: ssopg.DirectoryMixedDriftUser, User: ssopg.DirectoryUserDrift{Kind: scimorganization.DirectoryMembershipDriftInSync, Source: source[1]}},
		{Kind: ssopg.DirectoryMixedDriftGroup, Group: scimorganization.DirectoryMembershipDrift{Kind: scimorganization.DirectoryMembershipDriftInSync}},
		{Kind: ssopg.DirectoryMixedDriftRole, Role: ssopg.DirectoryGroupRoleDrift{Kind: ssopg.DirectoryGroupRoleDriftInSync, Source: scimpostgres.DirectoryGroupEdgePresent}},
	}
	got, err := inspector.ObserveBatchDrift(f.ctx, request)
	if err != nil || !slices.Equal(got, want) {
		t.Fatal("ordinary Apply did not converge all exact typed children at the fresh checkpoint and User revisions", err)
	}
	assertDirectoryMixedDriftAccess(t, journey, authorization.Allow)
	assertDirectoryMixedDriftUnchanged(t, journey, before)
}

func TestNativeDirectoryMixedDriftDeniesApplyOnlyAndLateInvalidWithoutPartialReport(t *testing.T) {
	journey := newDirectoryMixedJourney(t)
	f := journey.fixture.provider.f
	worker := journey.worker(t, f.pool)
	inspector := directoryMixedDriftInspector(t, journey)
	request, _ := directoryMixedDriftCurrentRequest(t, journey, journey.generation.Checkpoint)
	before := captureDirectoryMixedDriftState(t, journey)
	if result, err := worker.ObserveBatchDrift(f.ctx, request); !errors.Is(err, sso.ErrForbidden) || result != nil {
		t.Fatal("ordinary mixed Apply authority authorized inspection or disclosed a partial report", err)
	}
	assertDirectoryMixedDriftUnchanged(t, journey, before)
	if result, err := inspector.ApplyGeneration(f.ctx, request); !errors.Is(err, sso.ErrForbidden) || result.Checkpoint != ([32]byte{}) || len(result.ChildOutcomes) != 0 {
		t.Fatal("mixed inspection authority authorized Apply or disclosed protected outcomes", err)
	}
	assertDirectoryMixedDriftUnchanged(t, journey, before)

	invalid := request
	invalid.Deltas = slices.Clone(request.Deltas)
	invalid.Deltas[len(invalid.Deltas)-1] = sso.DirectoryDelta{}
	unmapped := request
	unmapped.Deltas = slices.Clone(request.Deltas)
	var err error
	unmapped.Deltas[len(unmapped.Deltas)-1], err = sso.NewDirectoryGroupMembershipDelta(commandID(t), journey.fixture.groupID, journey.users[0], sso.DirectoryMembershipAdd)
	if err != nil {
		t.Fatal(err)
	}
	stale := request
	staleUser, err := sso.NewDirectoryUserAdmissionDelta(commandID(t), journey.users[1], "stale-source-revision")
	if err != nil {
		t.Fatal(err)
	}
	stale.Deltas = []sso.DirectoryDelta{request.Deltas[0], request.Deltas[2], request.Deltas[3], staleUser}
	for _, test := range []struct {
		name    string
		request ssopg.DirectoryMixedApplyRequest
		wantErr error
	}{
		{name: "invalid late child", request: invalid, wantErr: sso.ErrInvalidInput},
		{name: "unmapped late Group", request: unmapped, wantErr: sso.ErrForbidden},
		{name: "mismatched late User revision", request: stale, wantErr: sso.ErrDirectoryReconciliation},
	} {
		t.Run(test.name, func(t *testing.T) {
			if result, err := inspector.ObserveBatchDrift(f.ctx, test.request); !errors.Is(err, test.wantErr) || result != nil {
				t.Fatal("invalid mixed suffix disclosed classifications for its valid typed prefix", err)
			}
			assertDirectoryMixedDriftAccess(t, journey, authorization.Deny)
			assertDirectoryMixedDriftUnchanged(t, journey, before)
		})
	}
}

func TestNativeDirectoryMixedDriftBoundsTheEntireRequest(t *testing.T) {
	journey := newDirectoryMixedJourney(t)
	f := journey.fixture.provider.f
	inspector := directoryMixedDriftInspector(t, journey)
	request, source := directoryMixedDriftCurrentRequest(t, journey, journey.generation.Checkpoint)
	before := captureDirectoryMixedDriftState(t, journey)
	deltas := make([]sso.DirectoryDelta, 129)
	for i := range deltas {
		var err error
		deltas[i], err = sso.NewDirectoryUserAdmissionDelta(commandID(t), journey.users[0], string(source[0].Revision))
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, size := range []int{0, 129} {
		request.Deltas = deltas[:size]
		if report, err := inspector.ObserveBatchDrift(f.ctx, request); !errors.Is(err, sso.ErrInvalidInput) || report != nil {
			t.Fatalf("size %d was not rejected without a report: %v", size, err)
		}
	}
	request.Deltas = deltas[:128]
	report, err := inspector.ObserveBatchDrift(f.ctx, request)
	if err != nil || len(report) != len(request.Deltas) {
		t.Fatalf("maximum supported preview returned %d reports: %v", len(report), err)
	}
	want := ssopg.DirectoryMixedDrift{Kind: ssopg.DirectoryMixedDriftUser, User: ssopg.DirectoryUserDrift{
		Kind: scimorganization.DirectoryMembershipDriftMissingSourceGrant, Source: source[0],
	}}
	for i, got := range report {
		if got != want {
			t.Fatalf("candidate %d did not independently observe the current source", i)
		}
	}
	assertDirectoryMixedDriftUnchanged(t, journey, before)
}

func directoryMixedDriftInspector(t *testing.T, journey directoryMixedJourney) *ssopg.DirectoryMixedSyncService {
	t.Helper()
	x := journey.fixture
	inspection := directoryServicePolicy(func(d authorization.DecisionContext) bool {
		return d.Request.Tenant == authorization.TenantID(x.scope.TenantID) &&
			d.Request.Subject.Kind == authorization.SubjectServiceAccount && d.Request.Subject.ID == directoryTestActor &&
			d.Request.Action == "identity.sso.directory-sync-inspect-mixed-drift"
	})
	config := journey.config
	config.ApplyAuthorization = directoryGroupPolicy(func(ctx context.Context, d authorization.DecisionContext, epoch uint64) (ssopg.ProviderUpdateAuthorizationEvidence, error) {
		decision, err := inspection.Decide(ctx, d)
		return ssopg.ProviderUpdateAuthorizationEvidence{Context: d, Decision: decision, ActorAuthorizationVersion: epoch,
			ValidUntil: d.Request.Environment.Time.Add(5 * time.Second)}, err
	})
	inspector, err := ssopg.NewDirectoryMixedSyncService(x.provider.f.pool, journey.scope, config)
	if err != nil {
		t.Fatal("compose separately authorized mixed drift inspection", err)
	}
	return inspector
}

func directoryMixedDriftCurrentRequest(t *testing.T, journey directoryMixedJourney, checkpoint [32]byte) (ssopg.DirectoryMixedApplyRequest, [2]scimpostgres.DirectoryUserObservation) {
	t.Helper()
	x := journey.fixture
	request := journey.request
	request.PredecessorCheckpoint, request.Deltas = checkpoint, slices.Clone(request.Deltas)
	var observations [2]scimpostgres.DirectoryUserObservation
	for i, user := range journey.users {
		current, err := x.native.Execute(x.provider.f.ctx, scim.Request{Operation: scim.UserGet, Credential: x.bearer, ResourceID: user})
		if err != nil || current.Status != 200 || current.ETag == "" {
			t.Fatal("read the exact current source User revision", i, err)
		}
		request.Deltas[i], err = sso.NewDirectoryUserAdmissionDelta(journey.childIDs[i], user, string(current.ETag))
		if err != nil {
			t.Fatal(err)
		}
		observations[i] = scimpostgres.DirectoryUserObservation{State: scimpostgres.DirectoryMembershipUserActive, Revision: current.ETag}
	}
	return request, observations
}

func assertDirectoryMixedDriftAccess(t *testing.T, journey directoryMixedJourney, want authorization.Outcome) {
	t.Helper()
	x, f := journey.fixture, journey.fixture.provider.f
	repository, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	roleSource, err := ssopg.NewDirectoryGroupRoleSyncService(f.pool, ssopg.DirectoryGroupRoleSyncConfig(journey.scope), ssopg.DirectorySyncGroupRolesConfig{
		Source: x.groups, Mapping: journey.roleMapping, Authorization: journey.config.Authorization, AuthorityNamespace: journey.config.AuthorityNamespace,
		ApplyAuthorization: directoryRoleReadPolicy{journey.config.ApplyAuthorization.(directoryGroupPolicy)},
	})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := repository.WithDirectoryTeamRoles(roleSource.CurrentRoleSources)
	if err != nil {
		t.Fatal(err)
	}
	for i, user := range journey.users {
		member, err := repository.ObserveCredentialAuthority(f.ctx, organization.CredentialAuthorityQuery{
			TenantID: x.scope.TenantID, OrganizationID: x.scope.OrganizationID, ActorID: identity.UserID(user),
		})
		if want == authorization.Deny {
			if err == nil {
				t.Fatal("inspection admitted a directory-only User to effective organization access", i)
			}
			continue
		}
		if err != nil || !member.Actor.Active || member.Actor.Role != organization.RoleMember {
			t.Fatal("ordinary Apply did not establish effective organization membership", i, err)
		}
		permissions, err := reader.Read(f.ctx, organization.Query{
			Operation: organization.CheckPermission, TenantID: x.scope.TenantID, OrganizationID: x.scope.OrganizationID,
			ActorID: identity.UserID(user), IncludeTeamRoles: true, Limit: 10,
		})
		if err != nil {
			t.Fatal("observe the effective native team roles", i, err)
		}
		if i == 0 {
			if len(permissions.DynamicRoles) != 1 || permissions.DynamicRoles[0].ID != "directory-reader" {
				t.Fatal("the explicitly role-mapped User lost its effective directory role")
			}
		} else if len(permissions.DynamicRoles) != 0 {
			t.Fatal("the membership-only User gained an effective directory role")
		}
	}
}

func captureDirectoryMixedDriftState(t *testing.T, journey directoryMixedJourney) string {
	t.Helper()
	x, f := journey.fixture, journey.fixture.provider.f
	var state string
	err := f.pool.Raw().QueryRow(f.ctx, `SELECT jsonb_build_object(
 'generation',(SELECT to_jsonb(g) FROM sso_providers.directory_sync_generations g
 WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4 AND generation_id=$5),
 'organizations',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM organization.organizations r),
 'memberships',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM organization.memberships r),
 'user_grants',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM organization.directory_membership_grants r),
 'teams',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM organization.teams r),
 'team_memberships',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM organization.team_memberships r),
 'group_grants',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM organization.directory_team_grants r),
 'roles',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM organization.custom_roles r),
 'bindings',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM organization.team_role_bindings r),
 'role_grants',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM organization.directory_team_role_grants r),
 'audits',(SELECT count(*) FROM audit.records),
 'events',(SELECT count(*) FROM outbox_messages),
 'commands',(SELECT count(*) FROM identity.commands),
 'claims',(SELECT count(*) FROM identity.identity_command_id_claims)
 )::text`, string(x.scope.TenantID), string(x.scope.OrganizationID), x.scope.ProviderID, x.scope.ConnectionID, string(journey.generation.ID)).Scan(&state)
	if err != nil {
		t.Fatal("observe the exact mixed generation, owner rows, and protected effect counts", err)
	}
	return state
}

func assertDirectoryMixedDriftUnchanged(t *testing.T, journey directoryMixedJourney, before string) {
	t.Helper()
	if after := captureDirectoryMixedDriftState(t, journey); after != before {
		t.Fatal("mixed inspection changed the generation, owner state, source attribution, or protected effects")
	}
}
