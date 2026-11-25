//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	database "github.com/faustbrian/go-postgres"
	scim "github.com/faustbrian/go-scim"
	scimorganization "github.com/faustbrian/go-scim/organization"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestNativeDirectorySyncMixedOrderedUsersMembershipAndRole(t *testing.T) {
	journey := newDirectoryMixedJourney(t)
	x, f := journey.fixture, journey.fixture.provider.f
	worker := journey.worker(t, f.pool)
	result, err := worker.ApplyGeneration(f.ctx, journey.request)
	if err != nil {
		t.Fatal("apply the real ordered User/User/Group/role batch", err)
	}
	journey.assertSettled(t, result)
	if replay, err := worker.ApplyGeneration(f.ctx, journey.request); err != nil || !reflect.DeepEqual(result, replay) {
		t.Fatal("mixed exact repeat replaced original ordered receipts or successor", err)
	}
	journey.assertSettled(t, result)
	if status, err := x.sync.Status(f.ctx, journey.generation.ID); err != nil || status.Version != journey.generation.Version+2 {
		t.Fatal("one mixed batch did not attach and settle exactly once", err)
	}
}

func TestNativeDirectorySyncMixedAdvancesAfterRoleBeforeUser(t *testing.T) {
	journey := newDirectoryMixedJourney(t, organizationpg.DirectoryTeamRoleSuccessorMigrationSource{Version: 692})
	fixture := journey.fixture.provider.f
	request, indices := journey.roleBeforeUserRequest()
	worker := journey.worker(t, fixture.pool)
	result, err := worker.ApplyGeneration(fixture.ctx, request)
	for i, child := range result.ChildOutcomes {
		if i >= len(indices) || child.Outcome != identity.CommitOutcomeCommitted || child.Binding.CommandID != journey.childIDs[indices[i]] {
			t.Fatal("an original child did not commit in order after the role changed owner version", i, child.Outcome, err)
		}
	}
	if err != nil || len(result.ChildOutcomes) != len(indices) || result.Checkpoint == ([32]byte{}) {
		t.Fatal("mixed generation failed to settle a role followed by a mapped User", err, len(result.ChildOutcomes))
	}
	if replay, err := journey.worker(t, fixture.pool).ApplyGeneration(fixture.ctx, request); err != nil || !reflect.DeepEqual(result, replay) {
		t.Fatal("fresh executor did not recover the same interleaved result", err)
	}
}

func TestNativeDirectorySyncMixedRecoversRoleBeforeUser(t *testing.T) {
	for _, drift := range []bool{false, true} {
		name := "original-prefix"
		if drift {
			name = "unrelated-owner-transition"
		}
		t.Run(name, func(t *testing.T) {
			journey := newDirectoryMixedJourney(t, organizationpg.DirectoryTeamRoleSuccessorMigrationSource{Version: 692})
			x, fixture := journey.fixture, journey.fixture.provider.f
			request, indices := journey.roleBeforeUserRequest()
			loss, fault := providerLossPool(t, fixture, "INSERT INTO organization.directory_team_role_grants")
			partial, err := journey.worker(t, loss).ApplyGeneration(fixture.ctx, request)
			if !fault.seen.Load() || !fault.lost.Load() || !errors.Is(err, sso.ErrDirectoryReconciliation) || partial.Checkpoint != ([32]byte{}) {
				t.Fatal("did not interrupt acknowledgment of the original committed role", err)
			}
			pending, err := x.sync.Status(fixture.ctx, journey.generation.ID)
			if err != nil || pending.State != ssopg.DirectorySyncReconciling || pending.AppliedCount != 0 {
				t.Fatal("uncertain role advanced generation before recovery", err)
			}
			if drift {
				fixture.seedUser(t, x.scope.TenantID, "directory-mixed-role-late-member")
				fixture.add(t, directoryTestTenant, "directory-mixed-role-late-member", organization.RoleMember, journey.beforeOwner+2)
			}
			fresh := journey.worker(t, fixture.pool)
			result, err := fresh.ApplyGeneration(fixture.ctx, request)
			if drift {
				if !errors.Is(err, sso.ErrDirectoryReconciliation) || len(result.ChildOutcomes) != 2 || result.Checkpoint != ([32]byte{}) {
					t.Fatal("unrelated owner version was accepted as a role successor", err, len(result.ChildOutcomes))
				}
				if status, err := x.sync.Status(fixture.ctx, pending.ID); err != nil || status != pending {
					t.Fatal("unrelated version changed the held original generation", err)
				}
				return
			}
			if err != nil || len(result.ChildOutcomes) != len(indices) || result.Checkpoint == ([32]byte{}) {
				t.Fatal("fresh worker could not continue after authenticating the original role prefix", err, len(result.ChildOutcomes))
			}
			for i, child := range result.ChildOutcomes {
				if child.Outcome != identity.CommitOutcomeCommitted || child.Binding.CommandID != journey.childIDs[indices[i]] {
					t.Fatal("recovery changed a child receipt or original order", i, child.Outcome)
				}
			}
		})
	}
}

func (j directoryMixedJourney) roleBeforeUserRequest() (ssopg.DirectoryMixedApplyRequest, [4]int) {
	request := j.request
	// The role target is the first newly admitted User. The last Group target
	// is the second User, so neither dependent write can be moved earlier.
	indices := [...]int{0, 3, 1, 2}
	request.Deltas = make([]sso.DirectoryDelta, len(indices))
	for i, index := range indices {
		request.Deltas[i] = j.request.Deltas[index]
	}
	return request, indices
}

func TestNativeDirectorySyncMixedRestartsAfterSecondUserLostAcknowledgment(t *testing.T) {
	journey := newDirectoryMixedJourney(t)
	x, f := journey.fixture, journey.fixture.provider.f
	lossPool, fault, writes := directoryMixedSecondUserLossPool(t, f)
	lost, err := journey.worker(t, lossPool).ApplyGeneration(f.ctx, journey.request)
	if !fault.seen.Load() || !fault.lost.Load() || writes.Load() != 2 || !errors.Is(err, sso.ErrDirectoryReconciliation) || lost.Checkpoint != ([32]byte{}) {
		t.Fatal("second original User COMMIT acknowledgment was not actually lost", writes.Load(), err)
	}
	journey.assertCommittedUsersAndNoSuffix(t)
	pending, err := x.sync.Status(f.ctx, journey.generation.ID)
	if err != nil || pending.State != ssopg.DirectorySyncReconciling || pending.Checkpoint != journey.generation.Checkpoint ||
		pending.ReadCount != 0 || pending.AppliedCount != 0 || pending.RejectedCount != 0 {
		t.Fatal("uncertain mixed prefix advanced or counted an incomplete batch", err)
	}
	competing := journey.request
	competing.Deltas = append([]sso.DirectoryDelta(nil), journey.request.Deltas...)
	competing.Deltas[0], err = sso.NewDirectoryUserAdmissionDelta(commandID(t), journey.users[0], string(journey.revisions[0]))
	if err != nil {
		t.Fatal(err)
	}
	fresh := journey.worker(t, f.pool)
	if out, err := fresh.ApplyGeneration(f.ctx, competing); err == nil || out.Checkpoint != ([32]byte{}) {
		t.Fatal("a competing batch replaced the held exact mixed original", err)
	}
	journey.assertCommittedUsersAndNoSuffix(t)
	if status, err := x.sync.Status(f.ctx, pending.ID); err != nil || status != pending {
		t.Fatal("competing mixed request changed the held generation", err)
	}
	recovered, err := fresh.ApplyGeneration(f.ctx, journey.request)
	if err != nil {
		t.Fatal("fresh authorized executor could not validate both User successors and continue the exact suffix", err)
	}
	for i, original := range lost.ChildOutcomes {
		if original.Outcome == identity.CommitOutcomeCommitted && (i >= len(recovered.ChildOutcomes) || !reflect.DeepEqual(original, recovered.ChildOutcomes[i])) {
			t.Fatal("restart changed a previously returned committed prefix receipt", i)
		}
	}
	journey.assertSettled(t, recovered)
	settled, err := x.sync.Status(f.ctx, pending.ID)
	if err != nil || settled.Version != pending.Version+1 {
		t.Fatal("restart did not perform exactly one mixed settlement", err)
	}
	if replay, err := journey.worker(t, f.pool).ApplyGeneration(f.ctx, journey.request); err != nil || !reflect.DeepEqual(recovered, replay) {
		t.Fatal("second fresh executor did not recover the same original mixed result", err)
	}
	if after, err := x.sync.Status(f.ctx, pending.ID); err != nil || after != settled {
		t.Fatal("settled exact replay advanced or counted the mixed batch twice", err)
	}
	journey.assertSettled(t, recovered)
}

func TestNativeDirectorySyncMixedCancelRecoversOnlyOriginalUserPrefix(t *testing.T) {
	journey := newDirectoryMixedJourney(t)
	x, f := journey.fixture, journey.fixture.provider.f
	pool, fault, writes := directoryMixedSecondUserLossPool(t, f)
	if out, err := journey.worker(t, pool).ApplyGeneration(f.ctx, journey.request); !errors.Is(err, sso.ErrDirectoryReconciliation) ||
		!fault.lost.Load() || writes.Load() != 2 || out.Checkpoint != ([32]byte{}) {
		t.Fatal("cancellation fixture did not lose the real second User acknowledgment", err)
	}
	pending, err := x.sync.Status(f.ctx, journey.generation.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = x.sync.Cancel(f.ctx, ssopg.DirectorySyncCancelRequest{GenerationID: pending.ID, ExpectedVersion: pending.Version,
		Key: directoryGenerationKey(t, "directory-mixed-cancel-user-prefix")})
	if err != nil && !errors.Is(err, sso.ErrDirectoryReconciliation) {
		t.Fatal("cancel the unresolved mixed original", err)
	}
	var original sso.DirectoryApplyResult
	var stopped ssopg.DirectorySyncGeneration
	for attempt := 0; attempt < 2; attempt++ {
		prefix, err := journey.worker(t, f.pool).ApplyGeneration(f.ctx, journey.request)
		if !errors.Is(err, sso.ErrDirectoryReconciliation) || prefix.Checkpoint != ([32]byte{}) || len(prefix.ChildOutcomes) != 2 {
			t.Fatal("canceled mixed retry did not expose only its verified original User prefix", attempt, err)
		}
		for i, receipt := range prefix.ChildOutcomes {
			if receipt.Binding.CommandID != journey.childIDs[i] || receipt.Outcome != identity.CommitOutcomeCommitted || receipt.Validate() != nil {
				t.Fatal("canceled mixed retry replaced or failed to verify an original committed User", i)
			}
		}
		if checkpoint, err := prefix.NextCheckpoint(journey.batch); !errors.Is(err, sso.ErrDirectoryReconciliation) || checkpoint != ([32]byte{}) {
			t.Fatal("canceled incomplete mixed prefix authorized a successor", err)
		}
		status, err := x.sync.Status(f.ctx, pending.ID)
		if err != nil || status.State != ssopg.DirectorySyncCanceled || status.Checkpoint != journey.generation.Checkpoint ||
			status.ReadCount != 0 || status.AppliedCount != 0 || status.RejectedCount != 0 {
			t.Fatal("canceled mixed recovery advanced or counted an incomplete batch", err)
		}
		if attempt == 0 {
			original, stopped = prefix, status
		} else if !reflect.DeepEqual(prefix, original) || status != stopped {
			t.Fatal("repeated cancellation recovery changed original receipts or the stopped generation")
		}
		journey.assertCommittedUsersAndNoSuffix(t)
	}
}

func TestNativeDirectorySyncMixedRejectsLateOwnerChangeBeforeSuffix(t *testing.T) {
	journey := newDirectoryMixedJourney(t)
	x, f := journey.fixture, journey.fixture.provider.f
	pool, fault, writes := directoryMixedSecondUserLossPool(t, f)
	if out, err := journey.worker(t, pool).ApplyGeneration(f.ctx, journey.request); !errors.Is(err, sso.ErrDirectoryReconciliation) ||
		!fault.lost.Load() || writes.Load() != 2 || out.Checkpoint != ([32]byte{}) {
		t.Fatal("owner-change fixture did not lose the real second User acknowledgment", err)
	}
	journey.assertCommittedUsersAndNoSuffix(t)
	pending, err := x.sync.Status(f.ctx, journey.generation.ID)
	if err != nil {
		t.Fatal(err)
	}
	// A separate native membership command advances the organization owner.
	// Recovery must not treat that unrelated successor as either User's effect.
	f.seedUser(t, x.scope.TenantID, "directory-mixed-late-member")
	f.add(t, directoryTestTenant, "directory-mixed-late-member", organization.RoleMember, journey.beforeOwner+2)
	for attempt := 0; attempt < 2; attempt++ {
		if out, err := journey.worker(t, f.pool).ApplyGeneration(f.ctx, journey.request); !errors.Is(err, sso.ErrDirectoryReconciliation) || out.Checkpoint != ([32]byte{}) {
			t.Fatal("an unrelated organization successor authorized the mixed suffix", attempt, err)
		}
		if after, err := x.sync.Status(f.ctx, pending.ID); err != nil || after != pending {
			t.Fatal("late organization-owner drift settled or changed the held original", err)
		}
		journey.assertNoSuffix(t)
	}
}

type directoryMixedJourney struct {
	fixture     directoryGroupApplyFixture
	config      ssopg.DirectorySyncMixedConfig
	scope       ssopg.DirectoryGroupSyncConfig
	generation  ssopg.DirectorySyncGeneration
	request     ssopg.DirectoryMixedApplyRequest
	batch       sso.DirectoryDeltaBatch
	childIDs    []identity.CommandID
	roleMapping scimorganization.DirectoryRoleMapper
	users       [2]string
	groups      [2]string
	revisions   [2]scim.Version
	beforeOwner uint64
}

func newDirectoryMixedJourney(t *testing.T, additional ...migrations.Source) directoryMixedJourney {
	t.Helper()
	base := []migrations.Source{
		organizationpg.DirectoryMembershipMigrationSource{Version: 687},
		organizationpg.DirectoryMembershipSuccessorMigrationSource{Version: 688},
		organizationpg.DynamicRoleMigrationSource{Version: 689},
		organizationpg.TeamRoleBindingMigrationSource{Version: 690},
		organizationpg.DirectoryTeamRoleMigrationSource{Version: 691},
	}
	x := newDirectoryGroupApplyFixture(t, append(base, additional...)...)
	f := x.provider.f
	f.teams = organization.TeamConfig{Version: 1, MaximumTeams: 10, MaximumMembers: 10, LifecycleVersion: 1}
	f.dynamicRoles = organization.DynamicRoleConfig{Version: 1, MaximumRoles: 10, TeamBindingsVersion: 1,
		Catalog: []organization.Permission{{ID: "read", Action: "document.read", ResourceType: "document"}}}
	f.compose(t)
	reader, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	owner := func() organization.CredentialAuthorityObservation {
		t.Helper()
		current, err := reader.ObserveCredentialAuthority(f.ctx, organization.CredentialAuthorityQuery{TenantID: x.scope.TenantID, OrganizationID: x.scope.OrganizationID})
		if err != nil {
			t.Fatal("read native organization owner", err)
		}
		return current
	}
	execute := func(prepared organizationpg.PreparedCommand, err error) {
		t.Helper()
		if err != nil {
			t.Fatal("prepare native role fixture", err)
		}
		result, err := f.service.Execute(f.ctx, prepared)
		if err != nil || result.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("commit native role fixture", err)
		}
	}
	execute(f.service.PrepareCreateDynamicRole(f.ctx, organization.DynamicRoleRequest{
		Authentication: f.auth(directoryTestTenant, "owner"), CommandID: commandID(t), OrganizationID: x.scope.OrganizationID,
		OrganizationVersion: owner().Version, RoleID: "directory-reader", Name: "Directory reader", CorrelationID: "directory-mixed-role-setup",
		Statements: []organization.RoleStatement{{PermissionID: "read", ResourceID: "one", Effect: authorization.Allow}},
	}, "127.0.0.1"))
	read := organization.DynamicRoleReadRequest{Authentication: f.auth(directoryTestTenant, "owner"), OrganizationID: x.scope.OrganizationID,
		RoleID: "directory-reader", TargetTeamID: directoryTestTeam, CorrelationID: "directory-mixed-role-setup"}
	view, err := f.service.GetDynamicRole(f.ctx, read)
	if err != nil {
		t.Fatal(err)
	}
	execute(f.service.PrepareAssignTeamDynamicRole(f.ctx, organization.TeamRoleBindingRequest{
		Authentication: read.Authentication, CommandID: commandID(t), OrganizationID: read.OrganizationID, RoleID: read.RoleID, TeamID: read.TargetTeamID,
		OrganizationVersion: view.Organization.Version, RoleVersion: view.DynamicRole.Version, TeamVersion: view.Team.Version,
		BindingVersion: view.TeamRoleBinding.Version, CorrelationID: "directory-mixed-role-setup",
	}, "127.0.0.1"))
	journey := directoryMixedJourney{fixture: x, beforeOwner: owner().Version}
	members := make([]scimorganization.DirectoryMemberUserMapping, 0, 3)
	for i := range journey.users {
		response, err := x.native.Execute(f.ctx, scim.Request{Operation: scim.UserCreate, Credential: x.bearer, ContentType: "application/scim+json",
			IdempotencyKey: "directory-mixed-user-" + strconv.Itoa(i),
			Body:           []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"MixedAdmission` + strconv.Itoa(i) + `","active":true}`)})
		if err != nil {
			t.Fatal("create real directory-only SCIM User", err)
		}
		journey.users[i], journey.revisions[i] = directoryFixtureSCIMID(t, response, 201), response.ETag
		members = append(members, scimorganization.DirectoryMemberUserMapping{MemberID: journey.users[i], UserID: identity.UserID(journey.users[i])})
		if _, err := reader.ObserveCredentialAuthority(f.ctx, organization.CredentialAuthorityQuery{TenantID: x.scope.TenantID,
			OrganizationID: x.scope.OrganizationID, ActorID: identity.UserID(journey.users[i])}); err == nil {
			t.Fatal("SCIM CRUD itself admitted a User to the organization")
		}
	}
	members = append(members, scimorganization.DirectoryMemberUserMapping{MemberID: x.userID, UserID: identity.UserID(x.userID)})
	ordinary, err := x.groups.Execute(f.ctx, scim.Request{Operation: scim.GroupCreate, Credential: x.bearer, ContentType: "application/scim+json",
		IdempotencyKey: "directory-mixed-ordinary-group",
		Body:           []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Mixed ordinary team","members":[{"type":"User","value":"` + journey.users[1] + `"}]}`)})
	if err != nil {
		t.Fatal("create real ordinary Group for a newly admitted User", err)
	}
	ordinaryID := directoryFixtureSCIMID(t, ordinary, 201)
	roleGroup, err := x.groups.Execute(f.ctx, scim.Request{Operation: scim.GroupCreate, Credential: x.bearer, ContentType: "application/scim+json",
		IdempotencyKey: "directory-mixed-role-group",
		Body:           []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Mixed explicit role","members":[{"type":"User","value":"` + journey.users[0] + `"}]}`)})
	if err != nil {
		t.Fatal("create real explicitly role-bearing Group for the other admitted User", err)
	}
	roleID := directoryFixtureSCIMID(t, roleGroup, 201)
	journey.groups = [2]string{ordinaryID, roleID}
	users, err := scimorganization.NewDirectoryUserMapper(scimorganization.DirectoryUserMappingConfig{
		TenantID: x.scope.TenantID, OrganizationID: x.scope.OrganizationID, ProviderID: sso.ProviderID(x.scope.ProviderID), ConnectionID: x.scope.ConnectionID,
		MappingVersion: 1, Members: members, AllowAdmission: true, AllowWithdrawal: true})
	if err != nil {
		t.Fatal(err)
	}
	directory := scimorganization.DirectoryMappingConfig{TenantID: x.scope.TenantID, OrganizationID: x.scope.OrganizationID,
		ProviderID: sso.ProviderID(x.scope.ProviderID), ConnectionID: x.scope.ConnectionID, MappingVersion: 1, Members: members,
		Groups: []scimorganization.DirectoryGroupTeamMapping{{GroupID: ordinaryID, TeamID: directoryTestTeam}}}
	groups, err := scimorganization.NewDirectoryMapper(directory)
	if err != nil {
		t.Fatal(err)
	}
	directory.Groups = []scimorganization.DirectoryGroupTeamMapping{{GroupID: roleID, TeamID: directoryTestTeam}}
	roles, err := scimorganization.NewDirectoryRoleMapper(scimorganization.DirectoryRoleMappingConfig{Directory: directory,
		Roles: []scimorganization.DirectoryGroupRoleMapping{{GroupID: roleID, TeamID: directoryTestTeam, RoleID: "directory-reader"}}})
	if err != nil {
		t.Fatal(err)
	}
	mapping, err := scimorganization.NewDirectoryMixedMapper(scimorganization.DirectoryMixedMappingConfig{Users: users, Groups: groups, Roles: roles})
	if err != nil {
		t.Fatal("compose explicit disjoint ordinary and role-bearing Group policies", err)
	}
	journey.roleMapping = roles
	policy := directoryServicePolicy(func(d authorization.DecisionContext) bool {
		if d.Request.Tenant != authorization.TenantID(x.scope.TenantID) || d.Request.Subject.Kind != authorization.SubjectServiceAccount || d.Request.Subject.ID != directoryTestActor {
			return false
		}
		switch d.Request.Action {
		case "identity.sso.directory-sync-apply-mixed", authorization.Action(sso.DirectoryUserAdmissionOperation().OperationID),
			authorization.Action(sso.DirectoryUserDeprovisionOperation().OperationID), authorization.Action(sso.DirectoryTeamMembershipOperation().OperationID):
			return true
		default:
			return false
		}
	})
	journey.config = ssopg.DirectorySyncMixedConfig{Source: x.groups, Mapping: mapping, Authorization: policy,
		AuthorityNamespace: directoryTestAuthority, MaximumMembers: 50, MaximumPerUser: 10,
		ApplyAuthorization: directoryGroupPolicy(func(ctx context.Context, d authorization.DecisionContext, version uint64) (ssopg.ProviderUpdateAuthorizationEvidence, error) {
			decision, err := policy.Decide(ctx, d)
			return ssopg.ProviderUpdateAuthorizationEvidence{Context: d, Decision: decision, ActorAuthorizationVersion: version,
				ValidUntil: d.Request.Environment.Time.Add(5 * time.Second)}, err
		})}
	journey.scope = ssopg.DirectoryGroupSyncConfig{TenantID: x.scope.TenantID, OrganizationID: x.scope.OrganizationID, ConnectionID: x.scope.ConnectionID,
		Clock: x.provider.config.Clock, MaximumDuration: x.provider.config.MaximumDuration, PolicyID: x.provider.config.PolicyID,
		PolicyVersion: x.provider.config.PolicyVersion, Coordinator: x.provider.config.Coordinator}
	journey.generation = x.start(t)
	deltas := make([]sso.DirectoryDelta, 0, 4)
	for i, user := range journey.users {
		id := commandID(t)
		delta, err := sso.NewDirectoryUserAdmissionDelta(id, user, string(journey.revisions[i]))
		if err != nil {
			t.Fatal(err)
		}
		deltas = append(deltas, delta)
		journey.childIDs = append(journey.childIDs, id)
	}
	for _, edge := range []struct{ group, member string }{{ordinaryID, journey.users[1]}, {roleID, journey.users[0]}} {
		id := commandID(t)
		delta, err := sso.NewDirectoryGroupMembershipDelta(id, edge.group, edge.member, sso.DirectoryMembershipAdd)
		if err != nil {
			t.Fatal(err)
		}
		deltas = append(deltas, delta)
		journey.childIDs = append(journey.childIDs, id)
	}
	journey.request = ssopg.DirectoryMixedApplyRequest{GenerationID: journey.generation.ID, ProviderID: journey.generation.Provider,
		MappingVersion: journey.generation.MappingVersion, PredecessorCheckpoint: journey.generation.Checkpoint, Deltas: deltas}
	journey.batch = sso.DirectoryDeltaBatch{TenantID: x.scope.TenantID, OrganizationID: x.scope.OrganizationID,
		ProviderID: journey.generation.Provider, ConnectionID: x.scope.ConnectionID, Generation: journey.generation.Number,
		MappingVersion: journey.generation.MappingVersion, PredecessorCheckpoint: journey.generation.Checkpoint, Deltas: deltas}
	return journey
}

func (j directoryMixedJourney) worker(t *testing.T, pool *database.Pool) *ssopg.DirectoryMixedSyncService {
	t.Helper()
	worker, err := ssopg.NewDirectoryMixedSyncService(pool, j.scope, j.config)
	if err != nil {
		t.Fatal("construct native mixed service", err)
	}
	return worker
}

func (j directoryMixedJourney) assertCommittedUsersAndNoSuffix(t *testing.T) {
	t.Helper()
	f := j.fixture.provider.f
	reader, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for _, user := range j.users {
		member, err := reader.ObserveCredentialAuthority(f.ctx, organization.CredentialAuthorityQuery{TenantID: j.fixture.scope.TenantID,
			OrganizationID: j.fixture.scope.OrganizationID, ActorID: identity.UserID(user)})
		if err != nil || !member.Actor.Active || member.Actor.Role != organization.RoleMember || member.Version != j.beforeOwner+2 {
			t.Fatal("both User admissions were not effective before the held suffix", err)
		}
	}
	j.assertNoSuffix(t)
}

func (j directoryMixedJourney) assertNoSuffix(t *testing.T) {
	t.Helper()
	f := j.fixture.provider.f
	var grants, roles, groupEvents, groupCommands int
	err := f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT count(*) FROM organization.directory_team_grants WHERE active),
 (SELECT count(*) FROM organization.directory_team_role_grants),
 (SELECT count(*) FROM outbox_messages WHERE topic IN ('sso.directory_sync.team_membership_changed.v1','sso.directory_sync.team_role_changed.v1')),
 (SELECT count(*) FROM identity.commands WHERE purpose=$1)`, sso.DirectoryTeamMembershipOperation().OperationID).
		Scan(&grants, &roles, &groupEvents, &groupCommands)
	if err != nil || grants != 0 || roles != 0 || groupEvents != 0 || groupCommands != 0 {
		t.Fatal("uncertain second User admitted or applied a Group suffix", grants, roles, groupEvents, groupCommands, err)
	}
}

func (j directoryMixedJourney) assertSettled(t *testing.T, result sso.DirectoryApplyResult) {
	t.Helper()
	x, f := j.fixture, j.fixture.provider.f
	if len(result.ChildOutcomes) != len(j.batch.Deltas) {
		t.Fatal("mixed result omitted or regrouped original children")
	}
	for i, child := range result.ChildOutcomes {
		operation := sso.DirectoryTeamMembershipOperation()
		if i < 2 {
			operation = sso.DirectoryUserAdmissionOperation()
		}
		if child.Binding.CommandID != j.childIDs[i] || child.Binding.OperationID != operation.OperationID ||
			child.Binding.SchemaID != operation.SchemaID || child.Outcome != identity.CommitOutcomeCommitted || child.Validate() != nil {
			t.Fatal("mixed result changed original ordered child identity or outcome", i)
		}
		var state string
		var encoded []byte
		err := f.pool.Raw().QueryRow(f.ctx, `SELECT state,result FROM identity.commands WHERE tenant_id=$1 AND purpose=$2
 AND command_id=decode(translate($3,'-_','+/')||'==','base64')`, string(x.scope.TenantID), child.Binding.OperationID, string(child.Binding.CommandID)).Scan(&state, &encoded)
		var original identity.CommandResult
		if err != nil || state != "committed" || json.Unmarshal(encoded, &original) != nil || !reflect.DeepEqual(child, original) {
			t.Fatal("mixed child differs from the native journal's original committed receipt", i, err)
		}
	}
	checkpoint, err := result.NextCheckpoint(j.batch)
	if err != nil || checkpoint == j.generation.Checkpoint || checkpoint == ([32]byte{}) {
		t.Fatal("complete mixed batch did not authorize its exact successor", err)
	}
	status, err := x.sync.Status(f.ctx, j.generation.ID)
	if err != nil || status.State != ssopg.DirectorySyncRunning || status.Checkpoint != checkpoint || status.ReadCount != 4 || status.AppliedCount != 4 || status.RejectedCount != 0 {
		t.Fatal("complete mixed batch did not settle all four original children exactly once", err)
	}
	for i, child := range result.ChildOutcomes[:2] {
		var before, after string
		err := f.pool.Raw().QueryRow(f.ctx, `SELECT directory_org_before::text,directory_org_after::text FROM organization.command_effects WHERE command_id=$1`, string(child.Binding.CommandID)).Scan(&before, &after)
		wanted := j.beforeOwner + uint64(i)
		if err != nil || before != strconv.FormatUint(wanted, 10) || after != strconv.FormatUint(wanted+1, 10) {
			t.Fatal("original Work did not retain each effective User organization successor", i, before, after, err)
		}
	}
	var users, grants, roles, userAudits, groupAudits, userEvents, ordinaryEvents, roleEvents int
	err = f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT count(*) FROM organization.directory_membership_grants WHERE active),
 (SELECT count(*) FROM organization.directory_team_grants WHERE active),
 (SELECT count(*) FROM organization.directory_team_role_grants),
 (SELECT count(*) FROM audit.records WHERE action=$1 AND outcome=1),
 (SELECT count(*) FROM audit.records WHERE action=$2 AND outcome=1),
 (SELECT count(*) FROM outbox_messages WHERE topic='sso.directory_sync.membership_changed.v1'),
 (SELECT count(*) FROM outbox_messages WHERE topic='sso.directory_sync.team_membership_changed.v1'),
 (SELECT count(*) FROM outbox_messages WHERE topic='sso.directory_sync.team_role_changed.v1')`,
		sso.DirectoryUserAdmissionOperation().OperationID, sso.DirectoryTeamMembershipOperation().OperationID).
		Scan(&users, &grants, &roles, &userAudits, &groupAudits, &userEvents, &ordinaryEvents, &roleEvents)
	if err != nil || users != 2 || grants != 2 || roles != 1 || userAudits != 2 || groupAudits != 2 || userEvents != 2 || ordinaryEvents != 1 || roleEvents != 1 {
		t.Fatal("mixed execution or exact recovery duplicated or omitted protected effects", users, grants, roles, userAudits, groupAudits, userEvents, ordinaryEvents, roleEvents, err)
	}
	reader, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for i, group := range j.groups {
		user := j.users[1-i]
		member, err := reader.ObserveCredentialAuthority(f.ctx, organization.CredentialAuthorityQuery{TenantID: x.scope.TenantID,
			OrganizationID: x.scope.OrganizationID, ActorID: identity.UserID(user)})
		if err != nil || !member.Actor.Active || member.Actor.Role != organization.RoleMember {
			t.Fatal("settled Group target lost its effective admitted organization membership", err)
		}
		grant, err := reader.ObserveDirectoryTeamMembership(f.ctx, organizationpg.DirectoryTeamGrantScope{
			TenantID: x.scope.TenantID, OrganizationID: x.scope.OrganizationID, ProviderID: organization.ID(x.scope.ProviderID),
			ConnectionID: organization.ID(x.scope.ConnectionID), GroupID: organization.ID(group), TeamID: directoryTestTeam, UserID: identity.UserID(user)})
		if err != nil || !grant.Source || grant.Local || grant.Version != 1 {
			t.Fatal("mixed Group effect did not retain its exact source-only contribution", i, err)
		}
	}
	var roleUser, roleGroup, roleID, memberResource string
	var providerVersion, mappingVersion, connectionVersion string
	err = f.pool.Raw().QueryRow(f.ctx, `SELECT user_id::text,group_id::text,role_id::text,member_resource_id::text,
 provider_version::text,mapping_version::text,connection_version::text FROM organization.directory_team_role_grants`).
		Scan(&roleUser, &roleGroup, &roleID, &memberResource, &providerVersion, &mappingVersion, &connectionVersion)
	if err != nil || roleUser != j.users[0] || roleGroup != j.groups[1] || roleID != "directory-reader" || memberResource != j.users[0] ||
		providerVersion != strconv.FormatUint(x.providerVersion, 10) || mappingVersion != strconv.FormatUint(j.generation.MappingVersion, 10) || connectionVersion != "1" {
		t.Fatal("ordinary Group gained a role or explicit role mapping lost its exact authority", err)
	}
	roleReader, err := ssopg.NewDirectoryGroupRoleSyncService(f.pool, ssopg.DirectoryGroupRoleSyncConfig(j.scope), ssopg.DirectorySyncGroupRolesConfig{
		Source: x.groups, Mapping: j.roleMapping, Authorization: j.config.Authorization, AuthorityNamespace: j.config.AuthorityNamespace,
		ApplyAuthorization: directoryRoleReadPolicy{j.config.ApplyAuthorization.(directoryGroupPolicy)},
	})
	if err != nil {
		t.Fatal("select native current-role reader for the mixed result", err)
	}
	claim := organizationpg.DirectoryTeamRoleSource{Scope: organizationpg.DirectoryTeamGrantScope{TenantID: x.scope.TenantID,
		OrganizationID: x.scope.OrganizationID, ProviderID: organization.ID(x.scope.ProviderID), ConnectionID: organization.ID(x.scope.ConnectionID),
		GroupID: organization.ID(roleGroup), TeamID: directoryTestTeam, UserID: identity.UserID(roleUser)},
		MemberResourceID: organization.ID(memberResource), RoleID: organization.ID(roleID), ProviderVersion: x.providerVersion,
		MappingVersion: j.generation.MappingVersion, ConnectionVersion: 1}
	if current, err := roleReader.CurrentRoleSources(f.ctx, []organizationpg.DirectoryTeamRoleSource{claim}); err != nil || len(current) != 1 || !current[0] {
		t.Fatal("mixed role result is not usable by the native current-role authority reader", err)
	}
}

// The existing fault driver still observes the server's exact COMMIT frame.
// Only its arming is delayed: count execution of the successor INSERT, including
// repeated Bind messages for pgx's cached prepared statement, not Parse traffic.
type directoryMixedSecondUserConn struct {
	net.Conn
	fault      *providerCommitFault
	writes     *atomic.Uint64
	statements map[string]bool
	buffer     []byte
}

func (c *directoryMixedSecondUserConn) Write(p []byte) (int, error) {
	if len(p) > 0 && p[0] == 0 {
		return c.Conn.Write(p)
	}
	c.buffer = append(c.buffer, p...)
	for len(c.buffer) >= 5 {
		length := binary.BigEndian.Uint32(c.buffer[1:5])
		if length < 4 || length > 16<<20 {
			return 0, errors.New("invalid mixed fixture PostgreSQL frontend frame")
		}
		if uint64(len(c.buffer)) < uint64(length)+1 {
			break
		}
		body := c.buffer[5 : int(length)+1]
		switch c.buffer[0] {
		case 'P':
			name, query, ok := bytes.Cut(body, []byte{0})
			if ok {
				c.statements[string(name)] = bytes.Contains(query, []byte("INSERT INTO organization.command_effects")) && bytes.Contains(query, []byte("directory_org_after"))
			}
		case 'B':
			_, rest, ok := bytes.Cut(body, []byte{0})
			if ok {
				name, _, found := bytes.Cut(rest, []byte{0})
				if found && c.statements[string(name)] && c.writes.Add(1) == 2 {
					c.fault.seen.Store(true)
				}
			}
		case 'Q':
			if bytes.Contains(body, []byte("INSERT INTO organization.command_effects")) && bytes.Contains(body, []byte("directory_org_after")) && c.writes.Add(1) == 2 {
				c.fault.seen.Store(true)
			}
		}
		c.buffer = c.buffer[int(length)+1:]
	}
	return c.Conn.Write(p)
}

func directoryMixedSecondUserLossPool(t *testing.T, f *orgFixture) (*database.Pool, *providerCommitFault, *atomic.Uint64) {
	t.Helper()
	fault := &providerCommitFault{target: "not-a-directory-sql-statement"}
	writes := new(atomic.Uint64)
	pool, err := database.Connect(f.ctx, database.Config{DSN: f.dsn, MaxConns: 2, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database = f.database
		c.ConnConfig.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			armed := &directoryMixedSecondUserConn{Conn: conn, fault: fault, writes: writes, statements: make(map[string]bool)}
			return &providerLossConn{Conn: armed, fault: fault}, nil
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := pool.Close(ctx); err != nil {
			t.Error("mixed fault pool cleanup", err)
		}
	})
	return pool, fault, writes
}
