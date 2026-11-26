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
	scim "github.com/faustbrian/go-scim"
	scimorganization "github.com/faustbrian/go-scim/organization"
	scimpostgres "github.com/faustbrian/go-scim/postgres"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestNativeDirectoryUserDriftInspectionAndOrdinaryApplyConverge(t *testing.T) {
	x := newDirectoryGroupApplyFixture(t, organizationpg.DirectoryMembershipMigrationSource{Version: 687})
	ctx := x.provider.f.ctx
	created, err := x.native.Execute(ctx, scim.Request{
		Operation: scim.UserCreate, Credential: x.bearer, ContentType: "application/scim+json",
		Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"DriftDirectoryOnly","active":true}`),
	})
	if err != nil {
		t.Fatal("create an explicitly active directory-only User", err)
	}
	resourceID := directoryFixtureSCIMID(t, created, 201)
	worker, inspector := directoryUserDriftWorkers(t, x, resourceID)
	generation := x.start(t)
	admission, err := sso.NewDirectoryUserAdmissionDelta(directoryUserDriftCommandID(t), resourceID, string(created.ETag))
	if err != nil {
		t.Fatal(err)
	}
	request := directoryUserDriftRequest(generation, admission)
	before := captureDirectoryUserDriftState(t, x, generation.ID, resourceID)
	if result, err := worker.ObserveDrift(ctx, request); !errors.Is(err, sso.ErrForbidden) || result != (ssopg.DirectoryUserDrift{}) {
		t.Fatal("ordinary User Apply permission authorized inspection or disclosed a result", err)
	}
	assertDirectoryUserDriftUnchanged(t, x, generation.ID, resourceID, before)
	if result, err := inspector.ApplyGeneration(ctx, request); !errors.Is(err, sso.ErrForbidden) || result.Checkpoint != ([32]byte{}) {
		t.Fatal("inspection permission authorized User Apply", err)
	}
	assertDirectoryUserDriftUnchanged(t, x, generation.ID, resourceID, before)

	missing, err := inspector.ObserveDrift(ctx, request)
	if err != nil || missing != (ssopg.DirectoryUserDrift{
		Kind:   scimorganization.DirectoryMembershipDriftMissingSourceGrant,
		Source: scimpostgres.DirectoryUserObservation{State: scimpostgres.DirectoryMembershipUserActive, Revision: created.ETag},
	}) {
		t.Fatal("active source without membership did not report its exact missing grant", err)
	}
	assertDirectoryUserDriftUnchanged(t, x, generation.ID, resourceID, before)
	granted, err := worker.ApplyGeneration(ctx, request)
	if err != nil || len(granted.ChildOutcomes) != 1 || granted.ChildOutcomes[0].Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("ordinary User Apply did not settle admission after inspection", err)
	}
	current, err := x.sync.Status(ctx, generation.ID)
	if err != nil || current.Checkpoint != granted.Checkpoint || current.AppliedCount != 1 || current.ReadCount != 1 {
		t.Fatal("ordinary admission did not advance the real generation exactly once", err)
	}
	before = captureDirectoryUserDriftState(t, x, generation.ID, resourceID)
	if result, err := inspector.ObserveDrift(ctx, request); !errors.Is(err, sso.ErrDirectoryReconciliation) || result != (ssopg.DirectoryUserDrift{}) {
		t.Fatal("superseded checkpoint disclosed User drift", err)
	}
	assertDirectoryUserDriftUnchanged(t, x, generation.ID, resourceID, before)
	request.PredecessorCheckpoint = current.Checkpoint
	converged, err := inspector.ObserveDrift(ctx, request)
	if err != nil || converged != (ssopg.DirectoryUserDrift{
		Kind:   scimorganization.DirectoryMembershipDriftInSync,
		Source: scimpostgres.DirectoryUserObservation{State: scimpostgres.DirectoryMembershipUserActive, Revision: created.ETag},
	}) || !before.attribution.Membership.ContributionActive || !before.attribution.Membership.Member.Active {
		t.Fatal("ordinary admission did not converge the exact source grant", err)
	}
	assertDirectoryUserDriftUnchanged(t, x, generation.ID, resourceID, before)

	inactive, err := x.native.Execute(ctx, scim.Request{
		Operation: scim.UserPatch, Credential: x.bearer, ResourceID: resourceID, IfMatch: created.ETag,
		ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}`),
	})
	if err != nil || inactive.Status != 200 {
		t.Fatal("deactivate the real SCIM User", err)
	}
	before = captureDirectoryUserDriftState(t, x, generation.ID, resourceID)
	if result, err := inspector.ObserveDrift(ctx, request); !errors.Is(err, sso.ErrDirectoryReconciliation) || result != (ssopg.DirectoryUserDrift{}) {
		t.Fatal("stale source revision disclosed a User drift classification", err)
	}
	assertDirectoryUserDriftUnchanged(t, x, generation.ID, resourceID, before)
	withdrawal, err := sso.NewDirectoryUserDeprovisionDelta(directoryUserDriftCommandID(t), resourceID, string(inactive.ETag), sso.DirectoryUserInactive)
	if err != nil {
		t.Fatal(err)
	}
	request = directoryUserDriftRequest(current, withdrawal)
	unexpected, err := inspector.ObserveDrift(ctx, request)
	if err != nil || unexpected != (ssopg.DirectoryUserDrift{
		Kind:   scimorganization.DirectoryMembershipDriftUnexpectedSourceGrant,
		Source: scimpostgres.DirectoryUserObservation{State: scimpostgres.DirectoryMembershipUserInactive, Revision: inactive.ETag},
	}) {
		t.Fatal("explicit inactivity did not expose the still-active exact source grant", err)
	}
	assertDirectoryUserDriftUnchanged(t, x, generation.ID, resourceID, before)
	repository, err := organizationpg.NewRepository(x.provider.f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	query := organization.CredentialAuthorityQuery{TenantID: x.scope.TenantID, OrganizationID: x.scope.OrganizationID, ActorID: identity.UserID(resourceID)}
	if authority, err := repository.ObserveCredentialAuthority(ctx, query); err != nil || !authority.Actor.Active {
		t.Fatal("inspection withdrew effective organization access", err)
	}
	removed, err := worker.ApplyGeneration(ctx, request)
	if err != nil || len(removed.ChildOutcomes) != 1 || removed.ChildOutcomes[0].Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("ordinary User Apply did not settle the inspected withdrawal", err)
	}
	current, err = x.sync.Status(ctx, generation.ID)
	if err != nil || current.Checkpoint != removed.Checkpoint || current.AppliedCount != 2 || current.ReadCount != 2 {
		t.Fatal("ordinary withdrawal did not advance the real generation exactly once", err)
	}
	if _, err := repository.ObserveCredentialAuthority(ctx, query); err == nil {
		t.Fatal("ordinary withdrawal retained directory-only organization access")
	}
	request.PredecessorCheckpoint = current.Checkpoint
	before = captureDirectoryUserDriftState(t, x, generation.ID, resourceID)
	converged, err = inspector.ObserveDrift(ctx, request)
	if err != nil || converged != (ssopg.DirectoryUserDrift{
		Kind:   scimorganization.DirectoryMembershipDriftInSync,
		Source: scimpostgres.DirectoryUserObservation{State: scimpostgres.DirectoryMembershipUserInactive, Revision: inactive.ETag},
	}) || before.attribution.Membership.ContributionActive {
		t.Fatal("ordinary withdrawal did not converge the explicit inactive source", err)
	}
	assertDirectoryUserDriftUnchanged(t, x, generation.ID, resourceID, before)
}

func TestNativeDirectoryUserDriftPreservesLocalMembership(t *testing.T) {
	x := newDirectoryGroupApplyFixture(t, organizationpg.DirectoryMembershipMigrationSource{Version: 687})
	ctx := x.provider.f.ctx
	user, err := x.native.Execute(ctx, scim.Request{Operation: scim.UserGet, Credential: x.bearer, ResourceID: x.userID})
	if err != nil || user.Status != 200 {
		t.Fatal("read the source revision for the existing local member", err)
	}
	active, err := x.native.Execute(ctx, scim.Request{
		Operation: scim.UserPatch, Credential: x.bearer, ResourceID: x.userID, IfMatch: user.ETag, ContentType: "application/scim+json",
		Body: []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":true}]}`),
	})
	if err != nil || active.Status != 200 {
		t.Fatal("make the existing local member explicitly active in the source", err)
	}
	_, inspector := directoryUserDriftWorkers(t, x, x.userID)
	generation := x.start(t)
	delta, err := sso.NewDirectoryUserAdmissionDelta(directoryUserDriftCommandID(t), x.userID, string(active.ETag))
	if err != nil {
		t.Fatal(err)
	}
	before := captureDirectoryUserDriftState(t, x, generation.ID, x.userID)
	result, err := inspector.ObserveDrift(ctx, directoryUserDriftRequest(generation, delta))
	if err != nil || result != (ssopg.DirectoryUserDrift{
		Kind: scimorganization.DirectoryMembershipDriftMissingSourceGrant, LocalGrant: true,
		Source: scimpostgres.DirectoryUserObservation{State: scimpostgres.DirectoryMembershipUserActive, Revision: active.ETag},
	}) || !before.attribution.Local || !before.attribution.Membership.Member.Active {
		t.Fatal("independent local membership concealed the missing exact directory grant", err)
	}
	assertDirectoryUserDriftUnchanged(t, x, generation.ID, x.userID, before)
}

func directoryUserDriftWorkers(t *testing.T, x directoryGroupApplyFixture, resourceID string) (*ssopg.DirectoryUserSyncService, *ssopg.DirectoryUserSyncService) {
	t.Helper()
	mapper, err := scimorganization.NewDirectoryUserMapper(scimorganization.DirectoryUserMappingConfig{
		TenantID: x.scope.TenantID, OrganizationID: x.scope.OrganizationID, ProviderID: sso.ProviderID(x.scope.ProviderID), ConnectionID: x.scope.ConnectionID,
		MappingVersion: 1, Members: []scimorganization.DirectoryMemberUserMapping{{MemberID: resourceID, UserID: identity.UserID(resourceID)}}, AllowAdmission: true, AllowWithdrawal: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := directoryServicePolicy(func(d authorization.DecisionContext) bool {
		return d.Request.Tenant == authorization.TenantID(x.scope.TenantID) && d.Request.Subject.Kind == authorization.SubjectServiceAccount &&
			d.Request.Subject.ID == directoryTestActor && (d.Request.Action == "identity.sso.directory-sync-apply" ||
			d.Request.Action == authorization.Action(sso.DirectoryUserAdmissionOperation().OperationID) ||
			d.Request.Action == authorization.Action(sso.DirectoryUserDeprovisionOperation().OperationID))
	})
	config := ssopg.DirectorySyncUsersConfig{
		Source: x.groups, Mapping: mapper, Authorization: policy, MaximumMembers: 50, MaximumPerUser: 10, AuthorityNamespace: directoryTestAuthority,
		ApplyAuthorization: directoryUserPolicy(func(ctx context.Context, d authorization.DecisionContext, version uint64) (ssopg.ProviderUpdateAuthorizationEvidence, error) {
			decision, err := policy.Decide(ctx, d)
			return ssopg.ProviderUpdateAuthorizationEvidence{Context: d, Decision: decision, ActorAuthorizationVersion: version,
				ValidUntil: d.Request.Environment.Time.Add(5 * time.Second)}, err
		}),
	}
	worker, err := x.sync.WithUserMembership(config)
	if err != nil {
		t.Fatal(err)
	}
	inspection := directoryServicePolicy(func(d authorization.DecisionContext) bool {
		return d.Request.Tenant == authorization.TenantID(x.scope.TenantID) && d.Request.Subject.Kind == authorization.SubjectServiceAccount &&
			d.Request.Subject.ID == directoryTestActor && d.Request.Action == "identity.sso.directory-sync-inspect-user-drift"
	})
	config.ApplyAuthorization = directoryUserPolicy(func(ctx context.Context, d authorization.DecisionContext, version uint64) (ssopg.ProviderUpdateAuthorizationEvidence, error) {
		decision, err := inspection.Decide(ctx, d)
		return ssopg.ProviderUpdateAuthorizationEvidence{Context: d, Decision: decision, ActorAuthorizationVersion: version,
			ValidUntil: d.Request.Environment.Time.Add(5 * time.Second)}, err
	})
	inspector, err := x.sync.WithUserMembership(config)
	if err != nil {
		t.Fatal(err)
	}
	return worker, inspector
}

func directoryUserDriftRequest(generation ssopg.DirectorySyncGeneration, delta sso.DirectoryDelta) ssopg.DirectoryUserApplyRequest {
	return ssopg.DirectoryUserApplyRequest{GenerationID: generation.ID, ProviderID: generation.Provider, MappingVersion: generation.MappingVersion,
		PredecessorCheckpoint: generation.Checkpoint, Delta: delta}
}

func directoryUserDriftCommandID(t *testing.T) identity.CommandID {
	t.Helper()
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

type directoryUserDriftState struct {
	generation                     ssopg.DirectorySyncGeneration
	attribution                    organizationpg.DirectoryMembershipAttribution
	grants, active, audits, events int
	commands, claims               int
}

func captureDirectoryUserDriftState(t *testing.T, x directoryGroupApplyFixture, generation identity.CommandID, resourceID string) directoryUserDriftState {
	t.Helper()
	f := x.provider.f
	state := directoryUserDriftState{}
	var err error
	state.generation, err = x.sync.Status(f.ctx, generation)
	if err != nil {
		t.Fatal("observe the exact generation", err)
	}
	repository, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	state.attribution, err = repository.ObserveDirectoryMembershipAttribution(f.ctx, organizationpg.DirectoryMembershipSource{
		TenantID: x.scope.TenantID, OrganizationID: x.scope.OrganizationID, UserID: identity.UserID(resourceID),
		ProviderID: organization.ID(x.scope.ProviderID), ConnectionID: organization.ID(x.scope.ConnectionID), ResourceID: organization.ID(resourceID),
	})
	if err != nil {
		t.Fatal("observe exact source and independent local membership attribution", err)
	}
	err = f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT count(*) FROM organization.directory_membership_grants),
 (SELECT count(*) FROM organization.directory_membership_grants WHERE active),
 (SELECT count(*) FROM audit.records),
 (SELECT count(*) FROM outbox_messages),
 (SELECT count(*) FROM identity.commands),
 (SELECT count(*) FROM identity.identity_command_id_claims)`).Scan(&state.grants, &state.active, &state.audits, &state.events, &state.commands, &state.claims)
	if err != nil {
		t.Fatal("observe protected effect counts", err)
	}
	return state
}

func assertDirectoryUserDriftUnchanged(t *testing.T, x directoryGroupApplyFixture, generation identity.CommandID, resourceID string, before directoryUserDriftState) {
	t.Helper()
	if after := captureDirectoryUserDriftState(t, x, generation, resourceID); after != before {
		t.Fatal("User drift inspection changed the generation, exact attribution, or protected effects")
	}
}
