//go:build integration

package postgres_test

import (
	"errors"
	"testing"

	identity "github.com/faustbrian/go-identity"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	scim "github.com/faustbrian/go-scim"
	scimorganization "github.com/faustbrian/go-scim/organization"
	scimpostgres "github.com/faustbrian/go-scim/postgres"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestNativeDirectoryUserDriftRetainedDeletionUsesExactRevision(t *testing.T) {
	x := newDirectoryGroupApplyFixture(t, organizationpg.DirectoryMembershipMigrationSource{Version: 687})
	ctx := x.provider.f.ctx
	created, err := x.native.Execute(ctx, scim.Request{
		Operation: scim.UserCreate, Credential: x.bearer, ContentType: "application/scim+json",
		Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"DriftRetainedDeletion","active":true}`),
	})
	if err != nil {
		t.Fatal("create an explicitly active source User", err)
	}
	resourceID := directoryFixtureSCIMID(t, created, 201)
	worker, inspector := directoryUserDriftWorkers(t, x, resourceID)
	generation := x.start(t)
	admission, err := sso.NewDirectoryUserAdmissionDelta(directoryUserDriftCommandID(t), resourceID, string(created.ETag))
	if err != nil {
		t.Fatal(err)
	}
	granted, err := worker.ApplyGeneration(ctx, directoryUserDriftRequest(generation, admission))
	if err != nil || len(granted.ChildOutcomes) != 1 || granted.ChildOutcomes[0].Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("establish the exact live directory grant", err)
	}
	current, err := x.sync.Status(ctx, generation.ID)
	if err != nil || current.Checkpoint != granted.Checkpoint {
		t.Fatal("observe the real admission successor", err)
	}
	before := captureDirectoryUserDriftState(t, x, generation.ID, resourceID)
	contradictory, err := sso.NewDirectoryUserDeprovisionDelta(directoryUserDriftCommandID(t), resourceID, string(created.ETag), sso.DirectoryUserInactive)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := inspector.ObserveDrift(ctx, directoryUserDriftRequest(current, contradictory)); !errors.Is(err, sso.ErrDirectoryReconciliation) || result != (ssopg.DirectoryUserDrift{}) {
		t.Fatal("the current active revision authorized a contradictory inactive classification", err)
	}
	assertDirectoryUserDriftUnchanged(t, x, generation.ID, resourceID, before)

	deleted, err := x.native.Execute(ctx, scim.Request{
		Operation: scim.UserDelete, Credential: x.bearer, ResourceID: resourceID, IfMatch: created.ETag,
	})
	if err != nil || deleted.Status != 204 {
		t.Fatal("delete the actual SCIM resource", err)
	}
	var deleteCommand string
	err = x.provider.f.pool.Raw().QueryRow(ctx, `SELECT command_id FROM scim.users
 WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4
 AND resource_id=$5 AND deleted_at IS NOT NULL`, string(x.scope.TenantID), string(x.scope.OrganizationID),
		string(x.scope.ProviderID), string(x.scope.ConnectionID), resourceID).Scan(&deleteCommand)
	if err != nil {
		t.Fatal("read the retained native delete command", err)
	}
	if _, err := identity.ParseCommandID(deleteCommand); err != nil {
		t.Fatal("the source tombstone did not retain a canonical delete command", err)
	}
	deleteRevision := scim.Version(`"` + deleteCommand + `"`)
	if deleteRevision == created.ETag {
		t.Fatal("the retained deletion reused the previous live revision")
	}
	withdrawal, err := sso.NewDirectoryUserDeprovisionDelta(directoryUserDriftCommandID(t), resourceID, string(deleteRevision), sso.DirectoryUserDeleted)
	if err != nil {
		t.Fatal(err)
	}
	before = captureDirectoryUserDriftState(t, x, generation.ID, resourceID)
	if !before.attribution.Membership.Member.Active || !before.attribution.Membership.ContributionActive {
		t.Fatal("SCIM deletion itself withdrew the live organization grant")
	}
	result, err := inspector.ObserveDrift(ctx, directoryUserDriftRequest(current, withdrawal))
	if err != nil || result != (ssopg.DirectoryUserDrift{
		Kind: scimorganization.DirectoryMembershipDriftUnexpectedSourceGrant,
		Source: scimpostgres.DirectoryUserObservation{State: scimpostgres.DirectoryMembershipUserDeleted,
			Revision: deleteRevision},
	}) {
		t.Fatal("the retained deletion did not expose its exact revision and live source grant", err)
	}
	assertDirectoryUserDriftUnchanged(t, x, generation.ID, resourceID, before)

	stale, err := sso.NewDirectoryUserDeprovisionDelta(directoryUserDriftCommandID(t), resourceID, string(created.ETag), sso.DirectoryUserDeleted)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := inspector.ObserveDrift(ctx, directoryUserDriftRequest(current, stale)); !errors.Is(err, sso.ErrDirectoryReconciliation) || result != (ssopg.DirectoryUserDrift{}) {
		t.Fatal("the previous live ETag disclosed retained deletion drift", err)
	}
	assertDirectoryUserDriftUnchanged(t, x, generation.ID, resourceID, before)
}

func TestNativeDirectoryUserDriftUnprovenSourceHidesAttribution(t *testing.T) {
	x := newDirectoryGroupApplyFixture(t, organizationpg.DirectoryMembershipMigrationSource{Version: 687})
	ctx := x.provider.f.ctx
	user, err := x.native.Execute(ctx, scim.Request{Operation: scim.UserGet, Credential: x.bearer, ResourceID: x.userID})
	if err != nil || user.Status != 200 {
		t.Fatal("read the fixture User with omitted active state", err)
	}
	absent, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	generation := x.start(t)
	for _, test := range []struct {
		name, resourceID string
	}{
		{name: "omitted active with independent local access", resourceID: x.userID},
		{name: "absent mapped source", resourceID: string(absent)},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, inspector := directoryUserDriftWorkers(t, x, test.resourceID)
			delta, err := sso.NewDirectoryUserAdmissionDelta(directoryUserDriftCommandID(t), test.resourceID, string(user.ETag))
			if err != nil {
				t.Fatal(err)
			}
			before := captureDirectoryUserDriftState(t, x, generation.ID, test.resourceID)
			if test.resourceID == x.userID && (!before.attribution.Local || !before.attribution.Membership.Member.Active) {
				t.Fatal("the omitted-active case did not retain independent local access")
			}
			result, err := inspector.ObserveDrift(ctx, directoryUserDriftRequest(generation, delta))
			if err != nil || result != (ssopg.DirectoryUserDrift{Kind: scimorganization.DirectoryMembershipDriftConflict}) {
				t.Fatal("unproven source disclosed a source revision, origin flag, or authoritative absence", err)
			}
			assertDirectoryUserDriftUnchanged(t, x, generation.ID, test.resourceID, before)
		})
	}
}
