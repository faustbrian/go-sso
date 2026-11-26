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
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestNativeDirectoryBatchDriftPreservesCandidateOrderAndIndependentLocalGrants(t *testing.T) {
	multi, inspector := newDirectoryBatchDriftFixture(t)
	fixture := multi.fixture
	ctx := fixture.provider.f.ctx
	request := directoryDriftRequest(multi.generation, multi.batch)
	before := captureDirectoryBatchDriftState(t, multi)
	for _, membership := range []organizationpg.DirectoryTeamMembershipObservation{before.original.membership, before.secondMembership} {
		if membership.Source || !membership.Local || membership.Version != 0 {
			t.Fatal("both exact source grants must be absent while the independent local membership remains")
		}
	}

	want := []scimorganization.DirectoryMembershipDrift{
		{Kind: scimorganization.DirectoryMembershipDriftMissingSourceGrant, LocalGrant: true},
		{Kind: scimorganization.DirectoryMembershipDriftInSync, LocalGrant: true},
	}
	for attempt := 0; attempt < 2; attempt++ {
		got, err := inspector.ObserveBatchDrift(ctx, request)
		if err != nil || !slices.Equal(got, want) {
			t.Fatalf("batch inspection did not classify each original candidate in order: %v", err)
		}
		assertDirectoryBatchDriftUnchanged(t, multi, before)
	}

	reversed := request
	reversed.Deltas = []sso.DirectoryDelta{request.Deltas[1], request.Deltas[0]}
	got, err := inspector.ObserveBatchDrift(ctx, reversed)
	if err != nil || !slices.Equal(got, []scimorganization.DirectoryMembershipDrift{want[1], want[0]}) {
		t.Fatal("inspection sorted or reused classifications instead of following candidate order", err)
	}
	assertDirectoryBatchDriftUnchanged(t, multi, before)

	changedActions := request
	changedActions.Deltas = make([]sso.DirectoryDelta, len(request.Deltas))
	for i, original := range request.Deltas {
		edge, err := original.GroupMembership()
		if err != nil {
			t.Fatal(err)
		}
		changedActions.Deltas[i], err = sso.NewDirectoryGroupMembershipDelta(edge.CommandID, edge.GroupID, edge.MemberID, sso.DirectoryMembershipRemove)
		if err != nil {
			t.Fatal(err)
		}
	}
	got, err = inspector.ObserveBatchDrift(ctx, changedActions)
	if err != nil || !slices.Equal(got, want) {
		t.Fatal("proposed removal changed comparison of actual source and local grants", err)
	}
	assertDirectoryBatchDriftUnchanged(t, multi, before)

	first := multi.batch
	first.Deltas = first.Deltas[:1]
	if _, err := multi.worker.Apply(ctx, multi.generation.ID, first); err != nil {
		t.Fatal("settle only the first original Group edge through Apply", err)
	}
	before = captureDirectoryBatchDriftState(t, multi)
	if !before.original.membership.Source || before.secondMembership.Source || before.original.generation.Checkpoint == request.PredecessorCheckpoint {
		t.Fatal("the first Group alone must have a source grant at the new checkpoint")
	}
	want = []scimorganization.DirectoryMembershipDrift{want[1], want[1]}
	for _, order := range []ssopg.DirectoryGroupApplyRequest{request, reversed} {
		order.PredecessorCheckpoint = before.original.generation.Checkpoint
		got, err := inspector.ObserveBatchDrift(ctx, order)
		if err != nil || !slices.Equal(got, want) {
			t.Fatal("one exact local source grant was reused for both Group targets", err)
		}
		assertDirectoryBatchDriftUnchanged(t, multi, before)
	}
}

func TestNativeDirectoryBatchDriftRejectsUnauthorizedUnmappedAndStaleWithoutPartialReport(t *testing.T) {
	multi, inspector := newDirectoryBatchDriftFixture(t)
	fixture := multi.fixture
	ctx := fixture.provider.f.ctx
	request := directoryDriftRequest(multi.generation, multi.batch)
	before := captureDirectoryBatchDriftState(t, multi)

	if result, err := multi.worker.ObserveBatchDrift(ctx, request); !errors.Is(err, sso.ErrForbidden) || result != nil {
		t.Fatal("ordinary Apply permission disclosed batch drift or authorized inspection", err)
	}
	assertDirectoryBatchDriftUnchanged(t, multi, before)

	oversized := request
	oversized.Deltas = make([]sso.DirectoryDelta, 129)
	for i := range oversized.Deltas {
		commandID, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		oversized.Deltas[i], err = sso.NewDirectoryGroupMembershipDelta(commandID, fixture.groupID, fixture.userID, sso.DirectoryMembershipAdd)
		if err != nil {
			t.Fatal(err)
		}
	}
	if result, err := multi.worker.ObserveBatchDrift(ctx, oversized); !errors.Is(err, sso.ErrInvalidInput) || result != nil {
		t.Fatal("129 candidates reached authorization instead of failing the source snapshot bound", err)
	}
	assertDirectoryBatchDriftUnchanged(t, multi, before)

	// This inspector maps the first real Group only, leaving a valid prefix
	// before the second real Group's missing explicit mapping.
	firstGroupOnly := directoryDriftInspector(t, fixture)
	if result, err := firstGroupOnly.ObserveBatchDrift(ctx, request); !errors.Is(err, sso.ErrForbidden) || result != nil {
		t.Fatal("unmapped suffix disclosed the mapped prefix's classification", err)
	}
	assertDirectoryBatchDriftUnchanged(t, multi, before)

	firstCandidate := multi.batch
	firstCandidate.Deltas = firstCandidate.Deltas[:1]
	if applied, err := multi.worker.Apply(ctx, multi.generation.ID, firstCandidate); err != nil || len(applied.ChildOutcomes) != 1 || applied.ChildOutcomes[0].Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("advance the real generation through ordinary Group Apply", err)
	}
	before = captureDirectoryBatchDriftState(t, multi)
	if before.original.generation.Checkpoint == request.PredecessorCheckpoint {
		t.Fatal("ordinary Apply did not make the inspected predecessor stale")
	}
	if result, err := inspector.ObserveBatchDrift(ctx, request); !errors.Is(err, sso.ErrDirectoryReconciliation) || result != nil {
		t.Fatal("stale predecessor disclosed current drift or a partial report", err)
	}
	assertDirectoryBatchDriftUnchanged(t, multi, before)
}

func newDirectoryBatchDriftFixture(t *testing.T) (directoryMultiEdgeFixture, *ssopg.DirectoryGroupSyncService) {
	t.Helper()
	multi := newDirectoryMultiEdgeFixture(t)
	fixture := multi.fixture
	ctx := fixture.provider.f.ctx
	current, err := fixture.groups.Execute(ctx, scim.Request{
		Operation: scim.GroupGet, Credential: fixture.bearer, ResourceID: multi.secondGroupID,
	})
	if err != nil || current.Status != 200 || current.ETag == "" {
		t.Fatal("read the second explicitly mapped real source Group", err)
	}
	withdrawn, err := fixture.groups.Execute(ctx, scim.Request{
		Operation: scim.GroupReplace, Credential: fixture.bearer, ResourceID: multi.secondGroupID, IfMatch: current.ETag,
		IdempotencyKey: "native-directory-batch-drift-second-absent", ContentType: "application/scim+json",
		Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Second directory group","members":[]}`),
	})
	if err != nil || withdrawn.Status != 200 {
		t.Fatal("withdraw the second real source edge before comparing its absent grant", err)
	}

	config := multi.config
	inspection := directoryServicePolicy(func(d authorization.DecisionContext) bool {
		return d.Request.Tenant == authorization.TenantID(fixture.scope.TenantID) &&
			d.Request.Subject.Kind == authorization.SubjectServiceAccount && d.Request.Subject.ID == directoryTestActor &&
			d.Request.Action == "identity.sso.directory-sync-inspect-drift"
	})
	config.ApplyAuthorization = directoryGroupPolicy(func(ctx context.Context, d authorization.DecisionContext, epoch uint64) (ssopg.ProviderUpdateAuthorizationEvidence, error) {
		decision, err := inspection.Decide(ctx, d)
		return ssopg.ProviderUpdateAuthorizationEvidence{Context: d, Decision: decision, ActorAuthorizationVersion: epoch,
			ValidUntil: d.Request.Environment.Time.Add(5 * time.Second)}, err
	})
	inspector, err := fixture.sync.WithGroupEdges(config)
	if err != nil {
		t.Fatal("select independently authorized inspection with both exact Group mappings", err)
	}
	return multi, inspector
}

type directoryBatchDriftState struct {
	original         directoryDriftState
	secondMembership organizationpg.DirectoryTeamMembershipObservation
}

func captureDirectoryBatchDriftState(t *testing.T, multi directoryMultiEdgeFixture) directoryBatchDriftState {
	t.Helper()
	fixture := multi.fixture
	state := directoryBatchDriftState{original: captureDirectoryDriftState(t, fixture, multi.generation.ID)}
	repository, err := organizationpg.NewRepository(fixture.provider.f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	state.secondMembership, err = repository.ObserveDirectoryTeamMembership(fixture.provider.f.ctx, organizationpg.DirectoryTeamGrantScope{
		TenantID: fixture.scope.TenantID, OrganizationID: fixture.scope.OrganizationID,
		ProviderID: organization.ID(fixture.scope.ProviderID), ConnectionID: organization.ID(fixture.scope.ConnectionID),
		GroupID: organization.ID(multi.secondGroupID), TeamID: directoryTestTeam, UserID: identity.UserID(fixture.userID),
	})
	if err != nil {
		t.Fatal("observe the second exact source contribution independently of the first Group", err)
	}
	return state
}

func assertDirectoryBatchDriftUnchanged(t *testing.T, multi directoryMultiEdgeFixture, before directoryBatchDriftState) {
	t.Helper()
	if after := captureDirectoryBatchDriftState(t, multi); after != before {
		t.Fatal("batch drift inspection changed a source/local contribution, generation, or protected effect")
	}
}
