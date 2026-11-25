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
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestNativeDirectoryDriftSeparatesSourceGrantFromIndependentLocalMembership(t *testing.T) {
	fixture := newDirectoryGroupApplyFixture(t)
	ctx := fixture.provider.f.ctx
	generation := fixture.start(t)
	inspector := directoryDriftInspector(t, fixture)
	add := fixture.batch(t, generation, sso.DirectoryMembershipAdd)
	request := directoryDriftRequest(generation, add)
	before := captureDirectoryDriftState(t, fixture, generation.ID)
	if before.membership.Source || !before.membership.Local || before.membership.Version != 0 {
		t.Fatal("fixture must have an independent local membership without this exact source grant")
	}
	missing, err := inspector.ObserveDrift(ctx, request)
	if err != nil || missing != (scimorganization.DirectoryMembershipDrift{
		Kind: scimorganization.DirectoryMembershipDriftMissingSourceGrant, LocalGrant: true,
	}) {
		t.Fatal("independent local membership substituted for the missing source grant", err)
	}
	assertDirectoryDriftUnchanged(t, fixture, generation.ID, before)

	// The ordinary protected Group writer, not inspection, repairs the drift.
	applied, err := fixture.worker(t, fixture.sync).Apply(ctx, generation.ID, add)
	if err != nil || len(applied.ChildOutcomes) != 1 || applied.ChildOutcomes[0].Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("apply original candidate through ordinary Group Apply", err)
	}
	current, err := fixture.sync.Status(ctx, generation.ID)
	if err != nil || current.AppliedCount != 1 || current.Checkpoint == generation.Checkpoint {
		t.Fatal("ordinary Group Apply did not advance the generation", err)
	}
	request.PredecessorCheckpoint = current.Checkpoint
	before = captureDirectoryDriftState(t, fixture, generation.ID)
	if !before.membership.Source || !before.membership.Local || before.membership.Version != 1 {
		t.Fatal("ordinary Group Apply did not retain both exact source and local contributions")
	}
	converged, err := inspector.ObserveDrift(ctx, request)
	if err != nil || converged != (scimorganization.DirectoryMembershipDrift{
		Kind: scimorganization.DirectoryMembershipDriftInSync, LocalGrant: true,
	}) {
		t.Fatal("fresh source and attributed grant were not in sync", err)
	}
	assertDirectoryDriftUnchanged(t, fixture, generation.ID, before)

	fixture.withdrawSourceMember(t)
	remove := fixture.batch(t, current, sso.DirectoryMembershipRemove)
	request = directoryDriftRequest(current, remove)
	before = captureDirectoryDriftState(t, fixture, generation.ID)
	unexpected, err := inspector.ObserveDrift(ctx, request)
	if err != nil || unexpected != (scimorganization.DirectoryMembershipDrift{
		Kind: scimorganization.DirectoryMembershipDriftUnexpectedSourceGrant, LocalGrant: true,
	}) {
		t.Fatal("public SCIM withdrawal did not expose the retained exact source grant", err)
	}
	assertDirectoryDriftUnchanged(t, fixture, generation.ID, before)
	removed, err := fixture.worker(t, fixture.sync).Apply(ctx, generation.ID, remove)
	if err != nil || len(removed.ChildOutcomes) != 1 || removed.ChildOutcomes[0].Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("withdraw through ordinary Group Apply", err)
	}
	current, err = fixture.sync.Status(ctx, generation.ID)
	if err != nil || current.AppliedCount != 2 {
		t.Fatal("observe the ordinary withdrawal successor", err)
	}
	request.PredecessorCheckpoint = current.Checkpoint
	before = captureDirectoryDriftState(t, fixture, generation.ID)
	if before.membership.Source || !before.membership.Local || before.membership.Version != 2 {
		t.Fatal("ordinary withdrawal did not preserve local membership and source tombstone")
	}
	converged, err = inspector.ObserveDrift(ctx, request)
	if err != nil || converged != (scimorganization.DirectoryMembershipDrift{
		Kind: scimorganization.DirectoryMembershipDriftInSync, LocalGrant: true,
	}) {
		t.Fatal("source absence and withdrawn attribution were not in sync", err)
	}
	assertDirectoryDriftUnchanged(t, fixture, generation.ID, before)
}

func TestNativeDirectoryDriftRequiresSeparateAuthorizationAndCurrentExactCandidate(t *testing.T) {
	fixture := newDirectoryGroupApplyFixture(t)
	ctx := fixture.provider.f.ctx
	generation := fixture.start(t)
	batch := fixture.batch(t, generation, sso.DirectoryMembershipAdd)
	request := directoryDriftRequest(generation, batch)
	before := captureDirectoryDriftState(t, fixture, generation.ID)
	if result, err := fixture.worker(t, fixture.sync).ObserveDrift(ctx, request); !errors.Is(err, sso.ErrForbidden) || result != (scimorganization.DirectoryMembershipDrift{}) {
		t.Fatal("ordinary Group Apply permission authorized inspection or disclosed a result", err)
	}
	assertDirectoryDriftUnchanged(t, fixture, generation.ID, before)

	inspector := directoryDriftInspector(t, fixture)
	foreignID, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	wrongProvider := request
	wrongProvider.ProviderID = "different-provider"
	wrongMapping := request
	wrongMapping.MappingVersion++
	wrongGeneration := request
	wrongGeneration.GenerationID = foreignID
	noCandidate := request
	noCandidate.Deltas = nil
	multipleCandidates := request
	multipleCandidates.Deltas = append(append([]sso.DirectoryDelta(nil), request.Deltas...), request.Deltas[0])
	for _, test := range []struct {
		name    string
		request ssopg.DirectoryGroupApplyRequest
	}{
		{"foreign provider", wrongProvider},
		{"different mapping", wrongMapping},
		{"unknown generation", wrongGeneration},
		{"no candidate", noCandidate},
		{"multiple candidates", multipleCandidates},
	} {
		t.Run(test.name, func(t *testing.T) {
			if result, err := inspector.ObserveDrift(ctx, test.request); err == nil || result != (scimorganization.DirectoryMembershipDrift{}) {
				t.Fatal("non-exact candidate disclosed a drift classification", err)
			}
			assertDirectoryDriftUnchanged(t, fixture, generation.ID, before)
		})
	}

	if _, err := fixture.worker(t, fixture.sync).Apply(ctx, generation.ID, batch); err != nil {
		t.Fatal("advance the original generation", err)
	}
	before = captureDirectoryDriftState(t, fixture, generation.ID)
	if result, err := inspector.ObserveDrift(ctx, request); !errors.Is(err, sso.ErrDirectoryReconciliation) || result != (scimorganization.DirectoryMembershipDrift{}) {
		t.Fatal("stale predecessor disclosed current membership drift", err)
	}
	assertDirectoryDriftUnchanged(t, fixture, generation.ID, before)
	current := before.generation
	stopped, err := fixture.sync.Cancel(ctx, ssopg.DirectorySyncCancelRequest{
		GenerationID: current.ID, ExpectedVersion: current.Version, Key: directoryGenerationKey(t, "directory-drift-cancel"),
	})
	if err != nil || stopped.Generation.State != ssopg.DirectorySyncCanceled {
		t.Fatal("cancel the inspected generation", err)
	}
	request.PredecessorCheckpoint = stopped.Generation.Checkpoint
	before = captureDirectoryDriftState(t, fixture, generation.ID)
	if result, err := inspector.ObserveDrift(ctx, request); !errors.Is(err, sso.ErrDirectoryReconciliation) || result != (scimorganization.DirectoryMembershipDrift{}) {
		t.Fatal("canceled generation disclosed a drift classification", err)
	}
	assertDirectoryDriftUnchanged(t, fixture, generation.ID, before)
}

func TestNativeDirectoryDriftCanInspectDryRunWithoutApplying(t *testing.T) {
	fixture := newDirectoryGroupApplyFixture(t)
	ctx := fixture.provider.f.ctx
	dry, err := fixture.sync.Start(ctx, ssopg.DirectorySyncStartRequest{
		ProviderID: sso.ProviderID(fixture.scope.ProviderID), ProviderVersion: fixture.providerVersion,
		MappingVersion: 1, Mode: ssopg.DirectorySyncDryRun, Key: directoryGenerationKey(t, "directory-drift-dry-run"),
	})
	if err != nil || dry.Completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("start a real dry-run generation", err)
	}
	request := directoryDriftRequest(dry.Generation, fixture.batch(t, dry.Generation, sso.DirectoryMembershipAdd))
	before := captureDirectoryDriftState(t, fixture, dry.Generation.ID)
	result, err := directoryDriftInspector(t, fixture).ObserveDrift(ctx, request)
	if err != nil || result != (scimorganization.DirectoryMembershipDrift{
		Kind: scimorganization.DirectoryMembershipDriftMissingSourceGrant, LocalGrant: true,
	}) {
		t.Fatal("dry-run could not inspect the exact missing source grant", err)
	}
	assertDirectoryDriftUnchanged(t, fixture, dry.Generation.ID, before)
}

func TestNativeDirectoryDriftInactiveSourceUserIsConflictNotWithdrawalAuthority(t *testing.T) {
	fixture := newDirectoryGroupApplyFixture(t)
	ctx := fixture.provider.f.ctx
	generation := fixture.start(t)
	user, err := fixture.native.Execute(ctx, scim.Request{Operation: scim.UserGet, Credential: fixture.bearer, ResourceID: fixture.userID})
	if err != nil || user.Status != 200 {
		t.Fatal("read public source User", err)
	}
	inactive, err := fixture.native.Execute(ctx, scim.Request{
		Operation: scim.UserPatch, Credential: fixture.bearer, ResourceID: fixture.userID, IfMatch: user.ETag,
		ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}`),
	})
	if err != nil || inactive.Status != 200 {
		t.Fatal("deactivate source User through public SCIM", err)
	}
	request := directoryDriftRequest(generation, fixture.batch(t, generation, sso.DirectoryMembershipAdd))
	before := captureDirectoryDriftState(t, fixture, generation.ID)
	result, err := directoryDriftInspector(t, fixture).ObserveDrift(ctx, request)
	if err != nil || result != (scimorganization.DirectoryMembershipDrift{
		Kind: scimorganization.DirectoryMembershipDriftConflict, LocalGrant: true,
	}) {
		t.Fatal("inactive source User was treated as an absent or applicable edge", err)
	}
	assertDirectoryDriftUnchanged(t, fixture, generation.ID, before)
}

func directoryDriftInspector(t *testing.T, fixture directoryGroupApplyFixture) *ssopg.DirectoryGroupSyncService {
	t.Helper()
	config := fixture.workerConfig(t)
	ordinary := config.ApplyAuthorization
	inspection := directoryServicePolicy(func(d authorization.DecisionContext) bool {
		return d.Request.Tenant == authorization.TenantID(fixture.scope.TenantID) &&
			d.Request.Subject.Kind == authorization.SubjectServiceAccount && d.Request.Subject.ID == directoryTestActor &&
			d.Request.Action == "identity.sso.directory-sync-inspect-drift"
	})
	config.ApplyAuthorization = directoryGroupPolicy(func(ctx context.Context, d authorization.DecisionContext, epoch uint64) (ssopg.ProviderUpdateAuthorizationEvidence, error) {
		if d.Request.Action != "identity.sso.directory-sync-inspect-drift" {
			return ordinary.ObserveDirectoryGroupAuthorization(ctx, d, epoch)
		}
		decision, err := inspection.Decide(ctx, d)
		return ssopg.ProviderUpdateAuthorizationEvidence{Context: d, Decision: decision, ActorAuthorizationVersion: epoch,
			ValidUntil: d.Request.Environment.Time.Add(5 * time.Second)}, err
	})
	inspector, err := fixture.sync.WithGroupEdges(config)
	if err != nil {
		t.Fatal("select separately authorized drift inspection", err)
	}
	return inspector
}

func directoryDriftRequest(generation ssopg.DirectorySyncGeneration, batch sso.DirectoryDeltaBatch) ssopg.DirectoryGroupApplyRequest {
	return ssopg.DirectoryGroupApplyRequest{GenerationID: generation.ID, ProviderID: generation.Provider,
		MappingVersion: generation.MappingVersion, PredecessorCheckpoint: generation.Checkpoint, Deltas: batch.Deltas}
}

type directoryDriftState struct {
	generation             ssopg.DirectorySyncGeneration
	membership             organizationpg.DirectoryTeamMembershipObservation
	grants, audits, events int
	commands, claims       int
}

func captureDirectoryDriftState(t *testing.T, fixture directoryGroupApplyFixture, generation identity.CommandID) directoryDriftState {
	t.Helper()
	f := fixture.provider.f
	state := directoryDriftState{}
	var err error
	state.generation, err = fixture.sync.Status(f.ctx, generation)
	if err != nil {
		t.Fatal("observe exact generation before comparison", err)
	}
	repository, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	state.membership, err = repository.ObserveDirectoryTeamMembership(f.ctx, organizationpg.DirectoryTeamGrantScope{
		TenantID: fixture.scope.TenantID, OrganizationID: fixture.scope.OrganizationID,
		ProviderID: organization.ID(fixture.scope.ProviderID), ConnectionID: organization.ID(fixture.scope.ConnectionID),
		GroupID: organization.ID(fixture.groupID), TeamID: directoryTestTeam, UserID: identity.UserID(fixture.userID),
	})
	if err != nil {
		t.Fatal("observe exact source and independent local contribution", err)
	}
	err = f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT count(*) FROM organization.directory_team_grants),
 (SELECT count(*) FROM audit.records),
 (SELECT count(*) FROM outbox_messages),
 (SELECT count(*) FROM identity.commands),
 (SELECT count(*) FROM identity.identity_command_id_claims)`).Scan(&state.grants, &state.audits, &state.events, &state.commands, &state.claims)
	if err != nil {
		t.Fatal("observe protected effect counts", err)
	}
	return state
}

func assertDirectoryDriftUnchanged(t *testing.T, fixture directoryGroupApplyFixture, generation identity.CommandID, before directoryDriftState) {
	t.Helper()
	if after := captureDirectoryDriftState(t, fixture, generation); after != before {
		t.Fatal("drift inspection changed exact generation, source/local membership, or protected effects")
	}
}
