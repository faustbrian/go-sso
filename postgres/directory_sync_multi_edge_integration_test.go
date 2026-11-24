//go:build integration

package postgres_test

import (
	"context"
	"encoding/json"
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

func TestNativeDirectorySyncCommitsOrderedMultiEdgeBatchAndReplaysExactReceipts(t *testing.T) {
	multi := newDirectoryMultiEdgeFixture(t)
	fixture := multi.fixture
	f := fixture.provider.f
	worker, generation, batch := multi.worker, multi.generation, multi.batch
	secondGroupID, childIDs := multi.secondGroupID, multi.childIDs

	applied, err := worker.Apply(f.ctx, generation.ID, batch)
	if err != nil || len(applied.ChildOutcomes) != len(childIDs) {
		t.Fatal("native Apply did not resolve both mapped children", err)
	}
	for i, child := range applied.ChildOutcomes {
		if child.Validate() != nil || child.Binding.CommandID != childIDs[i] || child.Outcome != identity.CommitOutcomeCommitted ||
			child.Feature == nil || child.Feature.Operation != sso.DirectoryTeamMembershipOperation() ||
			child.Feature.BeforeVersion != 0 || child.Feature.AfterVersion != 1 || child.AuditEventID == "" {
			t.Fatal("native Apply did not return committed original receipts in batch order", i)
		}
		assertDirectoryMultiEdgeJournalReceipt(t, fixture, child)
	}
	if applied.ChildOutcomes[0].AuditEventID == applied.ChildOutcomes[1].AuditEventID {
		t.Fatal("distinct child transitions reused an audit event")
	}
	successor, err := applied.NextCheckpoint(batch)
	if err != nil || successor == generation.Checkpoint || successor == ([32]byte{}) {
		t.Fatal("complete ordered batch did not produce a combined successor", err)
	}
	status, err := fixture.sync.Status(f.ctx, generation.ID)
	if err != nil || status.State != ssopg.DirectorySyncRunning || status.Checkpoint != successor ||
		status.ReadCount != 2 || status.AppliedCount != 2 || status.RejectedCount != 0 {
		t.Fatal("native status did not expose one combined two-child result", err)
	}
	assertDirectoryMultiEdgeEffects(t, fixture, []string{fixture.groupID, secondGroupID})

	replayed, err := worker.Apply(f.ctx, generation.ID, batch)
	if err != nil || !reflect.DeepEqual(replayed.ChildOutcomes, applied.ChildOutcomes) || replayed.Checkpoint != successor {
		t.Fatal("exact multi-edge replay did not recover the same ordered receipts and successor", err)
	}
	if replaySuccessor, err := replayed.NextCheckpoint(batch); err != nil || replaySuccessor != successor {
		t.Fatal("replayed result no longer binds the complete original batch", err)
	}
	if after, err := fixture.sync.Status(f.ctx, generation.ID); err != nil || after != status {
		t.Fatal("exact replay advanced or rewrote the original generation", err)
	}
	assertDirectoryMultiEdgeEffects(t, fixture, []string{fixture.groupID, secondGroupID})

	reordered := batch
	reordered.Deltas = []sso.DirectoryDelta{batch.Deltas[1], batch.Deltas[0]}
	distinct := batch
	distinct.Deltas = make([]sso.DirectoryDelta, len(batch.Deltas))
	for i, original := range batch.Deltas {
		edge, err := original.GroupMembership()
		if err != nil {
			t.Fatal(err)
		}
		id, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		distinct.Deltas[i], err = sso.NewDirectoryGroupMembershipDelta(id, edge.GroupID, edge.MemberID, edge.Action)
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, test := range []struct {
		name  string
		batch sso.DirectoryDeltaBatch
	}{
		{name: "reordered original child IDs", batch: reordered},
		{name: "distinct child IDs", batch: distinct},
	} {
		t.Run(test.name, func(t *testing.T) {
			out, err := worker.Apply(f.ctx, generation.ID, test.batch)
			if err == nil || out.Checkpoint != ([32]byte{}) {
				t.Fatal("a different batch reused the consumed predecessor")
			}
			if after, err := fixture.sync.Status(f.ctx, generation.ID); err != nil || after != status {
				t.Fatal("rejected stale predecessor changed the combined generation", err)
			}
			assertDirectoryMultiEdgeEffects(t, fixture, []string{fixture.groupID, secondGroupID})
			for _, child := range applied.ChildOutcomes {
				assertDirectoryMultiEdgeJournalReceipt(t, fixture, child)
			}
		})
	}
}

func TestNativeDirectorySyncMultiEdgeCountsOnlyDefinitiveRejections(t *testing.T) {
	for _, tc := range []struct {
		name      string
		committed uint64
	}{
		{name: "committed prefix and rejected suffix", committed: 1},
		{name: "all rejected without a hold", committed: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			multi := newDirectoryMultiEdgeFixture(t)
			fixture, f := multi.fixture, multi.fixture.provider.f
			if tc.committed == 0 {
				fixture.withdrawSourceMember(t)
			}
			current, err := fixture.groups.Execute(f.ctx, scim.Request{
				Operation: scim.GroupGet, Credential: fixture.bearer, ResourceID: multi.secondGroupID,
			})
			if err != nil || current.Status != 200 || current.ETag == "" {
				t.Fatal("read the second exact source group", current.Status, err)
			}
			changed, err := fixture.groups.Execute(f.ctx, scim.Request{
				Operation: scim.GroupReplace, Credential: fixture.bearer, ResourceID: multi.secondGroupID, IfMatch: current.ETag,
				IdempotencyKey: "native-directory-reject-second", ContentType: "application/scim+json",
				Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Second directory group","members":[]}`),
			})
			if err != nil || changed.Status != 200 {
				t.Fatal("remove the second edge through real SCIM", changed.Status, err)
			}
			settled, err := multi.worker.Apply(f.ctx, multi.generation.ID, multi.batch)
			if err != nil || len(settled.ChildOutcomes) != 2 {
				t.Fatal("complete terminal evidence did not settle", err)
			}
			for i, receipt := range settled.ChildOutcomes {
				want := identity.CommitOutcomeNotCommitted
				if uint64(i) < tc.committed {
					want = identity.CommitOutcomeCommitted
				}
				if receipt.Binding.CommandID != multi.childIDs[i] || receipt.Outcome != want || receipt.Validate() != nil {
					t.Fatal("unexpected original child outcome", i)
				}
			}
			next, err := settled.NextCheckpoint(multi.batch)
			if err != nil || next == multi.generation.Checkpoint {
				t.Fatal("terminal batch has no distinct successor", err)
			}
			status, err := fixture.sync.Status(f.ctx, multi.generation.ID)
			if err != nil || status.Checkpoint != next || status.ReadCount != 2 || status.AppliedCount != tc.committed || status.RejectedCount != 2-tc.committed {
				t.Fatalf("settlement miscounted definitive child outcomes: %+v, %v", status, err)
			}
			replayed, err := multi.worker.Apply(f.ctx, multi.generation.ID, multi.batch)
			if err != nil || !reflect.DeepEqual(settled, replayed) {
				t.Fatal("exact rejection replay changed original receipts", err)
			}
			var appliedGrants uint64
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM organization.directory_team_grants WHERE active`).Scan(&appliedGrants); err != nil || appliedGrants != tc.committed {
				t.Fatal("a rejected child left a grant", appliedGrants, err)
			}
		})
	}
}

func TestNativeDirectorySyncMultiEdgeRecoversOriginalPrefixBeforeRunningSuffix(t *testing.T) {
	multi := newDirectoryMultiEdgeFixture(t)
	fixture, batch, generation := multi.fixture, multi.batch, multi.generation
	f := fixture.provider.f
	held, original := multi.holdFirstChild(t)
	multi.rejectCompetingBatch(t, held)
	multi.assertOnlyOriginalPrefixEffects(t, original)

	resolved, err := multi.worker.Apply(f.ctx, generation.ID, batch)
	if err != nil || len(resolved.ChildOutcomes) != 2 || !reflect.DeepEqual(resolved.ChildOutcomes[0], original) {
		t.Fatal("exact retry did not retain its original committed prefix and finish the suffix", err)
	}
	for i, child := range resolved.ChildOutcomes {
		if child.Binding.CommandID != multi.childIDs[i] || child.Outcome != identity.CommitOutcomeCommitted || child.Validate() != nil {
			t.Fatal("recovery replaced an original child or returned an unresolved outcome", i)
		}
		assertDirectoryMultiEdgeJournalReceipt(t, fixture, child)
	}
	checkpoint, err := resolved.NextCheckpoint(batch)
	if err != nil || checkpoint == generation.Checkpoint || checkpoint == ([32]byte{}) {
		t.Fatal("complete recovery did not yield the combined original successor", err)
	}
	want := held
	want.State, want.Version, want.Checkpoint = ssopg.DirectorySyncRunning, held.Version+1, checkpoint
	want.ReadCount, want.AppliedCount = 2, 2
	if status, err := fixture.sync.Status(f.ctx, generation.ID); err != nil || status != want {
		t.Fatal("recovery did not settle the complete batch exactly once", err)
	}
	assertDirectoryMultiEdgeEffects(t, fixture, []string{fixture.groupID, multi.secondGroupID})

	replayed, err := multi.worker.Apply(f.ctx, generation.ID, batch)
	if err != nil || !reflect.DeepEqual(replayed, resolved) {
		t.Fatal("recovery replay changed the original ordered receipts or successor", err)
	}
	if status, err := fixture.sync.Status(f.ctx, generation.ID); err != nil || status != want {
		t.Fatal("recovery replay advanced the cursor or counts twice", err)
	}
	assertDirectoryMultiEdgeEffects(t, fixture, []string{fixture.groupID, multi.secondGroupID})
}

func TestNativeDirectorySyncMultiEdgeRecoversExpiredOriginalSuffixReservation(t *testing.T) {
	multi := newDirectoryMultiEdgeFixture(t)
	fixture, f := multi.fixture, multi.fixture.provider.f
	held, original := multi.holdFirstChild(t)
	loss, fault := providerLossService(t, f, fixture.provider.config, "INSERT INTO identity.commands")
	loss, err := loss.ForOrganization(string(fixture.scope.OrganizationID))
	if err != nil {
		t.Fatal(err)
	}
	sync, err := loss.DirectorySync(fixture.scope.ConnectionID, directoryAdminPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	worker, err := sync.WithGroupEdges(multi.config)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := worker.Apply(f.ctx, held.ID, multi.batch); err == nil || out.Checkpoint != ([32]byte{}) || !fault.lost.Load() {
		t.Fatal("suffix allocation did not lose its actual reservation acknowledgment", err)
	}
	if current, err := fixture.sync.Status(f.ctx, held.ID); err != nil || current != held {
		t.Fatal("unknown suffix reservation moved the predecessor", err)
	}
	// Age only the task-owned fixture lease. This simulates a crashed worker
	// without waiting out a production-length lease or creating a fake receipt.
	tag, err := f.pool.Raw().Exec(f.ctx, `UPDATE identity.commands SET lease_until=created_at
 WHERE tenant_id=$1 AND purpose=$2 AND state='pending'
 AND command_id=decode(translate($3,'-_','+/')||'==','base64')`, string(fixture.scope.TenantID),
		sso.DirectoryTeamMembershipOperation().OperationID, string(multi.childIDs[1]))
	if err != nil || tag.RowsAffected() != 1 {
		t.Fatal("could not age the exact original pending suffix lease", err)
	}
	settled, err := multi.worker.Apply(f.ctx, held.ID, multi.batch)
	if err != nil || len(settled.ChildOutcomes) != 2 || !reflect.DeepEqual(settled.ChildOutcomes[0], original) ||
		settled.ChildOutcomes[1].Binding.CommandID != multi.childIDs[1] || settled.ChildOutcomes[1].Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("expired exact reservation was not authoritatively recovered without a grant", err)
	}
	status, err := fixture.sync.Status(f.ctx, held.ID)
	if err != nil || status.Checkpoint != settled.Checkpoint || status.ReadCount != 2 || status.AppliedCount != 1 || status.RejectedCount != 1 {
		t.Fatal("expired reservation recovery did not settle the original exact receipts", err)
	}
	var grants int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM organization.directory_team_grants WHERE active`).Scan(&grants); err != nil || grants != 1 {
		t.Fatal("expired suffix reservation acquired a grant", grants, err)
	}
}

func TestNativeDirectorySyncMultiEdgeCancelStopsAfterOriginalCommittedPrefix(t *testing.T) {
	multi := newDirectoryMultiEdgeFixture(t)
	fixture, batch, generation := multi.fixture, multi.batch, multi.generation
	f := fixture.provider.f
	held, original := multi.holdFirstChild(t)
	request := ssopg.DirectorySyncCancelRequest{
		GenerationID: generation.ID, ExpectedVersion: held.Version,
		Key: directoryGenerationKey(t, "directory-cancel-multi-edge-prefix"),
	}
	_, err := fixture.sync.Cancel(f.ctx, request)
	if err != nil && !errors.Is(err, sso.ErrDirectoryReconciliation) {
		t.Fatal("native cancellation could not stop the held original batch", err)
	}
	stopping, err := fixture.sync.Status(f.ctx, generation.ID)
	if err != nil || stopping.Checkpoint != generation.Checkpoint || stopping.ReadCount != 0 || stopping.AppliedCount != 0 ||
		stopping.RejectedCount != 0 || (stopping.State != ssopg.DirectorySyncCanceling && stopping.State != ssopg.DirectorySyncCanceled) {
		t.Fatal("cancellation moved the incomplete batch cursor or settled its counts", err)
	}
	multi.rejectCompetingBatch(t, stopping)
	multi.assertOnlyOriginalPrefixEffects(t, original)

	for attempt := 0; attempt < 2; attempt++ {
		prefix, err := multi.worker.Apply(f.ctx, generation.ID, batch)
		if !errors.Is(err, sso.ErrDirectoryReconciliation) || prefix.Checkpoint != ([32]byte{}) ||
			len(prefix.ChildOutcomes) != 1 || !reflect.DeepEqual(prefix.ChildOutcomes[0], original) {
			t.Fatal("canceled exact retry did not report only the verified original prefix", attempt, err)
		}
		if checkpoint, err := prefix.NextCheckpoint(batch); !errors.Is(err, sso.ErrDirectoryReconciliation) || checkpoint != ([32]byte{}) {
			t.Fatal("a canceled prefix authorized an incomplete batch successor", attempt, err)
		}
		status, err := fixture.sync.Status(f.ctx, generation.ID)
		if err != nil || status.State != ssopg.DirectorySyncCanceled || status.Checkpoint != generation.Checkpoint ||
			status.ReadCount != 0 || status.AppliedCount != 0 || status.RejectedCount != 0 {
			t.Fatal("prefix recovery did not finalize cancellation at the original predecessor with zero settled counts", attempt, err)
		}
		if attempt == 0 {
			stopping = status
		} else if status != stopping {
			t.Fatal("repeated prefix recovery changed the finalized cancellation")
		}
		if _, err := fixture.sync.Cancel(f.ctx, request); err != nil && !errors.Is(err, sso.ErrDirectoryReconciliation) {
			t.Fatal("repeated native cancellation lost its stopped original batch", attempt, err)
		}
		if after, err := fixture.sync.Status(f.ctx, generation.ID); err != nil || after != stopping {
			t.Fatal("cancel replay changed the finalized generation", attempt, err)
		}
		multi.assertOnlyOriginalPrefixEffects(t, original)
	}
}

func TestNativeDirectorySyncMultiEdgeLateReservationCannotChangeStoppedPrefix(t *testing.T) {
	multi := newDirectoryMultiEdgeFixture(t)
	fixture, f := multi.fixture, multi.fixture.provider.f
	held, original := multi.holdFirstChild(t)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	config := multi.config
	policy := config.Authorization
	config.Authorization = directoryChildPolicyFunc(func(ctx context.Context, d authorization.DecisionContext) (authorization.Decision, error) {
		id, _ := d.Request.Resource.Attributes["identity.command.id"].String()
		admission, _ := d.Request.Resource.Attributes["identity.command.read-admission"].Bool()
		if admission && id == string(multi.childIDs[1]) {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return authorization.Decision{}, ctx.Err()
			}
		}
		return policy.Decide(ctx, d)
	})
	stale, err := fixture.sync.WithGroupEdges(config)
	if err != nil {
		t.Fatal(err)
	}
	var staleErr error
	go func() {
		defer close(done)
		_, staleErr = stale.Apply(f.ctx, held.ID, multi.batch)
	}()
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
		<-done
	})
	select {
	case <-entered:
	case <-done:
		t.Fatal("active worker stopped before suffix admission", staleErr)
	case <-time.After(2 * time.Second):
		t.Fatal("active suffix did not reach the admission barrier")
	}
	request := ssopg.DirectorySyncCancelRequest{GenerationID: held.ID, ExpectedVersion: held.Version,
		Key: directoryGenerationKey(t, "directory-cancel-before-late-suffix-reservation")}
	if _, err := fixture.sync.Cancel(f.ctx, request); err != nil {
		t.Fatal(err)
	}
	prefix, err := multi.worker.Apply(f.ctx, held.ID, multi.batch)
	if !errors.Is(err, sso.ErrDirectoryReconciliation) || len(prefix.ChildOutcomes) != 1 || !reflect.DeepEqual(prefix.ChildOutcomes[0], original) {
		t.Fatal("initial stop did not preserve original prefix", err)
	}
	close(release)
	<-done
	if staleErr == nil {
		t.Fatal("stale active worker settled a stopped batch")
	}
	var outcome string
	var encoded []byte
	err = f.pool.Raw().QueryRow(f.ctx, `SELECT state,result FROM identity.commands WHERE tenant_id=$1 AND purpose=$2
 AND command_id=decode(translate($3,'-_','+/')||'==','base64')`, string(fixture.scope.TenantID),
		sso.DirectoryTeamMembershipOperation().OperationID, string(multi.childIDs[1])).Scan(&outcome, &encoded)
	var rejected identity.CommandResult
	if err != nil || outcome != "aborted" || json.Unmarshal(encoded, &rejected) != nil || rejected.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("test did not exercise a late terminal suffix reservation", outcome, err)
	}
	again, err := multi.worker.Apply(f.ctx, held.ID, multi.batch)
	if !errors.Is(err, sso.ErrDirectoryReconciliation) || !reflect.DeepEqual(again, prefix) {
		t.Fatal("late rejected suffix changed the stopped prefix or cursor", err)
	}
	status, err := fixture.sync.Status(f.ctx, held.ID)
	if err != nil || status.State != ssopg.DirectorySyncCanceled || status.Checkpoint != held.Checkpoint || status.ReadCount != 0 || status.AppliedCount != 0 {
		t.Fatal("late suffix mutated the canceled generation", err)
	}
}

type directoryChildPolicyFunc func(context.Context, authorization.DecisionContext) (authorization.Decision, error)

func (f directoryChildPolicyFunc) Decide(ctx context.Context, d authorization.DecisionContext) (authorization.Decision, error) {
	return f(ctx, d)
}

type directoryMultiEdgeFixture struct {
	fixture       directoryGroupApplyFixture
	config        ssopg.DirectorySyncGroupEdgesConfig
	worker        *ssopg.DirectoryGroupSyncService
	generation    ssopg.DirectorySyncGeneration
	batch         sso.DirectoryDeltaBatch
	secondGroupID string
	childIDs      []identity.CommandID
}

func newDirectoryMultiEdgeFixture(t *testing.T) directoryMultiEdgeFixture {
	t.Helper()
	fixture := newDirectoryGroupApplyFixture(t)
	f := fixture.provider.f
	secondGroup, err := fixture.groups.Execute(f.ctx, scim.Request{
		Operation: scim.GroupCreate, Credential: fixture.bearer,
		IdempotencyKey: "native-directory-second-source-group", ContentType: "application/scim+json",
		Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Second directory group","members":[{"type":"User","value":"` + fixture.userID + `"}]}`),
	})
	if err != nil {
		t.Fatal("create second edge through native SCIM", err)
	}
	secondGroupID := directoryFixtureSCIMID(t, secondGroup, 201)
	if secondGroupID == fixture.groupID {
		t.Fatal("native SCIM did not allocate distinct source groups")
	}
	config := fixture.workerConfig(t)
	config.Mapping, err = scimorganization.NewDirectoryMapper(scimorganization.DirectoryMappingConfig{
		TenantID: fixture.scope.TenantID, OrganizationID: fixture.scope.OrganizationID,
		ProviderID: sso.ProviderID(fixture.scope.ProviderID), ConnectionID: fixture.scope.ConnectionID, MappingVersion: 1,
		Groups: []scimorganization.DirectoryGroupTeamMapping{
			{GroupID: fixture.groupID, TeamID: directoryTestTeam},
			{GroupID: secondGroupID, TeamID: directoryTestTeam},
		},
		Members: []scimorganization.DirectoryMemberUserMapping{{MemberID: fixture.userID, UserID: identity.UserID(fixture.userID)}},
	})
	if err != nil {
		t.Fatal("configure both source groups explicitly", err)
	}
	worker, err := fixture.sync.WithGroupEdges(config)
	if err != nil {
		t.Fatal("select native multi-edge worker", err)
	}
	generation := fixture.start(t)
	batch := fixture.batch(t, generation, sso.DirectoryMembershipAdd)
	secondChildID, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	secondEdge, err := sso.NewDirectoryGroupMembershipDelta(secondChildID, secondGroupID, fixture.userID, sso.DirectoryMembershipAdd)
	if err != nil {
		t.Fatal(err)
	}
	batch.Deltas = append(batch.Deltas, secondEdge)
	firstEdge, err := batch.Deltas[0].GroupMembership()
	if err != nil || firstEdge.CommandID == secondChildID {
		t.Fatal("batch must retain two distinct original child IDs", err)
	}
	return directoryMultiEdgeFixture{fixture: fixture, config: config, worker: worker, generation: generation,
		batch: batch, secondGroupID: secondGroupID, childIDs: []identity.CommandID{firstEdge.CommandID, secondChildID}}
}

func (m directoryMultiEdgeFixture) holdFirstChild(t *testing.T) (ssopg.DirectorySyncGeneration, sso.Completion) {
	t.Helper()
	fixture := m.fixture
	f := fixture.provider.f
	lossy, fault := providerLossService(t, f, fixture.provider.config, "SET state='reconciling',pending_batch")
	lossy, err := lossy.ForOrganization(string(fixture.scope.OrganizationID))
	if err != nil {
		t.Fatal(err)
	}
	bound, err := lossy.DirectorySync(fixture.scope.ConnectionID, directoryAdminPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	worker, err := bound.WithGroupEdges(m.config)
	if err != nil {
		t.Fatal(err)
	}
	uncertain, err := worker.Apply(f.ctx, m.generation.ID, m.batch)
	if !fault.seen.Load() || !fault.lost.Load() || !errors.Is(err, sso.ErrDirectoryReconciliation) || uncertain.Checkpoint != ([32]byte{}) {
		t.Fatal("first original child did not retain its actually lost commit acknowledgment", err)
	}
	want := m.generation
	want.State, want.Version = ssopg.DirectorySyncReconciling, m.generation.Version+1
	status, err := fixture.sync.Status(f.ctx, m.generation.ID)
	if err != nil || status != want {
		t.Fatal("unresolved prefix advanced the predecessor or settled batch counts", err)
	}
	var encoded []byte
	err = f.pool.Raw().QueryRow(f.ctx, `SELECT result FROM identity.commands
 WHERE tenant_id=$1 AND purpose=$2 AND command_id=decode(translate($3,'-_','+/')||'==','base64')
 AND state='committed' AND result_version=1`, string(fixture.scope.TenantID),
		sso.DirectoryTeamMembershipOperation().OperationID, string(m.childIDs[0])).Scan(&encoded)
	if err != nil {
		t.Fatal("first original child did not actually commit before losing acknowledgment", err)
	}
	var original sso.Completion
	if err := json.Unmarshal(encoded, &original); err != nil || original.Validate() != nil ||
		original.Binding.CommandID != m.childIDs[0] || original.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("held prefix does not have its original authoritative committed receipt", err)
	}
	m.assertOnlyOriginalPrefixEffects(t, original)
	return status, original
}

func (m directoryMultiEdgeFixture) rejectCompetingBatch(t *testing.T, held ssopg.DirectorySyncGeneration) {
	t.Helper()
	competing := m.batch
	competing.Deltas = []sso.DirectoryDelta{m.batch.Deltas[1], m.batch.Deltas[0]}
	f := m.fixture.provider.f
	if out, err := m.worker.Apply(f.ctx, m.generation.ID, competing); err == nil || out.Checkpoint != ([32]byte{}) {
		t.Fatal("a competing order took over the original held batch", err)
	}
	if status, err := m.fixture.sync.Status(f.ctx, m.generation.ID); err != nil || status != held {
		t.Fatal("a competing batch changed the held original generation", err)
	}
}

func (m directoryMultiEdgeFixture) assertOnlyOriginalPrefixEffects(t *testing.T, original sso.Completion) {
	t.Helper()
	assertDirectoryCancelGrantAndChildEffects(t, m.fixture)
	assertDirectoryMultiEdgeJournalReceipt(t, m.fixture, original)
	f := m.fixture.provider.f
	var suffixGrants, suffixCommands int
	err := f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT count(*) FROM organization.directory_team_grants WHERE group_id=$1),
 (SELECT count(*) FROM identity.commands WHERE tenant_id=$2 AND purpose=$3
 AND command_id=decode(translate($4,'-_','+/')||'==','base64'))`, m.secondGroupID,
		string(m.fixture.scope.TenantID), sso.DirectoryTeamMembershipOperation().OperationID, string(m.childIDs[1])).Scan(&suffixGrants, &suffixCommands)
	if err != nil || suffixGrants != 0 || suffixCommands != 0 {
		t.Fatal("unobserved original suffix acquired a grant or journal entry", suffixGrants, suffixCommands, err)
	}
}

func assertDirectoryMultiEdgeJournalReceipt(t *testing.T, fixture directoryGroupApplyFixture, expected sso.Completion) {
	t.Helper()
	var state string
	var version int
	var encoded []byte
	err := fixture.provider.f.pool.Raw().QueryRow(fixture.provider.f.ctx, `SELECT state,result_version,result
 FROM identity.commands WHERE tenant_id=$1 AND purpose=$2
 AND command_id=decode(translate($3,'-_','+/')||'==','base64')`,
		string(fixture.scope.TenantID), sso.DirectoryTeamMembershipOperation().OperationID, string(expected.Binding.CommandID)).Scan(&state, &version, &encoded)
	if err != nil || state != "committed" || version != 1 {
		t.Fatal("original child has no committed native journal receipt", err)
	}
	var actual identity.CommandResult
	if err := json.Unmarshal(encoded, &actual); err != nil || !reflect.DeepEqual(actual, expected) {
		t.Fatal("returned child differs from its exact native journal receipt", err)
	}
}

func assertDirectoryMultiEdgeEffects(t *testing.T, fixture directoryGroupApplyFixture, groupIDs []string) {
	t.Helper()
	f := fixture.provider.f
	repository, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: fixture.provider.config.MaximumDuration})
	if err != nil {
		t.Fatal(err)
	}
	for _, groupID := range groupIDs {
		grant := organizationpg.DirectoryTeamGrantScope{
			TenantID: fixture.scope.TenantID, OrganizationID: fixture.scope.OrganizationID,
			ProviderID: organization.ID(fixture.scope.ProviderID), ConnectionID: organization.ID(fixture.scope.ConnectionID),
			GroupID: organization.ID(groupID), TeamID: directoryTestTeam, UserID: identity.UserID(fixture.userID),
		}
		actual, err := repository.ObserveDirectoryTeamMembership(f.ctx, grant)
		if err != nil || !actual.Source || !actual.Local || actual.Version != 1 {
			t.Fatal("source grant or local contribution changed outside its original child", err)
		}
	}
	var grants, audits, events int
	err = f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT count(*) FROM organization.directory_team_grants WHERE version=1 AND active),
 (SELECT count(*) FROM audit.records WHERE action=$1 AND outcome=1),
 (SELECT count(*) FROM outbox_messages WHERE topic='sso.directory_sync.team_membership_changed.v1')`,
		sso.DirectoryTeamMembershipOperation().OperationID).Scan(&grants, &audits, &events)
	if err != nil || grants != 2 || audits != 2 || events != 2 {
		t.Fatal("multi-edge apply duplicated or omitted protected child effects", grants, audits, events, err)
	}
}
