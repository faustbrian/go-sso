//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestNativeDirectorySyncCancelPreservesAppliedCheckpoint(t *testing.T) {
	fixture := newDirectoryGroupApplyFixture(t)
	ctx := fixture.provider.f.ctx
	generation := fixture.start(t)
	worker := fixture.worker(t, fixture.sync)
	batch := fixture.batch(t, generation, sso.DirectoryMembershipAdd)
	applied, err := worker.Apply(ctx, generation.ID, batch)
	if err != nil || len(applied.ChildOutcomes) != 1 || applied.ChildOutcomes[0].Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("commit the original mapped child before cancellation", err)
	}
	checkpoint, err := applied.NextCheckpoint(batch)
	if err != nil || checkpoint == generation.Checkpoint {
		t.Fatal("original child did not establish its successor", err)
	}
	before, err := fixture.sync.Status(ctx, generation.ID)
	if err != nil || before.State != ssopg.DirectorySyncRunning || before.Checkpoint != checkpoint || before.ReadCount != 1 || before.AppliedCount != 1 {
		t.Fatal("read the applied generation before cancellation", err)
	}
	request := ssopg.DirectorySyncCancelRequest{
		GenerationID: generation.ID, ExpectedVersion: before.Version,
		Key: directoryGenerationKey(t, "directory-cancel-applied"),
	}

	stale := request
	stale.ExpectedVersion = generation.Version
	stale.Key = directoryGenerationKey(t, "directory-cancel-stale")
	if out, err := fixture.sync.Cancel(ctx, stale); !errors.Is(err, sso.ErrConflict) || out.Generation != (ssopg.DirectorySyncGeneration{}) {
		t.Fatal("stale cancellation changed or disclosed the generation", err)
	}
	denied, err := fixture.provider.base.DirectorySync(fixture.scope.ConnectionID, directoryAdminPolicy{deny: true})
	if err != nil {
		t.Fatal(err)
	}
	if out, err := denied.Cancel(ctx, request); !errors.Is(err, sso.ErrForbidden) || out.Generation != (ssopg.DirectorySyncGeneration{}) {
		t.Fatal("denied cancellation exposed a generation", err)
	}
	other, err := fixture.provider.base.DirectorySync("other-source", directoryAdminPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	otherRequest := request
	otherRequest.Key = directoryGenerationKey(t, "directory-cancel-other-source")
	if out, err := other.Cancel(ctx, otherRequest); !errors.Is(err, sso.ErrForbidden) || out.Generation != (ssopg.DirectorySyncGeneration{}) {
		t.Fatal("another source could cancel or observe this generation", err)
	}
	if unchanged, err := fixture.sync.Status(ctx, generation.ID); err != nil || unchanged != before {
		t.Fatal("rejected cancellation changed the original generation", err)
	}

	canceled, err := fixture.sync.Cancel(ctx, request)
	want := before
	want.State, want.Version = ssopg.DirectorySyncCanceled, before.Version+1
	if err != nil || canceled.Completion.Outcome != identity.CommitOutcomeCommitted || canceled.Completion.Validate() != nil || canceled.Generation != want {
		t.Fatal("idle cancellation did not preserve the applied cursor and counts in one transition", err)
	}
	replay, err := fixture.sync.Cancel(ctx, request)
	if err != nil || !reflect.DeepEqual(replay, canceled) {
		t.Fatal("exact cancellation did not recover its original completion and unchanged projection", err)
	}
	if out, err := denied.Cancel(ctx, request); !errors.Is(err, sso.ErrForbidden) || out.Generation != (ssopg.DirectorySyncGeneration{}) {
		t.Fatal("original completion bypassed current cancellation authorization", err)
	}
	future := fixture.batch(t, canceled.Generation, sso.DirectoryMembershipAdd)
	if out, err := worker.Apply(ctx, generation.ID, future); err == nil || out.Checkpoint != ([32]byte{}) {
		t.Fatal("canceled generation admitted a new child", err)
	}
	if status, err := fixture.sync.Status(ctx, generation.ID); err != nil || status != want {
		t.Fatal("replay or rejected child reopened the canceled generation", err)
	}
	assertDirectoryCancelGrantAndChildEffects(t, fixture)
}

func TestNativeDirectorySyncCancelSettlesOnlyOriginalUncertainChild(t *testing.T) {
	fixture := newDirectoryGroupApplyFixture(t)
	ctx := fixture.provider.f.ctx
	generation := fixture.start(t)
	batch := fixture.batch(t, generation, sso.DirectoryMembershipAdd)
	lossy, fault := providerLossService(t, fixture.provider.f, fixture.provider.config, "SET state='reconciling',pending_batch")
	lossy, err := lossy.ForOrganization(string(fixture.scope.OrganizationID))
	if err != nil {
		t.Fatal(err)
	}
	bound, err := lossy.DirectorySync(fixture.scope.ConnectionID, directoryAdminPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	uncertain, err := fixture.worker(t, bound).Apply(ctx, generation.ID, batch)
	if !fault.seen.Load() || !fault.lost.Load() || !errors.Is(err, sso.ErrDirectoryReconciliation) || uncertain.Checkpoint != ([32]byte{}) {
		t.Fatal("actual committed child did not retain its uncertain acknowledgment", err)
	}
	pending, err := fixture.sync.Status(ctx, generation.ID)
	wantPending := generation
	wantPending.State, wantPending.Version = ssopg.DirectorySyncReconciling, generation.Version+1
	if err != nil || pending != wantPending {
		t.Fatal("uncertain original child advanced the predecessor or counts", err)
	}
	assertDirectoryCancelGrantAndChildEffects(t, fixture)

	request := ssopg.DirectorySyncCancelRequest{
		GenerationID: generation.ID, ExpectedVersion: pending.Version,
		Key: directoryGenerationKey(t, "directory-cancel-uncertain"),
	}
	canceling, err := fixture.sync.Cancel(ctx, request)
	wantCanceling := pending
	wantCanceling.State, wantCanceling.Version = ssopg.DirectorySyncCanceling, pending.Version+1
	if err != nil || canceling.Completion.Outcome != identity.CommitOutcomeCommitted || canceling.Completion.Validate() != nil || canceling.Generation != wantCanceling {
		t.Fatal("cancellation discarded the held original or advanced its unresolved checkpoint", err)
	}
	replay, err := fixture.sync.Cancel(ctx, request)
	if err != nil || !reflect.DeepEqual(replay, canceling) {
		t.Fatal("repeated cancellation changed the original completion or pending state", err)
	}
	worker := fixture.worker(t, fixture.sync)
	competing := fixture.batch(t, canceling.Generation, sso.DirectoryMembershipAdd)
	if out, err := worker.Apply(ctx, generation.ID, competing); err == nil || out.Checkpoint != ([32]byte{}) {
		t.Fatal("canceling generation allowed another child to replace the held original", err)
	}
	if status, err := fixture.sync.Status(ctx, generation.ID); err != nil || status != wantCanceling {
		t.Fatal("competing child changed cancellation evidence", err)
	}

	resolved, err := worker.Apply(ctx, generation.ID, batch)
	member, memberErr := batch.Deltas[0].GroupMembership()
	if err != nil || memberErr != nil || len(resolved.ChildOutcomes) != 1 || resolved.ChildOutcomes[0].Outcome != identity.CommitOutcomeCommitted ||
		resolved.ChildOutcomes[0].Binding.CommandID != member.CommandID {
		t.Fatal("cancellation did not recover the exact original committed child", err, memberErr)
	}
	checkpoint, err := resolved.NextCheckpoint(batch)
	if err != nil || checkpoint == generation.Checkpoint {
		t.Fatal("original held child did not yield its committed successor", err)
	}
	wantCanceled := wantCanceling
	wantCanceled.State, wantCanceled.Version = ssopg.DirectorySyncCanceled, wantCanceling.Version+1
	wantCanceled.Checkpoint, wantCanceled.ReadCount, wantCanceled.AppliedCount = checkpoint, 1, 1
	status, err := fixture.sync.Status(ctx, generation.ID)
	if err != nil || status != wantCanceled {
		t.Fatal("settling the held original did not close cancellation with exactly one successor", err)
	}
	replay, err = fixture.sync.Cancel(ctx, request)
	if err != nil || !reflect.DeepEqual(replay.Completion, canceling.Completion) || replay.Generation != wantCanceled {
		t.Fatal("cancel replay lost its original completion or returned stale current status", err)
	}
	future := fixture.batch(t, status, sso.DirectoryMembershipAdd)
	if out, err := worker.Apply(ctx, generation.ID, future); err == nil || out.Checkpoint != ([32]byte{}) {
		t.Fatal("settled cancellation admitted a future child", err)
	}
	again, err := worker.Apply(ctx, generation.ID, batch)
	if err == nil && !reflect.DeepEqual(again, resolved) || err != nil && again.Checkpoint != ([32]byte{}) {
		t.Fatal("closed-generation retry returned another child result or disclosed a rejected successor", err)
	}
	if final, err := fixture.sync.Status(ctx, generation.ID); err != nil || final != wantCanceled {
		t.Fatal("original-child retry reopened cancellation or advanced its counts twice", err)
	}
	assertDirectoryCancelGrantAndChildEffects(t, fixture)
}

func assertDirectoryCancelGrantAndChildEffects(t *testing.T, fixture directoryGroupApplyFixture) {
	t.Helper()
	repository, err := organizationpg.NewRepository(fixture.provider.f.pool, organizationpg.Config{
		MaximumDuration: fixture.provider.config.MaximumDuration,
	})
	if err != nil {
		t.Fatal(err)
	}
	scope := organizationpg.DirectoryTeamGrantScope{
		TenantID: fixture.scope.TenantID, OrganizationID: fixture.scope.OrganizationID,
		ProviderID: organization.ID(fixture.scope.ProviderID), ConnectionID: organization.ID(fixture.scope.ConnectionID),
		GroupID: organization.ID(fixture.groupID), TeamID: directoryTestTeam, UserID: identity.UserID(fixture.userID),
	}
	grant, err := repository.ObserveDirectoryTeamMembership(fixture.provider.f.ctx, scope)
	if err != nil || !grant.Source || !grant.Local || grant.Version != 1 {
		t.Fatal("cancellation or settlement changed the committed source or local contribution", err)
	}
	var grants, audits, events int
	err = fixture.provider.f.pool.Raw().QueryRow(fixture.provider.f.ctx, `SELECT
 (SELECT count(*) FROM organization.directory_team_grants WHERE version=1 AND active),
 (SELECT count(*) FROM audit.records WHERE action=$1 AND outcome=1),
 (SELECT count(*) FROM outbox_messages WHERE topic='sso.directory_sync.team_membership_changed.v1')`,
		sso.DirectoryTeamMembershipOperation().OperationID).Scan(&grants, &audits, &events)
	if err != nil || grants != 1 || audits != 1 || events != 1 {
		t.Fatal("cancellation duplicated or lost original child effects", grants, audits, events, err)
	}
}

func TestNativeDirectorySyncCancelRecoversOriginalLostAcknowledgment(t *testing.T) {
	fixture := newDirectoryGroupApplyFixture(t)
	f := fixture.provider.f
	generation := fixture.start(t)
	lossy, fault := providerLossService(t, f, fixture.provider.config, "SET state=CASE state WHEN 'running' THEN 'canceled'")
	lossy, err := lossy.ForOrganization(string(fixture.scope.OrganizationID))
	if err != nil {
		t.Fatal(err)
	}
	service, err := lossy.DirectorySync(fixture.scope.ConnectionID, directoryAdminPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	request := ssopg.DirectorySyncCancelRequest{GenerationID: generation.ID, ExpectedVersion: generation.Version,
		Key: directoryGenerationKey(t, "directory-cancel-lost-commit")}
	unknown, err := service.Cancel(f.ctx, request)
	if !fault.seen.Load() || !fault.lost.Load() || err == nil || unknown.Completion.Outcome != identity.CommitOutcomeUnknown ||
		unknown.Completion.Binding.CommandID == "" || unknown.Generation != (ssopg.DirectorySyncGeneration{}) {
		t.Fatal("lost cancellation acknowledgment disclosed a generation or lost the original command", unknown.Completion.Outcome, err)
	}
	recovered, err := fixture.sync.Cancel(f.ctx, request)
	want := generation
	want.State, want.Version = ssopg.DirectorySyncCanceled, generation.Version+1
	if err != nil || recovered.Generation != want || recovered.Completion.Outcome != identity.CommitOutcomeCommitted ||
		recovered.Completion.Binding != unknown.Completion.Binding || recovered.Completion.Validate() != nil {
		t.Fatal("original cancel key did not recover the one committed transition", recovered.Completion.Outcome, err)
	}
	changed := request
	changed.ExpectedVersion++
	if result, err := fixture.sync.Cancel(f.ctx, changed); !errors.Is(err, sso.ErrConflict) || result.Generation != (ssopg.DirectorySyncGeneration{}) {
		t.Fatal("original key accepted a different transition", err)
	}
	var audits, events int
	err = f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT count(*) FROM audit.records WHERE action='identity.sso.directory-sync-cancel' AND outcome=1),
 (SELECT count(*) FROM outbox_messages WHERE topic='sso.directory_sync.cancellation_requested.v1')`).Scan(&audits, &events)
	if err != nil || audits != 1 || events != 1 {
		t.Fatal("lost acknowledgment recovery duplicated cancellation effects", audits, events, err)
	}
}

func TestNativeDirectorySyncCancelRejectsConcurrentStaleTransition(t *testing.T) {
	fixture := newDirectoryGroupApplyFixture(t)
	f := fixture.provider.f
	generation := fixture.start(t)
	type attempt struct {
		result ssopg.DirectorySyncCancelResult
		err    error
	}
	ready, outcomes := make(chan struct{}), make(chan attempt, 2)
	for _, name := range []string{"directory-cancel-concurrent-a", "directory-cancel-concurrent-b"} {
		request := ssopg.DirectorySyncCancelRequest{GenerationID: generation.ID, ExpectedVersion: generation.Version,
			Key: directoryGenerationKey(t, name)}
		go func() {
			<-ready
			result, err := fixture.sync.Cancel(f.ctx, request)
			outcomes <- attempt{result: result, err: err}
		}()
	}
	close(ready)
	var successes, conflicts int
	for range 2 {
		got := <-outcomes
		switch {
		case got.err == nil && got.result.Completion.Outcome == identity.CommitOutcomeCommitted:
			successes++
		case errors.Is(got.err, sso.ErrConflict) && got.result.Generation == (ssopg.DirectorySyncGeneration{}):
			conflicts++
		default:
			t.Error("competing transition produced an unexpected outcome", got.result.Completion.Outcome, got.err)
		}
	}
	want := generation
	want.State, want.Version = ssopg.DirectorySyncCanceled, generation.Version+1
	if status, err := fixture.sync.Status(f.ctx, generation.ID); err != nil || status != want || successes != 1 || conflicts != 1 {
		t.Fatal("competing commands did not converge on a single transition", successes, conflicts, err)
	}
}

func TestNativeDirectorySyncCancelDoesNotBypassDeniedReceiptQueryDuringRace(t *testing.T) {
	fixture := newDirectoryGroupApplyFixture(t)
	f := fixture.provider.f
	generation := fixture.start(t)
	request := ssopg.DirectorySyncCancelRequest{GenerationID: generation.ID, ExpectedVersion: generation.Version,
		Key: directoryGenerationKey(t, "directory-cancel-receipt-query-race")}
	gate := &directoryCancelQueryGate{entered: make(chan struct{}), release: make(chan struct{})}
	config := fixture.provider.config
	policy := *config.Coordinator.QueryPolicy
	policy.Authorization = gate
	config.Coordinator.QueryPolicy = &policy
	provider, err := ssopg.NewProviderService(f.pool, config, f.auth(string(fixture.scope.TenantID), "owner"), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	bound, err := provider.ForOrganization(string(fixture.scope.OrganizationID))
	if err != nil {
		t.Fatal(err)
	}
	denied, err := bound.DirectorySync(fixture.scope.ConnectionID, directoryAdminPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	var deniedResult ssopg.DirectorySyncCancelResult
	var deniedErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		deniedResult, deniedErr = denied.Cancel(f.ctx, request)
	}()
	t.Cleanup(func() {
		select {
		case <-gate.release:
		default:
			close(gate.release)
		}
		<-done
	})
	select {
	case <-gate.entered:
	case <-done:
		t.Fatal("request stopped before the separate receipt policy", deniedErr)
	case <-time.After(2 * time.Second):
		t.Fatal("receipt query did not reach the test fence")
	}
	winner, err := fixture.sync.Cancel(f.ctx, request)
	if err != nil || winner.Completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("authorized exact request did not commit during the denied query", err)
	}
	close(gate.release)
	<-done
	if !errors.Is(deniedErr, sso.ErrForbidden) || !reflect.DeepEqual(deniedResult, ssopg.DirectorySyncCancelResult{}) {
		t.Fatal("a denied query learned a racing command's outcome through reservation", deniedResult.Completion.Outcome, deniedErr)
	}
}

type directoryCancelQueryGate struct {
	entered, release chan struct{}
	first            atomic.Bool
}

func (p *directoryCancelQueryGate) Decide(ctx context.Context, d authorization.DecisionContext) (authorization.Decision, error) {
	if d.Request.Action != "identity.sso.directory-sync-cancel" {
		return (fixturePolicy{}).Decide(ctx, d)
	}
	if p.first.CompareAndSwap(false, true) {
		close(p.entered)
		select {
		case <-p.release:
		case <-ctx.Done():
			return authorization.Decision{}, ctx.Err()
		}
	}
	return authorization.Decision{Outcome: authorization.Deny, Revision: d.PolicyRevision}, nil
}
