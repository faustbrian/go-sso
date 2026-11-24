//go:build integration

package postgres_test

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
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

func TestNativeDirectorySyncCommitsMappedSCIMEdgeBeforeAdvancing(t *testing.T) {
	fixture := newDirectoryGroupApplyFixture(t)
	ctx := fixture.provider.f.ctx
	start := fixture.start(t)
	worker := fixture.worker(t, fixture.sync)
	organizationRepo, err := organizationpg.NewRepository(fixture.provider.f.pool, organizationpg.Config{
		MaximumDuration: fixture.provider.config.MaximumDuration,
	})
	if err != nil {
		t.Fatal(err)
	}
	grant := organizationpg.DirectoryTeamGrantScope{
		TenantID: fixture.scope.TenantID, OrganizationID: fixture.scope.OrganizationID,
		ProviderID: organization.ID(fixture.scope.ProviderID), ConnectionID: organization.ID(fixture.scope.ConnectionID),
		GroupID: organization.ID(fixture.groupID), TeamID: directoryTestTeam, UserID: identity.UserID(fixture.userID),
	}

	add := fixture.batch(t, start, sso.DirectoryMembershipAdd)
	result, err := worker.Apply(ctx, start.ID, add)
	if err != nil || len(result.ChildOutcomes) != 1 || result.ChildOutcomes[0].Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("mapped add did not obtain a committed original child", err)
	}
	added, err := result.NextCheckpoint(add)
	if err != nil || added == start.Checkpoint {
		t.Fatal("committed child did not yield the original successor", err)
	}
	status, err := fixture.sync.Status(ctx, start.ID)
	if err != nil || status.Checkpoint != added || status.AppliedCount != 1 {
		t.Fatal("native status did not expose committed cursor", err)
	}
	if actual, err := organizationRepo.ObserveDirectoryTeamMembership(ctx, grant); err != nil || !actual.Source || !actual.Local || actual.Version != 1 {
		t.Fatal("directory add did not preserve source and local contributions", err)
	}
	replay, err := worker.Apply(ctx, start.ID, add)
	if err != nil || len(replay.ChildOutcomes) != 1 || replay.ChildOutcomes[0].Binding != result.ChildOutcomes[0].Binding ||
		replay.ChildOutcomes[0].AuditEventID != result.ChildOutcomes[0].AuditEventID || replay.Checkpoint != added {
		t.Fatal("exact add did not recover its original receipt and checkpoint", err)
	}

	// A removal request alone is not authority: the actual SCIM group still
	// has this edge, so the current source grant and cursor must survive.
	premature := fixture.batch(t, status, sso.DirectoryMembershipRemove)
	if _, err := worker.Apply(ctx, start.ID, premature); err == nil {
		t.Fatal("withdrawal without the matching SCIM state succeeded")
	}
	if observed, err := fixture.sync.Status(ctx, start.ID); err != nil || observed.Checkpoint != added {
		t.Fatal("rejected source change advanced the cursor", err)
	}
	if actual, err := organizationRepo.ObserveDirectoryTeamMembership(ctx, grant); err != nil || !actual.Source || !actual.Local || actual.Version != 1 {
		t.Fatal("rejected source change mutated the original team state", err)
	}

	fixture.withdrawSourceMember(t)
	remove := fixture.batch(t, status, sso.DirectoryMembershipRemove)
	withdrawn, err := worker.Apply(ctx, start.ID, remove)
	if err != nil || len(withdrawn.ChildOutcomes) != 1 || withdrawn.ChildOutcomes[0].Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual SCIM withdrawal did not obtain the original committed child", err)
	}
	removed, err := withdrawn.NextCheckpoint(remove)
	if err != nil || removed == added {
		t.Fatal("withdrawal did not yield a distinct successor", err)
	}
	if observed, err := fixture.sync.Status(ctx, start.ID); err != nil || observed.Checkpoint != removed || observed.AppliedCount != 2 {
		t.Fatal("native status did not retain the committed withdrawal cursor", err)
	}
	if actual, err := organizationRepo.ObserveDirectoryTeamMembership(ctx, grant); err != nil || actual.Source || !actual.Local || actual.Version != 2 {
		t.Fatal("withdrawal removed the local contribution or lost its source tombstone", err)
	}
}

func TestNativeDirectorySyncRecoversOriginalChildAfterLostAcknowledgment(t *testing.T) {
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
	if !fault.seen.Load() || !fault.lost.Load() || !errors.Is(err, sso.ErrDirectoryReconciliation) ||
		uncertain.Checkpoint != ([32]byte{}) {
		t.Fatal("lost child acknowledgment did not retain reconciliation without disclosing a successor", err)
	}
	pending, err := fixture.sync.Status(ctx, generation.ID)
	if err != nil || pending.State != ssopg.DirectorySyncReconciling || pending.Checkpoint != generation.Checkpoint || pending.AppliedCount != 0 {
		t.Fatal("an unresolved child advanced the durable cursor", err)
	}
	healthy := fixture.worker(t, fixture.sync)
	competing := fixture.batch(t, generation, sso.DirectoryMembershipAdd)
	if out, err := healthy.Apply(ctx, generation.ID, competing); err == nil || out.Checkpoint != ([32]byte{}) {
		t.Fatal("a competing child could take over the original pending batch", err)
	}
	resolved, err := healthy.Apply(ctx, generation.ID, batch)
	if err != nil || len(resolved.ChildOutcomes) != 1 || resolved.ChildOutcomes[0].Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("retry did not recover the committed original child", err)
	}
	expected, err := resolved.NextCheckpoint(batch)
	if err != nil || expected == generation.Checkpoint {
		t.Fatal("resolved original child did not produce the successor", err)
	}
	status, err := fixture.sync.Status(ctx, generation.ID)
	if err != nil || status.State != ssopg.DirectorySyncRunning || status.Checkpoint != expected || status.AppliedCount != 1 {
		t.Fatal("recovered child did not install exactly one successor", err)
	}
	var grants, audits, events int
	err = fixture.provider.f.pool.Raw().QueryRow(ctx, `SELECT
 (SELECT count(*) FROM organization.directory_team_grants WHERE version=1 AND active),
 (SELECT count(*) FROM audit.records WHERE action=$1 AND outcome=1),
 (SELECT count(*) FROM outbox_messages WHERE topic='sso.directory_sync.team_membership_changed.v1')`,
		sso.DirectoryTeamMembershipOperation().OperationID).Scan(&grants, &audits, &events)
	if err != nil || grants != 1 || audits != 1 || events != 1 {
		t.Fatal("recovery duplicated or omitted original protected effects", grants, audits, events, err)
	}
}

func TestNativeDirectorySyncGroupEdgesCannotApplyDryRun(t *testing.T) {
	fixture := newDirectoryGroupApplyFixture(t)
	ctx := fixture.provider.f.ctx
	dry, err := fixture.sync.Start(ctx, ssopg.DirectorySyncStartRequest{
		ProviderID: sso.ProviderID(fixture.scope.ProviderID), ProviderVersion: fixture.providerVersion,
		MappingVersion: 1, Mode: ssopg.DirectorySyncDryRun, Key: directoryGenerationKey(t, "directory-group-dry"),
	})
	if err != nil || dry.Completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("generate actual dry-run state", err)
	}
	batch := fixture.batch(t, dry.Generation, sso.DirectoryMembershipAdd)
	if result, err := fixture.worker(t, fixture.sync).Apply(ctx, dry.Generation.ID, batch); err == nil || result.Checkpoint != ([32]byte{}) {
		t.Fatal("dry-run accepted an actual source change", err)
	}
	status, err := fixture.sync.Status(ctx, dry.Generation.ID)
	if err != nil || status != dry.Generation {
		t.Fatal("dry-run leaked a cursor or durable apply change", err)
	}
	var grants int
	if err := fixture.provider.f.pool.Raw().QueryRow(ctx, "SELECT count(*) FROM organization.directory_team_grants").Scan(&grants); err != nil || grants != 0 {
		t.Fatal("dry-run created a source grant", err)
	}
}

func TestNativeDirectorySyncRejectsExpiredApplyPolicyDuringWork(t *testing.T) {
	fixture := newDirectoryGroupApplyFixture(t)
	f := fixture.provider.f
	generation := fixture.start(t)
	if _, err := f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION organization.directory_test_delay() RETURNS trigger
 LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.4); RETURN NEW; END $$;
 CREATE TRIGGER directory_test_delay BEFORE INSERT ON organization.directory_team_grants
 FOR EACH ROW EXECUTE FUNCTION organization.directory_test_delay()`); err != nil {
		t.Fatal("install local delay after the original policy decision", err)
	}
	var deadline time.Time
	config := fixture.workerConfig(t)
	config.ApplyAuthorization = directoryGroupPolicy(func(_ context.Context, d authorization.DecisionContext, epoch uint64) (ssopg.ProviderUpdateAuthorizationEvidence, error) {
		deadline = d.Request.Environment.Time.Add(200 * time.Millisecond)
		return ssopg.ProviderUpdateAuthorizationEvidence{Context: d, Decision: authorization.Decision{Outcome: authorization.Allow, Revision: d.PolicyRevision},
			ActorAuthorizationVersion: epoch, ValidUntil: deadline}, nil
	})
	worker, err := fixture.sync.WithGroupEdges(config)
	if err != nil {
		t.Fatal(err)
	}
	batch := fixture.batch(t, generation, sso.DirectoryMembershipAdd)
	out, err := worker.Apply(f.ctx, generation.ID, batch)
	if deadline.IsZero() || time.Now().Before(deadline) || err == nil || out.Checkpoint != ([32]byte{}) {
		t.Fatal("expired original policy authorized a grant or successor", err)
	}
	status, err := fixture.sync.Status(f.ctx, generation.ID)
	if err != nil || status != generation {
		t.Fatal("expired policy moved the generation or retained a pending claim", err)
	}
	var grants, events int
	err = f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM organization.directory_team_grants),
 (SELECT count(*) FROM outbox_messages WHERE topic='sso.directory_sync.team_membership_changed.v1')`).Scan(&grants, &events)
	if err != nil || grants != 0 || events != 0 {
		t.Fatal("expired policy left a grant or event", grants, events, err)
	}
}

func (f directoryGroupApplyFixture) worker(t *testing.T, sync *ssopg.DirectorySyncService) *ssopg.DirectoryGroupSyncService {
	t.Helper()
	worker, err := sync.WithGroupEdges(f.workerConfig(t))
	if err != nil {
		t.Fatal("select explicit directory edge profile", err)
	}
	return worker
}

func (f directoryGroupApplyFixture) workerConfig(t *testing.T) ssopg.DirectorySyncGroupEdgesConfig {
	t.Helper()
	mapper, err := scimorganization.NewDirectoryMapper(scimorganization.DirectoryMappingConfig{
		TenantID: f.scope.TenantID, OrganizationID: f.scope.OrganizationID,
		ProviderID: sso.ProviderID(f.scope.ProviderID), ConnectionID: f.scope.ConnectionID, MappingVersion: 1,
		Groups:  []scimorganization.DirectoryGroupTeamMapping{{GroupID: f.groupID, TeamID: directoryTestTeam}},
		Members: []scimorganization.DirectoryMemberUserMapping{{MemberID: f.userID, UserID: identity.UserID(f.userID)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := directoryServicePolicy(func(d authorization.DecisionContext) bool {
		return d.Request.Tenant == authorization.TenantID(f.scope.TenantID) &&
			d.Request.Subject.Kind == authorization.SubjectServiceAccount && d.Request.Subject.ID == directoryTestActor &&
			(d.Request.Action == "identity.sso.directory-sync-apply" || d.Request.Action == authorization.Action(sso.DirectoryTeamMembershipOperation().OperationID))
	})
	return ssopg.DirectorySyncGroupEdgesConfig{
		Source: f.groups, Mapping: mapper, Authorization: policy, AuthorityNamespace: directoryTestAuthority,
		ApplyAuthorization: directoryGroupPolicy(func(ctx context.Context, d authorization.DecisionContext, version uint64) (ssopg.ProviderUpdateAuthorizationEvidence, error) {
			allowed, err := policy.Decide(ctx, d)
			return ssopg.ProviderUpdateAuthorizationEvidence{Context: d, Decision: allowed, ActorAuthorizationVersion: version,
				ValidUntil: d.Request.Environment.Time.Add(5 * time.Second)}, err
		}),
	}
}

func (f directoryGroupApplyFixture) batch(t *testing.T, g ssopg.DirectorySyncGeneration, action sso.DirectoryMembershipAction) sso.DirectoryDeltaBatch {
	t.Helper()
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	edge, err := sso.NewDirectoryGroupMembershipDelta(id, f.groupID, f.userID, action)
	if err != nil {
		t.Fatal(err)
	}
	return sso.DirectoryDeltaBatch{
		TenantID: f.scope.TenantID, OrganizationID: f.scope.OrganizationID, ProviderID: sso.ProviderID(f.scope.ProviderID), ConnectionID: f.scope.ConnectionID,
		Generation: g.Number, MappingVersion: g.MappingVersion, PredecessorCheckpoint: g.Checkpoint, Deltas: []sso.DirectoryDelta{edge},
	}
}

func (f directoryGroupApplyFixture) start(t *testing.T) ssopg.DirectorySyncGeneration {
	t.Helper()
	created, err := f.sync.Start(f.provider.f.ctx, ssopg.DirectorySyncStartRequest{
		ProviderID: sso.ProviderID(f.scope.ProviderID), ProviderVersion: f.providerVersion,
		MappingVersion: 1, Mode: ssopg.DirectorySyncApply, Key: directoryGenerationKey(t, "directory-group-apply"),
	})
	if err != nil || created.Completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("start real directory generation", err)
	}
	return created.Generation
}

func (f directoryGroupApplyFixture) withdrawSourceMember(t *testing.T) {
	t.Helper()
	response, err := f.groups.Execute(f.provider.f.ctx, scim.Request{
		Operation: scim.GroupReplace, Credential: f.bearer, ResourceID: f.groupID, IfMatch: f.groupETag,
		IdempotencyKey: "native-directory-source-removal", ContentType: "application/scim+json",
		Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Directory group","members":[]}`),
	})
	if err != nil || response.Status != 200 {
		t.Fatal("remove source member through native SCIM", response.Status, err)
	}
}

type directoryServicePolicy func(authorization.DecisionContext) bool

type directoryGroupPolicy func(context.Context, authorization.DecisionContext, uint64) (ssopg.ProviderUpdateAuthorizationEvidence, error)

func (p directoryGroupPolicy) ObserveDirectoryGroupAuthorization(ctx context.Context, d authorization.DecisionContext, epoch uint64) (ssopg.ProviderUpdateAuthorizationEvidence, error) {
	return p(ctx, d, epoch)
}

func (p directoryServicePolicy) Decide(ctx context.Context, d authorization.DecisionContext) (authorization.Decision, error) {
	if ctx.Err() != nil || d.Validate() != nil {
		return authorization.Decision{}, authorization.ErrDecisionUnavailable
	}
	outcome := authorization.Deny
	if d.PolicyRevision == 1 && p(d) {
		outcome = authorization.Allow
	}
	return authorization.Decision{Outcome: outcome, Revision: d.PolicyRevision}, nil
}

func directoryFixtureSCIMID(t *testing.T, response scim.Response, status int) string {
	t.Helper()
	var body struct {
		ID string `json:"id"`
	}
	if response.Status != status || json.Unmarshal(response.Body, &body) != nil || body.ID == "" || response.ETag == "" {
		t.Fatal("unexpected native SCIM response status or body", strconv.Itoa(response.Status))
	}
	return body.ID
}
