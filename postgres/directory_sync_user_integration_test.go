//go:build integration

package postgres_test

import (
	"context"
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

type directoryUserPolicy func(context.Context, authorization.DecisionContext, uint64) (ssopg.ProviderUpdateAuthorizationEvidence, error)

func (p directoryUserPolicy) ObserveDirectoryUserAuthorization(ctx context.Context, d authorization.DecisionContext, version uint64) (ssopg.ProviderUpdateAuthorizationEvidence, error) {
	return p(ctx, d, version)
}

func TestNativeDirectorySyncUserGrantWithdrawalAndLostAck(t *testing.T) {
	t.Run("running", func(t *testing.T) { proveDirectoryUserRecovery(t, false) })
	t.Run("canceling", func(t *testing.T) { proveDirectoryUserRecovery(t, true) })
}

func proveDirectoryUserRecovery(t *testing.T, cancelPending bool) {
	t.Helper()
	x := newDirectoryGroupApplyFixture(t, organizationpg.DirectoryMembershipMigrationSource{Version: 687})
	f := x.provider.f
	ctx := f.ctx
	response, err := x.native.Execute(ctx, scim.Request{Operation: scim.UserCreate, Credential: x.bearer, ContentType: "application/scim+json", IdempotencyKey: "native-directory-user-admission", Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"DirectoryOnly","displayName":"Directory-only Member","active":true}`)})
	if err != nil {
		t.Fatal(err)
	}
	resourceID := directoryFixtureSCIMID(t, response, 201)
	userID := identity.UserID(resourceID)
	mapper, err := scimorganization.NewDirectoryUserMapper(scimorganization.DirectoryUserMappingConfig{
		TenantID: x.scope.TenantID, OrganizationID: x.scope.OrganizationID, ProviderID: sso.ProviderID(x.scope.ProviderID), ConnectionID: x.scope.ConnectionID,
		MappingVersion: 1, Members: []scimorganization.DirectoryMemberUserMapping{{MemberID: resourceID, UserID: userID}}, AllowAdmission: true, AllowWithdrawal: true,
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
	config := ssopg.DirectorySyncUsersConfig{Source: x.groups, Mapping: mapper, Authorization: policy, MaximumMembers: 50, MaximumPerUser: 10,
		AuthorityNamespace: directoryTestAuthority, ApplyAuthorization: directoryUserPolicy(func(ctx context.Context, d authorization.DecisionContext, version uint64) (ssopg.ProviderUpdateAuthorizationEvidence, error) {
			allowed, err := policy.Decide(ctx, d)
			return ssopg.ProviderUpdateAuthorizationEvidence{Context: d, Decision: allowed, ActorAuthorizationVersion: version, ValidUntil: d.Request.Environment.Time.Add(5 * time.Second)}, err
		}),
	}
	worker, err := x.sync.WithUserMembership(config)
	if err != nil {
		t.Fatal(err)
	}
	store, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	query := organization.CredentialAuthorityQuery{TenantID: x.scope.TenantID, OrganizationID: x.scope.OrganizationID, ActorID: userID}
	if _, err := store.ObserveCredentialAuthority(ctx, query); err == nil {
		t.Fatal("SCIM User CRUD alone unexpectedly created organization authority")
	}
	generation := x.start(t)
	request := func(at ssopg.DirectorySyncGeneration, delta sso.DirectoryDelta) ssopg.DirectoryUserApplyRequest {
		return ssopg.DirectoryUserApplyRequest{GenerationID: at.ID, ProviderID: at.Provider, MappingVersion: at.MappingVersion, PredecessorCheckpoint: at.Checkpoint, Delta: delta}
	}
	newID := func() identity.CommandID {
		t.Helper()
		id, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	admission, err := sso.NewDirectoryUserAdmissionDelta(newID(), resourceID, string(response.ETag))
	if err != nil {
		t.Fatal(err)
	}
	grantRequest := request(generation, admission)
	granted, err := worker.ApplyGeneration(ctx, grantRequest)
	if err != nil || len(granted.ChildOutcomes) != 1 || granted.ChildOutcomes[0].Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("native generation did not settle User admission", err)
	}
	if replay, err := worker.ApplyGeneration(ctx, grantRequest); err != nil || !reflect.DeepEqual(granted, replay) {
		t.Fatal("admission did not replay the exact result", err)
	}
	member, err := store.ObserveCredentialAuthority(ctx, query)
	if err != nil || member.Actor.Role != organization.RoleMember || !member.Actor.Active {
		t.Fatal("directory-only grant did not reach authoritative organization access", err)
	}
	current, err := x.sync.Status(ctx, generation.ID)
	if err != nil || current.Checkpoint != granted.Checkpoint || current.ReadCount != 1 || current.AppliedCount != 1 {
		t.Fatal("admission cursor or counters did not settle exactly once", err)
	}
	inactive, err := x.native.Execute(ctx, scim.Request{Operation: scim.UserPatch, Credential: x.bearer, ResourceID: resourceID, IfMatch: response.ETag, ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}`)})
	if err != nil {
		t.Fatal(err)
	}
	stale, err := sso.NewDirectoryUserDeprovisionDelta(newID(), resourceID, string(response.ETag), sso.DirectoryUserInactive)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := worker.ApplyGeneration(ctx, request(current, stale)); err == nil || out.Checkpoint != ([32]byte{}) {
		t.Fatal("stale source revision settled a withdrawal", err)
	}
	if after, err := store.ObserveCredentialAuthority(ctx, query); err != nil || after.Actor != member.Actor {
		t.Fatal("stale revision changed membership", err)
	}
	withdraw, err := sso.NewDirectoryUserDeprovisionDelta(newID(), resourceID, string(inactive.ETag), sso.DirectoryUserInactive)
	if err != nil {
		t.Fatal(err)
	}
	withdrawRequest := request(current, withdraw)
	lossy, fault := providerLossService(t, f, x.provider.config, "SET state='reconciling',pending_batch")
	lossy, err = lossy.ForOrganization(string(x.scope.OrganizationID))
	if err != nil {
		t.Fatal(err)
	}
	bound, err := lossy.DirectorySync(x.scope.ConnectionID, directoryAdminPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	losingWorker, err := bound.WithUserMembership(config)
	if err != nil {
		t.Fatal(err)
	}
	uncertain, err := losingWorker.ApplyGeneration(ctx, withdrawRequest)
	if !fault.seen.Load() || !fault.lost.Load() || !errors.Is(err, sso.ErrDirectoryReconciliation) || uncertain.Checkpoint != ([32]byte{}) {
		t.Fatal("lost acknowledgment did not hold the real generation", err)
	}
	if _, err := store.ObserveCredentialAuthority(ctx, query); err == nil {
		t.Fatal("last grant was not actually withdrawn before the lost acknowledgment")
	}
	pending, err := x.sync.Status(ctx, generation.ID)
	if err != nil || pending.State != ssopg.DirectorySyncReconciling || pending.Checkpoint != current.Checkpoint ||
		pending.ReadCount != 1 || pending.AppliedCount != 1 {
		t.Fatal("unknown result was counted or advanced", err)
	}
	competing, err := sso.NewDirectoryUserDeprovisionDelta(newID(), resourceID, string(inactive.ETag), sso.DirectoryUserInactive)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := worker.ApplyGeneration(ctx, request(current, competing)); err == nil || out.Checkpoint != ([32]byte{}) {
		t.Fatal("a competing command replaced the pending withdrawal", err)
	}
	if cancelPending {
		cancel, err := x.sync.Cancel(ctx, ssopg.DirectorySyncCancelRequest{GenerationID: generation.ID,
			ExpectedVersion: pending.Version, Key: directoryGenerationKey(t, "native-directory-user-cancel")})
		if err != nil || cancel.Generation.State != ssopg.DirectorySyncCanceling || cancel.Generation.Checkpoint != current.Checkpoint {
			t.Fatal("cancellation did not keep the original withdrawal pending", err)
		}
		settlementPool, settlementFault := providerLossPool(t, f, "SET state=CASE state WHEN 'canceling' THEN 'canceled'")
		settlement, err := ssopg.NewDirectoryUserSyncService(settlementPool, ssopg.DirectoryUserSyncConfig{
			TenantID: x.scope.TenantID, OrganizationID: x.scope.OrganizationID, ConnectionID: x.scope.ConnectionID,
			Clock: x.provider.config.Clock, MaximumDuration: x.provider.config.MaximumDuration, PolicyID: x.provider.config.PolicyID,
			PolicyVersion: x.provider.config.PolicyVersion, Coordinator: x.provider.config.Coordinator,
		}, config)
		if err != nil {
			t.Fatal(err)
		}
		out, err := settlement.ApplyGeneration(ctx, withdrawRequest)
		if !settlementFault.lost.Load() || !errors.Is(err, sso.ErrDirectoryReconciliation) || out.Checkpoint != ([32]byte{}) {
			t.Fatal("lost cancellation settlement acknowledgment did not remain unknown", err)
		}
	}
	settled, err := worker.ApplyGeneration(ctx, withdrawRequest)
	if err != nil || len(settled.ChildOutcomes) != 1 || settled.ChildOutcomes[0].Outcome != identity.CommitOutcomeCommitted || settled.Checkpoint == current.Checkpoint {
		t.Fatal("could not recover the original withdrawal after its grant disappeared", err)
	}
	if replay, err := worker.ApplyGeneration(ctx, withdrawRequest); err != nil || !reflect.DeepEqual(settled, replay) {
		t.Fatal("withdrawal replay did not retain the exact receipt", err)
	}
	status, err := x.sync.Status(ctx, generation.ID)
	wantState := ssopg.DirectorySyncRunning
	if cancelPending {
		wantState = ssopg.DirectorySyncCanceled
	}
	if err != nil || status.State != wantState || status.Checkpoint != settled.Checkpoint || status.ReadCount != 2 || status.AppliedCount != 2 || status.RejectedCount != 0 {
		t.Fatal("replay counted extra effects or changed the checkpoint", err)
	}
	if cancelPending {
		if out, err := worker.ApplyGeneration(ctx, request(status, competing)); err == nil || out.Checkpoint != ([32]byte{}) {
			t.Fatal("canceled generation admitted a new User child", err)
		}
		if out, err := worker.ApplyGeneration(ctx, grantRequest); err == nil || out.Checkpoint != ([32]byte{}) {
			t.Fatal("canceled generation disclosed a receipt for a superseded User batch", err)
		}
	}
	var global string
	if err := f.pool.Raw().QueryRow(ctx, `SELECT status FROM identity.users WHERE tenant_id=$1 AND user_id=$2`, string(x.scope.TenantID), resourceID).Scan(&global); err != nil || global != "active" {
		t.Fatal("withdrawal changed global identity", err)
	}
	var grantAudits, withdrawalAudits, events int
	err = f.pool.Raw().QueryRow(ctx, `SELECT
 (SELECT count(*) FROM audit.records WHERE action=$1 AND outcome=1),
 (SELECT count(*) FROM audit.records WHERE action=$2 AND outcome=1),
 (SELECT count(*) FROM outbox_messages WHERE topic='sso.directory_sync.membership_changed.v1')`,
		sso.DirectoryUserAdmissionOperation().OperationID, sso.DirectoryUserDeprovisionOperation().OperationID).
		Scan(&grantAudits, &withdrawalAudits, &events)
	if err != nil || grantAudits != 1 || withdrawalAudits != 1 || events != 2 {
		t.Fatal("recovery duplicated or omitted protected effects", grantAudits, withdrawalAudits, events, err)
	}
}
