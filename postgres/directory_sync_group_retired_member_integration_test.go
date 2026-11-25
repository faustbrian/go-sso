//go:build integration

package postgres_test

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestNativeDirectorySyncRecoversCommittedGroupChildAfterMemberRemoval(t *testing.T) {
	fixture := newDirectoryGroupApplyFixture(t)
	f := fixture.provider.f
	ctx := f.ctx
	generation := fixture.start(t)
	batch := fixture.batch(t, generation, sso.DirectoryMembershipAdd)
	edge, err := batch.Deltas[0].GroupMembership()
	if err != nil {
		t.Fatal(err)
	}
	lossy, fault := providerLossService(t, f, fixture.provider.config, "SET state='reconciling',pending_batch")
	lossy, err = lossy.ForOrganization(string(fixture.scope.OrganizationID))
	if err != nil {
		t.Fatal(err)
	}
	bound, err := lossy.DirectorySync(fixture.scope.ConnectionID, directoryAdminPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	uncertain, err := fixture.worker(t, bound).Apply(ctx, generation.ID, batch)
	if !fault.seen.Load() || !fault.lost.Load() || !errors.Is(err, sso.ErrDirectoryReconciliation) || uncertain.Checkpoint != ([32]byte{}) {
		t.Fatal("lost child acknowledgment did not retain the unresolved original batch", err)
	}
	held := generation
	held.State, held.Version = ssopg.DirectorySyncReconciling, generation.Version+1
	if status, err := fixture.sync.Status(ctx, generation.ID); err != nil || status != held {
		t.Fatal("lost acknowledgment advanced the predecessor or settled its counts", err)
	}
	var encoded []byte
	err = f.pool.Raw().QueryRow(ctx, `SELECT result FROM identity.commands
 WHERE tenant_id=$1 AND purpose=$2 AND command_id=decode(translate($3,'-_','+/')||'==','base64')
 AND state='committed' AND result_version=1`, string(fixture.scope.TenantID),
		sso.DirectoryTeamMembershipOperation().OperationID, string(edge.CommandID)).Scan(&encoded)
	if err != nil {
		t.Fatal("original Group child did not actually commit before acknowledgment was lost", err)
	}
	var original sso.Completion
	if err := json.Unmarshal(encoded, &original); err != nil || original.Validate() != nil ||
		original.Binding.CommandID != edge.CommandID || original.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("held Group child has no valid original committed receipt", err)
	}

	readMembers := func() organization.View {
		t.Helper()
		view, err := f.service.ListMembers(ctx, organization.ReadRequest{
			Authentication: f.auth(string(fixture.scope.TenantID), "owner"), OrganizationID: fixture.scope.OrganizationID,
			Limit: 100, CorrelationID: "directory-retired-member-read",
		})
		if err != nil || view.NextCursor != "" {
			t.Fatal("read the complete current member list through the organization owner", err)
		}
		return view
	}
	current := readMembers()
	var memberVersion uint64
	for _, member := range current.Members {
		if member.UserID == identity.UserID(fixture.userID) {
			memberVersion = member.Version
		}
	}
	if memberVersion == 0 {
		t.Fatal("fixture SCIM user has no real active organization membership")
	}
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := f.service.PrepareRemoveMember(ctx, organization.MemberRequest{
		Authentication: f.auth(string(fixture.scope.TenantID), "owner"), CommandID: command,
		OrganizationID: fixture.scope.OrganizationID, UserID: identity.UserID(fixture.userID),
		OrganizationVersion: current.Organization.Version, MemberVersion: memberVersion,
		CorrelationID: "directory-retired-member-removal",
	}, "127.0.0.1")
	if err != nil {
		t.Fatal("prepare ordinary organization member removal after the Group child committed", err)
	}
	removed, err := f.service.Execute(ctx, prepared)
	if err != nil || removed.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("ordinary organization member removal did not commit", err)
	}
	for _, member := range readMembers().Members {
		if member.UserID == identity.UserID(fixture.userID) {
			t.Fatal("organization owner still lists the removed member as active")
		}
	}
	users, err := kernel.NewRepository(f.pool, kernel.Config{MaximumDuration: fixture.provider.config.MaximumDuration})
	if err != nil {
		t.Fatal(err)
	}
	userQuery := identity.GetUserQuery{TenantID: fixture.scope.TenantID, UserID: identity.UserID(fixture.userID)}
	user, err := users.Get(ctx, userQuery)
	if err != nil || user.Status != identity.StatusActive {
		t.Fatal("ordinary member removal must leave the global user active", err)
	}
	if status, err := fixture.sync.Status(ctx, generation.ID); err != nil || status != held {
		t.Fatal("ordinary member removal changed the held directory generation", err)
	}

	type effects struct {
		commands, audits, events int
		grants                   string
	}
	readEffects := func() effects {
		t.Helper()
		var actual effects
		err := f.pool.Raw().QueryRow(ctx, `SELECT
 (SELECT count(*) FROM identity.commands),
 (SELECT count(*) FROM audit.records),
 (SELECT count(*) FROM outbox_messages),
 (SELECT coalesce(jsonb_agg(to_jsonb(g) ORDER BY group_id,team_id,user_id),'[]'::jsonb)::text
 FROM organization.directory_team_grants g)`).Scan(&actual.commands, &actual.audits, &actual.events, &actual.grants)
		if err != nil {
			t.Fatal("read protected effects before or after original-child recovery", err)
		}
		return actual
	}
	before := readEffects()
	healthy := fixture.worker(t, fixture.sync)
	resolved, err := healthy.Apply(ctx, generation.ID, batch)
	if err != nil || len(resolved.ChildOutcomes) != 1 || !reflect.DeepEqual(resolved.ChildOutcomes[0], original) {
		t.Fatal("exact retry after member removal did not recover the identical committed Group child", err)
	}
	next, err := resolved.NextCheckpoint(batch)
	if err != nil || next == generation.Checkpoint {
		t.Fatal("recovered Group child did not yield its original successor", err)
	}
	want := held
	want.State, want.Version, want.Checkpoint = ssopg.DirectorySyncRunning, held.Version+1, next
	want.ReadCount, want.AppliedCount = 1, 1
	if status, err := fixture.sync.Status(ctx, generation.ID); err != nil || status != want {
		t.Fatal("original-child recovery did not advance the held checkpoint exactly once", err)
	}
	replayed, err := healthy.Apply(ctx, generation.ID, batch)
	if err != nil || !reflect.DeepEqual(replayed, resolved) {
		t.Fatal("settled exact retry changed the original receipt or successor", err)
	}
	if status, err := fixture.sync.Status(ctx, generation.ID); err != nil || status != want {
		t.Fatal("settled exact retry advanced the checkpoint or counters again", err)
	}
	fresh := fixture.batch(t, want, sso.DirectoryMembershipAdd)
	if out, err := healthy.Apply(ctx, generation.ID, fresh); err == nil || len(out.ChildOutcomes) != 0 || out.Checkpoint != ([32]byte{}) {
		t.Fatal("original-child recovery admitted a new Group effect for the removed member", err)
	}
	if status, err := fixture.sync.Status(ctx, generation.ID); err != nil || status != want {
		t.Fatal("the rejected new Group command advanced the checkpoint or counters", err)
	}
	assertDirectoryMultiEdgeJournalReceipt(t, fixture, original)
	if after := readEffects(); after != before {
		t.Fatal("original-child recovery created a command, audit, outbox event or changed a source grant")
	}
	if after, err := users.Get(ctx, userQuery); err != nil || after != user {
		t.Fatal("original-child recovery changed the global user", err)
	}
	for _, member := range readMembers().Members {
		if member.UserID == identity.UserID(fixture.userID) {
			t.Fatal("original-child recovery reactivated the removed organization member")
		}
	}
}
