package sso_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	sso "github.com/faustbrian/go-sso"
)

func TestDirectorySyncCheckpointRequiresEveryExactChildOutcome(t *testing.T) {
	batch := directoryBatch(t)
	committed := directoryReceipt("AQEBAQEBAQEBAQEBAQEBAQ", identity.CommitOutcomeCommitted)
	denied := directoryReceipt("AgICAgICAgICAgICAgICAg", identity.CommitOutcomeNotCommitted)
	result, err := sso.NewDirectoryApplyResult(batch, []sso.Completion{committed, denied})
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := result.NextCheckpoint(batch)
	if err != nil || checkpoint == ([32]byte{}) || checkpoint == batch.PredecessorCheckpoint ||
		checkpoint != result.Checkpoint || result.Generation != 9 || len(result.ChildOutcomes) != 2 {
		t.Fatalf("settled batch: checkpoint=%x, err=%v", checkpoint, err)
	}
	replay, err := sso.NewDirectoryApplyResult(batch, []sso.Completion{committed, denied})
	if err != nil || replay.Checkpoint != checkpoint {
		t.Fatal("unchanged inputs did not yield the original successor")
	}
	for _, outcome := range []identity.CommitOutcome{
		identity.CommitOutcomeUnknown, identity.CommitOutcomeInProgress, identity.CommitOutcomeConflict,
	} {
		pending := directoryReceipt(denied.Binding.CommandID, outcome)
		result, err := sso.NewDirectoryApplyResult(batch, []sso.Completion{committed, pending})
		if err != nil || len(result.ChildOutcomes) != 2 || result.ChildOutcomes[0].Outcome != identity.CommitOutcomeCommitted {
			t.Fatalf("outcome %v lost a known committed sibling: %v", outcome, err)
		}
		if next, err := result.NextCheckpoint(batch); !errors.Is(err, sso.ErrDirectoryReconciliation) || next != ([32]byte{}) {
			t.Fatalf("outcome %v could advance checkpoint: %x, %v", outcome, next, err)
		}
	}
	for key, receipts := range map[string][]sso.Completion{
		"missing":           {committed},
		"extra":             {committed, denied, denied},
		"reversed":          {denied, committed},
		"invalid":           {committed, {}},
		"foreign":           {committed, withDirectoryTenant(denied, "other")},
		"another operation": {committed, unrelatedDirectoryReceipt(denied)},
	} {
		t.Run(key, func(t *testing.T) {
			if got, err := sso.NewDirectoryApplyResult(batch, receipts); !errors.Is(err, sso.ErrInvalidInput) || got.Checkpoint != ([32]byte{}) {
				t.Fatalf("invalid child evidence selected a checkpoint: %v", err)
			}
		})
	}
}

func TestDirectorySyncCheckpointCannotMoveBetweenAdmissions(t *testing.T) {
	batch := directoryBatch(t)
	children := []sso.Completion{
		directoryReceipt("AQEBAQEBAQEBAQEBAQEBAQ", identity.CommitOutcomeCommitted),
		directoryReceipt("AgICAgICAgICAgICAgICAg", identity.CommitOutcomeNotCommitted),
	}
	result, err := sso.NewDirectoryApplyResult(batch, children)
	if err != nil {
		t.Fatal(err)
	}
	children[0].Feature.AfterVersion++
	children[0] = sso.Completion{}
	if _, err := result.NextCheckpoint(batch); err != nil {
		t.Fatal("editing caller slice changed the retained result")
	}
	for key, change := range map[string]func(*sso.DirectoryDeltaBatch){
		"tenant":       func(b *sso.DirectoryDeltaBatch) { b.TenantID = "other" },
		"provider":     func(b *sso.DirectoryDeltaBatch) { b.ProviderID = "other" },
		"connection":   func(b *sso.DirectoryDeltaBatch) { b.ConnectionID = "other" },
		"organization": func(b *sso.DirectoryDeltaBatch) { b.OrganizationID = "other" },
		"generation":   func(b *sso.DirectoryDeltaBatch) { b.Generation++ },
		"mapping":      func(b *sso.DirectoryDeltaBatch) { b.MappingVersion++ },
		"predecessor":  func(b *sso.DirectoryDeltaBatch) { b.PredecessorCheckpoint[0]++ },
		"delta": func(b *sso.DirectoryDeltaBatch) {
			b.Deltas[0] = directoryMembership(t, "AQEBAQEBAQEBAQEBAQEBAQ", "another-group", sso.DirectoryMembershipAdd)
		},
	} {
		t.Run(key, func(t *testing.T) {
			changed := directoryBatch(t)
			change(&changed)
			if got, err := result.NextCheckpoint(changed); !errors.Is(err, sso.ErrInvalidInput) || got != ([32]byte{}) {
				t.Fatalf("changed admission accepted: checkpoint=%x, err=%v", got, err)
			}
		})
	}
	result.Checkpoint[0] ^= 1
	if got, err := result.NextCheckpoint(batch); !errors.Is(err, sso.ErrInvalidInput) || got != ([32]byte{}) {
		t.Fatal("changed successor accepted")
	}
}

func TestDirectorySyncRejectsInvalidBatchAndMembership(t *testing.T) {
	batch := directoryBatch(t)
	for _, change := range []func(*sso.DirectoryDeltaBatch){
		func(b *sso.DirectoryDeltaBatch) { b.TenantID = "" },
		func(b *sso.DirectoryDeltaBatch) { b.ProviderID = "bad id" },
		func(b *sso.DirectoryDeltaBatch) { b.ConnectionID = "" },
		func(b *sso.DirectoryDeltaBatch) { b.OrganizationID = "" },
		func(b *sso.DirectoryDeltaBatch) { b.Generation = 0 },
		func(b *sso.DirectoryDeltaBatch) { b.MappingVersion = 0 },
		func(b *sso.DirectoryDeltaBatch) { b.PredecessorCheckpoint = [32]byte{} },
		func(b *sso.DirectoryDeltaBatch) { b.Deltas = nil },
		func(b *sso.DirectoryDeltaBatch) { b.Deltas = make([]sso.DirectoryDelta, 1001) },
		func(b *sso.DirectoryDeltaBatch) { b.Deltas[1] = sso.DirectoryDelta{} },
		func(b *sso.DirectoryDeltaBatch) { b.Deltas[1] = b.Deltas[0] },
	} {
		copy := directoryBatch(t)
		change(&copy)
		if !errors.Is(copy.Validate(), sso.ErrInvalidInput) {
			t.Fatal("invalid batch accepted")
		}
	}
	for _, delta := range []struct {
		id     identity.CommandID
		group  string
		member string
		action sso.DirectoryMembershipAction
	}{
		{"wrong-id", "group", "member", sso.DirectoryMembershipAdd},
		{"AQEBAQEBAQEBAQEBAQEBAQ", "bad group", "member", sso.DirectoryMembershipRemove},
		{"AQEBAQEBAQEBAQEBAQEBAQ", "group", "", sso.DirectoryMembershipAdd},
		{"AQEBAQEBAQEBAQEBAQEBAQ", "group", "member", 0},
	} {
		if _, err := sso.NewDirectoryGroupMembershipDelta(delta.id, delta.group, delta.member, delta.action); !errors.Is(err, sso.ErrInvalidInput) {
			t.Fatalf("invalid membership accepted: %v", err)
		}
	}
	if err := batch.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestDirectorySyncSnapshotsSourceAndRedactsCustody(t *testing.T) {
	batch := directoryBatch(t)
	snapshot, err := batch.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	batch.Deltas[0] = sso.DirectoryDelta{}
	group, err := snapshot.Deltas[0].GroupMembership()
	if err != nil || group.GroupID != "group" || group.MemberID != "member" || group.Action != sso.DirectoryMembershipAdd ||
		group.CommandID != "AQEBAQEBAQEBAQEBAQEBAQ" {
		t.Fatalf("snapshot did not retain exact group membership: %v", err)
	}
	result, err := sso.NewDirectoryApplyResult(snapshot, []sso.Completion{
		directoryReceipt(group.CommandID, identity.CommitOutcomeCommitted),
		directoryReceipt("AgICAgICAgICAgICAgICAg", identity.CommitOutcomeNotCommitted),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{snapshot.Deltas[0], snapshot, result} {
		if got := fmt.Sprintf("%+v %#v", value, value); !strings.Contains(got, "redacted") || strings.Contains(got, string(group.CommandID)) {
			t.Fatal("directory custody was disclosed by implicit formatting")
		}
		if got, err := json.Marshal(value); !errors.Is(err, sso.ErrSensitiveSerialization) || len(got) != 0 {
			t.Fatalf("directory custody was implicitly serialized: %v", err)
		}
	}
	result.ChildOutcomes[0] = directoryReceipt(group.CommandID, identity.CommitOutcomeNotCommitted)
	if got, err := result.NextCheckpoint(snapshot); !errors.Is(err, sso.ErrInvalidInput) || got != ([32]byte{}) {
		t.Fatal("replaced terminal outcome retained checkpoint authority")
	}
}

func directoryBatch(t *testing.T) sso.DirectoryDeltaBatch {
	t.Helper()
	return sso.DirectoryDeltaBatch{
		TenantID: "tenant", ProviderID: "provider", ConnectionID: "source", OrganizationID: "org",
		Generation: 9, MappingVersion: 7, PredecessorCheckpoint: [32]byte{1, 3, 5},
		Deltas: []sso.DirectoryDelta{
			directoryMembership(t, "AQEBAQEBAQEBAQEBAQEBAQ", "group", sso.DirectoryMembershipAdd),
			directoryMembership(t, "AgICAgICAgICAgICAgICAg", "group", sso.DirectoryMembershipRemove),
		},
	}
}

func directoryMembership(t *testing.T, id identity.CommandID, group string, action sso.DirectoryMembershipAction) sso.DirectoryDelta {
	t.Helper()
	delta, err := sso.NewDirectoryGroupMembershipDelta(id, group, "member", action)
	if err != nil {
		t.Fatal(err)
	}
	return delta
}

func directoryReceipt(id identity.CommandID, outcome identity.CommitOutcome) sso.Completion {
	operation := identity.FeatureOperation{
		Owner: "sso", OperationID: "identity.sso.directory-sync.apply-child",
		SchemaID: "sso.directory-team-membership", SchemaVersion: 1,
		RecordRequirement: identity.FeatureRecordRequired,
	}
	r := identity.CommandResult{
		Binding: identity.CommandBinding{
			CommandID: id, TenantID: "tenant", UserID: "user", ActorID: "service",
			ActorKind: authorization.SubjectServiceAccount, OperationID: operation.OperationID,
			PolicyID: "mapping", PolicyVersion: 7, SchemaID: operation.SchemaID, SchemaVersion: 1,
			CorrelationID: "run", RecordID: "mapped-local-target",
		},
		Outcome: outcome,
		Feature: &identity.FeatureReceipt{Operation: operation},
	}
	switch outcome {
	case identity.CommitOutcomeCommitted:
		r.Feature.AfterVersion = 1
		r.AuditEventID = "audit"
	case identity.CommitOutcomeInProgress:
		r.RetryAfter = time.Second
	}
	return r
}

func withDirectoryTenant(receipt sso.Completion, tenant identity.TenantID) sso.Completion {
	receipt.Binding.TenantID = tenant
	return receipt
}

func unrelatedDirectoryReceipt(receipt sso.Completion) sso.Completion {
	receipt.Binding.OperationID = "identity.user.create"
	receipt.Binding.SchemaID = "unrelated-schema"
	receipt.Binding.RecordID = ""
	receipt.Feature = nil
	return receipt
}
