package sso_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	sso "github.com/faustbrian/go-sso"
)

func TestDirectoryUserDeprovisionBindsExactSourceRevisionAndChild(t *testing.T) {
	const command identity.CommandID = "AgICAgICAgICAgICAgICAg"
	const resource, revision = "Source.User", `"Source.Value"`
	batch := directoryBatch(t)
	batch.Deltas[1] = deprovisionDelta(t, command, resource, revision, sso.DirectoryUserInactive)
	projected, err := batch.Deltas[1].UserDeprovision()
	if err != nil || projected.CommandID != command || projected.ResourceID != resource ||
		projected.SourceRevision != revision || projected.State != sso.DirectoryUserInactive {
		t.Fatal("lost original deprovisioning selection", err)
	}
	if _, err := batch.Deltas[1].GroupMembership(); !errors.Is(err, sso.ErrInvalidInput) {
		t.Fatal("legacy Group executor can interpret a User change", err)
	}
	for _, invalid := range []sso.DirectoryDelta{{}, batch.Deltas[0]} {
		if _, err := invalid.UserDeprovision(); !errors.Is(err, sso.ErrInvalidInput) {
			t.Fatal("accepted a non-User selection", err)
		}
	}
	if wire, err := json.Marshal(projected); len(wire) != 0 || !errors.Is(err, sso.ErrSensitiveSerialization) {
		t.Fatal("implicitly serialized the exact source selection", err)
	}
	if got := fmt.Sprintf("%#v", projected); strings.Contains(got, resource) || strings.Contains(got, revision) {
		t.Fatal("implicitly formatted exact source identifiers")
	}

	original, err := batch.Commitment()
	if err != nil || original == ([32]byte{}) {
		t.Fatal("valid mixed batch did not bind its admission", err)
	}
	for _, changed := range []sso.DirectoryDelta{
		deprovisionDelta(t, command, "source.User", revision, sso.DirectoryUserInactive),
		deprovisionDelta(t, command, resource, `"Source.value"`, sso.DirectoryUserInactive),
		deprovisionDelta(t, command, resource, revision, sso.DirectoryUserDeleted),
		directoryMembership(t, command, resource, sso.DirectoryMembershipRemove),
	} {
		snapshot, err := batch.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		snapshot.Deltas[1] = changed
		if binding, err := snapshot.Commitment(); err != nil || binding == original {
			t.Fatal("a changed selection reused the original commitment", err)
		}
	}
	snapshot, err := batch.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Deltas[1] = deprovisionDelta(t, "AQEBAQEBAQEBAQEBAQEBAQ", resource, revision, sso.DirectoryUserInactive)
	if !errors.Is(snapshot.Validate(), sso.ErrInvalidInput) {
		t.Fatal("a Group command ID was reused by a User delta")
	}

	first := directoryReceipt("AQEBAQEBAQEBAQEBAQEBAQ", identity.CommitOutcomeCommitted)
	second := directoryReceipt(command, identity.CommitOutcomeCommitted)
	if _, err := sso.NewDirectoryApplyResult(batch, []sso.Completion{first, second}); !errors.Is(err, sso.ErrInvalidInput) {
		t.Fatal("Group receipt settled a User deprovisioning child", err)
	}
	operation := sso.DirectoryUserDeprovisionOperation()
	second.Binding.OperationID, second.Binding.SchemaID = operation.OperationID, operation.SchemaID
	second.Binding.SchemaVersion, second.Feature.Operation = operation.SchemaVersion, operation
	result, err := sso.NewDirectoryApplyResult(batch, []sso.Completion{first, second})
	if err != nil {
		t.Fatal(err)
	}
	if next, err := result.NextCheckpoint(batch); next == ([32]byte{}) || err != nil {
		t.Fatal("exact ordered User receipt could not settle the batch", err)
	}
	second.Outcome, second.Feature.AfterVersion, second.AuditEventID = identity.CommitOutcomeUnknown, 0, ""
	unresolved, err := sso.NewDirectoryApplyResult(batch, []sso.Completion{first, second})
	if err != nil {
		t.Fatal(err)
	}
	if next, err := unresolved.NextCheckpoint(batch); next != ([32]byte{}) || !errors.Is(err, sso.ErrDirectoryReconciliation) {
		t.Fatal("unknown User outcome advanced the checkpoint", err)
	}
}

func TestDirectoryUserDeprovisionRejectsUnboundSelection(t *testing.T) {
	const command identity.CommandID = "AgICAgICAgICAgICAgICAg"
	for _, invalid := range []struct {
		command            identity.CommandID
		resource, revision string
		state              sso.DirectoryUserDeprovisionState
	}{
		{"unknown", "user", "r1", sso.DirectoryUserInactive},
		{command, "", "r1", sso.DirectoryUserInactive},
		{command, "user", "", sso.DirectoryUserInactive},
		{command, "user", "r\n1", sso.DirectoryUserInactive},
		{command, "user", strings.Repeat("r", 129), sso.DirectoryUserInactive},
		{command, "user", "r1", 0},
		{command, "user", "r1", 3},
	} {
		if _, err := sso.NewDirectoryUserDeprovisionDelta(invalid.command, invalid.resource, invalid.revision, invalid.state); !errors.Is(err, sso.ErrInvalidInput) {
			t.Fatal("accepted invalid source selection", err)
		}
	}
}

func TestDirectoryGroupOnlyCommitmentRemainsCompatible(t *testing.T) {
	batch := directoryBatch(t)
	commitment, err := batch.Commitment()
	if err != nil || fmt.Sprintf("%x", commitment) != "fded824cb16115ac48a94b4f08413e0a5ae827d178970a73886d76fb7bcdc182" {
		t.Fatal("changed the durable Group batch commitment", err)
	}
	receipts := []sso.Completion{
		directoryReceipt("AQEBAQEBAQEBAQEBAQEBAQ", identity.CommitOutcomeCommitted),
		directoryReceipt("AgICAgICAgICAgICAgICAg", identity.CommitOutcomeNotCommitted),
	}
	result, err := sso.NewDirectoryApplyResult(batch, receipts)
	if err != nil || fmt.Sprintf("%x", result.Checkpoint) != "2301e748dd885ee2cddcca7cc5bd046b777328f79129325ec792353d49bd3a7a" {
		t.Fatal("changed the durable Group checkpoint", err)
	}
}

func deprovisionDelta(t *testing.T, command identity.CommandID, resource, revision string, state sso.DirectoryUserDeprovisionState) sso.DirectoryDelta {
	t.Helper()
	delta, err := sso.NewDirectoryUserDeprovisionDelta(command, resource, revision, state)
	if err != nil {
		t.Fatal(err)
	}
	return delta
}
