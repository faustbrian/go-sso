package sso_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	sso "github.com/faustbrian/go-sso"
)

func TestDirectoryUserAdmissionPreservesDetachedExactSelection(t *testing.T) {
	const command identity.CommandID = "AgICAgICAgICAgICAgICAg"
	const resource, revision = "Source.User", `W/"Source.Value"`
	delta := admissionDelta(t, command, resource, revision)
	selected, err := delta.UserAdmission()
	if err != nil || selected.CommandID != command || selected.ResourceID != resource || selected.SourceRevision != revision {
		t.Fatal("lost exact admission selection", err)
	}
	selected.ResourceID, selected.SourceRevision = "other", "other"
	selected, err = delta.UserAdmission()
	if err != nil || selected.ResourceID != resource || selected.SourceRevision != revision {
		t.Fatal("the projection aliases the immutable admission", err)
	}
	for _, value := range []any{delta, selected} {
		formatted := fmt.Sprintf("%v %+v %#v", value, value, value)
		if !strings.Contains(formatted, "redacted") || strings.Contains(formatted, resource) || strings.Contains(formatted, revision) || strings.Contains(formatted, string(command)) {
			t.Fatal("implicit formatting disclosed the source selection")
		}
		if encoded, err := json.Marshal(value); len(encoded) != 0 || !errors.Is(err, sso.ErrSensitiveSerialization) {
			t.Fatal("implicit JSON serialization disclosed the source selection", err)
		}
		text := value.(interface{ MarshalText() ([]byte, error) })
		if encoded, err := text.MarshalText(); len(encoded) != 0 || !errors.Is(err, sso.ErrSensitiveSerialization) {
			t.Fatal("implicit text serialization disclosed the source selection", err)
		}
		var logged bytes.Buffer
		slog.New(slog.NewJSONHandler(&logged, nil)).Info("selection", "value", value)
		if !strings.Contains(logged.String(), "redacted") || strings.Contains(logged.String(), resource) || strings.Contains(logged.String(), string(command)) {
			t.Fatal("structured logging disclosed the source selection")
		}
	}
	for label, nonAdmission := range map[string]sso.DirectoryDelta{
		"zero":        {},
		"group":       directoryMembership(t, command, "group", sso.DirectoryMembershipAdd),
		"deprovision": deprovisionDelta(t, command, resource, revision, sso.DirectoryUserInactive),
	} {
		t.Run(label, func(t *testing.T) {
			if _, err := nonAdmission.UserAdmission(); !errors.Is(err, sso.ErrInvalidInput) {
				t.Fatal("another delta profile projected as admission", err)
			}
		})
	}
	if _, err := delta.GroupMembership(); !errors.Is(err, sso.ErrInvalidInput) {
		t.Fatal("Group executor interpreted User admission", err)
	}
	if _, err := delta.UserDeprovision(); !errors.Is(err, sso.ErrInvalidInput) {
		t.Fatal("deprovision executor interpreted User admission", err)
	}
}

func TestDirectoryUserAdmissionRejectsUnboundedOrMalformedSource(t *testing.T) {
	const command identity.CommandID = "AgICAgICAgICAgICAgICAg"
	for label, input := range map[string]struct {
		command            identity.CommandID
		resource, revision string
	}{
		"invalid command":       {"invalid", "user", "r1"},
		"empty resource":        {command, "", "r1"},
		"resource whitespace":   {command, "source user", "r1"},
		"resource control":      {command, "user\x7f", "r1"},
		"resource invalid UTF8": {command, "\xff", "r1"},
		"oversized resource":    {command, strings.Repeat("u", 129), "r1"},
		"empty revision":        {command, "user", ""},
		"revision whitespace":   {command, "user", "r 1"},
		"revision control":      {command, "user", "r\n1"},
		"revision invalid UTF8": {command, "user", "\xff"},
		"oversized revision":    {command, "user", strings.Repeat("r", 129)},
	} {
		t.Run(label, func(t *testing.T) {
			if _, err := sso.NewDirectoryUserAdmissionDelta(input.command, input.resource, input.revision); !errors.Is(err, sso.ErrInvalidInput) {
				t.Fatal("malformed source selection accepted", err)
			}
		})
	}
	if _, err := sso.NewDirectoryUserAdmissionDelta(command, strings.Repeat("u", 128), strings.Repeat("r", 128)); err != nil {
		t.Fatal("bounded exact inputs rejected", err)
	}
}

func TestDirectoryUserAdmissionUsesDistinctTypedCommitment(t *testing.T) {
	const command identity.CommandID = "AgICAgICAgICAgICAgICAg"
	const resource, revision = "Source.User", `"Source.Value"`
	batch := directoryBatch(t)
	batch.Deltas[1] = admissionDelta(t, command, resource, revision)
	original, err := batch.Commitment()
	if err != nil || original != admissionFramingCommitment(t, batch, 3) {
		t.Fatal("admission did not use v2 typed tag 3 framing", err)
	}
	for label, changed := range map[string]sso.DirectoryDelta{
		"resource case": admissionDelta(t, command, "source.User", revision),
		"revision case": admissionDelta(t, command, resource, `"Source.value"`),
		"child command": admissionDelta(t, "AwMDAwMDAwMDAwMDAwMDAw", resource, revision),
		"deprovision":   deprovisionDelta(t, command, resource, revision, sso.DirectoryUserInactive),
		"group":         directoryMembership(t, command, resource, sso.DirectoryMembershipAdd),
	} {
		t.Run(label, func(t *testing.T) {
			copy, err := batch.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			copy.Deltas[1] = changed
			if got, err := copy.Commitment(); err != nil || got == original {
				t.Fatal("a changed child reused the admission commitment", err)
			}
		})
	}
	snapshot, err := batch.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	batch.Deltas[1] = sso.DirectoryDelta{}
	if got, err := snapshot.Commitment(); err != nil || got != original {
		t.Fatal("editing the source slice changed the retained selection", err)
	}
	legacy := directoryBatch(t)
	legacy.Deltas[1] = deprovisionDelta(t, command, resource, revision, sso.DirectoryUserInactive)
	if got, err := legacy.Commitment(); err != nil || got != admissionFramingCommitment(t, legacy, 2) {
		t.Fatal("existing Group plus deprovision v2 framing changed", err)
	}
}

func TestDirectoryUserAdmissionRejectsCrossTypeStableCommands(t *testing.T) {
	const command identity.CommandID = "AgICAgICAgICAgICAgICAg"
	for label, other := range map[string]sso.DirectoryDelta{
		"group":       directoryMembership(t, command, "group", sso.DirectoryMembershipAdd),
		"deprovision": deprovisionDelta(t, command, "user", "r1", sso.DirectoryUserInactive),
		"admission":   admissionDelta(t, command, "other", "r2"),
	} {
		t.Run(label, func(t *testing.T) {
			batch := directoryBatch(t)
			batch.Deltas = []sso.DirectoryDelta{admissionDelta(t, command, "user", "r1"), other}
			if err := batch.Validate(); !errors.Is(err, sso.ErrInvalidInput) {
				t.Fatal("duplicate child command accepted", err)
			}
			if got, err := batch.Commitment(); got != ([32]byte{}) || !errors.Is(err, sso.ErrInvalidInput) {
				t.Fatal("duplicate command retained a commitment", err)
			}
		})
	}
}

func TestDirectoryUserAdmissionSettlesOnlyExactOperationReceipts(t *testing.T) {
	batch := directoryBatch(t)
	batch.Deltas[1] = admissionDelta(t, "AgICAgICAgICAgICAgICAg", "Source.User", "Revision")
	group := directoryReceipt("AQEBAQEBAQEBAQEBAQEBAQ", identity.CommitOutcomeCommitted)
	admission := admissionReceipt("AgICAgICAgICAgICAgICAg", identity.CommitOutcomeCommitted)
	result, err := sso.NewDirectoryApplyResult(batch, []sso.Completion{group, admission})
	if err != nil {
		t.Fatal(err)
	}
	if next, err := result.NextCheckpoint(batch); err != nil || next == ([32]byte{}) {
		t.Fatal("exact admission did not settle", err)
	}
	for label, operation := range map[string]identity.FeatureOperation{
		"group":          sso.DirectoryTeamMembershipOperation(),
		"deprovision":    sso.DirectoryUserDeprovisionOperation(),
		"wrong owner":    {Owner: "organization", OperationID: "identity.sso.directory-sync.apply-user-admission", SchemaID: "sso.directory-user-admission", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired},
		"schema version": {Owner: "sso", OperationID: "identity.sso.directory-sync.apply-user-admission", SchemaID: "sso.directory-user-admission", SchemaVersion: 2, RecordRequirement: identity.FeatureRecordRequired},
	} {
		t.Run(label, func(t *testing.T) {
			wrong := directoryReceipt(admission.Binding.CommandID, identity.CommitOutcomeCommitted)
			wrong.Binding.OperationID, wrong.Binding.SchemaID, wrong.Binding.SchemaVersion = operation.OperationID, operation.SchemaID, operation.SchemaVersion
			wrong.Feature.Operation = operation
			if _, err := sso.NewDirectoryApplyResult(batch, []sso.Completion{group, wrong}); !errors.Is(err, sso.ErrInvalidInput) {
				t.Fatal("another operation settled admission", err)
			}
			prefix := batch
			prefix.Deltas = []sso.DirectoryDelta{batch.Deltas[1], batch.Deltas[0]}
			if _, err := sso.NewDirectoryReconciliationResult(prefix, []sso.Completion{wrong}); !errors.Is(err, sso.ErrInvalidInput) {
				t.Fatal("another operation survived reconciliation", err)
			}
		})
	}
	for _, other := range []sso.DirectoryDelta{
		directoryMembership(t, admission.Binding.CommandID, "group", sso.DirectoryMembershipAdd),
		deprovisionDelta(t, admission.Binding.CommandID, "Source.User", "Revision", sso.DirectoryUserInactive),
	} {
		batch.Deltas[1] = other
		if _, err := sso.NewDirectoryApplyResult(batch, []sso.Completion{group, admission}); !errors.Is(err, sso.ErrInvalidInput) {
			t.Fatal("admission receipt settled another profile", err)
		}
	}
	operation := sso.DirectoryUserAdmissionOperation()
	expected := identity.FeatureOperation{Owner: "sso", OperationID: "identity.sso.directory-sync.apply-user-admission", SchemaID: "sso.directory-user-admission", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	if operation != expected || operation.Validate() != nil {
		t.Fatal("admission receipt has an unexpected contract")
	}
}

func TestDirectoryUserAdmissionUnknownAndObservedPrefixHoldCheckpoint(t *testing.T) {
	batch := directoryBatch(t)
	batch.Deltas[0] = admissionDelta(t, "AQEBAQEBAQEBAQEBAQEBAQ", "Source.User", "Revision")
	for _, outcome := range []identity.CommitOutcome{identity.CommitOutcomeUnknown, identity.CommitOutcomeInProgress, identity.CommitOutcomeConflict} {
		result, err := sso.NewDirectoryApplyResult(batch, []sso.Completion{
			admissionReceipt("AQEBAQEBAQEBAQEBAQEBAQ", outcome), directoryReceipt("AgICAgICAgICAgICAgICAg", identity.CommitOutcomeCommitted),
		})
		if err != nil {
			t.Fatal(err)
		}
		if next, err := result.NextCheckpoint(batch); next != ([32]byte{}) || !errors.Is(err, sso.ErrDirectoryReconciliation) {
			t.Fatal("unresolved admission advanced checkpoint", err)
		}
	}
	prefix, err := sso.NewDirectoryReconciliationResult(batch, []sso.Completion{admissionReceipt("AQEBAQEBAQEBAQEBAQEBAQ", identity.CommitOutcomeCommitted)})
	if err != nil {
		t.Fatal(err)
	}
	if next, err := prefix.NextCheckpoint(batch); next != ([32]byte{}) || !errors.Is(err, sso.ErrDirectoryReconciliation) {
		t.Fatal("unobserved suffix advanced checkpoint", err)
	}
	for _, outcome := range []identity.CommitOutcome{identity.CommitOutcomeCommitted, identity.CommitOutcomeNotCommitted} {
		settled, err := sso.NewDirectoryApplyResult(batch, []sso.Completion{admissionReceipt("AQEBAQEBAQEBAQEBAQEBAQ", outcome), directoryReceipt("AgICAgICAgICAgICAgICAg", identity.CommitOutcomeCommitted)})
		if err != nil {
			t.Fatal(err)
		}
		if next, err := settled.NextCheckpoint(batch); next == ([32]byte{}) || err != nil {
			t.Fatal("terminal admission held checkpoint", err)
		}
	}
}

func TestDirectoryUserAdmissionMixedBatchBindsAllThreeProfiles(t *testing.T) {
	batch := directoryBatch(t)
	batch.Deltas = append(batch.Deltas[:1],
		admissionDelta(t, "AgICAgICAgICAgICAgICAg", "Source.User", "Revision"),
		deprovisionDelta(t, "AwMDAwMDAwMDAwMDAwMDAw", "Other.User", "r2", sso.DirectoryUserDeleted),
	)
	deprovision := directoryReceipt("AwMDAwMDAwMDAwMDAwMDAw", identity.CommitOutcomeCommitted)
	operation := sso.DirectoryUserDeprovisionOperation()
	deprovision.Binding.OperationID, deprovision.Binding.SchemaID = operation.OperationID, operation.SchemaID
	deprovision.Feature.Operation = operation
	result, err := sso.NewDirectoryApplyResult(batch, []sso.Completion{
		directoryReceipt("AQEBAQEBAQEBAQEBAQEBAQ", identity.CommitOutcomeCommitted),
		admissionReceipt("AgICAgICAgICAgICAgICAg", identity.CommitOutcomeCommitted),
		deprovision,
	})
	if err != nil {
		t.Fatal("distinct ordered profile receipts rejected", err)
	}
	if checkpoint, err := result.NextCheckpoint(batch); checkpoint == ([32]byte{}) || err != nil {
		t.Fatal("mixed profiles did not settle", err)
	}
	batch.Deltas[1] = admissionDelta(t, "AgICAgICAgICAgICAgICAg", "Source.User", "revision")
	if checkpoint, err := result.NextCheckpoint(batch); checkpoint != ([32]byte{}) || !errors.Is(err, sso.ErrInvalidInput) {
		t.Fatal("a changed source revision retained the old successor", err)
	}
}

func admissionDelta(t *testing.T, command identity.CommandID, resource, revision string) sso.DirectoryDelta {
	t.Helper()
	delta, err := sso.NewDirectoryUserAdmissionDelta(command, resource, revision)
	if err != nil {
		t.Fatal(err)
	}
	return delta
}

func admissionReceipt(command identity.CommandID, outcome identity.CommitOutcome) sso.Completion {
	receipt := directoryReceipt(command, outcome)
	operation := sso.DirectoryUserAdmissionOperation()
	receipt.Binding.OperationID, receipt.Binding.SchemaID, receipt.Binding.SchemaVersion = operation.OperationID, operation.SchemaID, operation.SchemaVersion
	receipt.Feature.Operation = operation
	return receipt
}

// This independent byte oracle preserves the existing typed v2 format and
// fixes the admission tag without calling the production commitment builder.
func admissionFramingCommitment(t *testing.T, batch sso.DirectoryDeltaBatch, userTag byte) [32]byte {
	t.Helper()
	var wire bytes.Buffer
	wire.WriteString("golib/sso/directory-batch/v2")
	text := func(value string) {
		_ = binary.Write(&wire, binary.BigEndian, uint64(len(value)))
		wire.WriteString(value)
	}
	text(string(batch.TenantID))
	text(string(batch.ProviderID))
	text(batch.ConnectionID)
	text(string(batch.OrganizationID))
	_ = binary.Write(&wire, binary.BigEndian, batch.Generation)
	_ = binary.Write(&wire, binary.BigEndian, batch.MappingVersion)
	wire.Write(batch.PredecessorCheckpoint[:])
	_ = binary.Write(&wire, binary.BigEndian, uint64(2))
	group, err := batch.Deltas[0].GroupMembership()
	if err != nil {
		t.Fatal(err)
	}
	wire.WriteByte(1)
	text(string(group.CommandID))
	text(group.GroupID)
	text(group.MemberID)
	wire.WriteByte(byte(group.Action))
	wire.WriteByte(userTag)
	if userTag == 2 {
		user, err := batch.Deltas[1].UserDeprovision()
		if err != nil {
			t.Fatal(err)
		}
		text(string(user.CommandID))
		text(user.ResourceID)
		text(user.SourceRevision)
		wire.WriteByte(byte(user.State))
	} else {
		user, err := batch.Deltas[1].UserAdmission()
		if err != nil {
			t.Fatal(err)
		}
		text(string(user.CommandID))
		text(user.ResourceID)
		text(user.SourceRevision)
	}
	return sha256.Sum256(wire.Bytes())
}
