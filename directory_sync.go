package sso

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"log/slog"
	"slices"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

// ErrDirectoryReconciliation means an admitted child is not definitively
// resolved. The original batch and command IDs must be recovered before advancing.
const ErrDirectoryReconciliation Error = "sso: directory reconciliation required"

const maxDirectoryDeltas = 1000

// DirectorySyncContributor maps an admitted SSO batch to authoritative child
// commands. The SSO owner validates the result before moving the cursor. The
// caller must enlist the contributor before writing and retain child receipts
// under their original IDs; this interface alone authorizes no mutation.
type DirectorySyncContributor interface {
	ApplyDirectoryDelta(context.Context, DirectoryDeltaBatch) (DirectoryApplyResult, error)
}

// DirectoryTeamMembershipOperation identifies the exact internal child that
// settles a mapped group member change. It is a registration value for native
// composition, not an external operation, authorization or command receipt.
func DirectoryTeamMembershipOperation() identity.FeatureOperation {
	return identity.FeatureOperation{
		Owner: "sso", OperationID: "identity.sso.directory-sync.apply-child",
		SchemaID: "sso.directory-team-membership", SchemaVersion: 1,
		RecordRequirement: identity.FeatureRecordRequired,
	}
}

// DirectoryMembershipAction selects an explicit change to an external group
// edge. It does not select a local role, team, tenant, or permission.
type DirectoryMembershipAction uint8

const (
	DirectoryMembershipAdd DirectoryMembershipAction = iota + 1
	DirectoryMembershipRemove
)

// DirectoryGroupMembership is the exact source projection for the selected
// group member profile. GroupID identifies a Group; MemberID identifies a User
// in the same connection. The IDs are case-exact provider resource IDs, not
// externalId, local IDs, or display names. Nested group membership is unselected.
type DirectoryGroupMembership struct {
	CommandID identity.CommandID
	GroupID   string
	MemberID  string
	Action    DirectoryMembershipAction
}

// DirectoryDelta is a bounded, immutable source change with a stable child
// command ID. Zero is invalid; no local identity or policy authority follows
// from a valid value.
type DirectoryDelta struct {
	membership DirectoryGroupMembership
}

// NewDirectoryGroupMembershipDelta binds a selected group edge to its original
// child command. It preserves source IDs as supplied and performs no mapping.
func NewDirectoryGroupMembershipDelta(command identity.CommandID, groupID, memberID string, action DirectoryMembershipAction) (DirectoryDelta, error) {
	if _, err := identity.ParseCommandID(string(command)); err != nil ||
		!directorySourceID(groupID) || !directorySourceID(memberID) ||
		(action != DirectoryMembershipAdd && action != DirectoryMembershipRemove) {
		return DirectoryDelta{}, ErrInvalidInput
	}
	return DirectoryDelta{membership: DirectoryGroupMembership{
		CommandID: command, GroupID: groupID, MemberID: memberID, Action: action,
	}}, nil
}

// GroupMembership projects detached source data for trusted mapping. The zero
// value, or a future nonmembership profile, returns ErrInvalidInput.
func (d DirectoryDelta) GroupMembership() (DirectoryGroupMembership, error) {
	if d.membership.Action == 0 {
		return DirectoryGroupMembership{}, ErrInvalidInput
	}
	return d.membership, nil
}

// DirectoryDeltaBatch identifies one ordered batch in an SSO generation.
// Treat Deltas as read-only. Snapshot before retaining it or crossing a
// contributor boundary. The batch conveys no proof of current admission.
type DirectoryDeltaBatch struct {
	TenantID              identity.TenantID
	ProviderID            ProviderID
	ConnectionID          string
	OrganizationID        organization.ID
	Generation            uint64
	MappingVersion        uint64
	PredecessorCheckpoint [32]byte
	Deltas                []DirectoryDelta
}

// Validate checks shape, limits and unique child IDs. The native owner must
// independently admit the current provider, generation and predecessor.
func (b DirectoryDeltaBatch) Validate() error {
	if !directorySourceID(string(b.TenantID)) || !providerClaimName(string(b.ProviderID)) || !directorySourceID(b.ConnectionID) ||
		!protocolAssertionOrganizationID(b.OrganizationID) || b.Generation == 0 || b.MappingVersion == 0 ||
		b.PredecessorCheckpoint == ([32]byte{}) || len(b.Deltas) == 0 || len(b.Deltas) > maxDirectoryDeltas {
		return ErrInvalidInput
	}
	seen := make(map[identity.CommandID]struct{}, len(b.Deltas))
	for _, d := range b.Deltas {
		member, err := d.GroupMembership()
		if err != nil {
			return ErrInvalidInput
		}
		if _, exists := seen[member.CommandID]; exists {
			return ErrInvalidInput
		}
		seen[member.CommandID] = struct{}{}
	}
	return nil
}

// Snapshot returns a validated, detached batch. Do not mutate the source
// slice concurrently with this call.
func (b DirectoryDeltaBatch) Snapshot() (DirectoryDeltaBatch, error) {
	if err := b.Validate(); err != nil {
		return DirectoryDeltaBatch{}, err
	}
	b.Deltas = slices.Clone(b.Deltas)
	return b, nil
}

// Commitment identifies the validated scope, predecessor and ordered changes
// for durable admission and exact retries. Persist it only in the scoped
// generation that owns the batch. It proves neither admission nor completion.
func (b DirectoryDeltaBatch) Commitment() ([32]byte, error) {
	if err := b.Validate(); err != nil {
		return [32]byte{}, err
	}
	return directoryBatchBinding(b), nil
}

// DirectoryApplyResult retains an exact ordered outcome per admitted child.
// Treat ChildOutcomes and their receipt internals as read-only. A zero
// Checkpoint is required during reconciliation. Before any use for cursor
// movement, check NextCheckpoint against the original admitted batch.
type DirectoryApplyResult struct {
	Generation    uint64
	ChildOutcomes []Completion
	Checkpoint    [32]byte

	batch [32]byte
}

// NewDirectoryApplyResult attributes the ordered, structurally valid child
// receipts to an exact batch. Only terminal committed or not-committed
// outcomes produce a successor. Both the slice and its exact feature receipts
// are detached. The adapter must load authoritative results from the original
// coordinator; this function checks bindings, not persistence.
func NewDirectoryApplyResult(batch DirectoryDeltaBatch, outcomes []Completion) (DirectoryApplyResult, error) {
	binding, err := batch.Commitment()
	if err != nil {
		return DirectoryApplyResult{}, err
	}
	checkpoint, err := directorySuccessor(batch, binding, outcomes)
	if err != nil {
		return DirectoryApplyResult{}, err
	}
	copies := slices.Clone(outcomes)
	for i := range copies {
		feature := *copies[i].Feature
		copies[i].Feature = &feature
	}
	return DirectoryApplyResult{Generation: batch.Generation, ChildOutcomes: copies, Checkpoint: checkpoint, batch: binding}, nil
}

// NextCheckpoint checks the result against the original admitted batch. A
// changed result or admission returns ErrInvalidInput; an unresolved child
// returns ErrDirectoryReconciliation with no successor. This decision does
// not store a cursor: native SSO must conditionally persist the successor
// against the same generation, mapping and predecessor.
func (r DirectoryApplyResult) NextCheckpoint(batch DirectoryDeltaBatch) ([32]byte, error) {
	var zero [32]byte
	binding, err := batch.Commitment()
	if err != nil {
		return zero, err
	}
	if r.Generation != batch.Generation || r.batch != binding {
		return zero, ErrInvalidInput
	}
	next, err := directorySuccessor(batch, r.batch, r.ChildOutcomes)
	if err != nil || next != r.Checkpoint {
		return zero, ErrInvalidInput
	}
	if next == zero {
		return zero, ErrDirectoryReconciliation
	}
	return next, nil
}

func directorySourceID(raw string) bool {
	// Tenant and provider-local IDs use the same bounded case-exact shape as
	// other scoped opaque IDs. Canonical IDs still come from their own owners.
	return protocolAssertionOrganizationID(organization.ID(raw))
}

func directoryBatchBinding(batch DirectoryDeltaBatch) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("golib/sso/directory-batch/v1"))
	directoryHashText(h, string(batch.TenantID))
	directoryHashText(h, string(batch.ProviderID))
	directoryHashText(h, batch.ConnectionID)
	directoryHashText(h, string(batch.OrganizationID))
	directoryHashNumber(h, batch.Generation)
	directoryHashNumber(h, batch.MappingVersion)
	_, _ = h.Write(batch.PredecessorCheckpoint[:])
	directoryHashNumber(h, uint64(len(batch.Deltas)))
	for _, delta := range batch.Deltas {
		m := delta.membership
		directoryHashText(h, string(m.CommandID))
		directoryHashText(h, m.GroupID)
		directoryHashText(h, m.MemberID)
		_, _ = h.Write([]byte{byte(m.Action)})
	}
	return [32]byte(h.Sum(nil))
}

func directorySuccessor(batch DirectoryDeltaBatch, binding [32]byte, outcomes []Completion) ([32]byte, error) {
	var zero [32]byte
	if len(outcomes) != len(batch.Deltas) {
		return zero, ErrInvalidInput
	}
	h := sha256.New()
	_, _ = h.Write([]byte("golib/sso/directory-checkpoint/v1"))
	_, _ = h.Write(binding[:])
	settled := true
	operation := DirectoryTeamMembershipOperation()
	for i, receipt := range outcomes {
		b := receipt.Binding
		if b.CommandID != batch.Deltas[i].membership.CommandID || b.TenantID != batch.TenantID ||
			b.ActorKind != authorization.SubjectServiceAccount || receipt.Feature == nil ||
			receipt.Feature.Operation != operation || receipt.Validate() != nil {
			return zero, ErrInvalidInput
		}
		switch receipt.Outcome {
		case identity.CommitOutcomeCommitted, identity.CommitOutcomeNotCommitted:
			_, _ = h.Write([]byte{byte(receipt.Outcome)})
			directoryHashText(h, b.RecordID)
			directoryHashText(h, string(b.UserID))
			directoryHashText(h, string(b.ActorID))
			directoryHashText(h, b.PolicyID)
			directoryHashNumber(h, b.PolicyVersion)
			directoryHashText(h, b.CorrelationID)
			directoryHashNumber(h, receipt.Feature.BeforeVersion)
			directoryHashNumber(h, receipt.Feature.AfterVersion)
			directoryHashText(h, receipt.AuditEventID)
		case identity.CommitOutcomeUnknown, identity.CommitOutcomeInProgress, identity.CommitOutcomeConflict:
			settled = false
		default:
			return zero, ErrInvalidInput
		}
	}
	if !settled {
		return zero, nil
	}
	return [32]byte(h.Sum(nil)), nil
}

func directoryHashText(h hash.Hash, value string) {
	directoryHashNumber(h, uint64(len(value)))
	_, _ = h.Write([]byte(value))
}

func directoryHashNumber(h hash.Hash, value uint64) {
	n := binary.BigEndian.AppendUint64(nil, value)
	_, _ = h.Write(n)
}

func (DirectoryDelta) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("sso.DirectoryDelta(redacted)"))
}
func (DirectoryDeltaBatch) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("sso.DirectoryDeltaBatch(redacted)"))
}
func (DirectoryApplyResult) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("sso.DirectoryApplyResult(redacted)"))
}

func (DirectoryDelta) LogValue() slog.Value { return slog.StringValue("sso.DirectoryDelta(redacted)") }
func (DirectoryDeltaBatch) LogValue() slog.Value {
	return slog.StringValue("sso.DirectoryDeltaBatch(redacted)")
}
func (DirectoryApplyResult) LogValue() slog.Value {
	return slog.StringValue("sso.DirectoryApplyResult(redacted)")
}

func (DirectoryDelta) MarshalJSON() ([]byte, error)       { return nil, ErrSensitiveSerialization }
func (DirectoryDelta) MarshalText() ([]byte, error)       { return nil, ErrSensitiveSerialization }
func (DirectoryDeltaBatch) MarshalJSON() ([]byte, error)  { return nil, ErrSensitiveSerialization }
func (DirectoryDeltaBatch) MarshalText() ([]byte, error)  { return nil, ErrSensitiveSerialization }
func (DirectoryApplyResult) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (DirectoryApplyResult) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
