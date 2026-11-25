package sso

import (
	"fmt"
	"log/slog"

	identity "github.com/faustbrian/go-identity"
)

// DirectoryUserAdmissionOperation identifies the internal, source-owned
// organization admission child. It is distinct from deprovisioning and Group
// membership, and grants no authority to provision or activate an identity.
func DirectoryUserAdmissionOperation() identity.FeatureOperation {
	return identity.FeatureOperation{
		Owner: "sso", OperationID: "identity.sso.directory-sync.apply-user-admission",
		SchemaID: "sso.directory-user-admission", SchemaVersion: 1,
		RecordRequirement: identity.FeatureRecordRequired,
	}
}

// DirectoryUserAdmission is the detached selection for a source User's
// organization admission. ResourceID and SourceRevision preserve the exact
// source User identity and revision, not a local identity, externalId, role,
// or permission. Executors must obtain current source and policy authority.
type DirectoryUserAdmission struct {
	CommandID      identity.CommandID
	ResourceID     string
	SourceRevision string
}

// NewDirectoryUserAdmissionDelta binds the original child command to a bounded
// User and exact source revision. It performs no lookup, mapping, admission
// policy selection, or mutation. Reuse the exact input and command on retry.
func NewDirectoryUserAdmissionDelta(command identity.CommandID, resourceID, sourceRevision string) (DirectoryDelta, error) {
	if _, err := identity.ParseCommandID(string(command)); err != nil ||
		!directorySourceID(resourceID) || !providerClaimName(sourceRevision) {
		return DirectoryDelta{}, ErrInvalidInput
	}
	return DirectoryDelta{admission: DirectoryUserAdmission{
		CommandID: command, ResourceID: resourceID, SourceRevision: sourceRevision,
	}}, nil
}

// UserAdmission returns a detached admission selection. Zero, Group and
// deprovisioning deltas return ErrInvalidInput.
func (d DirectoryDelta) UserAdmission() (DirectoryUserAdmission, error) {
	if d.admission.CommandID == "" {
		return DirectoryUserAdmission{}, ErrInvalidInput
	}
	return d.admission, nil
}

func (DirectoryUserAdmission) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("sso.DirectoryUserAdmission(redacted)"))
}

func (DirectoryUserAdmission) LogValue() slog.Value {
	return slog.StringValue("sso.DirectoryUserAdmission(redacted)")
}

func (DirectoryUserAdmission) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (DirectoryUserAdmission) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
