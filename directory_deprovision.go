package sso

import (
	"fmt"
	"log/slog"

	identity "github.com/faustbrian/go-identity"
)

// DirectoryUserDeprovisionOperation identifies the internal, source-owned
// organization deprovisioning child. It is not a global identity lifecycle
// operation, authorization, or evidence of a durable command.
func DirectoryUserDeprovisionOperation() identity.FeatureOperation {
	return identity.FeatureOperation{
		Owner: "sso", OperationID: "identity.sso.directory-sync.apply-user-deprovision",
		SchemaID: "sso.directory-user-deprovision", SchemaVersion: 1,
		RecordRequirement: identity.FeatureRecordRequired,
	}
}

// DirectoryUserDeprovisionState selects the exact source condition for which
// the executor must obtain current evidence. It does not select a local
// disposition. Zero and unrecognized values are invalid.
type DirectoryUserDeprovisionState uint8

const (
	// DirectoryUserInactive requires a live source User explicitly marked inactive.
	DirectoryUserInactive DirectoryUserDeprovisionState = iota + 1
	// DirectoryUserDeleted requires a retained source User tombstone.
	DirectoryUserDeleted
)

// DirectoryUserDeprovision is the detached selection for a User change.
// ResourceID and SourceRevision are the source's case-exact, opaque User
// identity and revision, not a local identity, externalId, or policy choice.
// The executor must still verify the original source observation and resolve
// the configured disposition through the organization authority owner.
type DirectoryUserDeprovision struct {
	CommandID      identity.CommandID
	ResourceID     string
	SourceRevision string
	State          DirectoryUserDeprovisionState
}

// NewDirectoryUserDeprovisionDelta binds the original child to a bounded
// User and exact observed source revision. It performs no lookup, mapping,
// or policy selection. Reuse the same input and command ID on retry.
func NewDirectoryUserDeprovisionDelta(command identity.CommandID, resourceID, sourceRevision string, state DirectoryUserDeprovisionState) (DirectoryDelta, error) {
	if _, err := identity.ParseCommandID(string(command)); err != nil || !directorySourceID(resourceID) ||
		!providerClaimName(sourceRevision) || (state != DirectoryUserInactive && state != DirectoryUserDeleted) {
		return DirectoryDelta{}, ErrInvalidInput
	}
	return DirectoryDelta{user: DirectoryUserDeprovision{
		CommandID: command, ResourceID: resourceID, SourceRevision: sourceRevision, State: state,
	}}, nil
}

// UserDeprovision returns a detached User selection. Zero and Group deltas
// return ErrInvalidInput.
func (d DirectoryDelta) UserDeprovision() (DirectoryUserDeprovision, error) {
	if d.user.State == 0 {
		return DirectoryUserDeprovision{}, ErrInvalidInput
	}
	return d.user, nil
}

func (DirectoryUserDeprovision) Format(s fmt.State, _ rune) {
	_, _ = fmt.Fprint(s, "sso.DirectoryUserDeprovision(redacted)")
}

func (DirectoryUserDeprovision) LogValue() slog.Value {
	return slog.StringValue("sso.DirectoryUserDeprovision(redacted)")
}

func (DirectoryUserDeprovision) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (DirectoryUserDeprovision) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
