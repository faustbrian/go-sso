package saml

// LocalRevocation projects the exact locally selected session's revocation
// outcome independently of remote SAML support or outcome. It is comparable;
// copies share no mutable state. Its zero value is invalid.
//
// Committed outcomes have Committed true and ReconciliationRequired false.
// Authoritatively not-committed outcomes have both false. Unknown local outcomes
// have Committed false and ReconciliationRequired true.
//
// This value and Validate establish structure only, not authorization or proof
// of persistence. The owner must obtain the outcome from its authoritative local
// session operation; remote SAML fields must never supply SessionID or Version.
type LocalRevocation struct {
	// SessionID is the exact 1..128-byte visible ASCII Identity session ID.
	SessionID string
	// Version is the positive authoritative local revocation version.
	Version uint64
	// Committed is true only for an authoritatively committed local revocation.
	Committed bool
	// ReconciliationRequired is true when local completion is unknown.
	ReconciliationRequired bool
}

// Validate checks the projection without normalizing identity or changing state.
// Invalid identity, a zero version, or committed-but-unknown state returns only
// ErrInvalidInput, without exposing the supplied session identifier.
func (r LocalRevocation) Validate() error {
	if len(r.SessionID) == 0 || len(r.SessionID) > 128 || r.Version == 0 {
		return ErrInvalidInput
	}
	// Identity session IDs use exact visible ASCII bytes, not SAML subject text.
	for i := range len(r.SessionID) {
		if r.SessionID[i] < 33 || r.SessionID[i] > 126 {
			return ErrInvalidInput
		}
	}
	if r.Committed && r.ReconciliationRequired {
		return ErrInvalidInput
	}
	return nil
}
