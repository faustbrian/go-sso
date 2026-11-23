package saml

import (
	"fmt"
	"io"
	"log/slog"
)

type verifiedPOSTResponseData struct {
	evidence                       POSTResponseEvidence
	nameQualifier, spNameQualifier string
}

// LogoutSubjectEvidence is the exact signed NameID and session index from an
// accepted login assertion. Empty qualifiers or index mean they were absent,
// not configured defaults. This is for strong subject matching under SAML
// Profiles §4.4.4.1; it is not a local session, replay grant or revocation
// authority. Keep it only in custody bound to the issued local session.
type LogoutSubjectEvidence struct {
	ProviderSubject, SubjectFormat string
	NameQualifier, SPNameQualifier string
	SessionIndex                   string
}

// LogoutSubject returns the original subject context for a verified SP login.
// A zero or denied result returns no evidence.
func (v VerifiedPOSTResponse) LogoutSubject() (LogoutSubjectEvidence, error) {
	return v.verified.logoutSubject()
}

// LogoutSubject returns the original subject context for a verified IdP
// arrival. It adds no permission to issue a session before confirmation.
func (v VerifiedIDPInitiatedPOSTResponse) LogoutSubject() (LogoutSubjectEvidence, error) {
	return v.verified.logoutSubject()
}

func (v verifiedPOSTResponseData) logoutSubject() (LogoutSubjectEvidence, error) {
	if v.evidence.AssertionID == "" {
		return LogoutSubjectEvidence{}, ErrInvalidInput
	}
	return LogoutSubjectEvidence{
		ProviderSubject: v.evidence.ProviderSubject, SubjectFormat: v.evidence.SubjectFormat,
		NameQualifier: v.nameQualifier, SPNameQualifier: v.spNameQualifier, SessionIndex: v.evidence.SessionIndex,
	}, nil
}

func (LogoutSubjectEvidence) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "saml.LogoutSubjectEvidence(redacted)")
}
func (LogoutSubjectEvidence) LogValue() slog.Value {
	return slog.StringValue("saml.LogoutSubjectEvidence(redacted)")
}
func (LogoutSubjectEvidence) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (LogoutSubjectEvidence) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
