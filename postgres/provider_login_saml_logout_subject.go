package postgres

import (
	"context"
	"fmt"
	"log/slog"
	"unicode"
	"unicode/utf8"

	"github.com/faustbrian/go-sso"
)

// SAMLLogoutSubject retains the exact signed NameID context, including absent
// qualifiers and SessionIndex. It is evidence for binding to the issued local
// session, not session or logout authority. Do not log or publish its fields.
type SAMLLogoutSubject struct {
	ProviderSubject, SubjectFormat string
	NameQualifier, SPNameQualifier string
	SessionIndex                   string
}

// SAMLVerifiedLoginResponse is one trusted verification result. Evidence and
// LogoutSubject must describe the same verified assertion; callers must not
// parse a second response or reconstruct qualifiers from configuration.
type SAMLVerifiedLoginResponse struct {
	Evidence      SAMLVerifiedResponse
	LogoutSubject SAMLLogoutSubject
}

// SAMLResponseWithLogoutSubjectVerifier verifies the SP response once and
// returns both login evidence and exact signed logout subject context. It has
// the same bounded, no-I/O and no-retention contract as SAMLResponseVerifier.
type SAMLResponseWithLogoutSubjectVerifier func(context.Context, SAMLResponseVerificationInput) (SAMLVerifiedLoginResponse, error)

// SAMLIDPResponseWithLogoutSubjectVerifier verifies the unsolicited response
// once under the same trust contract as SAMLIDPResponseVerifier.
type SAMLIDPResponseWithLogoutSubjectVerifier func(context.Context, SAMLIDPResponseVerificationInput) (SAMLVerifiedLoginResponse, error)

// Only the existing encrypted preparation/origin may encode these scalars.
// Public result types intentionally reject diagnostic serialization.
type samlStoredLogoutSubject SAMLLogoutSubject

func (s samlStoredLogoutSubject) Format(f fmt.State, verb rune) {
	SAMLLogoutSubject(s).Format(f, verb)
}

func (s samlStoredLogoutSubject) LogValue() slog.Value {
	return SAMLLogoutSubject(s).LogValue()
}

func validSAMLLogoutSubject(subject SAMLLogoutSubject, evidence SAMLVerifiedResponse) bool {
	if subject.ProviderSubject != evidence.ProviderSubject || subject.SubjectFormat != evidence.SubjectFormat || subject.SessionIndex != evidence.SessionIndex || subject.ProviderSubject == "" {
		return false
	}
	for _, qualifier := range []string{subject.NameQualifier, subject.SPNameQualifier} {
		if len(qualifier) > 2048 || !utf8.ValidString(qualifier) {
			return false
		}
		for _, character := range qualifier {
			// XML 1.0 characters and the native detached-evidence control policy.
			// Never normalize invalid or lossy qualifier text into another subject.
			if unicode.IsControl(character) || character == 0xfffe || character == 0xffff {
				return false
			}
		}
	}
	return true
}

func validSAMLLoginLogoutSubject(v SAMLVerifiedLoginResponse, idp, sp string) bool {
	return validSAMLLogoutSubject(v.LogoutSubject, v.Evidence) &&
		(v.LogoutSubject.NameQualifier == "" || v.LogoutSubject.NameQualifier == idp) &&
		(v.LogoutSubject.SPNameQualifier == "" || v.LogoutSubject.SPNameQualifier == sp)
}

func (s *ProviderSAMLLoginCompletionService) verifyLoginResponse(ctx context.Context, input SAMLResponseVerificationInput) (SAMLVerifiedLoginResponse, error) {
	if s.verifyLogoutSubject == nil {
		if s.verify == nil {
			return SAMLVerifiedLoginResponse{}, sso.ErrForbidden
		}
		evidence, err := s.verify(ctx, input)
		if err != nil {
			return SAMLVerifiedLoginResponse{}, err
		}
		return SAMLVerifiedLoginResponse{Evidence: evidence}, nil
	}
	verified, err := s.verifyLogoutSubject(ctx, input)
	if err != nil {
		return SAMLVerifiedLoginResponse{}, err
	}
	if !validSAMLResponseEvidence(verified.Evidence, input.Now) || !validSAMLLoginLogoutSubject(verified, input.IdentityProviderEntityID, input.SPEntityID) {
		return SAMLVerifiedLoginResponse{}, sso.ErrForbidden
	}
	return verified, nil
}

func (s *ProviderSAMLIDPAdmissionService) verifyLoginResponse(ctx context.Context, input SAMLIDPResponseVerificationInput) (SAMLVerifiedLoginResponse, error) {
	if s.verifyLogoutSubject == nil {
		if s.verify == nil {
			return SAMLVerifiedLoginResponse{}, sso.ErrForbidden
		}
		evidence, err := s.verify(ctx, input)
		if err != nil {
			return SAMLVerifiedLoginResponse{}, err
		}
		return SAMLVerifiedLoginResponse{Evidence: evidence}, nil
	}
	verified, err := s.verifyLogoutSubject(ctx, input)
	if err != nil {
		return SAMLVerifiedLoginResponse{}, err
	}
	if !validSAMLResponseEvidence(verified.Evidence, input.Now) || !validSAMLLoginLogoutSubject(verified, input.IdentityProviderEntityID, input.SPEntityID) {
		return SAMLVerifiedLoginResponse{}, sso.ErrForbidden
	}
	return verified, nil
}

func (SAMLLogoutSubject) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprint(f, "sso.postgres.SAMLLogoutSubject(redacted)")
}
func (SAMLLogoutSubject) LogValue() slog.Value {
	return slog.StringValue("sso.postgres.SAMLLogoutSubject(redacted)")
}
func (SAMLLogoutSubject) MarshalJSON() ([]byte, error) { return nil, sso.ErrSensitiveSerialization }
func (SAMLLogoutSubject) MarshalText() ([]byte, error) { return nil, sso.ErrSensitiveSerialization }
func (SAMLVerifiedLoginResponse) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprint(f, "sso.postgres.SAMLVerifiedLoginResponse(redacted)")
}
func (SAMLVerifiedLoginResponse) LogValue() slog.Value {
	return slog.StringValue("sso.postgres.SAMLVerifiedLoginResponse(redacted)")
}
func (SAMLVerifiedLoginResponse) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}
func (SAMLVerifiedLoginResponse) MarshalText() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}
