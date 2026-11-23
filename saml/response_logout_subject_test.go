package saml

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// OASIS Core §§2.2.2, 2.2.3, 3.3.4; Profiles §§4.1.5, 4.4.4.1.
// Logout must use the strongly matching identifier originally signed by the
// IdP, not one reconstructed from the account name or the selected entities.
func TestVerifiedPOSTLogoutSubjectRetainsOnlySignedFields(t *testing.T) {
	key, certificate := idpResponseSigningFixture(t)
	sp, err := NewPOSTResponseProfile(POSTResponseConfig{SPEntityID: fixtureSP, IdentityProviderEntityID: fixtureIdP,
		AssertionConsumerURL: fixtureACS, SigningCertificates: [][]byte{certificate}})
	if err != nil {
		t.Fatal(err)
	}
	idp, err := NewIDPInitiatedPOSTResponseProfile(idpResponseConfigFixture(certificate))
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"SP initiated", "IdP initiated"} {
		t.Run(mode, func(t *testing.T) {
			verify := func(t *testing.T, f idpResponseFixture) (LogoutSubjectEvidence, error, error) {
				t.Helper()
				now := f.responseIssuedAt.Add(30 * time.Second)
				if mode == "SP initiated" {
					f.destination, f.recipient = fixtureACS, fixtureACS
					f.responseCorrelation, f.confirmationCorrelation = ` InResponseTo="`+fixtureID+`"`, ` InResponseTo="`+fixtureID+`"`
					result, verifyErr := sp.Validate(t.Context(), POSTResponseInput{SAMLResponse: signedIDPResponseFixture(t, key, f),
						RequestID: fixtureID, Now: now, IssuedAt: f.responseIssuedAt.Add(-30 * time.Second), ExpiresAt: now.Add(time.Minute)})
					logout, evidenceErr := result.LogoutSubject()
					return logout, verifyErr, evidenceErr
				}
				result, verifyErr := idp.Validate(t.Context(), IDPInitiatedPOSTResponseInput{SAMLResponse: signedIDPResponseFixture(t, key, f), Now: now})
				logout, evidenceErr := result.LogoutSubject()
				return logout, verifyErr, evidenceErr
			}

			fixture := newIDPResponseFixture()
			fixture.nameIDQualifiers = ` NameQualifier="` + fixtureIdP + `" SPNameQualifier="` + fixtureSP + `"`
			got, verifyErr, evidenceErr := verify(t, fixture)
			want := LogoutSubjectEvidence{ProviderSubject: "member-042", SubjectFormat: samlPersistentNameID,
				NameQualifier: fixtureIdP, SPNameQualifier: fixtureSP, SessionIndex: "member-session"}
			if verifyErr != nil || evidenceErr != nil || got != want {
				t.Fatal("validated SAML response did not preserve the original logout subject and session index", verifyErr, evidenceErr)
			}
			if strings.Contains(fmt.Sprintf("%#v", got), want.SessionIndex) || strings.Contains(got.LogValue().String(), want.ProviderSubject) {
				t.Fatal("logout subject escaped implicit redaction")
			}
			if _, err := json.Marshal(got); !errors.Is(err, ErrSensitiveSerialization) {
				t.Fatal("logout subject allowed implicit serialization", err)
			}

			fixture.nameIDQualifiers, fixture.sessionIndexAttribute = "", ""
			got, verifyErr, evidenceErr = verify(t, fixture)
			want.NameQualifier, want.SPNameQualifier, want.SessionIndex = "", "", ""
			if verifyErr != nil || evidenceErr != nil || got != want {
				t.Fatal("valid sign-in acquired qualifiers or an index not present in the signed assertion", verifyErr, evidenceErr)
			}

			fixture.nameIDQualifiers = ` NameQualifier="urn:example:different-idp"`
			got, verifyErr, evidenceErr = verify(t, fixture)
			if !errors.Is(verifyErr, ErrInvalidInput) || !errors.Is(evidenceErr, ErrInvalidInput) || got != (LogoutSubjectEvidence{}) {
				t.Fatal("response rejected for a mismatched qualifier still supplied logout subject evidence", verifyErr, evidenceErr)
			}

			fixture.nameIDQualifiers = ` NameQualifier="` + fixtureIdP + `" SPNameQualifier="` + fixtureSP + `"`
			fixture.omitAssertionSignature = true
			got, verifyErr, evidenceErr = verify(t, fixture)
			if !errors.Is(verifyErr, ErrInvalidSignature) || !errors.Is(evidenceErr, ErrInvalidInput) || got != (LogoutSubjectEvidence{}) {
				t.Fatal("response rejected for lack of assertion signature still supplied logout subject evidence", verifyErr, evidenceErr)
			}
		})
	}
}
