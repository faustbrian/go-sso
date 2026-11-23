package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
)

func samlLogoutSubjectFixture() SAMLVerifiedLoginResponse {
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	return SAMLVerifiedLoginResponse{
		Evidence:      SAMLVerifiedResponse{ResponseID: "_response", AssertionID: "_assertion", ProviderSubject: "member<&é", SubjectFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", SessionIndex: "original-session", AssertionExpiresAt: now.Add(time.Minute), ValidUntil: now.Add(time.Minute)},
		LogoutSubject: SAMLLogoutSubject{ProviderSubject: "member<&é", SubjectFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", NameQualifier: "urn:original:idp", SPNameQualifier: "urn:original:sp", SessionIndex: "original-session"},
	}
}

func TestSAMLLogoutSubjectCombinedVerificationRetainsExactEvidence(t *testing.T) {
	want := samlLogoutSubjectFixture()
	input := SAMLResponseVerificationInput{IdentityProviderEntityID: "urn:original:idp", SPEntityID: "urn:original:sp", Now: want.Evidence.ValidUntil.Add(-time.Minute)}
	for _, absent := range []bool{false, true} {
		selected := want
		if absent {
			selected.Evidence.SessionIndex = ""
			selected.LogoutSubject.NameQualifier, selected.LogoutSubject.SPNameQualifier, selected.LogoutSubject.SessionIndex = "", "", ""
		}
		calls := 0
		service := &ProviderSAMLLoginCompletionService{verifyLogoutSubject: func(context.Context, SAMLResponseVerificationInput) (SAMLVerifiedLoginResponse, error) {
			calls++
			return selected, nil
		}}
		got, err := service.verifyLoginResponse(context.Background(), input)
		if err != nil || got != selected || calls != 1 {
			t.Fatal("combined verification lost original subject or verified twice", err)
		}
	}
	for _, edit := range []func(*SAMLVerifiedLoginResponse){
		func(v *SAMLVerifiedLoginResponse) { v.LogoutSubject.ProviderSubject = "replacement" },
		func(v *SAMLVerifiedLoginResponse) { v.LogoutSubject.SubjectFormat = "" },
		func(v *SAMLVerifiedLoginResponse) { v.LogoutSubject.SessionIndex = "replacement" },
		func(v *SAMLVerifiedLoginResponse) { v.LogoutSubject.NameQualifier = "urn:another:idp" },
		func(v *SAMLVerifiedLoginResponse) { v.LogoutSubject.SPNameQualifier = "urn:another:sp" },
		func(v *SAMLVerifiedLoginResponse) { v.LogoutSubject.NameQualifier = "bad\xff" },
		func(v *SAMLVerifiedLoginResponse) { v.LogoutSubject.NameQualifier = "bad\ufffe" },
	} {
		bad := want
		edit(&bad)
		service := &ProviderSAMLLoginCompletionService{verifyLogoutSubject: func(context.Context, SAMLResponseVerificationInput) (SAMLVerifiedLoginResponse, error) {
			return bad, nil
		}}
		if got, err := service.verifyLoginResponse(context.Background(), input); err == nil || got != (SAMLVerifiedLoginResponse{}) {
			t.Fatal("invalid combined evidence disclosed subject")
		}
	}
	service := &ProviderSAMLLoginCompletionService{verifyLogoutSubject: func(context.Context, SAMLResponseVerificationInput) (SAMLVerifiedLoginResponse, error) {
		return want, sso.ErrForbidden
	}}
	if got, err := service.verifyLoginResponse(context.Background(), input); err == nil || got != (SAMLVerifiedLoginResponse{}) {
		t.Fatal("failed verifier disclosed subject")
	}
}

func TestSAMLLogoutSubjectSealedPreparationsPreserveExactSubjectAndLegacyDecoding(t *testing.T) {
	c, _, _, _ := providerLoginPayloadFixture(t)
	aad, err := envelope.NewContext(map[string]string{"purpose": "subject-custody-test"})
	if err != nil {
		t.Fatal(err)
	}
	want := samlLogoutSubjectFixture()
	want.LogoutSubject.SPNameQualifier = "https://app.example/saml2/provider/metadata"
	subject := samlStoredLogoutSubject(want.LogoutSubject)
	for _, mode := range []string{"sp", "idp"} {
		for _, selected := range []bool{false, true} {
			var original *samlStoredLogoutSubject
			if selected {
				original = &subject
			}
			var plain []byte
			if mode == "sp" {
				plain, err = encodeSAMLCallbackOutput(samlCallbackOutput{Schema: 1}, original)
			} else {
				plain, err = encodeSAMLIDPArrivalOrigin(samlIDPArrivalOrigin{Version: 1, Issuer: "urn:original:idp", ExternalOrigin: "https://app.example", Route: samlIDPArrivalRoute{ProviderID: "provider"}, Evidence: samlIDPArrivalEvidence(want.Evidence)}, original)
			}
			if err != nil {
				t.Fatal(err)
			}
			if !selected && bytes.Contains(plain, []byte("LogoutSubject")) {
				t.Fatal("legacy payload byte shape changed")
			}
			sealed, err := c.seal(context.Background(), aad, plain, 65536)
			if err != nil {
				t.Fatal(err)
			}
			opened, err := c.open(context.Background(), aad, sealed, 65536, 32768)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "sp" {
				got, err := decodeSAMLCallbackOutput(opened, original)
				if err != nil || (selected && (got.LogoutSubject == nil || *got.LogoutSubject != subject)) {
					t.Fatal("SP preparation lost exact subject", err)
				}
				if selected {
					other := subject
					other.NameQualifier = "urn:replacement"
					if _, err := decodeSAMLCallbackOutput(opened, &other); err == nil {
						t.Fatal("SP preparation substituted fresh subject")
					}
				}
				if !selected {
					if _, err := decodeSAMLCallbackOutput(opened, &subject); err == nil {
						t.Fatal("legacy preparation invented selected logout subject")
					}
				}
			} else {
				got, err := decodeSAMLIDPArrivalOrigin(opened, selected)
				if err != nil || (selected && (got.LogoutSubject == nil || *got.LogoutSubject != subject)) {
					t.Fatal("IdP pending origin lost exact subject", err)
				}
				if _, err := decodeSAMLIDPArrivalOrigin(opened, !selected); err == nil {
					t.Fatal("IdP origin silently crossed verifier selection")
				}
			}
		}
	}
}

func TestSAMLLogoutSubjectPublicResultsAreRedacted(t *testing.T) {
	v := samlLogoutSubjectFixture()
	for _, sensitive := range []any{v, v.LogoutSubject} {
		if _, err := json.Marshal(sensitive); !errors.Is(err, sso.ErrSensitiveSerialization) {
			t.Fatal("subject serialized", err)
		}
		if strings.Contains(fmt.Sprintf("%+v", sensitive), "original") || strings.Contains(fmt.Sprintf("%#v", sensitive), "member") {
			t.Fatal("subject diagnostic leaked")
		}
	}
	if strings.Contains(fmt.Sprintf("%+v", samlStoredLogoutSubject(v.LogoutSubject)), "original") {
		t.Fatal("private subject diagnostic leaked")
	}
}

func TestSAMLLogoutSubjectIDPRestoreRejectsDifferentOriginalIssuerOrSP(t *testing.T) {
	v := samlLogoutSubjectFixture()
	v.LogoutSubject.SPNameQualifier = "https://app.example/saml2/provider/metadata"
	subject := samlStoredLogoutSubject(v.LogoutSubject)
	origin := samlIDPArrivalOrigin{Version: 2, Issuer: "urn:original:idp", ExternalOrigin: "https://app.example", Route: samlIDPArrivalRoute{ProviderID: "provider"}, Evidence: samlIDPArrivalEvidence(v.Evidence), LogoutSubject: &subject}
	for _, edit := range []func(*samlIDPArrivalOrigin){
		func(o *samlIDPArrivalOrigin) { o.Issuer = "urn:replacement:idp" },
		func(o *samlIDPArrivalOrigin) { o.ExternalOrigin = "https://replacement.example" },
		func(o *samlIDPArrivalOrigin) { o.Route.ProviderID = "replacement" },
	} {
		other := origin
		edit(&other)
		plain, err := providerLoginPayloadEncode(other)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := decodeSAMLIDPArrivalOrigin(plain, true); err == nil || got.LogoutSubject != nil {
			t.Fatal("restored subject crossed original IdP/SP selection")
		}
	}
}

func TestSAMLLogoutSubjectIDPCombinedVerificationDoesNotInventQualifiers(t *testing.T) {
	want := samlLogoutSubjectFixture()
	input := SAMLIDPResponseVerificationInput{IdentityProviderEntityID: "urn:original:idp", SPEntityID: "urn:original:sp", Now: want.Evidence.ValidUntil.Add(-time.Minute)}
	calls := 0
	service := &ProviderSAMLIDPAdmissionService{verifyLogoutSubject: func(context.Context, SAMLIDPResponseVerificationInput) (SAMLVerifiedLoginResponse, error) {
		calls++
		return want, nil
	}}
	got, err := service.verifyLoginResponse(context.Background(), input)
	if err != nil || got != want || calls != 1 {
		t.Fatal("IdP verifier lost original combined subject", err)
	}
	service.verifyLogoutSubject = nil
	service.verify = func(context.Context, SAMLIDPResponseVerificationInput) (SAMLVerifiedResponse, error) {
		return want.Evidence, nil
	}
	got, err = service.verifyLoginResponse(context.Background(), input)
	if err != nil || got.Evidence != want.Evidence || got.LogoutSubject != (SAMLLogoutSubject{}) {
		t.Fatal("legacy verifier invented qualifiers", err)
	}
	legacy := SAMLResponseVerifier(func(context.Context, SAMLResponseVerificationInput) (SAMLVerifiedResponse, error) {
		return want.Evidence, nil
	})
	combined := SAMLResponseWithLogoutSubjectVerifier(func(context.Context, SAMLResponseVerificationInput) (SAMLVerifiedLoginResponse, error) {
		return want, nil
	})
	if owner, err := NewProviderSAMLLoginCompletionServiceWithLogoutSubject(nil, ProviderSAMLLoginCompletionConfig{Verify: legacy}, combined); owner != nil || !errors.Is(err, sso.ErrInvalidInput) {
		t.Fatal("ambiguous SP verifier selection accepted", err)
	}
	if owner, err := NewProviderSAMLIDPAdmissionServiceWithLogoutSubject(nil, ProviderSAMLIDPAdmissionConfig{Verify: service.verify}, service.verifyLogoutSubject); owner != nil || !errors.Is(err, sso.ErrInvalidInput) {
		t.Fatal("ambiguous IdP verifier selection accepted", err)
	}
}
