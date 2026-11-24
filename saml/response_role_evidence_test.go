package saml

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-sso"
)

func TestResponseAssertionIssuedAtUsesAuthenticatedAssertionForBothBindings(t *testing.T) {
	key, certificate := idpResponseSigningFixture(t)
	fixture := newIDPResponseFixture()
	fixture.assertionIssuedAt = fixture.responseIssuedAt.Add(-10*time.Second + 123456789*time.Nanosecond)
	want := fixture.assertionIssuedAt
	now := fixture.responseIssuedAt.Add(30 * time.Second)
	sp, err := NewPOSTResponseProfile(POSTResponseConfig{SPEntityID: fixtureSP, IdentityProviderEntityID: fixtureIdP,
		AssertionConsumerURL: fixtureACS, SigningCertificates: [][]byte{certificate}})
	if err != nil {
		t.Fatal(err)
	}
	idp, err := NewIDPInitiatedPOSTResponseProfile(idpResponseConfigFixture(certificate))
	if err != nil {
		t.Fatal(err)
	}
	unsolicited, err := idp.Validate(t.Context(), IDPInitiatedPOSTResponseInput{SAMLResponse: signedIDPResponseFixture(t, key, fixture), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := unsolicited.AssertionIssuedAt(); err != nil || !got.Equal(want) {
		t.Fatal("unsolicited assertion time was replaced by response, acceptance or expiry time", got, err)
	}
	fixture.destination, fixture.recipient = fixtureACS, fixtureACS
	fixture.responseCorrelation, fixture.confirmationCorrelation = ` InResponseTo="`+fixtureID+`"`, ` InResponseTo="`+fixtureID+`"`
	input := responseAttributeInput("")
	input.SAMLResponse = signedIDPResponseFixture(t, key, fixture)
	correlated, err := sp.Validate(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := correlated.AssertionIssuedAt(); err != nil || !got.Equal(want) {
		t.Fatal("correlated assertion time was replaced by response, acceptance or expiry time", got, err)
	}
	raw, err := base64.StdEncoding.DecodeString(input.SAMLResponse)
	if err != nil {
		t.Fatal(err)
	}
	input.SAMLResponse = base64.StdEncoding.EncodeToString([]byte(strings.Replace(string(raw), want.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), 1)))
	denied, err := sp.Validate(t.Context(), input)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatal("modified assertion issue time was not authenticated", err)
	}
	if got, err := denied.AssertionIssuedAt(); !errors.Is(err, ErrInvalidInput) || !got.IsZero() {
		t.Fatal("denied result retained assertion time", got, err)
	}
	if got, err := (VerifiedPOSTResponse{}).AssertionIssuedAt(); !errors.Is(err, ErrInvalidInput) || !got.IsZero() {
		t.Fatal("zero SP result returned assertion time", got, err)
	}
	if got, err := (VerifiedIDPInitiatedPOSTResponse{}).AssertionIssuedAt(); !errors.Is(err, ErrInvalidInput) || !got.IsZero() {
		t.Fatal("zero unsolicited result returned assertion time", got, err)
	}
}

func TestPOSTResponseRoleClaimsProjectExactSignedBooleanEvidence(t *testing.T) {
	key, certificate := idpResponseSigningFixture(t)
	profile, provider := roleEvidenceProfile(t, certificate)
	selected, err := profile.WithRoleClaims([]string{"role_reader", "urn:example:role:writer"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, value string
		presence    sso.AttributePresence
		boolean     *bool
	}{
		{name: "absent", presence: sso.AttributeAbsent},
		{name: "null", value: `<a:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:nil="true"></a:AttributeValue>`, presence: sso.AttributeNull},
		{name: "true", value: `<a:AttributeValue>true</a:AttributeValue>`, presence: sso.AttributeValue, boolean: roleEvidenceBoolean(true)},
		{name: "false", value: `<a:AttributeValue>false</a:AttributeValue>`, presence: sso.AttributeValue, boolean: roleEvidenceBoolean(false)},
		{name: "schema one", value: `<a:AttributeValue>1</a:AttributeValue>`, presence: sso.AttributeValue, boolean: roleEvidenceBoolean(true)},
		{name: "schema zero", value: `<a:AttributeValue>0</a:AttributeValue>`, presence: sso.AttributeValue, boolean: roleEvidenceBoolean(false)},
		{name: "typed boolean", value: `<a:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:boolean">true</a:AttributeValue>`, presence: sso.AttributeValue, boolean: roleEvidenceBoolean(true)},
		{name: "not nil", value: `<a:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:nil="false">false</a:AttributeValue>`, presence: sso.AttributeValue, boolean: roleEvidenceBoolean(false)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attribute := ""
			if tc.value != "" {
				attribute = `<a:Attribute Name="role_reader">` + tc.value + `</a:Attribute>`
			}
			attribute += `<a:Attribute Name="urn:example:role:writer"><a:AttributeValue>false</a:AttributeValue></a:Attribute>`
			attribute += `<a:Attribute FriendlyName="role_reader" Name="ROLE_READER"><a:AttributeValue>true</a:AttributeValue></a:Attribute>`
			xml := signedResponseFixture(t, key, fixtureID, fixtureIdP, fixtureSP, fixtureACS, "_assertion", true, responseAttributeStatement(attribute))
			if tc.name == "typed boolean" {
				xml = strings.Replace(xml, `<p:Response `, `<p:Response xmlns:xs="http://www.w3.org/2001/XMLSchema" `, 1)
			}
			result, err := selected.Validate(t.Context(), responseAttributeInput(xml))
			if err != nil {
				t.Fatal("valid signed role evidence denied", err)
			}
			assertion, err := result.ProtocolAssertion()
			if err != nil || assertion.Validate() != nil || len(assertion.Attributes) != 6 ||
				string(assertion.ProviderID) != provider.ID || string(assertion.OrganizationID) != provider.OrganizationID ||
				assertion.ProviderSubject != "member-042" || assertion.ProviderProfileVersion != provider.Version || assertion.MappingVersion != provider.MappingVersion {
				t.Fatal("role projection lost exact mapped scope or shape", err)
			}
			assertResponseAttribute(t, assertion, "name_id", sso.AttributeValue, stringPointer("member-042"), nil, provider)
			for _, name := range []string{"mail", "verified", "display"} {
				assertResponseAttribute(t, assertion, name, sso.AttributeAbsent, nil, nil, provider)
			}
			assertResponseAttribute(t, assertion, "role_reader", tc.presence, nil, tc.boolean, provider)
			assertResponseAttribute(t, assertion, "urn:example:role:writer", sso.AttributeValue, nil, roleEvidenceBoolean(false), provider)
			if got, err := result.AssertionIssuedAt(); err != nil || !got.Equal(time.Date(2026, 11, 23, 4, 0, 30, 0, time.UTC)) {
				t.Fatal("role projection lost signed assertion issue time", got, err)
			}
		})
	}
}

func TestPOSTResponseRoleClaimsRejectMalformedAndAmbiguousSignedEvidence(t *testing.T) {
	key, certificate := idpResponseSigningFixture(t)
	profile, _ := roleEvidenceProfile(t, certificate)
	profile, err := profile.WithRoleClaims([]string{"role_reader"})
	if err != nil {
		t.Fatal(err)
	}
	const attribute = `<a:Attribute Name="role_reader"><a:AttributeValue>true</a:AttributeValue></a:Attribute>`
	for _, tc := range []struct{ name, attributes string }{
		{"duplicate", attribute + attribute},
		{"duplicate across statements", attribute + `</a:AttributeStatement><a:AttributeStatement>` + attribute},
		{"multiple values", `<a:Attribute Name="role_reader"><a:AttributeValue>true</a:AttributeValue><a:AttributeValue>false</a:AttributeValue></a:Attribute>`},
		{"missing value", `<a:Attribute Name="role_reader"></a:Attribute>`},
		{"invalid boolean", `<a:Attribute Name="role_reader"><a:AttributeValue>yes</a:AttributeValue></a:Attribute>`},
		{"string boolean", `<a:Attribute Name="role_reader"><a:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">true</a:AttributeValue></a:Attribute>`},
		{"nested scalar", `<a:Attribute Name="role_reader"><a:AttributeValue><a:NameID>true</a:NameID></a:AttributeValue></a:Attribute>`},
		{"null with text", `<a:Attribute Name="role_reader"><a:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:nil="true">false</a:AttributeValue></a:Attribute>`},
		{"empty boolean", `<a:Attribute Name="role_reader"><a:AttributeValue></a:AttributeValue></a:Attribute>`},
		{"uppercase boolean", `<a:Attribute Name="role_reader"><a:AttributeValue>TRUE</a:AttributeValue></a:Attribute>`},
		{"whitespace boolean", `<a:Attribute Name="role_reader"><a:AttributeValue> true </a:AttributeValue></a:Attribute>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			xml := signedResponseFixture(t, key, fixtureID, fixtureIdP, fixtureSP, fixtureACS, "_assertion", true, responseAttributeStatement(tc.attributes))
			result, err := profile.Validate(t.Context(), responseAttributeInput(xml))
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatal("malformed selected role evidence accepted", err)
			}
			if _, err := result.ProtocolAssertion(); !errors.Is(err, ErrInvalidInput) {
				t.Fatal("denied role evidence exposed mapped observations", err)
			}
			if _, err := result.Evidence(); !errors.Is(err, ErrInvalidInput) {
				t.Fatal("denied role evidence exposed replay evidence", err)
			}
			if got, err := result.AssertionIssuedAt(); !errors.Is(err, ErrInvalidInput) || !got.IsZero() {
				t.Fatal("denied role evidence exposed signed issue time", got, err)
			}
		})
	}
}

func TestPOSTResponseRoleSelectionIsBoundedImmutableAndOptIn(t *testing.T) {
	key, certificate := idpResponseSigningFixture(t)
	original, provider := roleEvidenceProfile(t, certificate)
	names := []string{"role_reader"}
	selected, err := original.WithRoleClaims(names)
	if err != nil {
		t.Fatal(err)
	}
	names[0] = "mail"
	reselected, err := selected.WithRoleClaims([]string{"role_writer"})
	if err != nil {
		t.Fatal(err)
	}
	cleared, err := selected.WithRoleClaims(nil)
	if err != nil {
		t.Fatal(err)
	}
	const attributes = `<a:Attribute Name="role_reader"><a:AttributeValue>true</a:AttributeValue></a:Attribute><a:Attribute Name="role_writer"><a:AttributeValue>false</a:AttributeValue></a:Attribute>`
	xml := signedResponseFixture(t, key, fixtureID, fixtureIdP, fixtureSP, fixtureACS, "_assertion", true, responseAttributeStatement(attributes))
	for _, tc := range []struct {
		name    string
		profile POSTResponseProfile
		role    string
		boolean bool
	}{
		{name: "original mapping", profile: original},
		{name: "selected snapshot", profile: selected, role: "role_reader", boolean: true},
		{name: "replacement", profile: reselected, role: "role_writer", boolean: false},
		{name: "cleared", profile: cleared},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := tc.profile.Validate(t.Context(), responseAttributeInput(xml))
			if err != nil {
				t.Fatal(err)
			}
			assertion, err := result.ProtocolAssertion()
			wantCount := 4
			if tc.role != "" {
				wantCount++
			}
			if err != nil || len(assertion.Attributes) != wantCount {
				t.Fatal("role selector changed another immutable profile", err)
			}
			if tc.role != "" {
				assertResponseAttribute(t, assertion, tc.role, sso.AttributeValue, nil, roleEvidenceBoolean(tc.boolean), provider)
			}
		})
	}
	boundary := make([]string, 100)
	for i := range boundary {
		boundary[i] = fmt.Sprintf("role_%03d", i)
	}
	maximal, err := original.WithRoleClaims(boundary)
	if err != nil {
		t.Fatal("100-role organization budget was rejected", err)
	}
	xml = signedResponseFixture(t, key, fixtureID, fixtureIdP, fixtureSP, fixtureACS, "_assertion", true,
		responseAttributeStatement(`<a:Attribute Name="role_099"><a:AttributeValue>true</a:AttributeValue></a:Attribute>`))
	result, err := maximal.Validate(t.Context(), responseAttributeInput(xml))
	if err != nil {
		t.Fatal("full bounded projection was rejected", err)
	}
	assertion, err := result.ProtocolAssertion()
	if err != nil || len(assertion.Attributes) != 104 {
		t.Fatal("full bounded projection lost observations", err)
	}
	assertResponseAttribute(t, assertion, "role_000", sso.AttributeAbsent, nil, nil, provider)
	assertResponseAttribute(t, assertion, "role_099", sso.AttributeValue, nil, roleEvidenceBoolean(true), provider)
	for _, names := range [][]string{
		{""}, {"name_id"}, {"mail"}, {"verified"}, {"display"}, {"role_reader", "role_reader"},
		{"nonce"}, {"at_hash"}, {"c_hash"}, {"access_token"}, {"refresh_token"}, {"id_token"},
		{"role with space"}, {"role\nreader"}, {"role_é"}, {"\xff"}, {strings.Repeat("r", 129)}, append(boundary, "role_100"),
	} {
		if _, err := selected.WithRoleClaims(names); !errors.Is(err, ErrInvalidInput) {
			t.Fatal("invalid or overlapping role selector accepted", err)
		}
	}
	if _, err := (POSTResponseProfile{}).WithRoleClaims([]string{"role_reader"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("zero verifier accepted a role selector", err)
	}
	unmapped, err := NewPOSTResponseProfile(POSTResponseConfig{SPEntityID: fixtureSP, IdentityProviderEntityID: fixtureIdP,
		AssertionConsumerURL: fixtureACS, SigningCertificates: [][]byte{certificate}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unmapped.WithRoleClaims([]string{"role_reader"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("unmapped verifier accepted a role selector", err)
	}
}

func roleEvidenceProfile(t *testing.T, certificate []byte) (POSTResponseProfile, sso.Provider) {
	t.Helper()
	profile, err := NewPOSTResponseProfile(POSTResponseConfig{SPEntityID: fixtureSP, IdentityProviderEntityID: fixtureIdP,
		AssertionConsumerURL: fixtureACS, SigningCertificates: [][]byte{certificate}})
	if err != nil {
		t.Fatal(err)
	}
	provider, mapping := responseAttributeMappingFixture(t)
	profile, err = profile.WithAssertionMapping(provider, mapping)
	if err != nil {
		t.Fatal(err)
	}
	return profile, provider
}

func roleEvidenceBoolean(value bool) *bool { return &value }
