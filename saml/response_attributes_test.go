package saml

import (
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	sso "github.com/faustbrian/go-sso"
)

// OASIS Core §§2.3.3 and 2.7.3: mapping consumes only selected values in the
// exact authenticated assertion. A signed email-verification claim is still an
// assertion, not an independent verification or source-of-truth decision.
func TestPOSTResponseMapsOnlySelectedSignedAttributeEvidence(t *testing.T) {
	key, certificate := idpResponseSigningFixture(t)
	profile, err := NewPOSTResponseProfile(POSTResponseConfig{SPEntityID: fixtureSP, IdentityProviderEntityID: fixtureIdP,
		AssertionConsumerURL: fixtureACS, SigningCertificates: [][]byte{certificate}})
	if err != nil {
		t.Fatal(err)
	}
	provider, mapping := responseAttributeMappingFixture(t)
	selected, err := profile.WithAssertionMapping(provider, mapping)
	if err != nil {
		t.Fatal("valid selected SAML mapping was rejected", err)
	}
	email, display, empty := "member@example.test", "Member Exact", ""
	verified, unverified := true, false
	for _, tc := range []struct {
		name         string
		xml          string
		presence     sso.AttributePresence
		email        *string
		display      *string
		verification *bool
	}{
		{name: "absent", presence: sso.AttributeAbsent},
		{name: "explicit nil", xml: `<a:AttributeStatement><a:Attribute Name="mail"><a:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:nil="true"></a:AttributeValue></a:Attribute></a:AttributeStatement>`, presence: sso.AttributeNull},
		{name: "empty plain string", xml: `<a:AttributeStatement><a:Attribute Name="mail"><a:AttributeValue></a:AttributeValue></a:Attribute></a:AttributeStatement>`, presence: sso.AttributeValue, email: &empty},
		{name: "signed scalars do not confer trust", xml: responseAttributeStatement(`<a:Attribute Name="mail"><a:AttributeValue>member@example.test</a:AttributeValue></a:Attribute><a:Attribute Name="verified"><a:AttributeValue>true</a:AttributeValue></a:Attribute><a:Attribute Name="display"><a:AttributeValue>Member Exact</a:AttributeValue></a:Attribute>`), presence: sso.AttributeValue, email: &email, display: &display, verification: &verified},
		{name: "typed string and boolean", xml: responseAttributeStatement(`<a:Attribute Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><a:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">member@example.test</a:AttributeValue></a:Attribute><a:Attribute Name="verified"><a:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:boolean">1</a:AttributeValue></a:Attribute>`), presence: sso.AttributeValue, email: &email, verification: &verified},
		{name: "false is a value", xml: responseAttributeStatement(`<a:Attribute Name="verified"><a:AttributeValue>false</a:AttributeValue></a:Attribute>`), presence: sso.AttributeAbsent, verification: &unverified},
		{name: "unknown and FriendlyName aliases do not map", xml: responseAttributeStatement(`<a:Attribute FriendlyName="mail" Name="unknown"><a:AttributeValue>member@example.test</a:AttributeValue></a:Attribute><a:Attribute Name="MAIL"><a:AttributeValue>member@example.test</a:AttributeValue></a:Attribute><a:Attribute Name="roles"><a:AttributeValue>administrator</a:AttributeValue></a:Attribute>`), presence: sso.AttributeAbsent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			xml := signedResponseFixture(t, key, fixtureID, fixtureIdP, fixtureSP, fixtureACS, "_assertion", true, tc.xml)
			if tc.name == "typed string and boolean" {
				// The QName prefix only occurs in an attribute value, so its
				// declaration is omitted by exclusive canonicalization.
				xml = strings.Replace(xml, `<p:Response `, `<p:Response xmlns:xs="http://www.w3.org/2001/XMLSchema" `, 1)
			}
			result, err := selected.Validate(t.Context(), responseAttributeInput(xml))
			if err != nil {
				t.Fatal("valid dual-signed mapped response rejected", err)
			}
			assertion, err := result.ProtocolAssertion()
			if err != nil {
				t.Fatal("validated response supplied no protocol assertion", err)
			}
			assertResponseAttributeScope(t, assertion, provider)
			assertResponseAttribute(t, assertion, "name_id", sso.AttributeValue, stringPointer("member-042"), nil, provider)
			assertResponseAttribute(t, assertion, "mail", tc.presence, tc.email, nil, provider)
			displayPresence, verificationPresence := sso.AttributeAbsent, sso.AttributeAbsent
			if tc.display != nil {
				displayPresence = sso.AttributeValue
			}
			if tc.verification != nil {
				verificationPresence = sso.AttributeValue
			}
			assertResponseAttribute(t, assertion, "display", displayPresence, tc.display, nil, provider)
			assertResponseAttribute(t, assertion, "verified", verificationPresence, nil, tc.verification, provider)
			assertion.Attributes[0] = sso.VerifiedAttribute{}
			detached, err := result.ProtocolAssertion()
			if err != nil || detached.Validate() != nil {
				t.Fatal("caller mutation escaped the detached observation collection", err)
			}
		})
	}
}

func TestPOSTResponseRejectsAmbiguousSelectedAttributesWithoutEvidence(t *testing.T) {
	key, certificate := idpResponseSigningFixture(t)
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
	const mail = `<a:Attribute Name="mail"><a:AttributeValue>member@example.test</a:AttributeValue></a:Attribute>`
	for _, tc := range []struct{ name, xml string }{
		{"duplicate selected name", responseAttributeStatement(mail + mail)},
		{"duplicate across statements", responseAttributeStatement(mail) + responseAttributeStatement(mail)},
		{"multiple values", responseAttributeStatement(`<a:Attribute Name="mail"><a:AttributeValue>first@example.test</a:AttributeValue><a:AttributeValue>second@example.test</a:AttributeValue></a:Attribute>`)},
		{"missing value", responseAttributeStatement(`<a:Attribute Name="mail"></a:Attribute>`)},
		{"nested scalar", responseAttributeStatement(`<a:Attribute Name="mail"><a:AttributeValue><a:NameID>member@example.test</a:NameID></a:AttributeValue></a:Attribute>`)},
		{"null with text", responseAttributeStatement(`<a:Attribute Name="mail"><a:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:nil="true">member@example.test</a:AttributeValue></a:Attribute>`)},
		{"invalid boolean", responseAttributeStatement(`<a:Attribute Name="verified"><a:AttributeValue>yes</a:AttributeValue></a:Attribute>`)},
		{"encrypted attribute cannot be treated as absent", responseAttributeStatement(`<a:EncryptedAttribute></a:EncryptedAttribute>`)},
		{"controlled string", responseAttributeStatement("<a:Attribute Name=\"mail\"><a:AttributeValue>member\n@example.test</a:AttributeValue></a:Attribute>")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			xml := signedResponseFixture(t, key, fixtureID, fixtureIdP, fixtureSP, fixtureACS, "_assertion", true, tc.xml)
			result, err := profile.Validate(t.Context(), responseAttributeInput(xml))
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatal("ambiguous selected scalar was not denied", err)
			}
			if _, err := result.Evidence(); err == nil {
				t.Fatal("rejected mapping returned successful SAML evidence")
			}
			if _, err := result.ProtocolAssertion(); err == nil {
				t.Fatal("rejected mapping returned successful protocol evidence")
			}
		})
	}
	t.Run("attribute mutation breaks authentication", func(t *testing.T) {
		xml := signedResponseFixture(t, key, fixtureID, fixtureIdP, fixtureSP, fixtureACS, "_assertion", true, responseAttributeStatement(mail))
		xml = strings.Replace(xml, "member@example.test", "attacker@example.test", 1)
		result, err := profile.Validate(t.Context(), responseAttributeInput(xml))
		if !errors.Is(err, ErrInvalidSignature) {
			t.Fatal("mapped attribute was consumed without its original signatures", err)
		}
		if _, err := result.ProtocolAssertion(); err == nil {
			t.Fatal("modified signed attribute returned protocol evidence")
		}
	})
}

func TestIDPInitiatedResponseMapsSignedNameIDWithExactScope(t *testing.T) {
	key, certificate := idpResponseSigningFixture(t)
	profile, err := NewIDPInitiatedPOSTResponseProfile(idpResponseConfigFixture(certificate))
	if err != nil {
		t.Fatal(err)
	}
	provider, mapping := responseAttributeMappingFixture(t)
	selected, err := profile.WithAssertionMapping(provider, mapping)
	if err != nil {
		t.Fatal(err)
	}
	fixture := newIDPResponseFixture()
	result, err := selected.Validate(t.Context(), IDPInitiatedPOSTResponseInput{SAMLResponse: signedIDPResponseFixture(t, key, fixture), Now: fixture.responseIssuedAt.Add(30 * time.Second)})
	if err != nil {
		t.Fatal("permitted dual-signed unsolicited response rejected", err)
	}
	assertion, err := result.ProtocolAssertion()
	if err != nil {
		t.Fatal(err)
	}
	assertResponseAttributeScope(t, assertion, provider)
	assertResponseAttribute(t, assertion, "name_id", sso.AttributeValue, stringPointer("member-042"), nil, provider)
	for _, name := range []string{"mail", "verified", "display"} {
		assertResponseAttribute(t, assertion, name, sso.AttributeAbsent, nil, nil, provider)
	}
}

func TestResponseAttributeMappingIsOptIn(t *testing.T) {
	key, certificate := idpResponseSigningFixture(t)
	sp, err := NewPOSTResponseProfile(POSTResponseConfig{SPEntityID: fixtureSP, IdentityProviderEntityID: fixtureIdP,
		AssertionConsumerURL: fixtureACS, SigningCertificates: [][]byte{certificate}})
	if err != nil {
		t.Fatal(err)
	}
	xml := signedResponseFixture(t, key, fixtureID, fixtureIdP, fixtureSP, fixtureACS, "_assertion", true)
	spResult, err := sp.Validate(t.Context(), responseAttributeInput(xml))
	if err != nil {
		t.Fatal("legacy SP response no longer accepted", err)
	}
	if _, err := spResult.Evidence(); err != nil {
		t.Fatal(err)
	}
	if _, err := spResult.ProtocolAssertion(); err == nil {
		t.Fatal("unselected SP profile silently created mapped protocol evidence")
	}
	idp, err := NewIDPInitiatedPOSTResponseProfile(idpResponseConfigFixture(certificate))
	if err != nil {
		t.Fatal(err)
	}
	fixture := newIDPResponseFixture()
	idpResult, err := idp.Validate(t.Context(), IDPInitiatedPOSTResponseInput{SAMLResponse: signedIDPResponseFixture(t, key, fixture), Now: fixture.responseIssuedAt.Add(30 * time.Second)})
	if err != nil {
		t.Fatal("legacy IdP response no longer accepted", err)
	}
	if _, err := idpResult.Evidence(); err != nil {
		t.Fatal(err)
	}
	if _, err := idpResult.ProtocolAssertion(); err == nil {
		t.Fatal("unselected IdP profile silently created mapped protocol evidence")
	}
}

func TestResponseAttributeMappingRejectsInvalidProviderAndSelection(t *testing.T) {
	_, certificate := idpResponseSigningFixture(t)
	sp, err := NewPOSTResponseProfile(POSTResponseConfig{SPEntityID: fixtureSP, IdentityProviderEntityID: fixtureIdP,
		AssertionConsumerURL: fixtureACS, SigningCertificates: [][]byte{certificate}})
	if err != nil {
		t.Fatal(err)
	}
	idp, err := NewIDPInitiatedPOSTResponseProfile(idpResponseConfigFixture(certificate))
	if err != nil {
		t.Fatal(err)
	}
	provider, mapping := responseAttributeMappingFixture(t)
	spec, err := mapping.Spec()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*sso.Provider, *sso.AttributeMappingSpec)
	}{
		{"missing provider", func(p *sso.Provider, _ *sso.AttributeMappingSpec) { p.ID = "" }},
		{"missing organization", func(p *sso.Provider, _ *sso.AttributeMappingSpec) { p.OrganizationID = "" }},
		{"wrong protocol", func(p *sso.Provider, _ *sso.AttributeMappingSpec) { p.Protocol = "oidc" }},
		{"missing provider version", func(p *sso.Provider, _ *sso.AttributeMappingSpec) { p.Version = 0 }},
		{"disabled provider", func(p *sso.Provider, _ *sso.AttributeMappingSpec) { p.Enabled = false }},
		{"mismatched mapping version", func(p *sso.Provider, _ *sso.AttributeMappingSpec) { p.MappingVersion++ }},
		{"non-NameID subject", func(_ *sso.Provider, m *sso.AttributeMappingSpec) { m.SubjectClaim = "mail" }},
		{"duplicate selected names", func(_ *sso.Provider, m *sso.AttributeMappingSpec) { m.DisplayNameClaim = m.EmailClaim }},
		{"reserved NameID alias", func(_ *sso.Provider, m *sso.AttributeMappingSpec) { m.EmailClaim = "name_id" }},
		{"verification without email", func(_ *sso.Provider, m *sso.AttributeMappingSpec) { m.EmailClaim = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidateProvider, candidateSpec := provider, spec
			tc.change(&candidateProvider, &candidateSpec)
			candidateMapping, err := sso.NewAttributeMapping(candidateSpec)
			if err != nil {
				t.Fatal("test setup was rejected before SAML-specific validation", err)
			}
			if _, err := sp.WithAssertionMapping(candidateProvider, candidateMapping); !errors.Is(err, ErrInvalidInput) {
				t.Fatal("SP profile accepted invalid provider or mapping selection", err)
			}
			if _, err := idp.WithAssertionMapping(candidateProvider, candidateMapping); !errors.Is(err, ErrInvalidInput) {
				t.Fatal("IdP profile accepted invalid provider or mapping selection", err)
			}
		})
	}
	provider.ID = "other-provider"
	if _, err := idp.WithAssertionMapping(provider, mapping); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("IdP profile accepted a provider outside its exact configured route", err)
	}
}

func responseAttributeMappingFixture(t *testing.T) (sso.Provider, sso.AttributeMapping) {
	t.Helper()
	provider := sso.Provider{ID: "test", OrganizationID: "organization-exact", Protocol: "saml", Version: 17, MappingVersion: 9, Enabled: true}
	mapping, err := sso.NewAttributeMapping(sso.AttributeMappingSpec{Version: 9, SubjectClaim: "name_id", EmailClaim: "mail", VerifiedEmailClaim: "verified", DisplayNameClaim: "display"})
	if err != nil {
		t.Fatal(err)
	}
	return provider, mapping
}

func responseAttributeInput(xml string) POSTResponseInput {
	issued := time.Date(2026, 11, 23, 4, 0, 0, 0, time.UTC)
	return POSTResponseInput{SAMLResponse: base64.StdEncoding.EncodeToString([]byte(xml)), RequestID: fixtureID,
		IssuedAt: issued, Now: issued.Add(time.Minute), ExpiresAt: issued.Add(5 * time.Minute)}
}

func responseAttributeStatement(attributes string) string {
	return `<a:AttributeStatement>` + attributes + `</a:AttributeStatement>`
}

func stringPointer(value string) *string { return &value }

func assertResponseAttributeScope(t *testing.T, assertion sso.ProtocolAssertion, provider sso.Provider) {
	t.Helper()
	if err := assertion.Validate(); err != nil {
		t.Fatal("mapped assertion violates SSO evidence contract", err)
	}
	if string(assertion.ProviderID) != provider.ID || string(assertion.OrganizationID) != provider.OrganizationID ||
		assertion.ProviderSubject != "member-042" || assertion.ProviderProfileVersion != provider.Version || assertion.MappingVersion != provider.MappingVersion || len(assertion.Attributes) != 4 {
		t.Fatal("mapped assertion lost exact provider, organization, subject, policy versions or selected observations")
	}
	for index, name := range []string{"name_id", "mail", "verified", "display"} {
		observation, err := assertion.Attributes[index].Spec()
		if err != nil || observation.Name != name {
			t.Fatal("selected observation order changed", err)
		}
	}
}

func assertResponseAttribute(t *testing.T, assertion sso.ProtocolAssertion, name string, presence sso.AttributePresence, text *string, boolean *bool, provider sso.Provider) {
	t.Helper()
	want := sso.VerifiedAttributeSpec{Name: name, Presence: presence, StringValue: text, BooleanValue: boolean,
		Provenance: sso.AttributeProvenance{ProviderID: sso.ProviderID(provider.ID), ProviderProfileVersion: provider.Version, Issuer: fixtureIdP, Source: sso.AttributeSourceSAMLAssertion}}
	for _, attribute := range assertion.Attributes {
		got, err := attribute.Spec()
		if err != nil {
			t.Fatal(err)
		}
		if got.Name == name {
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("selected %s changed its exact scalar, presence, trust flags or provenance", name)
			}
			return
		}
	}
	t.Fatalf("missing explicit observation for %s", name)
}

func FuzzSAMLSelectedAttributeValue(f *testing.F) {
	f.Add(`<AttributeValue xmlns="urn:oasis:names:tc:SAML:2.0:assertion">direct text</AttributeValue>`, false)
	f.Add(`<AttributeValue xmlns="urn:oasis:names:tc:SAML:2.0:assertion">false</AttributeValue>`, true)
	f.Add(`<AttributeValue xmlns="urn:oasis:names:tc:SAML:2.0:assertion"><Bad/></AttributeValue>`, false)
	f.Add(`<AttributeValue xmlns="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:nil="true"></AttributeValue>`, true)
	f.Fuzz(func(t *testing.T, raw string, boolean bool) {
		value, err := parseSAMLDocument(t.Context(), []byte(raw))
		if err != nil || !samlElement(value, samlAssertionNS, "AttributeValue") {
			return
		}
		var spec sso.VerifiedAttributeSpec
		if !readSAMLScalar(value, samlScalarClaim{name: "selected", boolean: boolean}, &spec) {
			return
		}
		switch spec.Presence {
		case sso.AttributeNull:
			if spec.StringValue != nil || spec.BooleanValue != nil {
				t.Fatal("null observation has a value")
			}
		case sso.AttributeValue:
			if boolean && (spec.BooleanValue == nil || spec.StringValue != nil) {
				t.Fatal("boolean projection has the wrong shape")
			}
			if !boolean && (spec.StringValue == nil || spec.BooleanValue != nil || len(*spec.StringValue) > maximumSAMLScalarBytes) {
				t.Fatal("string projection has the wrong shape or exceeded its byte bound")
			}
		default:
			t.Fatal("present wire value was reported as absent")
		}
	})
}
