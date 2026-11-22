package sso_test

import (
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"testing"

	organization "github.com/faustbrian/go-organization"
	"github.com/faustbrian/go-sso"
)

func protocolAssertionInput() sso.ProtocolAssertion {
	return sso.ProtocolAssertion{
		ProviderID: "enterprise-provider", OrganizationID: organization.ID("enterprise-org"),
		ProviderSubject: "Case.Exact:subject", ProviderProfileVersion: 7, MappingVersion: 11,
	}
}

func TestProtocolAssertionPreservesExactValidatedBindings(t *testing.T) {
	for _, subject := range []string{"a", "Case.Exact:subject", "subject with spaces", "é", strings.Repeat("s", 512), strings.Repeat("é", 256)} {
		input := protocolAssertionInput()
		input.ProviderSubject = subject
		input.OrganizationID = "Örg.Exact"
		input.ProviderProfileVersion = math.MaxUint64
		input.MappingVersion = math.MaxUint64
		assertion, err := sso.NewProtocolAssertion(input)
		if err != nil {
			t.Fatal("bounded exact assertion rejected", err)
		}
		if assertion.ProviderID != input.ProviderID || assertion.OrganizationID != input.OrganizationID || assertion.ProviderSubject != subject || assertion.ProviderProfileVersion != input.ProviderProfileVersion || assertion.MappingVersion != input.MappingVersion {
			t.Fatal("construction altered the selected scope, subject or version")
		}
		if err := assertion.Validate(); err != nil {
			t.Fatal("constructed assertion rejected", err)
		}
	}
}

func TestProtocolAssertionRejectsInvalidBindings(t *testing.T) {
	cases := map[string]func(*sso.ProtocolAssertion){
		"empty provider":          func(a *sso.ProtocolAssertion) { a.ProviderID = "" },
		"padded provider":         func(a *sso.ProtocolAssertion) { a.ProviderID = " provider" },
		"oversized provider":      func(a *sso.ProtocolAssertion) { a.ProviderID = sso.ProviderID(strings.Repeat("p", 129)) },
		"non ASCII provider":      func(a *sso.ProtocolAssertion) { a.ProviderID = "pröv" },
		"empty organization":      func(a *sso.ProtocolAssertion) { a.OrganizationID = "" },
		"padded organization":     func(a *sso.ProtocolAssertion) { a.OrganizationID = " org" },
		"oversized organization":  func(a *sso.ProtocolAssertion) { a.OrganizationID = organization.ID(strings.Repeat("o", 129)) },
		"empty subject":           func(a *sso.ProtocolAssertion) { a.ProviderSubject = "" },
		"oversized subject":       func(a *sso.ProtocolAssertion) { a.ProviderSubject = strings.Repeat("s", 513) },
		"invalid UTF8 subject":    func(a *sso.ProtocolAssertion) { a.ProviderSubject = "subject\xff" },
		"NUL subject":             func(a *sso.ProtocolAssertion) { a.ProviderSubject = "subject\x00" },
		"newline subject":         func(a *sso.ProtocolAssertion) { a.ProviderSubject = "subject\n" },
		"DEL subject":             func(a *sso.ProtocolAssertion) { a.ProviderSubject = "subject\x7f" },
		"Unicode control subject": func(a *sso.ProtocolAssertion) { a.ProviderSubject = "subject\u0085" },
		"zero profile version":    func(a *sso.ProtocolAssertion) { a.ProviderProfileVersion = 0 },
		"zero mapping version":    func(a *sso.ProtocolAssertion) { a.MappingVersion = 0 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			input := protocolAssertionInput()
			mutate(&input)
			if err := input.Validate(); err != sso.ErrInvalidInput {
				t.Fatal("invalid assertion did not return only the redacted input category")
			}
			assertion, err := sso.NewProtocolAssertion(input)
			if err != sso.ErrInvalidInput || assertion.Validate() != sso.ErrInvalidInput {
				t.Fatal("invalid construction returned a usable assertion")
			}
		})
	}
	if err := (sso.ProtocolAssertion{}).Validate(); err != sso.ErrInvalidInput {
		t.Fatal("zero assertion was usable")
	}
}

func TestProtocolAssertionRedactsImplicitDisclosure(t *testing.T) {
	assertion := protocolAssertionInput()
	spec := protocolAttributeSpec()
	attribute, err := sso.NewVerifiedAttribute(spec)
	if err != nil {
		t.Fatal(err)
	}
	assertion.Attributes = []sso.VerifiedAttribute{attribute}
	for _, value := range []any{assertion, spec, spec.Provenance, attribute} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
			got := fmt.Sprintf(format, value)
			if !strings.Contains(got, "redacted") || strings.Contains(got, "enterprise-provider") || strings.Contains(got, "enterprise-org") || strings.Contains(got, "Case.Exact:subject") || strings.Contains(got, "private-name") || strings.Contains(got, "issuer.example") {
				t.Fatal("implicit formatting disclosed protocol evidence")
			}
		}
		if _, err := json.Marshal(value); !errors.Is(err, sso.ErrSensitiveSerialization) {
			t.Fatal("implicit JSON serialization admitted", err)
		}
		marshaler, ok := value.(encoding.TextMarshaler)
		if !ok {
			t.Fatal("missing text serialization denial")
		}
		if data, err := marshaler.MarshalText(); err != sso.ErrSensitiveSerialization || len(data) != 0 {
			t.Fatal("implicit text serialization admitted")
		}
		logValue, ok := value.(slog.LogValuer)
		if !ok || !strings.Contains(logValue.LogValue().String(), "redacted") {
			t.Fatal("missing structured log redaction")
		}
	}
}

func protocolAttributeSpec() sso.VerifiedAttributeSpec {
	value := "private-name"
	return sso.VerifiedAttributeSpec{
		Name: "name", Presence: sso.AttributeValue, StringValue: &value,
		Verified: true, Authoritative: false,
		Provenance: sso.AttributeProvenance{
			ProviderID: "enterprise-provider", ProviderProfileVersion: 7,
			Issuer: "https://issuer.example", Source: sso.AttributeSourceOIDCIDToken,
		},
	}
}

func TestProtocolAssertionAttributePreservesPresenceAndTrustMetadata(t *testing.T) {
	for _, presence := range []sso.AttributePresence{sso.AttributeAbsent, sso.AttributeNull, sso.AttributeValue} {
		for _, verified := range []bool{false, true} {
			for _, authoritative := range []bool{false, true} {
				spec := protocolAttributeSpec()
				spec.Presence, spec.Verified, spec.Authoritative = presence, verified, authoritative
				if presence != sso.AttributeValue {
					spec.StringValue = nil
				}
				attribute, err := sso.NewVerifiedAttribute(spec)
				if err != nil {
					t.Fatal("declared presence and trust metadata rejected", err)
				}
				got, err := attribute.Spec()
				if err != nil || got.Name != spec.Name || got.Presence != presence || got.Verified != verified || got.Authoritative != authoritative || got.Provenance != spec.Provenance {
					t.Fatal("presence or distinct trust metadata changed")
				}
				if presence != sso.AttributeValue && (got.StringValue != nil || got.BooleanValue != nil) {
					t.Fatal("missing or null attribute gained a value")
				}
			}
		}
	}
	for _, value := range []string{"", "private-name", strings.Repeat("é", 256)} {
		spec := protocolAttributeSpec()
		spec.StringValue = &value
		attribute, err := sso.NewVerifiedAttribute(spec)
		if err != nil {
			t.Fatal("bounded string value rejected", err)
		}
		got, err := attribute.Spec()
		if err != nil || got.StringValue == nil || *got.StringValue != value || got.BooleanValue != nil {
			t.Fatal("exact string value changed")
		}
	}
	for _, value := range []bool{false, true} {
		spec := protocolAttributeSpec()
		spec.StringValue, spec.BooleanValue = nil, &value
		attribute, err := sso.NewVerifiedAttribute(spec)
		if err != nil {
			t.Fatal("boolean value rejected", err)
		}
		got, err := attribute.Spec()
		if err != nil || got.BooleanValue == nil || *got.BooleanValue != value || got.StringValue != nil {
			t.Fatal("exact boolean value changed")
		}
	}
}

func TestProtocolAssertionAttributeOwnsDetachedValues(t *testing.T) {
	spec := protocolAttributeSpec()
	attribute, err := sso.NewVerifiedAttribute(spec)
	if err != nil {
		t.Fatal(err)
	}
	*spec.StringValue = "changed source"
	first, err := attribute.Spec()
	if err != nil || first.StringValue == nil || *first.StringValue != "private-name" {
		t.Fatal("attribute borrowed mutable input")
	}
	*first.StringValue = "changed projection"
	again, err := attribute.Spec()
	if err != nil || again.StringValue == nil || *again.StringValue != "private-name" {
		t.Fatal("projection changed immutable attribute")
	}
	input := protocolAssertionInput()
	input.Attributes = []sso.VerifiedAttribute{attribute}
	assertion, err := sso.NewProtocolAssertion(input)
	if err != nil {
		t.Fatal(err)
	}
	input.Attributes[0] = sso.VerifiedAttribute{}
	if err := assertion.Validate(); err != nil {
		t.Fatal("assertion borrowed attribute slice", err)
	}
	assertion.Attributes[0] = sso.VerifiedAttribute{}
	if err := assertion.Validate(); err != sso.ErrInvalidInput {
		t.Fatal("mutated assertion admitted zero attribute")
	}
	boolean := false
	spec.StringValue, spec.BooleanValue = nil, &boolean
	booleanAttribute, err := sso.NewVerifiedAttribute(spec)
	if err != nil {
		t.Fatal(err)
	}
	boolean = true
	booleanProjection, err := booleanAttribute.Spec()
	if err != nil || booleanProjection.BooleanValue == nil || *booleanProjection.BooleanValue {
		t.Fatal("attribute borrowed boolean input")
	}
	*booleanProjection.BooleanValue = true
	booleanAgain, err := booleanAttribute.Spec()
	if err != nil || booleanAgain.BooleanValue == nil || *booleanAgain.BooleanValue {
		t.Fatal("projection changed immutable boolean attribute")
	}
}

func TestProtocolAssertionAttributeRejectsInvalidShape(t *testing.T) {
	otherBool := false
	cases := map[string]func(*sso.VerifiedAttributeSpec){
		"empty name":                  func(s *sso.VerifiedAttributeSpec) { s.Name = "" },
		"oversized name":              func(s *sso.VerifiedAttributeSpec) { s.Name = strings.Repeat("n", 129) },
		"padded name":                 func(s *sso.VerifiedAttributeSpec) { s.Name = " name" },
		"unknown presence":            func(s *sso.VerifiedAttributeSpec) { s.Presence = "unknown" },
		"zero presence":               func(s *sso.VerifiedAttributeSpec) { s.Presence = "" },
		"absent with value":           func(s *sso.VerifiedAttributeSpec) { s.Presence = sso.AttributeAbsent },
		"null with value":             func(s *sso.VerifiedAttributeSpec) { s.Presence = sso.AttributeNull },
		"missing value":               func(s *sso.VerifiedAttributeSpec) { s.StringValue = nil },
		"both value types":            func(s *sso.VerifiedAttributeSpec) { s.BooleanValue = &otherBool },
		"oversized value":             func(s *sso.VerifiedAttributeSpec) { value := strings.Repeat("v", 513); s.StringValue = &value },
		"invalid UTF8 value":          func(s *sso.VerifiedAttributeSpec) { value := "\xff"; s.StringValue = &value },
		"control value":               func(s *sso.VerifiedAttributeSpec) { value := "secret\n"; s.StringValue = &value },
		"missing provenance provider": func(s *sso.VerifiedAttributeSpec) { s.Provenance.ProviderID = "" },
		"zero provenance profile":     func(s *sso.VerifiedAttributeSpec) { s.Provenance.ProviderProfileVersion = 0 },
		"missing issuer":              func(s *sso.VerifiedAttributeSpec) { s.Provenance.Issuer = "" },
		"non HTTPS issuer":            func(s *sso.VerifiedAttributeSpec) { s.Provenance.Issuer = "http://issuer.example" },
		"issuer query":                func(s *sso.VerifiedAttributeSpec) { s.Provenance.Issuer = "https://issuer.example?tenant=one" },
		"unknown source":              func(s *sso.VerifiedAttributeSpec) { s.Provenance.Source = "userinfo" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			spec := protocolAttributeSpec()
			mutate(&spec)
			attribute, err := sso.NewVerifiedAttribute(spec)
			if err != sso.ErrInvalidInput {
				t.Fatal("invalid attribute admitted")
			}
			if _, err := attribute.Spec(); err != sso.ErrInvalidInput {
				t.Fatal("failed attribute construction returned a usable value")
			}
		})
	}
}

func TestProtocolAssertionRejectsForeignDuplicateAndOversizedAttributes(t *testing.T) {
	for _, mutate := range []func(*sso.VerifiedAttributeSpec){
		func(s *sso.VerifiedAttributeSpec) { s.Provenance.ProviderID = "other-provider" },
		func(s *sso.VerifiedAttributeSpec) { s.Provenance.ProviderProfileVersion++ },
	} {
		spec := protocolAttributeSpec()
		mutate(&spec)
		attribute, err := sso.NewVerifiedAttribute(spec)
		if err != nil {
			t.Fatal(err)
		}
		input := protocolAssertionInput()
		input.Attributes = []sso.VerifiedAttribute{attribute}
		if _, err := sso.NewProtocolAssertion(input); err != sso.ErrInvalidInput {
			t.Fatal("foreign evidence entered selected assertion")
		}
	}
	input := protocolAssertionInput()
	for index := range 256 {
		spec := protocolAttributeSpec()
		spec.Name = fmt.Sprintf("claim-%d", index)
		attribute, err := sso.NewVerifiedAttribute(spec)
		if err != nil {
			t.Fatal(err)
		}
		input.Attributes = append(input.Attributes, attribute)
	}
	if _, err := sso.NewProtocolAssertion(input); err != nil {
		t.Fatal("bounded attributes rejected", err)
	}
	lastAttribute := input.Attributes[255]
	input.Attributes[255] = input.Attributes[0]
	if _, err := sso.NewProtocolAssertion(input); err != sso.ErrInvalidInput {
		t.Fatal("duplicate attribute name admitted")
	}
	input.Attributes[255] = lastAttribute
	extraSpec := protocolAttributeSpec()
	extraSpec.Name = "claim-256"
	extraAttribute, err := sso.NewVerifiedAttribute(extraSpec)
	if err != nil {
		t.Fatal(err)
	}
	input.Attributes = append(input.Attributes, extraAttribute)
	if _, err := sso.NewProtocolAssertion(input); err != sso.ErrInvalidInput {
		t.Fatal("oversized attribute collection admitted")
	}
}

func TestProtocolAssertionOAuthAttributesPreserveEvidenceAndDetach(t *testing.T) {
	for _, presence := range []sso.AttributePresence{sso.AttributeAbsent, sso.AttributeNull, sso.AttributeValue} {
		for _, verified := range []bool{false, true} {
			for _, authoritative := range []bool{false, true} {
				spec := protocolAttributeSpec()
				spec.Provenance.Source = sso.AttributeSourceOAuthIdentityEndpoint
				spec.Presence, spec.Verified, spec.Authoritative = presence, verified, authoritative
				if presence != sso.AttributeValue {
					spec.StringValue = nil
				}
				attribute, err := sso.NewVerifiedAttribute(spec)
				if err != nil {
					t.Fatal("authenticated OAuth endpoint evidence rejected", err)
				}
				input := protocolAssertionInput()
				input.Attributes = []sso.VerifiedAttribute{attribute}
				assertion, err := sso.NewProtocolAssertion(input)
				if err != nil {
					t.Fatal(err)
				}
				input.Attributes[0] = sso.VerifiedAttribute{}
				got, err := assertion.Attributes[0].Spec()
				if err != nil || got.Presence != presence || got.Verified != verified || got.Authoritative != authoritative || got.Provenance != spec.Provenance {
					t.Fatal("OAuth provenance, trust, presence or ownership changed")
				}
				if got.StringValue != nil {
					*got.StringValue = "changed projection"
					if *spec.StringValue != "private-name" {
						t.Fatal("projection changed caller input")
					}
					again, _ := assertion.Attributes[0].Spec()
					if *again.StringValue != "private-name" {
						t.Fatal("projection changed assertion evidence")
					}
				}
			}
		}
	}
	boolean := false
	spec := protocolAttributeSpec()
	spec.Provenance.Source = sso.AttributeSourceOAuthIdentityEndpoint
	spec.StringValue, spec.BooleanValue = nil, &boolean
	attribute, err := sso.NewVerifiedAttribute(spec)
	if err != nil {
		t.Fatal(err)
	}
	boolean = true
	got, _ := attribute.Spec()
	if got.BooleanValue == nil || *got.BooleanValue {
		t.Fatal("OAuth false scalar lost or borrowed")
	}
}

func TestProtocolAssertionRejectsMixedEvidenceAuthorities(t *testing.T) {
	for name, mutate := range map[string]func(*sso.VerifiedAttributeSpec){
		"issuer": func(s *sso.VerifiedAttributeSpec) { s.Provenance.Issuer = "https://other-issuer.example" },
		"source": func(s *sso.VerifiedAttributeSpec) { s.Provenance.Source = sso.AttributeSourceOAuthIdentityEndpoint },
	} {
		t.Run(name, func(t *testing.T) {
			first, err := sso.NewVerifiedAttribute(protocolAttributeSpec())
			if err != nil {
				t.Fatal(err)
			}
			spec := protocolAttributeSpec()
			spec.Name = "other-claim"
			mutate(&spec)
			second, err := sso.NewVerifiedAttribute(spec)
			if err != nil {
				t.Fatal(err)
			}
			input := protocolAssertionInput()
			input.Attributes = []sso.VerifiedAttribute{first, second}
			if input.Validate() != sso.ErrInvalidInput {
				t.Fatal("mixed assertion authority admitted")
			}
			if result, err := sso.NewProtocolAssertion(input); err != sso.ErrInvalidInput || result.Validate() != sso.ErrInvalidInput {
				t.Fatal("mixed authority construction returned usable evidence")
			}
		})
	}
}
