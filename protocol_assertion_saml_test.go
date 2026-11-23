package sso_test

import (
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/faustbrian/go-sso"
)

func samlProtocolAttributeSpec(issuer string) sso.VerifiedAttributeSpec {
	spec := protocolAttributeSpec()
	spec.Provenance.Issuer = issuer
	spec.Provenance.Source = sso.AttributeSourceSAMLAssertion
	return spec
}

func TestProtocolAssertionSAMLAttributesPreserveExactEntityID(t *testing.T) {
	for name, issuer := range map[string]string{
		"HTTPS":           "https://IdP.example/Entity%2fExact",
		"URN":             "urn:example:IdP:Enterprise",
		"uppercase URN":   "URN:example:IdP:Enterprise",
		"uppercase HTTPS": "HTTPS://IdP.example/Entity%2fExact",
		"absolute URI":    "http://idp.example/entity",
		"query":           "https://idp.example/entity?tenant=Exact",
		"short URI":       "x:a",
		"1024 byte URI":   "urn:example:" + strings.Repeat("a", 1024-len("urn:example:")),
		"escaped opaque":  "urn:example:tenant%2FExact",
	} {
		t.Run(name, func(t *testing.T) {
			spec := samlProtocolAttributeSpec(issuer)
			attribute, err := sso.NewVerifiedAttribute(spec)
			if err != nil {
				t.Fatal("bounded absolute SAML entity ID rejected", err)
			}
			input := protocolAssertionInput()
			input.Attributes = []sso.VerifiedAttribute{attribute}
			assertion, err := sso.NewProtocolAssertion(input)
			if err != nil {
				t.Fatal("SAML attribute could not enter selected assertion", err)
			}
			got, err := assertion.Attributes[0].Spec()
			if err != nil || got.Provenance != spec.Provenance || got.Provenance.Issuer != issuer || got.Provenance.Source != "saml-assertion" {
				t.Fatal("SAML provider, profile, issuer or source changed")
			}
		})
	}
}

func TestProtocolAssertionSAMLAttributesRejectInvalidProvenance(t *testing.T) {
	cases := map[string]func(*sso.VerifiedAttributeSpec){
		"missing provider": func(s *sso.VerifiedAttributeSpec) { s.Provenance.ProviderID = "" },
		"zero profile":     func(s *sso.VerifiedAttributeSpec) { s.Provenance.ProviderProfileVersion = 0 },
		"missing issuer":   func(s *sso.VerifiedAttributeSpec) { s.Provenance.Issuer = "" },
		"oversized issuer": func(s *sso.VerifiedAttributeSpec) {
			s.Provenance.Issuer = "urn:example:" + strings.Repeat("a", 1025-len("urn:example:"))
		},
		"relative issuer":       func(s *sso.VerifiedAttributeSpec) { s.Provenance.Issuer = "idp.example/entity" },
		"scheme relative":       func(s *sso.VerifiedAttributeSpec) { s.Provenance.Issuer = "//idp.example/entity" },
		"empty absolute value":  func(s *sso.VerifiedAttributeSpec) { s.Provenance.Issuer = "urn:" },
		"empty HTTPS authority": func(s *sso.VerifiedAttributeSpec) { s.Provenance.Issuer = "https://" },
		"leading space":         func(s *sso.VerifiedAttributeSpec) { s.Provenance.Issuer = " urn:example:idp" },
		"embedded space":        func(s *sso.VerifiedAttributeSpec) { s.Provenance.Issuer = "urn:example:id p" },
		"control":               func(s *sso.VerifiedAttributeSpec) { s.Provenance.Issuer = "urn:example:idp\n" },
		"DEL":                   func(s *sso.VerifiedAttributeSpec) { s.Provenance.Issuer = "urn:example:idp\x7f" },
		"non ASCII":             func(s *sso.VerifiedAttributeSpec) { s.Provenance.Issuer = "urn:example:ä" },
		"invalid UTF8":          func(s *sso.VerifiedAttributeSpec) { s.Provenance.Issuer = "urn:example:\xff" },
		"invalid HTTPS escape":  func(s *sso.VerifiedAttributeSpec) { s.Provenance.Issuer = "https://idp.example/%zz" },
		"invalid URN escape":    func(s *sso.VerifiedAttributeSpec) { s.Provenance.Issuer = "urn:example:%zz" },
		"incomplete URN escape": func(s *sso.VerifiedAttributeSpec) { s.Provenance.Issuer = "urn:example:%2" },
		"backslash":             func(s *sso.VerifiedAttributeSpec) { s.Provenance.Issuer = "urn:example:idp\\entity" },
		"angle bracket":         func(s *sso.VerifiedAttributeSpec) { s.Provenance.Issuer = "urn:example:<idp>" },
		"userinfo":              func(s *sso.VerifiedAttributeSpec) { s.Provenance.Issuer = "https://user@idp.example/entity" },
		"fragment":              func(s *sso.VerifiedAttributeSpec) { s.Provenance.Issuer = "urn:example:idp#fragment" },
		"empty fragment":        func(s *sso.VerifiedAttributeSpec) { s.Provenance.Issuer = "urn:example:idp#" },
		"unknown source":        func(s *sso.VerifiedAttributeSpec) { s.Provenance.Source = "saml-response" },
		"absent source":         func(s *sso.VerifiedAttributeSpec) { s.Provenance.Source = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			spec := samlProtocolAttributeSpec("urn:example:idp")
			mutate(&spec)
			attribute, err := sso.NewVerifiedAttribute(spec)
			if err != sso.ErrInvalidInput {
				t.Fatal("invalid SAML provenance did not return the redacted input error")
			}
			if _, err := attribute.Spec(); err != sso.ErrInvalidInput {
				t.Fatal("invalid SAML provenance returned usable evidence")
			}
		})
	}
}

func TestProtocolAssertionSAMLSourceDoesNotEstablishClaimTrust(t *testing.T) {
	for _, presence := range []sso.AttributePresence{sso.AttributeAbsent, sso.AttributeNull, sso.AttributeValue} {
		for _, verified := range []bool{false, true} {
			for _, authoritative := range []bool{false, true} {
				spec := samlProtocolAttributeSpec("urn:example:idp")
				spec.Presence, spec.Verified, spec.Authoritative = presence, verified, authoritative
				if presence != sso.AttributeValue {
					spec.StringValue = nil
				}
				attribute, err := sso.NewVerifiedAttribute(spec)
				if err != nil {
					t.Fatal("explicit SAML claim evidence rejected", err)
				}
				input := protocolAssertionInput()
				input.Attributes = []sso.VerifiedAttribute{attribute}
				assertion, err := sso.NewProtocolAssertion(input)
				if err != nil {
					t.Fatal(err)
				}
				got, err := assertion.Attributes[0].Spec()
				if err != nil || got.Presence != presence || got.Verified != verified || got.Authoritative != authoritative {
					t.Fatal("SAML source inferred verification or claim authority")
				}
				if presence != sso.AttributeValue && (got.StringValue != nil || got.BooleanValue != nil) {
					t.Fatal("absent or null SAML observation gained a value")
				}
			}
		}
	}
}

func TestProtocolAssertionSAMLAttributesCannotMixSelectedEvidence(t *testing.T) {
	for name, mutate := range map[string]func(*sso.VerifiedAttributeSpec){
		"provider": func(s *sso.VerifiedAttributeSpec) { s.Provenance.ProviderID = "other-provider" },
		"profile":  func(s *sso.VerifiedAttributeSpec) { s.Provenance.ProviderProfileVersion++ },
		"issuer":   func(s *sso.VerifiedAttributeSpec) { s.Provenance.Issuer = "https://idp.example/other" },
		"source":   func(s *sso.VerifiedAttributeSpec) { s.Provenance.Source = sso.AttributeSourceOIDCIDToken },
	} {
		t.Run(name, func(t *testing.T) {
			first, err := sso.NewVerifiedAttribute(samlProtocolAttributeSpec("https://idp.example/entity"))
			if err != nil {
				t.Fatal(err)
			}
			spec := samlProtocolAttributeSpec("https://idp.example/entity")
			spec.Name = "other-name"
			mutate(&spec)
			second, err := sso.NewVerifiedAttribute(spec)
			if err != nil {
				t.Fatal(err)
			}
			input := protocolAssertionInput()
			input.Attributes = []sso.VerifiedAttribute{first, second}
			if _, err := sso.NewProtocolAssertion(input); err != sso.ErrInvalidInput {
				t.Fatal("SAML observations crossed selected provider, profile, issuer or source")
			}
		})
	}
}

func TestProtocolAssertionSAMLDoesNotRelaxLegacyIssuerRules(t *testing.T) {
	for _, source := range []sso.AttributeSource{sso.AttributeSourceOIDCIDToken, sso.AttributeSourceOAuthIdentityEndpoint} {
		for _, issuer := range []string{"urn:example:idp", "http://idp.example/entity", "https://idp.example/entity?tenant=Exact"} {
			spec := protocolAttributeSpec()
			spec.Provenance.Source, spec.Provenance.Issuer = source, issuer
			if _, err := sso.NewVerifiedAttribute(spec); err != sso.ErrInvalidInput {
				t.Fatal("SAML URI acceptance relaxed a legacy issuer rule")
			}
		}
		spec := protocolAttributeSpec()
		spec.Provenance.Source = source
		spec.Provenance.Issuer = "https://idp.example/" + strings.Repeat("a", 2048-len("https://idp.example/"))
		if _, err := sso.NewVerifiedAttribute(spec); err != nil {
			t.Fatal("SAML bound narrowed a legacy HTTPS issuer", err)
		}
	}
}

func TestProtocolAssertionSAMLAttributesRemainRedacted(t *testing.T) {
	spec := samlProtocolAttributeSpec("urn:private-enterprise:idp")
	attribute, err := sso.NewVerifiedAttribute(spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{spec.Provenance, spec, attribute} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
			got := fmt.Sprintf(format, value)
			if !strings.Contains(got, "redacted") || strings.Contains(got, "private-enterprise") || strings.Contains(got, "private-name") {
				t.Fatal("implicit formatting disclosed SAML evidence")
			}
		}
		if _, err := json.Marshal(value); !errors.Is(err, sso.ErrSensitiveSerialization) {
			t.Fatal("implicit JSON serialization admitted SAML evidence")
		}
		if data, err := value.(encoding.TextMarshaler).MarshalText(); err != sso.ErrSensitiveSerialization || len(data) != 0 {
			t.Fatal("implicit text serialization admitted SAML evidence")
		}
		if got := value.(slog.LogValuer).LogValue().String(); !strings.Contains(got, "redacted") || strings.Contains(got, "private-enterprise") {
			t.Fatal("structured logging disclosed SAML provenance")
		}
	}
}
