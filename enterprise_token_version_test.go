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

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	"github.com/faustbrian/go-sso"
)

func enterpriseTokenVersionSpec() sso.TokenVersionSpec {
	return sso.TokenVersionSpec{
		TenantID: "token-tenant", OrganizationID: "enterprise-org", ProviderID: "enterprise-provider",
		ProviderSubject: "Case.Exact:subject", CommandID: identity.CommandID("AQEBAQEBAQEBAQEBAQEBAQ"),
		CredentialGeneration: 3, Version: 5, Purpose: sso.EnterpriseTokenPurpose,
	}
}

func TestEnterpriseTokenVersionPreservesDetachedExactBindings(t *testing.T) {
	spec := enterpriseTokenVersionSpec()
	spec.CredentialGeneration, spec.Version = math.MaxUint64, math.MaxUint64
	spec.OrganizationID = organization.ID("Örg.Exact")
	spec.ProviderSubject = " Subject.Exact:é "
	reference, err := sso.NewTokenVersion(spec)
	if err != nil {
		t.Fatal("bounded token correlation rejected", err)
	}
	got, err := reference.Spec()
	if err != nil || got != spec {
		t.Fatal("reference changed exact correlation bindings")
	}
	again, err := sso.NewTokenVersion(got)
	if err != nil || reference != again {
		t.Fatal("trusted storage projection did not preserve comparable identity")
	}
	spec.TenantID, got.ProviderSubject = "changed source", "changed projection"
	unchanged, _ := reference.Spec()
	if unchanged.TenantID != "token-tenant" || unchanged.ProviderSubject != " Subject.Exact:é " {
		t.Fatal("caller mutation changed opaque correlation")
	}
	for name, mutate := range map[string]func(*sso.TokenVersionSpec){
		"tenant":       func(s *sso.TokenVersionSpec) { s.TenantID = "another-tenant" },
		"organization": func(s *sso.TokenVersionSpec) { s.OrganizationID = "another-org" },
		"provider":     func(s *sso.TokenVersionSpec) { s.ProviderID = "another-provider" },
		"subject":      func(s *sso.TokenVersionSpec) { s.ProviderSubject = "subject" },
		"command":      func(s *sso.TokenVersionSpec) { s.CommandID = "AgICAgICAgICAgICAgICAg" },
		"generation":   func(s *sso.TokenVersionSpec) { s.CredentialGeneration-- },
		"version":      func(s *sso.TokenVersionSpec) { s.Version-- },
	} {
		t.Run(name, func(t *testing.T) {
			changed := unchanged
			mutate(&changed)
			other, err := sso.NewTokenVersion(changed)
			if err != nil || other == reference {
				t.Fatal("different binding collapsed into same correlation")
			}
		})
	}
}

func TestEnterpriseTokenVersionRejectsInvalidShape(t *testing.T) {
	for name, mutate := range map[string]func(*sso.TokenVersionSpec){
		"empty tenant":               func(s *sso.TokenVersionSpec) { s.TenantID = "" },
		"padded tenant":              func(s *sso.TokenVersionSpec) { s.TenantID = " tenant" },
		"oversized tenant":           func(s *sso.TokenVersionSpec) { s.TenantID = identity.TenantID(strings.Repeat("t", 129)) },
		"empty organization":         func(s *sso.TokenVersionSpec) { s.OrganizationID = "" },
		"control organization":       func(s *sso.TokenVersionSpec) { s.OrganizationID = "org\n" },
		"empty provider":             func(s *sso.TokenVersionSpec) { s.ProviderID = "" },
		"non ASCII provider":         func(s *sso.TokenVersionSpec) { s.ProviderID = "pröv" },
		"empty subject":              func(s *sso.TokenVersionSpec) { s.ProviderSubject = "" },
		"oversized subject":          func(s *sso.TokenVersionSpec) { s.ProviderSubject = strings.Repeat("s", 513) },
		"invalid UTF8 subject":       func(s *sso.TokenVersionSpec) { s.ProviderSubject = "\xff" },
		"control subject":            func(s *sso.TokenVersionSpec) { s.ProviderSubject = "subject\x00" },
		"empty command":              func(s *sso.TokenVersionSpec) { s.CommandID = "" },
		"zero command entropy":       func(s *sso.TokenVersionSpec) { s.CommandID = "AAAAAAAAAAAAAAAAAAAAAA" },
		"noncanonical command":       func(s *sso.TokenVersionSpec) { s.CommandID = "AQEBAQEBAQEBAQEBAQEBAQ==" },
		"zero credential generation": func(s *sso.TokenVersionSpec) { s.CredentialGeneration = 0 },
		"zero token version":         func(s *sso.TokenVersionSpec) { s.Version = 0 },
		"empty purpose":              func(s *sso.TokenVersionSpec) { s.Purpose = "" },
		"different purpose":          func(s *sso.TokenVersionSpec) { s.Purpose = "client-secret" },
	} {
		t.Run(name, func(t *testing.T) {
			spec := enterpriseTokenVersionSpec()
			mutate(&spec)
			reference, err := sso.NewTokenVersion(spec)
			if err != sso.ErrInvalidInput || reference != (sso.TokenVersion{}) {
				t.Fatal("invalid shape returned usable correlation or disclosed input")
			}
			if got, err := reference.Spec(); err != sso.ErrInvalidInput || got != (sso.TokenVersionSpec{}) {
				t.Fatal("invalid reference projected bindings")
			}
		})
	}
	if got, err := (sso.TokenVersion{}).Spec(); err != sso.ErrInvalidInput || got != (sso.TokenVersionSpec{}) {
		t.Fatal("zero reference projected bindings")
	}
}

func TestProtocolAssertionTokenReferenceRejectsCrossBindings(t *testing.T) {
	input := protocolAssertionInput()
	if _, err := sso.NewProtocolAssertion(input); err != nil {
		t.Fatal("omitted optional reference rejected", err)
	}
	for name, mutate := range map[string]func(*sso.TokenVersionSpec){
		"organization": func(s *sso.TokenVersionSpec) { s.OrganizationID = "other-org" },
		"provider":     func(s *sso.TokenVersionSpec) { s.ProviderID = "other-provider" },
		"subject case": func(s *sso.TokenVersionSpec) { s.ProviderSubject = "case.Exact:subject" },
	} {
		t.Run(name, func(t *testing.T) {
			spec := enterpriseTokenVersionSpec()
			mutate(&spec)
			reference, err := sso.NewTokenVersion(spec)
			if err != nil {
				t.Fatal(err)
			}
			input.TokenReference = reference
			if input.Validate() != sso.ErrInvalidInput {
				t.Fatal("cross-bound token reference admitted")
			}
			if result, err := sso.NewProtocolAssertion(input); err != sso.ErrInvalidInput || result.Validate() != sso.ErrInvalidInput {
				t.Fatal("cross-bound reference constructed usable assertion")
			}
		})
	}
	reference, err := sso.NewTokenVersion(enterpriseTokenVersionSpec())
	if err != nil {
		t.Fatal(err)
	}
	input.TokenReference = reference
	assertion, err := sso.NewProtocolAssertion(input)
	if err != nil || assertion.TokenReference != reference {
		t.Fatal("matching reference rejected or changed", err)
	}
	input.TokenReference = sso.TokenVersion{}
	if assertion.TokenReference != reference || assertion.Validate() != nil {
		t.Fatal("caller mutation changed assertion token correlation")
	}
}

func TestEnterpriseTokenVersionDeniesImplicitDisclosure(t *testing.T) {
	spec := enterpriseTokenVersionSpec()
	reference, err := sso.NewTokenVersion(spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{spec, reference} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
			got := fmt.Sprintf(format, value)
			if !strings.Contains(got, "redacted") || strings.Contains(got, "token-tenant") || strings.Contains(got, "enterprise-provider") || strings.Contains(got, "Case.Exact:subject") || strings.Contains(got, string(spec.CommandID)) {
				t.Fatal("implicit formatting disclosed token correlation")
			}
		}
		if data, err := json.Marshal(value); !errors.Is(err, sso.ErrSensitiveSerialization) || len(data) != 0 {
			t.Fatal("implicit JSON serialization admitted")
		}
		text, ok := value.(encoding.TextMarshaler)
		if !ok {
			t.Fatal("missing text serialization denial")
		}
		if data, err := text.MarshalText(); err != sso.ErrSensitiveSerialization || len(data) != 0 {
			t.Fatal("implicit text serialization admitted")
		}
		logValue, ok := value.(slog.LogValuer)
		if !ok || !strings.Contains(logValue.LogValue().String(), "redacted") {
			t.Fatal("missing structured log redaction")
		}
	}
}
