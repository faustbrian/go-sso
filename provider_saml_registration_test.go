package sso_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-sso"
)

func samlRegistrationSpec() sso.SAMLConfigurationSpec {
	return sso.SAMLConfigurationSpec{
		EntityID:         "HTTPS://idp.example/Exact%2fEntity?realm=One",
		RedirectEndpoint: "https://idp.example/SAML%2fLogin?tenant=One%2fTwo&mode=fixed",
		// Deliberately not a valid certificate: root validates bounded shape,
		// while the native SAML constructor owns DER/key/profile validation.
		SigningCertificates: [][]byte{{0x30, 0x01, 0x01}, {0x30, 0x01, 0x02}},
	}
}

func samlRegistration(t testing.TB) sso.ProviderRegisterSamlRequest {
	t.Helper()
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	key, err := identity.NewIdempotencyKey([]byte("saml-registration-test"))
	if err != nil {
		t.Fatal(err)
	}
	mapping, err := sso.NewAttributeMapping(sso.AttributeMappingSpec{Version: 1, SubjectClaim: "NameID"})
	if err != nil {
		t.Fatal(err)
	}
	configuration, err := sso.NewSAMLConfiguration(samlRegistrationSpec())
	if err != nil {
		t.Fatal(err)
	}
	return sso.ProviderRegisterSamlRequest{CommandID: command, OrganizationID: "organization-1", Configuration: configuration,
		Domains: []string{"example.com"}, Mapping: mapping, IdempotencyKey: key}
}

func TestSAMLRegistrationIntentPreservesExplicitConfiguration(t *testing.T) {
	r := samlRegistration(t)
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	got, err := r.Configuration.Spec()
	if err != nil || !reflect.DeepEqual(got, samlRegistrationSpec()) {
		t.Fatal("lost exact explicit configuration")
	}
	for _, entity := range []string{"urn:example:identity:Exact", "URN:example:identity:Exact", "https://idp.example/entity"} {
		spec := samlRegistrationSpec()
		spec.EntityID = entity
		config, err := sso.NewSAMLConfiguration(spec)
		if err != nil {
			t.Fatal("supported entity rejected", err)
		}
		got, err := config.Spec()
		if err != nil || got.EntityID != entity {
			t.Fatal("entity identifier normalized")
		}
	}
}

func TestSAMLConfigurationOwnsDetachedCertificateCopies(t *testing.T) {
	spec := samlRegistrationSpec()
	config, err := sso.NewSAMLConfiguration(spec)
	if err != nil {
		t.Fatal(err)
	}
	spec.SigningCertificates[0][0] = 0xff
	spec.SigningCertificates[1] = nil
	got, err := config.Spec()
	if err != nil || !reflect.DeepEqual(got, samlRegistrationSpec()) {
		t.Fatal("constructor borrowed mutable certificate data")
	}
	got.SigningCertificates[0][0] = 0xee
	got.SigningCertificates[1] = nil
	again, err := config.Spec()
	if err != nil || !reflect.DeepEqual(again, samlRegistrationSpec()) {
		t.Fatal("projection exposed mutable certificate data")
	}
	if got, err := (sso.SAMLConfiguration{}).Spec(); err != sso.ErrInvalidInput || !reflect.DeepEqual(got, sso.SAMLConfigurationSpec{}) {
		t.Fatal("zero configuration acquired a usable projection")
	}
}

func TestSAMLConfigurationDeniesUnsafeOrUnboundedInput(t *testing.T) {
	cases := map[string]func(*sso.SAMLConfigurationSpec){
		"empty entity":               func(s *sso.SAMLConfigurationSpec) { s.EntityID = "" },
		"plaintext entity":           func(s *sso.SAMLConfigurationSpec) { s.EntityID = "http://idp.example/entity" },
		"other entity scheme":        func(s *sso.SAMLConfigurationSpec) { s.EntityID = "ftp://idp.example/entity" },
		"entity fragment":            func(s *sso.SAMLConfigurationSpec) { s.EntityID += "#fragment" },
		"entity user info":           func(s *sso.SAMLConfigurationSpec) { s.EntityID = "https://user@idp.example/entity" },
		"entity raw query delimiter": func(s *sso.SAMLConfigurationSpec) { s.EntityID = "https://idp.example/entity?realm=<tenant>" },
		"empty URN":                  func(s *sso.SAMLConfigurationSpec) { s.EntityID = "urn:" },
		"oversized entity":           func(s *sso.SAMLConfigurationSpec) { s.EntityID = "urn:example:" + strings.Repeat("e", 1024) },
		"empty redirect":             func(s *sso.SAMLConfigurationSpec) { s.RedirectEndpoint = "" },
		"plaintext redirect":         func(s *sso.SAMLConfigurationSpec) { s.RedirectEndpoint = "http://idp.example/login" },
		"redirect user info":         func(s *sso.SAMLConfigurationSpec) { s.RedirectEndpoint = "https://user@idp.example/login" },
		"redirect fragment":          func(s *sso.SAMLConfigurationSpec) { s.RedirectEndpoint += "#fragment" },
		"redirect dot path":          func(s *sso.SAMLConfigurationSpec) { s.RedirectEndpoint = "https://idp.example/a/%2e%2e/login" },
		"redirect escaped control":   func(s *sso.SAMLConfigurationSpec) { s.RedirectEndpoint = "https://idp.example/%0a" },
		"redirect escaped backslash": func(s *sso.SAMLConfigurationSpec) { s.RedirectEndpoint = "https://idp.example/%5c" },
		"redirect malformed query":   func(s *sso.SAMLConfigurationSpec) { s.RedirectEndpoint += "&tenant=%zz" },
		"oversized redirect": func(s *sso.SAMLConfigurationSpec) {
			s.RedirectEndpoint = "https://idp.example/" + strings.Repeat("r", 2048)
		},
		"missing certificate":   func(s *sso.SAMLConfigurationSpec) { s.SigningCertificates = nil },
		"empty certificate":     func(s *sso.SAMLConfigurationSpec) { s.SigningCertificates = [][]byte{nil} },
		"oversized certificate": func(s *sso.SAMLConfigurationSpec) { s.SigningCertificates = [][]byte{make([]byte, 64*1024+1)} },
		"too many certificates": func(s *sso.SAMLConfigurationSpec) { s.SigningCertificates = [][]byte{{1}, {2}, {3}, {4}, {5}, {6}} },
		"duplicate certificate": func(s *sso.SAMLConfigurationSpec) { s.SigningCertificates = [][]byte{{1}, {1}} },
	}
	for _, reserved := range []string{"SAMLRequest", "samlresponse", "RelayState", "SigAlg", "Signature", "%53AMLRequest"} {
		cases["reserved query "+reserved] = func(s *sso.SAMLConfigurationSpec) { s.RedirectEndpoint += "&" + reserved + "=value" }
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			spec := samlRegistrationSpec()
			mutate(&spec)
			if _, err := sso.NewSAMLConfiguration(spec); err != sso.ErrInvalidInput {
				t.Fatal("expected redacted structural denial", err)
			}
		})
	}
}

func TestSAMLConfigurationAcceptsExactStructuralBounds(t *testing.T) {
	spec := samlRegistrationSpec()
	spec.EntityID = "urn:example:" + strings.Repeat("e", 1024-len("urn:example:"))
	spec.RedirectEndpoint = "https://idp.example/" + strings.Repeat("r", 2048-len("https://idp.example/"))
	spec.SigningCertificates = [][]byte{make([]byte, 64*1024), {1}, {2}, {3}, {4}}
	if _, err := sso.NewSAMLConfiguration(spec); err != nil {
		t.Fatal("inclusive structural bound rejected", err)
	}
}

func TestSAMLConfigurationPreservesEscapedEntityQuery(t *testing.T) {
	spec := samlRegistrationSpec()
	spec.EntityID = "https://idp.example/entity?realm=%3Ctenant%3E"
	configuration, err := sso.NewSAMLConfiguration(spec)
	if err != nil {
		t.Fatal("encoded IdP entity query rejected", err)
	}
	got, err := configuration.Spec()
	if err != nil || got.EntityID != spec.EntityID {
		t.Fatal("encoded IdP entity query was rewritten", err)
	}
}

func TestSAMLRegistrationIntentDeniesIncompleteOrAmbiguousScope(t *testing.T) {
	cases := map[string]func(*sso.ProviderRegisterSamlRequest){
		"missing command":       func(r *sso.ProviderRegisterSamlRequest) { r.CommandID = "" },
		"invalid command":       func(r *sso.ProviderRegisterSamlRequest) { r.CommandID = "not-a-command" },
		"missing organization":  func(r *sso.ProviderRegisterSamlRequest) { r.OrganizationID = "" },
		"invalid organization":  func(r *sso.ProviderRegisterSamlRequest) { r.OrganizationID = "organization\n" },
		"missing idempotency":   func(r *sso.ProviderRegisterSamlRequest) { r.IdempotencyKey = identity.IdempotencyKey{} },
		"missing configuration": func(r *sso.ProviderRegisterSamlRequest) { r.Configuration = sso.SAMLConfiguration{} },
		"missing mapping":       func(r *sso.ProviderRegisterSamlRequest) { r.Mapping = sso.AttributeMapping{} },
		"missing domains":       func(r *sso.ProviderRegisterSamlRequest) { r.Domains = nil },
		"noncanonical domain":   func(r *sso.ProviderRegisterSamlRequest) { r.Domains = []string{"Example.COM"} },
		"duplicate domain":      func(r *sso.ProviderRegisterSamlRequest) { r.Domains = []string{"example.com", "example.com"} },
		"oversized domain":      func(r *sso.ProviderRegisterSamlRequest) { r.Domains = []string{strings.Repeat("a", 254)} },
		"too many domains":      func(r *sso.ProviderRegisterSamlRequest) { r.Domains = make([]string, 129) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := samlRegistration(t)
			mutate(&r)
			if err := r.Validate(); err != sso.ErrInvalidInput {
				t.Fatal("expected redacted registration denial", err)
			}
		})
	}
}

func TestSAMLRegistrationIntentRedactsImplicitProjection(t *testing.T) {
	r := samlRegistration(t)
	for _, value := range []any{r, r.Configuration} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
			if got := fmt.Sprintf(format, value); !strings.HasSuffix(got, "(redacted)") {
				t.Fatal("unredacted formatting")
			}
		}
		if _, err := json.Marshal(value); !errors.Is(err, sso.ErrSensitiveSerialization) {
			t.Fatal("implicit JSON allowed", err)
		}
		text := value.(interface{ MarshalText() ([]byte, error) })
		if _, err := text.MarshalText(); err != sso.ErrSensitiveSerialization {
			t.Fatal("implicit text allowed", err)
		}
		if got := slog.AnyValue(value).Resolve().String(); !strings.HasSuffix(got, "(redacted)") {
			t.Fatal("unredacted structured logging")
		}
	}
}
