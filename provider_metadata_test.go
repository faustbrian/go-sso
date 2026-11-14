package sso_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/faustbrian/go-sso"
)

func staticOIDCSpec() sso.OIDCStaticMetadataSpec {
	return sso.OIDCStaticMetadataSpec{
		Issuer:                "https://issuer.example.com/company",
		AuthorizationEndpoint: "https://issuer.example.com/authorize",
		TokenEndpoint:         "https://issuer.example.com/token",
		JWKSURI:               "https://issuer.example.com/keys",
	}
}

func TestOIDCStaticMetadataPreservesExplicitEndpointsWithoutDiscovery(t *testing.T) {
	spec := staticOIDCSpec()
	metadata, err := sso.NewOIDCStaticMetadata(spec)
	if err != nil {
		t.Fatal("valid explicit static metadata", err)
	}
	got, err := metadata.Spec()
	if err != nil || got != spec {
		t.Fatal("static configuration was changed", err)
	}
	if _, err := (sso.OIDCStaticMetadata{}).Spec(); !errors.Is(err, sso.ErrInvalidInput) {
		t.Fatal("zero metadata admitted", err)
	}
	if wire, err := json.Marshal(metadata); !errors.Is(err, sso.ErrSensitiveSerialization) || len(wire) != 0 {
		t.Fatal("implicit metadata export allowed")
	}
	if strings.Contains(fmt.Sprintf("%+v", metadata), spec.Issuer) {
		t.Fatal("metadata diagnostics disclosed configuration")
	}
}

func TestOIDCStaticMetadataRejectsAmbiguousOrUnboundedConfiguration(t *testing.T) {
	for name, change := range map[string]func(*sso.OIDCStaticMetadataSpec){
		"missing issuer":  func(s *sso.OIDCStaticMetadataSpec) { s.Issuer = "" },
		"insecure issuer": func(s *sso.OIDCStaticMetadataSpec) { s.Issuer = "http://issuer.example.com" },
		"issuer query":    func(s *sso.OIDCStaticMetadataSpec) { s.Issuer += "?tenant=other" },
		"issuer fragment": func(s *sso.OIDCStaticMetadataSpec) { s.Issuer += "#other" },
		"embedded credentials": func(s *sso.OIDCStaticMetadataSpec) {
			s.TokenEndpoint = "https://user:password@issuer.example.com/token"
		},
		"missing endpoint":   func(s *sso.OIDCStaticMetadataSpec) { s.AuthorizationEndpoint = "" },
		"relative endpoint":  func(s *sso.OIDCStaticMetadataSpec) { s.JWKSURI = "/keys" },
		"endpoint fragment":  func(s *sso.OIDCStaticMetadataSpec) { s.TokenEndpoint += "#other" },
		"unbounded endpoint": func(s *sso.OIDCStaticMetadataSpec) { s.JWKSURI += strings.Repeat("a", 4097) },
	} {
		t.Run(name, func(t *testing.T) {
			spec := staticOIDCSpec()
			change(&spec)
			_, err := sso.NewOIDCStaticMetadata(spec)
			if !errors.Is(err, sso.ErrInvalidInput) {
				t.Fatal("ambiguous static metadata admitted", err)
			}
		})
	}
}

func TestOIDCStaticMetadataPreservesEndpointQueriesAndExactURLBudget(t *testing.T) {
	spec := staticOIDCSpec()
	spec.AuthorizationEndpoint += "?deployment=company&path=a%2Fb"
	spec.TokenEndpoint += "?deployment=company"
	spec.JWKSURI += strings.Repeat("a", 4096-len(spec.JWKSURI))
	metadata, err := sso.NewOIDCStaticMetadata(spec)
	if err != nil {
		t.Fatal("valid endpoint query or exact URL bound rejected", err)
	}
	got, err := metadata.Spec()
	if err != nil || got != spec {
		t.Fatal("configured endpoint bytes changed", err)
	}
	spec.JWKSURI += "a"
	if _, err := sso.NewOIDCStaticMetadata(spec); !errors.Is(err, sso.ErrInvalidInput) {
		t.Fatal("URL bound exceeded", err)
	}
}

func TestOIDCStaticMetadataEnforcesTheRegistrationIssuerBudget(t *testing.T) {
	spec := staticOIDCSpec()
	spec.Issuer += strings.Repeat("a", 2048-len(spec.Issuer))
	metadata, err := sso.NewOIDCStaticMetadata(spec)
	if err != nil {
		t.Fatal("exact registration issuer bound rejected", err)
	}
	got, err := metadata.Spec()
	if err != nil || got.Issuer != spec.Issuer {
		t.Fatal("issuer identity changed", err)
	}
	spec.Issuer += "a"
	if _, err := sso.NewOIDCStaticMetadata(spec); !errors.Is(err, sso.ErrInvalidInput) {
		t.Fatal("registration issuer bound exceeded", err)
	}
}

func FuzzOIDCStaticMetadata(f *testing.F) {
	for _, seed := range []string{"https://issuer.example.com/path", "https://issuer.example.com/path?x=1", "https://user:password@issuer.example.com/path", "http://issuer.example.com/", "https://issuer.example.com/#fragment", "\x00", strings.Repeat("a", 4097)} {
		f.Add(seed, uint8(0))
		f.Add(seed, uint8(1))
	}
	f.Fuzz(func(t *testing.T, raw string, field uint8) {
		spec := staticOIDCSpec()
		switch field % 4 {
		case 0:
			spec.Issuer = raw
		case 1:
			spec.AuthorizationEndpoint = raw
		case 2:
			spec.TokenEndpoint = raw
		case 3:
			spec.JWKSURI = raw
		}
		metadata, err := sso.NewOIDCStaticMetadata(spec)
		if err != nil {
			if !errors.Is(err, sso.ErrInvalidInput) {
				t.Fatal("non-redacted metadata error")
			}
			return
		}
		got, err := metadata.Spec()
		if err != nil || got != spec {
			t.Fatal("accepted exact metadata bytes changed")
		}
		if _, err = json.Marshal(metadata); !errors.Is(err, sso.ErrSensitiveSerialization) {
			t.Fatal("metadata implicitly serialized")
		}
	})
}
