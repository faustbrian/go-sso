package sso_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/faustbrian/go-sso"
)

func TestStaticOIDCUpdateConfigurationIsExplicitAndRedacted(t *testing.T) {
	if _, err := sso.NewStaticOIDCProviderConfiguration(sso.OIDCStaticMetadata{}); !errors.Is(err, sso.ErrInvalidInput) {
		t.Fatal("zero metadata selected update profile", err)
	}
	if _, err := (sso.TypedProviderConfiguration{}).StaticOIDC(); !errors.Is(err, sso.ErrInvalidInput) {
		t.Fatal("zero configuration projected metadata", err)
	}
	spec := sso.OIDCStaticMetadataSpec{Issuer: "https://update.example.com", AuthorizationEndpoint: "https://update.example.com/authorize", TokenEndpoint: "https://update.example.com/token", JWKSURI: "https://update.example.com/keys"}
	metadata, err := sso.NewOIDCStaticMetadata(spec)
	if err != nil {
		t.Fatal(err)
	}
	configuration, err := sso.NewStaticOIDCProviderConfiguration(metadata)
	if err != nil {
		t.Fatal(err)
	}
	projection, err := configuration.StaticOIDC()
	if err != nil {
		t.Fatal(err)
	}
	actual, err := projection.Spec()
	if err != nil || actual != spec {
		t.Fatal("update configuration changed explicit locations", err)
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if strings.Contains(fmt.Sprintf(format, configuration), spec.Issuer) {
			t.Fatal("update configuration formatted endpoint")
		}
	}
	if _, err = json.Marshal(configuration); !errors.Is(err, sso.ErrSensitiveSerialization) {
		t.Fatal("implicit update configuration serialization admitted", err)
	}
}
