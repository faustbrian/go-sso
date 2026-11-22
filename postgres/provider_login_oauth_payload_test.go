package postgres

import (
	"bytes"
	"testing"
)

func TestProviderLoginOAuth2PayloadBindsProtocolWithoutChangingOIDC(t *testing.T) {
	_, legacy, _, _ := providerLoginPayloadFixture(t)
	oauth := legacy
	oauth.Protocol = providerProtocolOAuth2
	oauth.Command.SchemaID = "identity.sso.signin-start.oauth2-v1"
	if oauth.validate() != nil {
		t.Fatal("intact OAuth input denied")
	}
	for _, stage := range []struct {
		purpose string
		gen     uint64
	}{{"output", 1}, {"binding", 0}} {
		legacyAAD, err := providerLoginPayloadAAD(legacy, stage.purpose, stage.gen)
		if err != nil {
			t.Fatal(err)
		}
		oauthAAD, err := providerLoginPayloadAAD(oauth, stage.purpose, stage.gen)
		if err != nil || bytes.Equal(legacyAAD.AdditionalData(), oauthAAD.AdditionalData()) {
			t.Fatal("OAuth preparation replayed OIDC custody", err)
		}
	}
	encoded, err := providerLoginPayloadEncode(legacy)
	defer clear(encoded)
	if err != nil || bytes.Contains(encoded, []byte(`"Protocol"`)) {
		t.Fatal("legacy durable encoding changed", err)
	}
	for _, mutate := range []func(*providerLoginPayloadInput){
		func(p *providerLoginPayloadInput) { p.Protocol = "" },
		func(p *providerLoginPayloadInput) { p.Protocol = "oidc" }, // use the original absent representation
		func(p *providerLoginPayloadInput) { p.Protocol = "unknown" },
		func(p *providerLoginPayloadInput) { p.Command.SchemaID = legacy.Command.SchemaID },
		func(p *providerLoginPayloadInput) { p.Link = &providerLoginMemberIntent{} },
	} {
		changed := oauth
		mutate(&changed)
		if changed.validate() == nil {
			t.Fatal("substituted protocol or schema accepted")
		}
	}
}
