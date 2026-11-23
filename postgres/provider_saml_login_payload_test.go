package postgres

import (
	"context"
	"encoding/base64"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/risk"
)

func TestProviderSAMLLoginPayloadPreservesOriginalRelayStateWithoutPKCE(t *testing.T) {
	c, input, now, _ := providerLoginPayloadFixture(t)
	c.PKCEKeys, c.CurrentPKCEKey = nil, 0
	input.Protocol, input.ClientID = providerProtocolSAML, ""
	input.Issuer = "urn:example:enterprise:original"
	input.RedirectURI = "https://app.example/saml2/provider/acs"
	input.Command.OperationID, input.Command.SchemaID = "identity.sso.saml-start", "identity.sso.saml-start.v1"
	input.ExpiresAt = input.IssuedAt.Add(5 * time.Minute)
	ctx := context.Background()
	if wire, err := c.generate(ctx, input, 1, risk.PreparedAuthenticationAdmission{}); err == nil || wire != nil {
		t.Fatal("unsigned SAML start acquired durable custody")
	}
	var signed url.URL
	signCalls := 0
	wire, err := c.generateWithSAMLRedirect(ctx, input, 1, risk.PreparedAuthenticationAdmission{},
		func(_ context.Context, requestID string, issuedAt time.Time, relayState string) (url.URL, error) {
			signCalls++
			if requestID != "_"+string(input.Command.CommandID) || !issuedAt.Equal(input.IssuedAt) {
				t.Fatal("signer did not receive the original AuthnRequest identity or time")
			}
			signed = url.URL{Scheme: "https", Host: "enterprise.example", Path: "/saml", RawQuery: url.Values{
				"SAMLRequest": {"request"}, "RelayState": {relayState},
				"SigAlg": {"http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1"}, "Signature": {"test-signature"},
			}.Encode()}
			return signed, nil
		})
	if err != nil {
		t.Fatal("prepare SAML with state-key custody and no fake PKCE", err)
	}
	out, err := c.restore(ctx, input, 1, wire)
	if err != nil || out.State.pkceKey != 0 || out.State.pkceCommitment != ([32]byte{}) || out.State.callbackCommand == input.Command.CommandID {
		t.Fatal("restore original no-PKCE SAML preparation", err)
	}
	if verifier, err := out.State.verifier.MarshalBinary(); err == nil || len(verifier) != 0 {
		t.Fatal("SAML preparation carried a recoverable PKCE verifier")
	}
	binding, err := out.State.binding.MarshalBinary()
	if err != nil {
		t.Fatal("project authenticated SAML row", err)
	}
	original, err := c.redirectState(ctx, input, binding)
	decoded, decodeErr := base64.RawURLEncoding.Strict().DecodeString(original.State)
	defer clear(decoded)
	if err != nil || decodeErr != nil || len(decoded) != 32 || len(original.State) != 43 || original.Nonce != "" || original.Challenge != "" {
		t.Fatal("SAML disclosure retained nonopaque or sibling query values", err, decodeErr)
	}
	recovered, err := c.samlRedirect(ctx, input, binding)
	if err != nil || recovered != signed || recovered.Query().Get("RelayState") != original.State || signCalls != 1 {
		t.Fatal("SAML recovery did not reuse the exact original signed redirect", err)
	}
	plan, err := out.Issuance.Plan()
	if err != nil || len(plan.Grants) != 1 || string(plan.Grants[0].Purpose) != "identity.sso.saml-acs" || !plan.Grants[0].ExpiresAt.Equal(input.ExpiresAt) {
		t.Fatal("prepared SAML state lost its exclusive callback grant", err)
	}
	*now = now.Add(time.Minute)
	again, err := c.restore(ctx, input, 1, wire)
	if err != nil || !reflect.DeepEqual(out.State, again.State) {
		t.Fatal("SAML replay regenerated original custody", err)
	}
	for _, change := range []func(*providerLoginPayloadInput){
		func(i *providerLoginPayloadInput) { i.Protocol = providerProtocolOAuth2 },
		func(i *providerLoginPayloadInput) { i.Command.AnonymousFlowID += "x" },
		func(i *providerLoginPayloadInput) { i.RedirectURI = "https://app.example/saml2/other/acs" },
		func(i *providerLoginPayloadInput) { i.ExpiresAt = i.ExpiresAt.Add(time.Second) },
	} {
		changed := input
		change(&changed)
		if _, err := c.restore(ctx, changed, 1, wire); err == nil {
			t.Fatal("modified or foreign protocol SAML envelope restored")
		}
	}
	*now = input.ExpiresAt
	if _, err := c.restore(ctx, input, 1, wire); err == nil {
		t.Fatal("SAML restored its original state at its exclusive expiry")
	}
}

func TestProviderSAMLLoginPayloadRequiresExactFrontchannelPath(t *testing.T) {
	origin := "https://identity.example"
	if got, ok := samlProviderCallbackURL(origin, "_exact-Provider"); !ok || got != origin+"/saml2/_exact-Provider/acs" {
		t.Fatal("canonical provider lost its exact registered ACS")
	}
	for _, origin := range []string{"http://identity.example", "https://IDENTITY.example", "https://identity.example/portal", "https://identity.example?tenant=other"} {
		if got, ok := samlProviderCallbackURL(origin, "provider"); ok || got != "" {
			t.Fatal("unregistered deployment origin selected an ACS")
		}
	}
	for _, provider := range []string{"", "..", "a/b", "a%2Fb", "a;b", "{provider}"} {
		if got, ok := samlProviderCallbackURL(origin, provider); ok || got != "" {
			t.Fatal("noncanonical provider path selected an ACS")
		}
	}
}
