package postgres

import (
	"crypto/sha256"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

func TestSAMLIDPLogoutReplayIDBindsExactInstalledIssuerAndRequestID(t *testing.T) {
	original := samlLogoutIssuerScope{organization: "organization-a", provider: "provider-a", issuer: "urn:idp:a"}
	const request = "_signed-id"
	id := samlIDPLogoutReplayID(original, request)
	if id == ([32]byte{}) || id != samlIDPLogoutReplayID(original, request) {
		t.Fatal("same installed request does not select one replay key")
	}
	for _, changed := range []samlLogoutIssuerScope{
		{organization: "organization-b", provider: original.provider, issuer: original.issuer},
		{organization: original.organization, provider: "provider-b", issuer: original.issuer},
		{organization: original.organization, provider: original.provider, issuer: "urn:idp:b"},
	} {
		if samlIDPLogoutReplayID(changed, request) == id {
			t.Fatal("another installed subject namespace shares request replay custody")
		}
	}
	if samlIDPLogoutReplayID(original, "_different-signed-id") == id {
		t.Fatal("distinct signed request selected the same replay custody")
	}
}

func TestSAMLIDPLogoutRelayStateRetainsLegacyRequestIntent(t *testing.T) {
	phase := samlIDPLogoutPhase{
		service:       &ProviderSAMLIDPLogoutService{login: &ProviderLoginService{config: ProviderLoginConfig{ConfigurationID: "installed-v1"}}},
		profile:       samlIDPLogoutProvider{config: ProviderSAMLIDPLogoutProfile{IdentityProviderEntityID: "urn:provider:one", ResponseEndpoint: "https://idp.example.test/slo"}},
		messageDigest: sha256.Sum256([]byte("signed-wire")),
		replayID:      sha256.Sum256([]byte("installed-request-id")),
	}
	// Existing installations stored this exact intent representation before
	// selecting RelayState; outstanding retry keys must still resolve it.
	legacy, err := json.Marshal(struct {
		Configuration   string
		Provider        ProviderSAMLIDPLogoutProfile
		Request, Replay [32]byte
	}{"installed-v1", phase.profile.config, phase.messageDigest, phase.replayID})
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(legacy)
	field := func() [32]byte {
		t.Helper()
		intent, err := phase.requestIntent()
		fields, ok := intent.Fields()
		if err != nil || !ok || len(fields) != 1 || fields[0].Name != "sso.saml.idp-logout.request" || len(fields[0].Value.Bytes) != len(want) {
			t.Fatal("invalid request intent", err)
		}
		return [32]byte(fields[0].Value.Bytes)
	}
	if field() != want {
		t.Fatal("absence changed the deployed request fingerprint")
	}
	first := sha256.Sum256([]byte("Opaque-A"))
	second := sha256.Sum256([]byte("Opaque-B"))
	phase.relayDigest = &first
	selected := field()
	phase.relayDigest = &second
	if selected == want || field() == selected {
		t.Fatal("different opaque state did not change the original request intent")
	}
}

func FuzzSAMLIDPLogoutRelayState(f *testing.F) {
	for _, seed := range []string{"", "opaque-A_9", strings.Repeat("A", 80), strings.Repeat("A", 81), "https://elsewhere.example", "a\x00b", "£"} {
		f.Add(seed)
	}
	grammar := regexp.MustCompile(`^[A-Za-z0-9_-]{1,80}$`)
	f.Fuzz(func(t *testing.T, input string) {
		if got, err := parseSAMLIDPLogoutRelayState([]string{input}); grammar.MatchString(input) {
			if err != nil || got != input {
				t.Fatal("valid opaque state was rejected or changed")
			}
		} else if err == nil || got != "" {
			t.Fatal("invalid opaque state was accepted or disclosed")
		}
		if got, err := parseSAMLIDPLogoutRelayState([]string{input, input}); err == nil || got != "" {
			t.Fatal("duplicate state was accepted or disclosed")
		}
		if got, err := parseSAMLIDPLogoutRelayState(nil); err != nil || got != "" {
			t.Fatal("absent state required a value")
		}
	})
}
