package postgres

import "testing"

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
