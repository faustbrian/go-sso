package postgres

import (
	"bytes"
	"testing"
)

func TestSAMLLogoutRelayCustodyPreservesHistoricalEncoding(t *testing.T) {
	// Existing envelope authentication requires byte-for-byte JSON custody,
	// including field order. An unselected Relay must not rewrite old bytes.
	type historicalBinding struct {
		Anchor                                                samlLogoutIssuanceAnchor
		Subject                                               samlStoredLogoutSubject
		Issuer, Endpoint, FinalRedirect, Redirect             string
		SessionVersion, ProviderVersion, CredentialGeneration uint64
	}
	old := historicalBinding{Issuer: "urn:example:idp", Endpoint: "https://idp.example/slo", FinalRedirect: "https://app.example/done", Redirect: "https://idp.example/slo?original-wire", SessionVersion: 2, ProviderVersion: 3, CredentialGeneration: 4}
	current := samlLogoutRequestBinding{Anchor: old.Anchor, Subject: old.Subject, Issuer: old.Issuer, Endpoint: old.Endpoint, FinalRedirect: old.FinalRedirect, Redirect: old.Redirect, SessionVersion: old.SessionVersion, ProviderVersion: old.ProviderVersion, CredentialGeneration: old.CredentialGeneration}
	want, err := providerLoginPayloadEncode(old)
	if err != nil {
		t.Fatal(err)
	}
	got, err := providerLoginPayloadEncode(current)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("unselected Relay changed historical sealed payload representation", err)
	}
	var restored samlLogoutRequestBinding
	if providerLoginPayloadDecode(want, &restored) != nil || restored != current || restored.Relay != nil {
		t.Fatal("historical no-state custody did not restore unchanged")
	}
}
