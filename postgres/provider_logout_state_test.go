package postgres

import (
	"bytes"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-sso/oidc"
)

func TestProviderLogoutStateSealsTheOriginalProviderAndSession(t *testing.T) {
	config, _, _, _ := providerLoginPayloadFixture(t)
	start, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	completion, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	state := oidc.NewRPLogoutState([32]byte{1})
	key := [32]byte{2}
	issued := time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC)
	row := providerLogoutRow{TenantID: "tenant-a", StartCommandID: start, StateKeyVersion: 1,
		StateDigest: providerLogoutStateDigest("tenant-a", key, state), IssuedAt: issued, ExpiresAt: issued.Add(time.Minute)}
	bound := providerLogoutBinding{
		UserID: "user-a", OrganizationID: "organization-a", ProviderID: "provider-a", SessionID: "session-a",
		CredentialID: "credential-a", SessionVersion: 7, ProviderVersion: 9, CredentialVersion: 3, CompletionCommandID: completion,
		Protocol:      oidc.RPLogoutProfileConfig{Issuer: "https://provider.example.test", ClientID: "client-a", EndSessionEndpoint: "https://provider.example.test/end-session", CallbackURI: "https://identity.example.test/sso/oidc/provider-a/logout/callback"},
		FinalRedirect: "https://identity.example.test/signed-out",
	}
	wire, err := sealProviderLogoutBinding(t.Context(), config, row, bound)
	if err != nil {
		t.Fatal("seal original one-use binding", err)
	}
	if bytes.Contains(wire, []byte(bound.SessionID)) || bytes.Contains(wire, []byte(bound.FinalRedirect)) || bytes.Contains(wire, []byte(state.Encode())) {
		t.Fatal("private logout metadata stored in clear")
	}
	got, err := openProviderLogoutBinding(t.Context(), config, row, wire)
	if err != nil || got != bound {
		t.Fatal("original provider/session/target binding changed", err)
	}
	for name, change := range map[string]func(*providerLogoutRow){
		"tenant":       func(r *providerLogoutRow) { r.TenantID = "tenant-b" },
		"command":      func(r *providerLogoutRow) { r.StartCommandID = completion },
		"state key":    func(r *providerLogoutRow) { r.StateKeyVersion++ },
		"state digest": func(r *providerLogoutRow) { r.StateDigest[0] ^= 1 },
		"issued":       func(r *providerLogoutRow) { r.IssuedAt = issued.Add(time.Second) },
		"expiry":       func(r *providerLogoutRow) { r.ExpiresAt = r.ExpiresAt.Add(time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := row
			change(&candidate)
			if got, err := openProviderLogoutBinding(t.Context(), config, candidate, wire); err == nil || got != (providerLogoutBinding{}) {
				t.Fatal("transplanted state binding admitted", err)
			}
		})
	}
	broken := bytes.Clone(wire)
	broken[len(broken)-1] ^= 1
	if got, err := openProviderLogoutBinding(t.Context(), config, row, broken); err == nil || got != (providerLogoutBinding{}) {
		t.Fatal("tampered state binding admitted", err)
	}
	if row.StateDigest == providerLogoutStateDigest("tenant-b", key, state) || row.StateDigest == providerLogoutStateDigest("tenant-a", [32]byte{3}, state) {
		t.Fatal("state lookup lost its tenant or key boundary")
	}
	for name, change := range map[string]func(*providerLogoutBinding){
		"same command": func(b *providerLogoutBinding) { b.CompletionCommandID = start },
		"foreign callback route": func(b *providerLogoutBinding) {
			b.Protocol.CallbackURI = "https://identity.example.test/sso/oidc/provider-b/logout/callback"
		},
		"invalid final target":   func(b *providerLogoutBinding) { b.FinalRedirect = "http://example.test" },
		"absent session version": func(b *providerLogoutBinding) { b.SessionVersion = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := bound
			change(&candidate)
			if got, err := sealProviderLogoutBinding(t.Context(), config, row, candidate); err == nil || got != nil {
				t.Fatal("invalid logout preparation sealed", err)
			}
		})
	}
}
