package postgres

import (
	"bytes"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/risk"
)

func providerLoginCallbackTerminalFixture(t *testing.T) (providerLoginPayloadConfig, providerLoginCallbackLookup) {
	t.Helper()
	c, input, now, _ := providerLoginPayloadFixture(t)
	output, err := c.generate(t.Context(), input, 1, risk.PreparedAuthenticationAdmission{})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(output)
	restored, err := c.restore(t.Context(), input, 1, output)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := restored.State.binding.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(wire)
	stored, err := c.openBinding(t.Context(), input, wire)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(stored.Proof) })
	return c, providerLoginCallbackLookup{Row: input.rowIdentity(), ObservedAt: *now, Binding: stored}
}

func TestProviderLoginCallbackTerminalKeepsOnlyOriginalAuthenticatedCorrelation(t *testing.T) {
	c, found := providerLoginCallbackTerminalFixture(t)
	wire, err := c.sealProviderLoginCallbackTerminal(t.Context(), found)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(wire)
	opened, err := c.openProviderLoginCallbackTerminal(t.Context(), found.Row, wire)
	if err != nil || opened.Metadata != found.Binding.Metadata || len(opened.Proof) != 0 || opened.Plan != (providerLoginStoredPlan{}) {
		t.Fatal("terminal custody did not retain exact original metadata without proof or plan", err)
	}
	if _, err := c.openCommittedBinding(t.Context(), found.Row, wire); err == nil {
		t.Fatal("terminal receipt was admitted as a pending execution capability")
	}
	aad, err := providerLoginCallbackTerminalAAD(found.Row)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := c.open(t.Context(), aad, wire, 65536, 49152)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	if bytes.Contains(plain, []byte(`"Proof"`)) || bytes.Contains(plain, []byte(`"Plan"`)) || bytes.Contains(plain, found.Binding.Proof) {
		t.Fatal("terminal binding retained recoverable callback capability material")
	}
}

func TestProviderLoginCallbackTerminalRejectsPendingAndSubstitutedReceipts(t *testing.T) {
	c, found := providerLoginCallbackTerminalFixture(t)
	pendingAAD, err := found.Row.aad()
	if err != nil {
		t.Fatal(err)
	}
	pendingPlain, err := providerLoginPayloadEncode(found.Binding)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(pendingPlain)
	pending, err := c.seal(t.Context(), pendingAAD, pendingPlain, 65536)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(pending)
	if _, err := c.openProviderLoginCallbackTerminal(t.Context(), found.Row, pending); err == nil {
		t.Fatal("old proof-bearing pending envelope was silently treated as a terminal receipt")
	}
	wire, err := c.sealProviderLoginCallbackTerminal(t.Context(), found)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(wire)
	for name, change := range map[string]func(*providerLoginRowIdentity){
		"provider":   func(r *providerLoginRowIdentity) { r.ProviderID = "other" },
		"generation": func(r *providerLoginRowIdentity) { r.CredentialGeneration++ },
		"mapping":    func(r *providerLoginRowIdentity) { r.MappingVersion++ },
		"expiry":     func(r *providerLoginRowIdentity) { r.ExpiresAt = r.ExpiresAt.Add(-time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			row := found.Row
			change(&row)
			if _, err := c.openProviderLoginCallbackTerminal(t.Context(), row, wire); err == nil {
				t.Fatal("terminal receipt crossed original login row identity")
			}
		})
	}
	terminalAAD, err := providerLoginCallbackTerminalAAD(found.Row)
	if err != nil {
		t.Fatal(err)
	}
	for name, plain := range map[string][]byte{
		"proof-bearing terminal plaintext": pendingPlain,
		"unknown terminal schema":          []byte(`{"Schema":2,"Metadata":{}}`),
	} {
		t.Run(name, func(t *testing.T) {
			wire, err := c.seal(t.Context(), terminalAAD, plain, 65536)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(wire)
			if _, err := c.openProviderLoginCallbackTerminal(t.Context(), found.Row, wire); err == nil {
				t.Fatal("nonterminal representation was admitted under terminal envelope context")
			}
		})
	}
	terminal := found
	completed := found.ObservedAt.Add(time.Second)
	terminal.CompletedAt = &completed
	if wire, err := c.sealProviderLoginCallbackTerminal(t.Context(), terminal); err == nil || len(wire) != 0 {
		clear(wire)
		t.Fatal("already terminal custody could be resealed as a fresh completion")
	}
}
