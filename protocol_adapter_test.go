package sso_test

import (
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/session"
	"github.com/faustbrian/go-sso"
)

func protocolLoginTransaction(t *testing.T) (sso.LoginTransaction, time.Time) {
	t.Helper()
	now := time.Date(2026, 11, 22, 20, 0, 0, 0, time.UTC)
	remember, err := session.NewRememberPolicy(session.RememberPolicySpec{
		Choice: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute,
		RefreshAfter: 5 * time.Minute, FreshFor: 15 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := sso.NewLoginTransaction(sso.LoginTransaction{
		TenantID: "example-tenant", ID: "AQEBAQEBAQEBAQEBAQEBAQ", ProviderID: "example-provider",
		OrganizationID: "example-organization", Protocol: "oauth2", CommandID: "AgICAgICAgICAgICAgICAg",
		Callback:  url.URL{Scheme: "https", Host: "identity.example.com", Path: "/sso/oauth/callback"},
		ExpiresAt: now.Add(time.Minute), ProviderVersion: 11, MappingVersion: 7, RememberPolicy: remember,
	}, 5)
	if err != nil {
		t.Fatal(err)
	}
	return transaction, now
}

func TestProtocolLoginTransactionRejectsChangesToRetainedAuthority(t *testing.T) {
	original, now := protocolLoginTransaction(t)
	generation, err := original.ValidateAt(now)
	if err != nil || generation != 5 {
		t.Fatalf("original generation not preserved: generation %d, error %v", generation, err)
	}

	for _, tc := range []struct {
		name   string
		change func(*sso.LoginTransaction)
	}{
		{"foreign tenant", func(v *sso.LoginTransaction) { v.TenantID = "foreign-tenant" }},
		{"foreign provider", func(v *sso.LoginTransaction) { v.ProviderID = "foreign-provider" }},
		{"foreign organization", func(v *sso.LoginTransaction) { v.OrganizationID = "foreign-organization" }},
		{"protocol switch", func(v *sso.LoginTransaction) { v.Protocol = "oidc" }},
		{"callback host substitution", func(v *sso.LoginTransaction) { v.Callback.Host = "foreign.example.com" }},
		{"later expiry", func(v *sso.LoginTransaction) { v.ExpiresAt = v.ExpiresAt.Add(time.Second) }},
		{"mapping change", func(v *sso.LoginTransaction) { v.MappingVersion++ }},
		{"provider change", func(v *sso.LoginTransaction) { v.ProviderVersion++ }},
		{"completion command substitution", func(v *sso.LoginTransaction) { v.CommandID = "AwMDAwMDAwMDAwMDAwMDAw" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := original
			tc.change(&changed)
			if generation, err := changed.ValidateAt(now); !errors.Is(err, sso.ErrInvalidInput) || generation != 0 {
				t.Fatalf("modified transaction validated: generation %d, error %v", generation, err)
			}
		})
	}
	if generation, err := original.ValidateAt(original.ExpiresAt); !errors.Is(err, sso.ErrInvalidInput) || generation != 0 {
		t.Fatalf("transaction accepted at exclusive expiry: generation %d, error %v", generation, err)
	}
	if _, err := (sso.LoginTransaction{}).ValidateAt(now); !errors.Is(err, sso.ErrInvalidInput) {
		t.Fatal("zero accepted", err)
	}
}

func TestProtocolStartResultPreservesEarlierCapabilityCutoff(t *testing.T) {
	transaction, now := protocolLoginTransaction(t)
	cutoff := now.Add(15 * time.Second)
	result := sso.ProtocolStartResult{
		Redirect:  url.URL{Scheme: "https", Host: "issuer.example.com", Path: "/authorize", RawQuery: "response_type=code&state=example"},
		ExpiresAt: cutoff,
	}
	if err := result.ValidateFor(transaction, now, cutoff); err != nil {
		t.Fatal("exact authorization redirect rejected", err)
	}
	result.ExpiresAt = cutoff.Add(time.Nanosecond)
	if err := result.ValidateFor(transaction, now, cutoff); !errors.Is(err, sso.ErrInvalidInput) {
		t.Fatal("redirect renewed capability expiry", err)
	}
	result.ExpiresAt = cutoff
	result.Redirect.RawPath = "/different"
	if err := result.ValidateFor(transaction, now, cutoff); !errors.Is(err, sso.ErrInvalidInput) {
		t.Fatal("inconsistent raw URL accepted", err)
	}
	result.Redirect.RawPath = ""
	result.Redirect.RawQuery = "state=%zz"
	if err := result.ValidateFor(transaction, now, cutoff); !errors.Is(err, sso.ErrInvalidInput) {
		t.Fatal("invalid query encoding accepted", err)
	}
	result.Redirect.RawQuery = "state=" + strings.Repeat("a", 5000)
	if err := result.ValidateFor(transaction, now, cutoff); err != nil {
		t.Fatal("redirect within native authorization URL limit rejected", err)
	}
}

func TestProtocolStartCommandSelectsExactEnabledProvider(t *testing.T) {
	transaction, now := protocolLoginTransaction(t)
	command := sso.ProtocolStartCommand{Transaction: transaction, Provider: sso.Provider{
		ID: transaction.ProviderID, OrganizationID: string(transaction.OrganizationID), Protocol: transaction.Protocol,
		Version: transaction.ProviderVersion, MappingVersion: transaction.MappingVersion, Enabled: true,
	}}
	if generation, err := command.ValidateAt(now); generation != 5 || err != nil {
		t.Fatalf("metadata version replaced original credential generation: generation %d, error %v", generation, err)
	}
	for _, tc := range []struct {
		name   string
		change func(*sso.Provider)
	}{
		{"disabled", func(p *sso.Provider) { p.Enabled = false }},
		{"foreign organization", func(p *sso.Provider) { p.OrganizationID = "foreign" }},
		{"foreign provider", func(p *sso.Provider) { p.ID = "foreign" }},
		{"changed version", func(p *sso.Provider) { p.Version++ }},
		{"changed mapping", func(p *sso.Provider) { p.MappingVersion++ }},
		{"protocol substitution", func(p *sso.Provider) { p.Protocol = "oidc" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := command
			tc.change(&changed.Provider)
			if generation, err := changed.ValidateAt(now); generation != 0 || !errors.Is(err, sso.ErrInvalidInput) {
				t.Fatalf("wrong provider accepted: generation %d, error %v", generation, err)
			}
		})
	}
}
