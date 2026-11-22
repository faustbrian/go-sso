package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
)

func providerOAuth2CallbackCustodyFixture(t *testing.T, protocol string) (providerLoginPayloadConfig, providerLoginCallbackLookup, []byte, []byte) {
	t.Helper()
	c, input, now, _ := providerLoginPayloadFixture(t)
	input.Protocol = protocol
	if protocol == providerProtocolOAuth2 {
		input.Command.SchemaID = "identity.sso.signin-start.oauth2-v1"
	}
	output, err := c.generate(t.Context(), input, 1, risk.PreparedAuthenticationAdmission{})
	if err != nil {
		t.Fatal("original start could not generate callback custody", err)
	}
	defer clear(output)
	restored, err := c.restore(t.Context(), input, 1, output)
	if err != nil {
		t.Fatal("original start could not restore callback custody", err)
	}
	bound, err := restored.State.binding.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	stored, err := c.openCommittedBinding(t.Context(), input.rowIdentity(), bound)
	if err != nil {
		t.Fatal("original row could not authenticate callback custody", err)
	}
	verifier, err := restored.State.verifier.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(bound); clear(verifier); clear(stored.Proof) })
	return c, providerLoginCallbackLookup{Row: input.rowIdentity(), ObservedAt: *now, Binding: stored}, verifier, bound
}

func TestProviderOAuth2CallbackCustodyReadsOriginalProtocolBoundState(t *testing.T) {
	c, found, _, binding := providerOAuth2CallbackCustodyFixture(t, providerProtocolOAuth2)
	m := found.Binding.Metadata
	if m.Input.Issuer != "https://enterprise.example" || m.Input.Protocol != providerProtocolOAuth2 || m.Public.Nonce != "" {
		t.Fatal("OAuth callback lost original issuer or protocol-specific metadata")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(m.Public.State)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	digest, err := providerLoginProtocolStateDigest(c.StateKeys[m.StateKey], m.StateKey, found.Row.TenantID, providerProtocolOAuth2, raw)
	if err != nil || digest != m.StateDigest {
		t.Fatal("callback cannot locate the exact original OAuth start state", err)
	}
	oidcDigest, err := providerLoginStateDigest(c.StateKeys[m.StateKey], m.StateKey, found.Row.TenantID, raw)
	if err != nil || oidcDigest == digest {
		t.Fatal("OAuth callback state aliases the published OIDC state domain", err)
	}
	for _, mutate := range []func(*providerLoginRowIdentity){
		func(r *providerLoginRowIdentity) { r.Protocol = "" },
		func(r *providerLoginRowIdentity) { r.Protocol = "oidc" },
		func(r *providerLoginRowIdentity) { r.Protocol = "unknown" },
		func(r *providerLoginRowIdentity) { r.ProviderID = "other-provider" },
		func(r *providerLoginRowIdentity) { r.CredentialGeneration++ },
	} {
		row := found.Row
		mutate(&row)
		if opened, err := c.openCommittedBinding(t.Context(), row, binding); err == nil || len(opened.Proof) != 0 {
			clear(opened.Proof)
			t.Fatal("OAuth pending custody accepted substituted durable row identity")
		}
	}
	var service *ProviderLoginService
	if _, err := service.lookupProviderOAuth2LoginCallback(t.Context(), m.Public.State); err == nil {
		t.Fatal("OAuth lookup without trusted service authority succeeded")
	}
}

func TestProviderOAuth2CallbackCustodyBorrowsOnlyOriginalUnexpiredVerifier(t *testing.T) {
	c, found, wire, _ := providerOAuth2CallbackCustodyFixture(t, providerProtocolOAuth2)
	m := found.Binding.Metadata
	calls := 0
	var borrowed []byte
	use := func(_ context.Context, verifier []byte) error {
		calls++
		borrowed = verifier
		challenge := sha256.Sum256(verifier)
		if len(verifier) != 43 || base64.RawURLEncoding.EncodeToString(challenge[:]) != m.Public.Challenge {
			t.Fatal("borrowed verifier did not match original OAuth redirect challenge")
		}
		return nil
	}
	if err := c.withOAuth2CallbackVerifier(t.Context(), m, found.ObservedAt, wire, use); err != nil || calls != 1 {
		t.Fatal("original OAuth custody did not yield one scoped use", err)
	}
	if !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
		t.Fatal("verifier remained available after scoped borrower returned")
	}
	for name, change := range map[string]func(*providerLoginBindingMetadata, *time.Time, []byte){
		"OIDC protocol":          func(m *providerLoginBindingMetadata, _ *time.Time, _ []byte) { m.Input.Protocol = "" },
		"explicit OIDC protocol": func(m *providerLoginBindingMetadata, _ *time.Time, _ []byte) { m.Input.Protocol = "oidc" },
		"unknown protocol":       func(m *providerLoginBindingMetadata, _ *time.Time, _ []byte) { m.Input.Protocol = "unknown" },
		"issuer": func(m *providerLoginBindingMetadata, _ *time.Time, _ []byte) {
			m.Input.Issuer = "https://other.example"
		},
		"provider": func(m *providerLoginBindingMetadata, _ *time.Time, _ []byte) { m.Input.ProviderID = "other-provider" },
		"callback command": func(m *providerLoginBindingMetadata, _ *time.Time, _ []byte) {
			m.CallbackCommand = m.Input.Command.CommandID
		},
		"state digest": func(m *providerLoginBindingMetadata, _ *time.Time, _ []byte) { m.StateDigest[0] ^= 1 },
		"commitment":   func(m *providerLoginBindingMetadata, _ *time.Time, _ []byte) { m.PKCECommitment[0] ^= 1 },
		"challenge": func(m *providerLoginBindingMetadata, _ *time.Time, _ []byte) {
			m.Public.Challenge = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		},
		"unexpected nonce": func(m *providerLoginBindingMetadata, _ *time.Time, _ []byte) {
			m.Public.Nonce = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		},
		"retired key": func(m *providerLoginBindingMetadata, _ *time.Time, _ []byte) { m.PKCEKey++ },
		"ciphertext":  func(_ *providerLoginBindingMetadata, _ *time.Time, wire []byte) { wire[len(wire)-1] ^= 1 },
		"expiry":      func(m *providerLoginBindingMetadata, now *time.Time, _ []byte) { *now = m.Input.ExpiresAt },
		"before issuance": func(m *providerLoginBindingMetadata, now *time.Time, _ []byte) {
			*now = m.Input.IssuedAt.Add(-time.Nanosecond)
		},
	} {
		t.Run(name, func(t *testing.T) {
			metadata, now, ciphertext := m, found.ObservedAt, bytes.Clone(wire)
			defer clear(ciphertext)
			change(&metadata, &now, ciphertext)
			var denied identity.ForbiddenError
			if err := c.withOAuth2CallbackVerifier(t.Context(), metadata, now, ciphertext, use); !errors.As(err, &denied) || calls != 1 {
				t.Fatal("foreign or expired OAuth custody reached verifier borrower", err)
			}
		})
	}
	if err := c.withOAuth2CallbackVerifier(t.Context(), m, m.Input.ExpiresAt.Add(-time.Nanosecond), wire, func(context.Context, []byte) error { return context.Canceled }); !errors.Is(err, context.Canceled) {
		t.Fatal("OAuth verifier borrower lost its exact outcome before strict expiry", err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := c.withOAuth2CallbackVerifier(cancelled, m, found.ObservedAt, wire, use); !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatal("cancelled OAuth custody reached verifier borrower", err)
	}
	oidc, original, oidcWire, _ := providerOAuth2CallbackCustodyFixture(t, "")
	if err := c.withCallbackVerifier(t.Context(), m, found.ObservedAt, wire, use); err == nil || calls != 1 {
		t.Fatal("published OIDC wrapper accepted OAuth custody")
	}
	if err := oidc.withOAuth2CallbackVerifier(t.Context(), original.Binding.Metadata, original.ObservedAt, oidcWire, use); err == nil || calls != 1 {
		t.Fatal("OAuth wrapper accepted original published OIDC custody")
	}
}

func TestProviderOAuth2CallbackTerminalCustodyKeepsCorrelationWithoutExecutionProof(t *testing.T) {
	c, found, _, pending := providerOAuth2CallbackCustodyFixture(t, providerProtocolOAuth2)
	wire, err := c.sealProviderOAuth2LoginCallbackTerminal(t.Context(), found)
	if err != nil {
		t.Fatal("OAuth callback could not seal terminal correlation", err)
	}
	defer clear(wire)
	opened, err := c.openProviderOAuth2LoginCallbackTerminal(t.Context(), found.Row, wire)
	if err != nil || !equalProviderLoginBindingMetadata(opened.Metadata, found.Binding.Metadata) || len(opened.Proof) != 0 || opened.Plan != (providerLoginStoredPlan{}) {
		t.Fatal("OAuth terminal custody lost correlation or retained executable capability", err)
	}
	if _, err := c.openCommittedBinding(t.Context(), found.Row, wire); err == nil {
		t.Fatal("OAuth terminal correlation became pending execution authority")
	}
	if _, err := c.openProviderOAuth2LoginCallbackTerminal(t.Context(), found.Row, pending); err == nil {
		t.Fatal("OAuth pending execution proof became terminal correlation")
	}
	if _, err := c.openProviderLoginCallbackTerminal(t.Context(), found.Row, wire); err == nil {
		t.Fatal("published OIDC terminal wrapper accepted OAuth correlation")
	}
	if sealed, err := c.sealProviderLoginCallbackTerminal(t.Context(), found); err == nil || len(sealed) != 0 {
		clear(sealed)
		t.Fatal("published OIDC terminal sealer accepted OAuth custody")
	}
	oidc, original, _, _ := providerOAuth2CallbackCustodyFixture(t, "")
	oidcWire, err := oidc.sealProviderLoginCallbackTerminal(t.Context(), original)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(oidcWire)
	if _, err := c.openProviderOAuth2LoginCallbackTerminal(t.Context(), original.Row, oidcWire); err == nil {
		t.Fatal("OAuth terminal wrapper accepted published OIDC correlation")
	}
	for name, mutate := range map[string]func(*providerLoginRowIdentity){
		"protocol":   func(r *providerLoginRowIdentity) { r.Protocol = "" },
		"provider":   func(r *providerLoginRowIdentity) { r.ProviderID = "other-provider" },
		"generation": func(r *providerLoginRowIdentity) { r.CredentialGeneration++ },
		"mapping":    func(r *providerLoginRowIdentity) { r.MappingVersion++ },
		"expiry":     func(r *providerLoginRowIdentity) { r.ExpiresAt = r.ExpiresAt.Add(-time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			row := found.Row
			mutate(&row)
			if _, err := c.openProviderOAuth2LoginCallbackTerminal(t.Context(), row, wire); err == nil {
				t.Fatal("OAuth terminal correlation crossed original row identity")
			}
		})
	}
}
