package saml

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/session"
	"github.com/faustbrian/go-sso"
)

func TestSPProtocolAdapterSignsOriginalRequestThroughInterface(t *testing.T) {
	config, provider, _ := spProtocolAdapterFixture(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	config.Signer = key
	config.Request.RelayState = "owner_issued_opaque_handle"
	adapter, err := NewSPProtocolAdapter(config)
	if err != nil {
		t.Fatal(err)
	}
	var protocol sso.ProtocolAdapter = adapter
	result, err := protocol.Start(t.Context(), sso.ProtocolStartCommand{Transaction: config.Transaction, Provider: provider})
	if err != nil || !result.ExpiresAt.Equal(config.CapabilityExpiresAt) {
		t.Fatal("original capability cutoff was not preserved", err)
	}
	signed, signatureField, ok := strings.Cut(result.Redirect.RawQuery, "&Signature=")
	if !ok {
		t.Fatal("signed redirect missing signature")
	}
	signature, err := base64.StdEncoding.DecodeString(result.Redirect.Query().Get("Signature"))
	if err != nil || signatureField == "" {
		t.Fatal("invalid signature encoding", err)
	}
	digest := sha256.Sum256([]byte(signed))
	if err := rsa.VerifyPSS(&key.PublicKey, crypto.SHA256, digest[:], signature, &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: sha256.Size}); err != nil {
		t.Fatal("original query signature did not verify", err)
	}
	compressed, err := base64.StdEncoding.DecodeString(result.Redirect.Query().Get("SAMLRequest"))
	if err != nil {
		t.Fatal(err)
	}
	reader := flate.NewReader(bytes.NewReader(compressed))
	defer reader.Close()
	var request requestXML
	if err := xml.NewDecoder(reader).Decode(&request); err != nil {
		t.Fatal(err)
	}
	if request.ID != config.Request.ID || request.IssueTime != config.Request.IssuedAt.Format(time.RFC3339Nano) ||
		request.Consumer != fixtureACS || request.Issuer != fixtureSP || result.Redirect.Query().Get("RelayState") != config.Request.RelayState {
		t.Fatal("adapter changed the owner-issued request or selected SP scope")
	}
}

func TestSPProtocolAdapterCompletesMappedSignedResponseAndClosesPayload(t *testing.T) {
	config, provider, encoded := spProtocolAdapterFixture(t)
	adapter, err := NewSPProtocolAdapter(config)
	if err != nil {
		t.Fatal(err)
	}
	var protocol sso.ProtocolAdapter = adapter
	for _, verifiedResult := range []bool{false, true} {
		payload := &spAdapterPayload{Reader: strings.NewReader(encoded)}
		callback := sso.ProtocolCallback{Transaction: config.Transaction, Payload: payload, MaximumBytes: uint64(len(encoded) + 1)}
		var assertion sso.ProtocolAssertion
		if verifiedResult {
			verified, err := adapter.CompleteVerified(t.Context(), callback)
			if err != nil {
				t.Fatal(err)
			}
			evidence, err := verified.Evidence()
			if err != nil || evidence.ResponseID != "_response" || evidence.AssertionID != "_assertion" ||
				evidence.ProviderSubject != "member-042" || evidence.ValidUntil.After(config.CapabilityExpiresAt) {
				t.Fatal("completion lost the replay pair or original acceptance cutoff", err)
			}
			assertion, err = verified.ProtocolAssertion()
			if err != nil {
				t.Fatal(err)
			}
		} else {
			assertion, err = protocol.Complete(t.Context(), callback)
			if err != nil {
				t.Fatal(err)
			}
		}
		if payload.closes != 1 {
			t.Fatal("completion did not close transferred payload exactly once")
		}
		assertResponseAttributeScope(t, assertion, provider)
		assertResponseAttribute(t, assertion, "mail", sso.AttributeValue, stringPointer("member@example.test"), nil, provider)
	}
}

type spAdapterClock struct{ now time.Time }

func (c *spAdapterClock) Now() time.Time { return c.now }

type spAdapterPayload struct {
	io.Reader
	closes int
}

func (p *spAdapterPayload) Close() error { p.closes++; return nil }

func spProtocolAdapterFixture(t *testing.T) (SPProtocolAdapterConfig, sso.Provider, string) {
	t.Helper()
	key, certificate := idpResponseSigningFixture(t)
	provider, mapping := responseAttributeMappingFixture(t)
	response, err := NewPOSTResponseProfile(POSTResponseConfig{SPEntityID: fixtureSP, IdentityProviderEntityID: fixtureIdP,
		AssertionConsumerURL: fixtureACS, SigningCertificates: [][]byte{certificate}})
	if err != nil {
		t.Fatal(err)
	}
	response, err = response.WithAssertionMapping(provider, mapping)
	if err != nil {
		t.Fatal(err)
	}
	redirect, err := NewAuthnRedirectProfile(AuthnRedirectConfig{SPEntityID: fixtureSP, AssertionConsumerURL: fixtureACS, IdentityProviderURL: "https://idp.example/sso"})
	if err != nil {
		t.Fatal(err)
	}
	issued := time.Date(2026, 11, 23, 4, 0, 0, 0, time.UTC)
	remember, err := session.NewRememberPolicy(session.RememberPolicySpec{Choice: session.BrowserSession, AbsoluteTTL: time.Hour,
		IdleTTL: 30 * time.Minute, RefreshAfter: 5 * time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	acs, err := url.Parse(fixtureACS)
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := sso.NewLoginTransaction(sso.LoginTransaction{TenantID: "tenant-exact", ID: "AQEBAQEBAQEBAQEBAQEBAQ",
		CommandID: "AgICAgICAgICAgICAgICAg", ProviderID: provider.ID, OrganizationID: "organization-exact", Protocol: "saml",
		Callback: *acs, ExpiresAt: issued.Add(5 * time.Minute), ProviderVersion: provider.Version, MappingVersion: provider.MappingVersion, RememberPolicy: remember}, 3)
	if err != nil {
		t.Fatal(err)
	}
	config := SPProtocolAdapterConfig{Transaction: transaction, CredentialGeneration: 3, Request: AuthnRequest{ID: fixtureID, IssuedAt: issued},
		CapabilityExpiresAt: issued.Add(3 * time.Minute), Clock: &spAdapterClock{now: issued.Add(time.Minute)}, RedirectProfile: redirect, ResponseProfile: response}
	xml := signedResponseFixture(t, key, fixtureID, fixtureIdP, fixtureSP, fixtureACS, "_assertion", true,
		responseAttributeStatement(`<a:Attribute Name="mail"><a:AttributeValue>member@example.test</a:AttributeValue></a:Attribute>`))
	return config, provider, base64.StdEncoding.EncodeToString([]byte(xml))
}

func TestSPProtocolAdapterRefusesInvalidCompletionAndAlwaysCloses(t *testing.T) {
	config, _, encoded := spProtocolAdapterFixture(t)
	adapter, err := NewSPProtocolAdapter(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*sso.ProtocolCallback)
	}{
		{"different transaction", func(c *sso.ProtocolCallback) { c.Transaction.CommandID = "AwMDAwMDAwMDAwMDAwMDAw" }},
		{"zero budget", func(c *sso.ProtocolCallback) { c.MaximumBytes = 0 }},
		{"exact budget cannot prove EOF", func(c *sso.ProtocolCallback) { c.MaximumBytes = uint64(len(encoded)) }},
		{"over budget", func(c *sso.ProtocolCallback) { c.MaximumBytes = 8 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := &spAdapterPayload{Reader: strings.NewReader(encoded)}
			callback := sso.ProtocolCallback{Transaction: config.Transaction, Payload: payload, MaximumBytes: uint64(len(encoded) + 1)}
			tc.change(&callback)
			result, err := adapter.CompleteVerified(t.Context(), callback)
			if !errors.Is(err, ErrInvalidInput) || payload.closes != 1 {
				t.Fatal("invalid callback was not denied with exact-once close", err)
			}
			if _, err := result.Evidence(); err == nil {
				t.Fatal("denied callback disclosed usable evidence")
			}
		})
	}
	for _, wire := range []string{"%%%", "SAMLResponse=" + url.QueryEscape(encoded), "<form>" + encoded + "</form>", strings.Repeat("A", maximumPOSTBase64Bytes+1)} {
		payload := &spAdapterPayload{Reader: strings.NewReader(wire)}
		if _, err := adapter.Complete(t.Context(), sso.ProtocolCallback{Transaction: config.Transaction, Payload: payload, MaximumBytes: uint64(len(wire) + 1)}); err == nil || payload.closes != 1 {
			t.Fatal("malformed or protocol-overlimit callback was not closed and denied")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	payload := &spAdapterPayload{Reader: strings.NewReader(encoded)}
	if _, err := adapter.Complete(ctx, sso.ProtocolCallback{Transaction: config.Transaction, Payload: payload, MaximumBytes: uint64(len(encoded) + 1)}); !errors.Is(err, context.Canceled) || payload.closes != 1 {
		t.Fatal("canceled callback was not closed and denied", err)
	}
}

func TestSPProtocolAdapterRejectsMismatchedConfigurationScope(t *testing.T) {
	config, _, _ := spProtocolAdapterFixture(t)
	for _, tc := range []struct {
		name   string
		change func(*SPProtocolAdapterConfig)
	}{
		{"zero transaction", func(c *SPProtocolAdapterConfig) { c.Transaction = sso.LoginTransaction{} }},
		{"credential generation", func(c *SPProtocolAdapterConfig) { c.CredentialGeneration++ }},
		{"unmapped response", func(c *SPProtocolAdapterConfig) { c.ResponseProfile.mapping = nil }},
		{"provider", func(c *SPProtocolAdapterConfig) {
			m := *c.ResponseProfile.mapping
			m.provenance.ProviderID = "foreign"
			c.ResponseProfile.mapping = &m
		}},
		{"organization", func(c *SPProtocolAdapterConfig) {
			m := *c.ResponseProfile.mapping
			m.organizationID = "foreign"
			c.ResponseProfile.mapping = &m
		}},
		{"provider version", func(c *SPProtocolAdapterConfig) {
			m := *c.ResponseProfile.mapping
			m.provenance.ProviderProfileVersion++
			c.ResponseProfile.mapping = &m
		}},
		{"mapping version", func(c *SPProtocolAdapterConfig) {
			m := *c.ResponseProfile.mapping
			m.mappingVersion++
			c.ResponseProfile.mapping = &m
		}},
		{"redirect ACS", func(c *SPProtocolAdapterConfig) { c.RedirectProfile.config.AssertionConsumerURL += "/other" }},
		{"response ACS", func(c *SPProtocolAdapterConfig) { c.ResponseProfile.acs += "/other" }},
		{"SP identity", func(c *SPProtocolAdapterConfig) { c.ResponseProfile.sp += "/other" }},
		{"zero redirect", func(c *SPProtocolAdapterConfig) { c.RedirectProfile = AuthnRedirectProfile{} }},
		{"zero response", func(c *SPProtocolAdapterConfig) { c.ResponseProfile = POSTResponseProfile{} }},
		{"nil clock", func(c *SPProtocolAdapterConfig) { c.Clock = nil }},
		{"zero cutoff", func(c *SPProtocolAdapterConfig) { c.CapabilityExpiresAt = time.Time{} }},
		{"cutoff reached", func(c *SPProtocolAdapterConfig) { c.CapabilityExpiresAt = c.Clock.Now() }},
		{"invalid original request", func(c *SPProtocolAdapterConfig) { c.Request.ID = "" }},
		{"future original request", func(c *SPProtocolAdapterConfig) { c.Request.IssuedAt = c.Clock.Now().Add(time.Second) }},
		{"zero original issue time", func(c *SPProtocolAdapterConfig) { c.Request.IssuedAt = time.Time{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := config
			tc.change(&candidate)
			if adapter, err := NewSPProtocolAdapter(candidate); !errors.Is(err, ErrInvalidInput) || adapter != nil {
				t.Fatal("mismatched original scope was accepted", err)
			}
		})
	}
}

func TestSPProtocolAdapterDoesNotRenewOrReadOutsideOriginalScope(t *testing.T) {
	config, provider, encoded := spProtocolAdapterFixture(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	config.Signer = key
	adapter, err := NewSPProtocolAdapter(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*sso.ProtocolStartCommand){
		func(c *sso.ProtocolStartCommand) { c.Provider.ID = "foreign" },
		func(c *sso.ProtocolStartCommand) { c.Provider.OrganizationID = "foreign" },
		func(c *sso.ProtocolStartCommand) { c.Provider.Version++ },
		func(c *sso.ProtocolStartCommand) { c.Provider.MappingVersion++ },
		func(c *sso.ProtocolStartCommand) { c.Provider.Protocol = "oidc" },
		func(c *sso.ProtocolStartCommand) { c.Provider.Enabled = false },
		func(c *sso.ProtocolStartCommand) { c.Transaction.ExpiresAt = c.Transaction.ExpiresAt.Add(time.Hour) },
	} {
		command := sso.ProtocolStartCommand{Transaction: config.Transaction, Provider: provider}
		change(&command)
		if result, err := adapter.Start(t.Context(), command); err == nil || result.Redirect.Host != "" {
			t.Fatal("changed command produced a redirect")
		}
	}
	completionOnly := config
	completionOnly.Signer = nil
	withoutSigner, err := NewSPProtocolAdapter(completionOnly)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := withoutSigner.Start(t.Context(), sso.ProtocolStartCommand{Transaction: config.Transaction, Provider: provider}); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("completion-only adapter unexpectedly allowed Start without signer", err)
	}
	for _, now := range []time.Time{config.Request.IssuedAt.Add(-time.Nanosecond), config.CapabilityExpiresAt, config.Transaction.ExpiresAt} {
		config.Clock.(*spAdapterClock).now = now
		payload := &spAdapterPayload{Reader: spAdapterForbiddenRead{t: t}}
		if _, err := adapter.Complete(t.Context(), sso.ProtocolCallback{Transaction: config.Transaction, Payload: payload, MaximumBytes: uint64(len(encoded) + 1)}); err == nil || payload.closes != 1 {
			t.Fatal("stale original scope was read or failed cleanup")
		}
	}
}

type spAdapterForbiddenRead struct{ t *testing.T }

func (r spAdapterForbiddenRead) Read([]byte) (int, error) {
	r.t.Error("adapter read payload outside original valid scope")
	return 0, io.EOF
}

func TestSPProtocolAdapterClosesOnReadFailureAndExpiryDuringRead(t *testing.T) {
	config, _, encoded := spProtocolAdapterFixture(t)
	adapter, err := NewSPProtocolAdapter(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, reader := range []io.Reader{
		spAdapterReadError{},
		spAdapterReadFunc(func(p []byte) (int, error) {
			config.Clock.(*spAdapterClock).now = config.CapabilityExpiresAt
			return copy(p, encoded), io.EOF
		}),
	} {
		payload := &spAdapterPayload{Reader: reader}
		if _, err := adapter.Complete(t.Context(), sso.ProtocolCallback{Transaction: config.Transaction, Payload: payload, MaximumBytes: uint64(len(encoded) + 1)}); err == nil || payload.closes != 1 {
			t.Fatal("failed or expired read disclosed assertion or failed cleanup")
		}
	}
}

type spAdapterReadError struct{}

func (spAdapterReadError) Read([]byte) (int, error) { return 0, errors.New("read unavailable") }

type spAdapterReadFunc func([]byte) (int, error)

func (read spAdapterReadFunc) Read(p []byte) (int, error) { return read(p) }

func TestSPProtocolAdapterRejectsCanceledReadAndClosesForNilInputs(t *testing.T) {
	config, _, encoded := spProtocolAdapterFixture(t)
	adapter, err := NewSPProtocolAdapter(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	payload := &spAdapterPayload{Reader: spAdapterReadFunc(func(p []byte) (int, error) {
		cancel()
		return copy(p, encoded), io.EOF
	})}
	if _, err := adapter.Complete(ctx, sso.ProtocolCallback{Transaction: config.Transaction, Payload: payload, MaximumBytes: uint64(len(encoded) + 1)}); !errors.Is(err, context.Canceled) || payload.closes != 1 {
		t.Fatal("cancellation during synchronous Read disclosed assertion or failed cleanup", err)
	}
	for _, candidate := range []*SPProtocolAdapter{nil, {}, adapter} {
		payload := &spAdapterPayload{Reader: spAdapterForbiddenRead{t: t}}
		if _, err := candidate.CompleteVerified(nil, sso.ProtocolCallback{Transaction: config.Transaction, Payload: payload, MaximumBytes: 32}); !errors.Is(err, ErrInvalidInput) || payload.closes != 1 {
			t.Fatal("nil adapter/context failed closed payload ownership", err)
		}
		if _, err := candidate.CompleteVerified(t.Context(), sso.ProtocolCallback{Transaction: config.Transaction}); !errors.Is(err, ErrInvalidInput) {
			t.Fatal("nil payload accepted", err)
		}
	}
}

func TestSPProtocolAdapterBoundsActualReadWithoutSentinelOverrun(t *testing.T) {
	config, _, _ := spProtocolAdapterFixture(t)
	adapter, err := NewSPProtocolAdapter(config)
	if err != nil {
		t.Fatal(err)
	}
	consumed := 0
	payload := &spAdapterPayload{Reader: spAdapterReadFunc(func(p []byte) (int, error) {
		for i := range p {
			p[i] = 'A'
		}
		consumed += len(p)
		return len(p), nil
	})}
	if _, err := adapter.Complete(t.Context(), sso.ProtocolCallback{Transaction: config.Transaction, Payload: payload, MaximumBytes: 12}); !errors.Is(err, ErrInvalidInput) || consumed != 12 || payload.closes != 1 {
		t.Fatal("adapter exceeded caller byte budget or failed closed", err)
	}
}

func TestSPProtocolAdapterDoesNotDiscloseRedirectAfterSigningCutoff(t *testing.T) {
	config, provider, _ := spProtocolAdapterFixture(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	config.Signer = spAdapterSigner{Signer: key, afterSign: func() { config.Clock.(*spAdapterClock).now = config.CapabilityExpiresAt }}
	adapter, err := NewSPProtocolAdapter(config)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := adapter.Start(t.Context(), sso.ProtocolStartCommand{Transaction: config.Transaction, Provider: provider}); !errors.Is(err, ErrInvalidInput) || result.Redirect.Host != "" {
		t.Fatal("signing renewed the original capability cutoff", err)
	}
}

type spAdapterSigner struct {
	crypto.Signer
	afterSign func()
}

func (s spAdapterSigner) Sign(random io.Reader, digest []byte, options crypto.SignerOpts) ([]byte, error) {
	signature, err := s.Signer.Sign(random, digest, options)
	s.afterSign()
	return signature, err
}

func TestSPProtocolAdapterRedactsBorrowedCredentialsAndOriginalState(t *testing.T) {
	config, _, _ := spProtocolAdapterFixture(t)
	config.Request.RelayState = "private_state_handle"
	adapter, err := NewSPProtocolAdapter(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{config, adapter} {
		if strings.Contains(fmt.Sprintf("%#v", value), config.Request.RelayState) {
			t.Fatal("adapter configuration exposed private original state")
		}
		if _, err := json.Marshal(value); !errors.Is(err, ErrSensitiveSerialization) {
			t.Fatal("adapter configuration allowed implicit serialization", err)
		}
	}
}
