package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	"github.com/faustbrian/go-sso"
)

func providerLoginPayloadFixture(t *testing.T) (providerLoginPayloadConfig, providerLoginPayloadInput, *time.Time, *capability.KeySet) {
	t.Helper()
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	signing := bytes.Repeat([]byte{9}, 32)
	signer, err := capability.NewHMACSHA256Signer("signing", signing)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := capability.NewHMACSHA256Verifier(signing)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := capability.NewKeySet([]capability.Key{{Issuer: "https://identity.example", ID: "signing", Verifier: verifier}})
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := capabilitypg.NewIssuer(capabilitypg.IssuerConfig{Crypto: capability.ServiceConfig{Issuer: "https://identity.example", Signer: signer, Resolver: keys, Clock: func() time.Time { return now }, Limits: capability.DefaultLimits()}, Audience: "identity", CurrentReplayKeyVersion: 1, RetainedReplayKeys: map[uint32][32]byte{1: {6}}, PreparationTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	codec, err := capabilitypg.NewIssuancePreparationCodec(issuer, capabilitypg.IssuancePreparationConfig{Deployment: "sso-test", ActiveEnvelopeKey: "checkpoint", EnvelopeKeys: map[string][]byte{"checkpoint": bytes.Repeat([]byte{7}, 32)}, VerificationKeys: []capabilitypg.PreparationVerificationKey{{ID: "signing", HMAC: signing}}, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := keyring.New(map[string][]byte{"login": bytes.Repeat([]byte{4}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	crypto, err := envelope.NewService(provider)
	if err != nil {
		t.Fatal(err)
	}
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	flow, err := identity.NewPreAuthTransactionID()
	if err != nil {
		t.Fatal(err)
	}
	b := identity.CommandBinding{CommandID: command, TenantID: "tenant", AnonymousFlowID: string(flow), ActorID: "enterprise-login", ActorKind: authorization.SubjectServiceAccount, OperationID: "identity.sso.signin-start", SchemaID: "identity.sso.signin-start.oidc-v1", SchemaVersion: 1, PolicyID: "policy", PolicyVersion: 1, CorrelationID: string(command), RecordID: string(command)}
	c := providerLoginPayloadConfig{Envelope: crypto, KeyReference: "login", Issuer: issuer, Codec: codec, CapabilityIssuer: "https://identity.example", Audience: "identity", StateKeys: map[uint32][32]byte{1: {2}}, PKCEKeys: map[uint32][32]byte{1: {3}}, CurrentStateKey: 1, CurrentPKCEKey: 1}
	i := providerLoginPayloadInput{Command: b, OrganizationID: "organization", ProviderID: "provider", Issuer: "https://enterprise.example", ClientID: "client", RedirectURI: "https://app.example/sso/callback", ProviderVersion: 2, CredentialGeneration: 3, MappingVersion: 4, InputFingerprint: [32]byte{5}, IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute), BrowserOrigin: "https://app.example", SuccessCallback: "https://app.example/success", ErrorCallback: "https://app.example/error", Remember: session.RememberPolicySpec{Choice: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: time.Hour, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute}}
	return c, i, &now, keys
}

func TestProviderLoginPayloadCallbackLookupAndOpenNeedsOnlyDurableRowIdentity(t *testing.T) {
	c, input, _, _ := providerLoginPayloadFixture(t)
	wire, err := c.generate(context.Background(), input, 1, risk.PreparedAuthenticationAdmission{})
	if err != nil {
		t.Fatal(err)
	}
	out, err := c.restore(context.Background(), input, 1, wire)
	if err != nil {
		t.Fatal(err)
	}
	bindingWire, err := out.State.binding.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	public, err := c.redirectState(context.Background(), input, bindingWire)
	if err != nil {
		t.Fatal(err)
	}
	rawState, err := base64.RawURLEncoding.Strict().DecodeString(public.State)
	defer clear(rawState)
	if err != nil || len(rawState) != 32 {
		t.Fatal("callback did not receive original opaque state", err)
	}
	// This is all that an indexed lookup has before the encrypted row is read:
	// the trusted tenant, retained key version and callback's opaque state.
	digest, err := providerLoginStateDigest(c.StateKeys[out.State.stateKey], out.State.stateKey, input.Command.TenantID, rawState)
	if err != nil || digest != out.State.stateDigest {
		t.Fatal("callback cannot find row before decrypting original input", err)
	}
	row := providerLoginRowIdentity{TenantID: input.Command.TenantID, OrganizationID: input.OrganizationID, ProviderID: input.ProviderID, ProviderVersion: input.ProviderVersion, CredentialGeneration: input.CredentialGeneration, MappingVersion: input.MappingVersion, StartCommandID: input.Command.CommandID, IssuedAt: input.IssuedAt, ExpiresAt: input.ExpiresAt}
	opened, err := c.openCommittedBinding(context.Background(), row, bindingWire)
	if err != nil {
		t.Fatal("callback cannot authenticate binding with durable row identity", err)
	}
	defer clear(opened.Proof)
	if !reflect.DeepEqual(opened.Metadata.Input, input) || opened.Metadata.Input.BrowserOrigin != input.BrowserOrigin || opened.Metadata.Input.SuccessCallback != input.SuccessCallback || opened.Metadata.Input.ErrorCallback != input.ErrorCallback || opened.Metadata.Input.Remember != input.Remember {
		t.Fatal("binding discarded original application continuation or remember policy")
	}
	for _, tenant := range []identity.TenantID{"other-tenant", ""} {
		other, err := providerLoginStateDigest(c.StateKeys[out.State.stateKey], out.State.stateKey, tenant, rawState)
		if err == nil && other == digest {
			t.Fatal("state lookup crossed tenant")
		}
	}
	otherVersion, err := providerLoginStateDigest(c.StateKeys[out.State.stateKey], out.State.stateKey+1, input.Command.TenantID, rawState)
	if err != nil || otherVersion == digest {
		t.Fatal("state lookup omitted retained key version", err)
	}
	for _, change := range []func(*providerLoginRowIdentity){
		func(r *providerLoginRowIdentity) { r.TenantID = "other-tenant" },
		func(r *providerLoginRowIdentity) { r.OrganizationID = "other-organization" },
		func(r *providerLoginRowIdentity) { r.ProviderID = "other-provider" },
		func(r *providerLoginRowIdentity) { r.ProviderVersion++ },
		func(r *providerLoginRowIdentity) { r.CredentialGeneration++ },
		func(r *providerLoginRowIdentity) { r.MappingVersion++ },
		func(r *providerLoginRowIdentity) { r.StartCommandID = "AQEBAQEBAQEBAQEBAQEBAQ" },
		func(r *providerLoginRowIdentity) { r.IssuedAt = r.IssuedAt.Add(time.Second) },
		func(r *providerLoginRowIdentity) { r.ExpiresAt = r.ExpiresAt.Add(-time.Second) },
	} {
		other := row
		change(&other)
		if got, err := c.openCommittedBinding(context.Background(), other, bindingWire); err == nil || len(got.Proof) != 0 {
			clear(got.Proof)
			t.Fatal("binding accepted foreign SQL row scope")
		}
	}
	corrupt := bytes.Clone(bindingWire)
	corrupt[len(corrupt)-1] ^= 1
	if got, err := c.openCommittedBinding(context.Background(), row, corrupt); err == nil || len(got.Proof) != 0 {
		clear(got.Proof)
		t.Fatal("callback opened tampered binding")
	}
	// Even a correctly encrypted but internally inconsistent stored frame must
	// not bypass recomputation of its keyed lookup identity.
	aad, err := row.aad()
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*providerLoginStoredBinding){
		func(b *providerLoginStoredBinding) { b.Metadata.StateDigest[0] ^= 1 },
		func(b *providerLoginStoredBinding) {
			b.Metadata.Public.State = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
		},
		func(b *providerLoginStoredBinding) { b.Metadata.Input.Remember = session.RememberPolicySpec{} },
	} {
		invalid := opened
		change(&invalid)
		plain, err := providerLoginPayloadEncode(invalid)
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := c.seal(context.Background(), aad, plain, 65536)
		clear(plain)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := c.openCommittedBinding(context.Background(), row, sealed); err == nil || len(got.Proof) != 0 {
			clear(got.Proof)
			t.Fatal("internally inconsistent row custody admitted")
		}
	}
}

func TestProviderLoginPayloadAcceptsExactSelectedProfileBounds(t *testing.T) {
	c, input, _, _ := providerLoginPayloadFixture(t)
	input.ClientID = strings.Repeat(" ", 1024)
	issuerPrefix := "https://enterprise.example/"
	input.Issuer = issuerPrefix + strings.Repeat("a", 2048-len(issuerPrefix))
	prefix := "https://app.example/"
	input.RedirectURI = prefix + strings.Repeat("a", 2048-len(prefix))
	configured := StaticOIDCLoginProfile{ProviderID: "provider", OrganizationID: "organization", Domain: "enterprise.example", ClientID: input.ClientID, ProtocolRedirectURI: input.RedirectURI, ProviderVersion: input.ProviderVersion, CredentialGeneration: input.CredentialGeneration, MappingVersion: input.MappingVersion, Scopes: []string{"openid"}}
	if _, err := normalizeStaticOIDCLoginProfile(configured); err != nil {
		t.Fatal("test is not within selected profile's accepted bounds", err)
	}
	wire, err := c.generate(context.Background(), input, 1, risk.PreparedAuthenticationAdmission{})
	if err != nil {
		t.Fatal("selected valid profile cannot prepare login custody", err)
	}
	out, err := c.restore(context.Background(), input, 1, wire)
	if err != nil {
		t.Fatal("selected valid profile cannot restore login custody", err)
	}
	bindingWire, err := out.State.binding.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	stored, err := c.openBinding(context.Background(), input, bindingWire)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(stored.Proof)
	if stored.Metadata.Input.Issuer != input.Issuer || stored.Metadata.Input.RedirectURI != input.RedirectURI || stored.Metadata.Input.ClientID != input.ClientID {
		t.Fatal("selected profile was truncated or normalized")
	}
}

func TestProviderLoginPayloadPreservesUpperBoundHTMLBytesWithinDurableBudget(t *testing.T) {
	c, input, _, _ := providerLoginPayloadFixture(t)
	input.ClientID = strings.Repeat("<&>", 341) + "<"
	issuerPrefix := "https://enterprise.example/"
	input.Issuer = issuerPrefix + strings.Repeat("<", 2048-len(issuerPrefix))
	if _, err := sso.NewOIDCStaticMetadata(sso.OIDCStaticMetadataSpec{Issuer: input.Issuer, AuthorizationEndpoint: input.Issuer, TokenEndpoint: input.Issuer, JWKSURI: input.Issuer}); err != nil {
		t.Fatal("test exceeds actual static issuer contract", err)
	}
	originPrefix := "https://"
	input.BrowserOrigin = originPrefix + strings.Repeat("a", 2048-len(originPrefix))
	callbackPrefix := "https://app.example/callback?"
	input.SuccessCallback = callbackPrefix + strings.Repeat("&", 2048-len(callbackPrefix))
	input.ErrorCallback = input.SuccessCallback
	redirectPrefix := "https://app.example/"
	input.RedirectURI = redirectPrefix + strings.Repeat("a", 2048-len(redirectPrefix))
	wire, err := c.generate(context.Background(), input, 1, risk.PreparedAuthenticationAdmission{})
	if err != nil {
		t.Fatal("accepted original URL/client bytes exceeded durable binding budget", err)
	}
	out, err := c.restore(context.Background(), input, 1, wire)
	if err != nil {
		t.Fatal(err)
	}
	bindingWire, err := out.State.binding.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	stored, err := c.openCommittedBinding(context.Background(), input.rowIdentity(), bindingWire)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(stored.Proof)
	if !reflect.DeepEqual(stored.Metadata.Input, input) {
		t.Fatal("durable binding modified original URL or client bytes")
	}
	plain, err := providerLoginPayloadEncode(stored)
	defer clear(plain)
	if err != nil || len(plain) > 49152 || len(bindingWire) > 65536 {
		t.Fatal("upper valid original input cannot round-trip within durable ceilings", err)
	}
}

func TestProviderLoginPayloadRestoresOriginalIssuanceWithoutRenewal(t *testing.T) {
	c, input, now, _ := providerLoginPayloadFixture(t)
	admitted := risk.PreparedAuthenticationAdmission{KeyVersion: 1, PolicyVersion: 2, ProofDigest: [32]byte{7}}
	wire, err := c.generate(context.Background(), input, 3, admitted)
	if err != nil {
		t.Fatal(err)
	}
	first, err := c.restore(context.Background(), input, 3, wire)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := first.Issuance.Plan()
	if err != nil || len(plan.Grants) != 1 || plan.Grants[0].Purpose != "identity.sso.oidc-callback" || plan.Grants[0].MaxUses != 1 || !plan.Grants[0].ExpiresAt.Equal(input.ExpiresAt) || !reflect.DeepEqual(first.Risk, admitted) {
		t.Fatal("original issuance or risk custody changed", err)
	}
	if first.State.callbackCommand == input.Command.CommandID || first.State.stateDigest == ([32]byte{}) || first.State.pkceCommitment == ([32]byte{}) {
		t.Fatal("incomplete native storage projection")
	}
	binding, err := first.State.binding.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	state, err := c.redirectState(context.Background(), input, binding)
	if err != nil || len(state.State) != 43 || len(state.Nonce) != 43 || len(state.Challenge) != 43 {
		t.Fatal("public redirect state unavailable", err)
	}
	*now = now.Add(time.Minute)
	again, err := c.restore(context.Background(), input, 3, wire)
	if err != nil {
		t.Fatal(err)
	}
	againPlan, err := again.Issuance.Plan()
	if err != nil || !reflect.DeepEqual(plan, againPlan) || !reflect.DeepEqual(first.State, again.State) {
		t.Fatal("restoration regenerated original custody", err)
	}
	*now = input.ExpiresAt
	if _, err := c.restore(context.Background(), input, 3, wire); err == nil {
		t.Fatal("expired issuance restored")
	}
}

func TestProviderLoginPayloadRejectsCrossScopeGenerationAndTampering(t *testing.T) {
	c, input, _, _ := providerLoginPayloadFixture(t)
	wire, err := c.generate(context.Background(), input, 1, risk.PreparedAuthenticationAdmission{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.restore(context.Background(), input, 2, wire); err == nil {
		t.Fatal("generation rebound")
	}
	for _, change := range []func(*providerLoginPayloadInput){
		func(i *providerLoginPayloadInput) { i.Command.AnonymousFlowID += "x" },
		func(i *providerLoginPayloadInput) { i.Command.PolicyVersion++ },
		func(i *providerLoginPayloadInput) { i.OrganizationID = "other" },
		func(i *providerLoginPayloadInput) { i.ProviderID = "other" },
		func(i *providerLoginPayloadInput) { i.ProviderVersion++ },
		func(i *providerLoginPayloadInput) { i.CredentialGeneration++ },
		func(i *providerLoginPayloadInput) { i.MappingVersion++ },
		func(i *providerLoginPayloadInput) { i.Issuer = "https://other.example" },
		func(i *providerLoginPayloadInput) { i.ClientID = "other" },
		func(i *providerLoginPayloadInput) { i.RedirectURI = "https://other.example/callback" },
		func(i *providerLoginPayloadInput) { i.InputFingerprint[0] ^= 1 },
		func(i *providerLoginPayloadInput) { i.BrowserOrigin = "https://other.example" },
		func(i *providerLoginPayloadInput) { i.SuccessCallback = "https://app.example/other-success" },
		func(i *providerLoginPayloadInput) { i.ErrorCallback = "https://app.example/other-error" },
		func(i *providerLoginPayloadInput) { i.Remember.AbsoluteTTL += time.Minute },
		func(i *providerLoginPayloadInput) { i.ExpiresAt = i.ExpiresAt.Add(time.Second) },
	} {
		other := input
		change(&other)
		if _, err := c.restore(context.Background(), other, 1, wire); err == nil {
			t.Fatal("foreign input restored")
		}
	}
	corrupt := bytes.Clone(wire)
	corrupt[len(corrupt)-1] ^= 1
	if _, err := c.restore(context.Background(), input, 1, corrupt); err == nil {
		t.Fatal("corrupt ciphertext restored")
	}
}

func TestProviderLoginPayloadUsesRetainedKeysForOriginalOperations(t *testing.T) {
	c, input, _, _ := providerLoginPayloadFixture(t)
	wire, err := c.generate(context.Background(), input, 1, risk.PreparedAuthenticationAdmission{})
	if err != nil {
		t.Fatal(err)
	}
	c.StateKeys[2], c.PKCEKeys[2] = [32]byte{10}, [32]byte{11}
	c.CurrentStateKey, c.CurrentPKCEKey = 2, 2
	if _, err := c.restore(context.Background(), input, 1, wire); err != nil {
		t.Fatal("retained original keys rejected", err)
	}
	delete(c.StateKeys, 1)
	if _, err := c.restore(context.Background(), input, 1, wire); err == nil {
		t.Fatal("missing retained state key admitted")
	}
	c.StateKeys[1] = [32]byte{2}
	delete(c.PKCEKeys, 1)
	if _, err := c.restore(context.Background(), input, 1, wire); err == nil {
		t.Fatal("missing retained PKCE key admitted")
	}
}

func TestProviderLoginPayloadBindsActualCanonicalProofAndSeparatePKCE(t *testing.T) {
	c, input, now, keys := providerLoginPayloadFixture(t)
	wire, err := c.generate(context.Background(), input, 1, risk.PreparedAuthenticationAdmission{})
	if err != nil {
		t.Fatal(err)
	}
	out, err := c.restore(context.Background(), input, 1, wire)
	if err != nil {
		t.Fatal(err)
	}
	bindingWire, err := out.State.binding.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	binding, err := c.openBinding(context.Background(), input, bindingWire)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(binding.Proof)
	grant, err := capability.Verify(context.Background(), string(binding.Proof), keys, capability.VerifyOptions{Issuer: c.CapabilityIssuer, Now: *now, Limits: capability.DefaultLimits()})
	if err != nil {
		t.Fatal(err)
	}
	payload := grant.Payload()
	if payload.Subject != input.Command.AnonymousFlowID || payload.Tenant != string(input.Command.TenantID) || payload.Resource != input.Command.RecordID || payload.Operation != "identity.sso.oidc-callback" || payload.CorrelationID != input.Command.CorrelationID || payload.MaxUses != 1 || payload.Bearer || !payload.ExpiresAt.Equal(input.ExpiresAt) {
		t.Fatal("canonical capability changed original browser scope")
	}
	metadata, err := providerLoginPayloadEncode(binding.Metadata)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(metadata)
	metadataDigest := sha256.Sum256(metadata)
	if payload.Caveats["identity.sso.rp.binding"] != base64.RawURLEncoding.EncodeToString(metadataDigest[:]) {
		t.Fatal("canonical proof omitted complete original authorization binding")
	}
	plan, err := out.Issuance.Plan()
	if err != nil || sha256.Sum256(binding.Proof) != plan.Grants[0].ProofFingerprint {
		t.Fatal("capability checkpoint does not retain exact proof", err)
	}
	aad, err := providerLoginVerifierAAD(binding.Metadata)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := c.Envelope.Decrypt(context.Background(), envelope.DecryptRequest{Envelope: out.State.verifier, Context: aad})
	defer clear(verifier)
	if err != nil || len(verifier) != 43 {
		t.Fatal("separate verifier custody unavailable", err)
	}
	challenge := sha256.Sum256(verifier)
	if base64.RawURLEncoding.EncodeToString(challenge[:]) != binding.Metadata.Public.Challenge {
		t.Fatal("authorization challenge differs from encrypted verifier")
	}
	if bytes.Contains(wire, binding.Proof) || bytes.Contains(wire, verifier) || bytes.Contains(bindingWire, verifier) {
		t.Fatal("plaintext exchange custody persisted")
	}
	foreign := input
	foreign.InputFingerprint[0] ^= 1
	if _, err := c.redirectState(context.Background(), foreign, bindingWire); err == nil {
		t.Fatal("persisted redirect binding omitted authorization input fingerprint")
	}
}

func TestProviderLoginPayloadRejectsInvalidOriginalInputAndPreservesCancellation(t *testing.T) {
	c, input, _, _ := providerLoginPayloadFixture(t)
	for name, change := range map[string]func(*providerLoginPayloadInput){
		"social operation":            func(i *providerLoginPayloadInput) { i.Command.OperationID = "identity.oauth.signin-start" },
		"authenticated subject":       func(i *providerLoginPayloadInput) { i.Command.UserID = "user" },
		"missing authorization input": func(i *providerLoginPayloadInput) { i.InputFingerprint = [32]byte{} },
		"renewable subsecond expiry":  func(i *providerLoginPayloadInput) { i.ExpiresAt = i.ExpiresAt.Add(time.Nanosecond) },
		"overlong lifetime":           func(i *providerLoginPayloadInput) { i.ExpiresAt = i.ExpiresAt.Add(time.Second) },
		"empty lifetime":              func(i *providerLoginPayloadInput) { i.ExpiresAt = i.IssuedAt },
	} {
		t.Run(name, func(t *testing.T) {
			other := input
			change(&other)
			if wire, err := c.generate(context.Background(), other, 1, risk.PreparedAuthenticationAdmission{}); err == nil || len(wire) != 0 {
				t.Fatal("invalid original operation generated capability custody")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.generate(ctx, input, 1, risk.PreparedAuthenticationAdmission{}); !errors.Is(err, identity.CancelledError{}) {
		t.Fatal("cancellation lost native error category", err)
	}
	if _, err := c.generate(nil, input, 1, risk.PreparedAuthenticationAdmission{}); err == nil {
		t.Fatal("nil context admitted")
	}
	for _, value := range []any{c, input, providerLoginPublicState{State: "private-state"}, providerLoginStoredBinding{Proof: []byte("private-proof")}, providerLoginPayloadOutput{}} {
		for _, format := range []string{"%v", "%#v", "%x"} {
			if got := fmt.Sprintf(format, value); !strings.Contains(got, "redacted") || strings.Contains(got, "private-") {
				t.Fatal("native custody formatting was not redacted")
			}
		}
	}
}
