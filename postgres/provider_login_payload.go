package postgres

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

type providerLoginPayloadConfig struct {
	Envelope                        *envelope.Service
	KeyReference                    string
	Issuer                          *capabilitypg.Issuer
	Codec                           *capabilitypg.IssuancePreparationCodec
	CapabilityIssuer, Audience      string
	StateKeys, PKCEKeys             map[uint32][32]byte
	CurrentStateKey, CurrentPKCEKey uint32
}

type providerLoginPayloadInput struct {
	Command                                                   identity.CommandBinding
	OrganizationID, ProviderID, Issuer, ClientID, RedirectURI string
	ProviderVersion, CredentialGeneration, MappingVersion     uint64
	InputFingerprint                                          [32]byte
	IssuedAt, ExpiresAt                                       time.Time
	BrowserOrigin, SuccessCallback, ErrorCallback             string
	Remember                                                  session.RememberPolicySpec
}

// Only immutable columns available after the tenant/key-version/state-digest
// lookup select binding AAD. No inbound issuer, provider or encrypted input is
// needed to locate and authenticate the original row.
type providerLoginRowIdentity struct {
	TenantID                                              identity.TenantID
	OrganizationID, ProviderID                            string
	ProviderVersion, CredentialGeneration, MappingVersion uint64
	StartCommandID                                        identity.CommandID
	IssuedAt, ExpiresAt                                   time.Time
}

func (i providerLoginPayloadInput) rowIdentity() providerLoginRowIdentity {
	return providerLoginRowIdentity{TenantID: i.Command.TenantID, OrganizationID: i.OrganizationID,
		ProviderID: i.ProviderID, ProviderVersion: i.ProviderVersion, CredentialGeneration: i.CredentialGeneration,
		MappingVersion: i.MappingVersion, StartCommandID: i.Command.CommandID, IssuedAt: i.IssuedAt, ExpiresAt: i.ExpiresAt}
}

type providerLoginPublicState struct {
	State, Nonce, Challenge string
}

type providerLoginPayloadOutput struct {
	State    providerLoginTransactionState
	Issuance capabilitypg.PreparedIssuance
	Risk     risk.PreparedAuthenticationAdmission
}

// These projections deliberately bypass public serialization guards only
// inside the existing encrypted preparation and transaction owners.
type providerLoginStoredAdmission risk.PreparedAuthenticationAdmission
type providerLoginStoredGrant kernel.CapabilityPlan

type providerLoginStoredPlan struct {
	Contributor kernel.ContributorDescriptor
	Grant       providerLoginStoredGrant
}

func (p providerLoginStoredPlan) native() kernel.CapabilityIssuancePlan {
	return kernel.CapabilityIssuancePlan{Contributor: p.Contributor, Grants: []kernel.CapabilityPlan{kernel.CapabilityPlan(p.Grant)}}
}

type providerLoginBindingMetadata struct {
	Schema                      uint8
	Input                       providerLoginPayloadInput
	CallbackCommand             identity.CommandID
	Public                      providerLoginPublicState
	StateKey, PKCEKey           uint32
	StateDigest, PKCECommitment [32]byte
}

// The callback proof never appears in the public redirect or an indexed
// column. The binding envelope is its retained ciphertext owner; the raw
// verifier is deliberately absent and has a separately erasable envelope.
type providerLoginStoredBinding struct {
	Metadata providerLoginBindingMetadata
	Plan     providerLoginStoredPlan
	Proof    []byte
}

type providerLoginStoredOutput struct {
	Schema                        uint8
	Generation                    uint64
	Binding, Verifier, Checkpoint []byte
	Plan                          providerLoginStoredPlan
	Admission                     providerLoginStoredAdmission
}

func (providerLoginPayloadConfig) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.providerLoginPayloadConfig(redacted)")
}

func (providerLoginPayloadInput) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.providerLoginPayloadInput(redacted)")
}

func (providerLoginRowIdentity) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.providerLoginRowIdentity(redacted)")
}

func (providerLoginPublicState) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.providerLoginPublicState(redacted)")
}

func (providerLoginStoredBinding) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.providerLoginStoredBinding(redacted)")
}

func (providerLoginPayloadOutput) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.providerLoginPayloadOutput(redacted)")
}

func (i providerLoginPayloadInput) validate() error {
	op := identity.FeatureOperation{Owner: "sso", OperationID: "identity.sso.signin-start", SchemaID: "identity.sso.signin-start.oidc-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
	if i.Command.ValidateFor(op) != nil || i.Command.RecordID != string(i.Command.CommandID) || i.Command.UserID != "" || i.InputFingerprint == ([32]byte{}) || i.ProviderVersion == 0 || i.CredentialGeneration == 0 || i.MappingVersion == 0 {
		return identity.ForbiddenError{}
	}
	if _, err := identity.ParsePreAuthTransactionID(i.Command.AnonymousFlowID); err != nil {
		return identity.ForbiddenError{}
	}
	for _, value := range []string{i.OrganizationID, i.ProviderID} {
		if !providerLoginPayloadText(value, 128) {
			return identity.ForbiddenError{}
		}
	}
	// Match the selected static profile's actual accepted bounds, not the
	// secret-envelope Context's unrelated 1024-byte per-value ceiling.
	if !providerLoginVisible(i.ClientID, 1024) || !providerLoginVisible(i.RedirectURI, 2048) || !validProviderLoginCallback(i.RedirectURI) {
		return identity.ForbiddenError{}
	}
	if !providerLoginPayloadIssuer(i.Issuer) || !validProviderLoginOrigin(i.BrowserOrigin) || !validProviderLoginCallback(i.SuccessCallback) || !validProviderLoginCallback(i.ErrorCallback) {
		return identity.ForbiddenError{}
	}
	if _, err := session.NewRememberPolicy(i.Remember); err != nil {
		return identity.ForbiddenError{}
	}
	if !providerLoginPayloadTime(i.IssuedAt) || !providerLoginPayloadTime(i.ExpiresAt) || !i.ExpiresAt.After(i.IssuedAt) || i.ExpiresAt.Sub(i.IssuedAt) > 10*time.Minute {
		return identity.ForbiddenError{}
	}
	return nil
}

func providerLoginPayloadIssuer(raw string) bool {
	if len(raw) == 0 || len(raw) > 2048 || !utf8.ValidString(raw) || strings.ContainsAny(raw, "\r\n\t #") {
		return false
	}
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Opaque == "" && u.RawQuery == "" && !u.ForceQuery && u.Fragment == ""
}

func providerLoginPayloadTenant(tenant identity.TenantID) bool {
	return (identity.User{ID: "validation", TenantID: tenant, Status: identity.StatusActive, Version: 1}).Validate(tenant) == nil
}

func (r providerLoginRowIdentity) aad() (envelope.Context, error) {
	if !providerLoginPayloadTenant(r.TenantID) || !providerLoginPayloadText(r.OrganizationID, 128) || !providerLoginPayloadText(r.ProviderID, 128) || r.ProviderVersion == 0 || r.CredentialGeneration == 0 || r.MappingVersion == 0 || !providerLoginPayloadTime(r.IssuedAt) || !providerLoginPayloadTime(r.ExpiresAt) || !r.ExpiresAt.After(r.IssuedAt) || r.ExpiresAt.Sub(r.IssuedAt) > 10*time.Minute {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	if _, err := identity.ParseCommandID(string(r.StartCommandID)); err != nil {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	plain, err := providerLoginPayloadEncode(r)
	if err != nil {
		return envelope.Context{}, identity.UnavailableError{}
	}
	defer clear(plain)
	digest := sha256.Sum256(plain)
	return envelope.NewContext(map[string]string{"profile": "identity-sso-oidc-login-row-binding-v1", "binding": hex.EncodeToString(digest[:])})
}

func providerLoginPayloadText(value string, maximum int) bool {
	if len(value) < 1 || len(value) > maximum {
		return false
	}
	for _, ch := range []byte(value) {
		if ch < 0x21 || ch > 0x7e {
			return false
		}
	}
	return true
}

func providerLoginPayloadTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond() == 0 && value.Unix() > 0 && value.Year() <= 9999
}

func (c providerLoginPayloadConfig) ready() bool {
	return c.Envelope != nil && c.KeyReference != "" && c.Issuer != nil && c.Codec != nil && c.CapabilityIssuer != "" && c.Audience != "" && c.CurrentStateKey != 0 && c.CurrentPKCEKey != 0 && c.StateKeys[c.CurrentStateKey] != ([32]byte{}) && c.PKCEKeys[c.CurrentPKCEKey] != ([32]byte{})
}

// Generation and complete original input belong to preparation AAD. The
// durable binding uses SQL-observable row identity so the callback can decrypt
// first, then authenticate the retained original input rather than guess it.
func providerLoginPayloadAAD(i providerLoginPayloadInput, purpose string, generation uint64) (envelope.Context, error) {
	if i.validate() != nil || purpose != "output" && purpose != "binding" || purpose == "output" && generation == 0 || purpose == "binding" && generation != 0 {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	if purpose == "binding" {
		return i.rowIdentity().aad()
	}
	plain, err := providerLoginPayloadEncode(i)
	if err != nil {
		return envelope.Context{}, identity.UnavailableError{}
	}
	defer clear(plain)
	digest := sha256.Sum256(plain)
	values := map[string]string{"profile": "identity-sso-oidc-login-" + purpose + "-v1", "binding": hex.EncodeToString(digest[:])}
	if purpose == "output" {
		values["generation"] = strconv.FormatUint(generation, 10)
	}
	aad, err := envelope.NewContext(values)
	if err != nil {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	return aad, nil
}

// REFERENCE_CONFIGURATION struct:ref.oauth.rp_transaction requires original
// PKCE scope. Hash the complete framed metadata, preserving accepted 2048-byte
// URLs beyond Context's per-value limit without truncation. The commitment is
// excluded because it is subsequently computed over this AAD and the verifier.
func providerLoginVerifierAAD(metadata providerLoginBindingMetadata) (envelope.Context, error) {
	if metadata.Schema != 1 || metadata.Input.validate() != nil || metadata.StateDigest == ([32]byte{}) || metadata.StateKey == 0 || metadata.PKCEKey == 0 {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	metadata.PKCECommitment = [32]byte{}
	plain, err := providerLoginPayloadEncode(metadata)
	if err != nil {
		return envelope.Context{}, identity.UnavailableError{}
	}
	defer clear(plain)
	digest := sha256.Sum256(plain)
	return envelope.NewContext(map[string]string{"profile": "identity-sso-oidc-pkce-metadata-v1", "response_mode": "query", "binding": hex.EncodeToString(digest[:])})
}

// Before any row exists in memory the callback knows only its trusted tenant
// and opaque state. Retained versions permit bounded primary-key lookups; no
// callback-supplied issuer or provider participates in authority selection.
func providerLoginStateDigest(key [32]byte, version uint32, tenant identity.TenantID, state []byte) ([32]byte, error) {
	if key == ([32]byte{}) || version == 0 || !providerLoginPayloadTenant(tenant) || len(state) != 32 {
		return [32]byte{}, identity.ForbiddenError{}
	}
	return providerLoginPayloadMAC(key, version, "identity.sso.oidc.state-lookup.v1", []byte("identity.sso.oidc-callback"), []byte(tenant), state), nil
}

func providerLoginPayloadMAC(key [32]byte, version uint32, domain string, fields ...[]byte) [32]byte {
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte(domain))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(binary.BigEndian.AppendUint32(nil, version))
	for _, field := range fields {
		_, _ = mac.Write(binary.BigEndian.AppendUint32(nil, uint32(len(field))))
		_, _ = mac.Write(field)
	}
	var digest [32]byte
	copy(digest[:], mac.Sum(nil))
	return digest
}

func (c providerLoginPayloadConfig) generate(ctx context.Context, input providerLoginPayloadInput, generation uint64, admitted risk.PreparedAuthenticationAdmission) ([]byte, error) {
	if err := providerLoginPayloadContext(ctx); err != nil {
		return nil, err
	}
	if !c.ready() {
		return nil, identity.ForbiddenError{}
	}
	aad, err := providerLoginPayloadAAD(input, "output", generation)
	if err != nil {
		return nil, err
	}
	var state, nonce, rawVerifier [32]byte
	defer clear(state[:])
	defer clear(nonce[:])
	defer clear(rawVerifier[:])
	for _, raw := range [][]byte{state[:], nonce[:], rawVerifier[:]} {
		if _, err := rand.Read(raw); err != nil {
			return nil, identity.UnavailableError{}
		}
	}
	callback, err := identity.NewCommandID()
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	verifier := base64.RawURLEncoding.AppendEncode(nil, rawVerifier[:])
	defer clear(verifier)
	challenge := sha256.Sum256(verifier)
	digest, err := providerLoginStateDigest(c.StateKeys[c.CurrentStateKey], c.CurrentStateKey, input.Command.TenantID, state[:])
	if err != nil {
		return nil, err
	}
	metadata := providerLoginBindingMetadata{Schema: 1, Input: input, CallbackCommand: callback, Public: providerLoginPublicState{State: base64.RawURLEncoding.EncodeToString(state[:]), Nonce: base64.RawURLEncoding.EncodeToString(nonce[:]), Challenge: base64.RawURLEncoding.EncodeToString(challenge[:])}, StateKey: c.CurrentStateKey, PKCEKey: c.CurrentPKCEKey, StateDigest: digest}
	vaad, err := providerLoginVerifierAAD(metadata)
	if err != nil {
		return nil, err
	}
	encryptedVerifier, err := c.seal(ctx, vaad, verifier, 4096)
	if err != nil {
		return nil, err
	}
	commitment := providerLoginPayloadMAC(c.PKCEKeys[c.CurrentPKCEKey], c.CurrentPKCEKey, "identity.sso.oidc.pkce-verifier.v1", vaad.AdditionalData(), []byte(input.IssuedAt.Format(time.RFC3339Nano)), []byte(input.ExpiresAt.Format(time.RFC3339Nano)), verifier)
	metadata.PKCECommitment = commitment
	plainMetadata, err := providerLoginPayloadEncode(metadata)
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	defer clear(plainMetadata)
	metadataDigest := sha256.Sum256(plainMetadata)
	b := input.Command
	issued, err := c.Issuer.Prepare(ctx, b, []capability.Payload{{Version: 1, Issuer: c.CapabilityIssuer, Audiences: []string{c.Audience}, Subject: b.AnonymousFlowID, Tenant: string(b.TenantID), Resource: b.RecordID, CorrelationID: b.CorrelationID, Operation: "identity.sso.oidc-callback", IssuedAt: input.IssuedAt, NotBefore: input.IssuedAt, ExpiresAt: input.ExpiresAt, MaxUses: 1, Caveats: map[string]string{"identity.sso.rp.binding": base64.RawURLEncoding.EncodeToString(metadataDigest[:])}}})
	if err != nil {
		return nil, err
	}
	plan, err := issued.Plan()
	if err != nil || len(plan.Grants) != 1 || plan.RegistrationUserID != "" || plan.ResetRecipientUserID != "" || plan.MagicLinkRecipientUserID != "" || plan.MFAContinuationUserID != "" {
		return nil, identity.ForbiddenError{}
	}
	stored := providerLoginStoredBinding{Metadata: metadata, Plan: providerLoginStoredPlan{Contributor: plan.Contributor, Grant: providerLoginStoredGrant(plan.Grants[0])}}
	defer func() { clear(stored.Proof) }()
	checkpoint, err := c.Codec.CheckpointPreparation(ctx, issued, generation, func(ctx context.Context, index uint16, proof []byte) error {
		if err := providerLoginPayloadContext(ctx); err != nil {
			return err
		}
		if index != 0 || len(stored.Proof) != 0 || len(proof) == 0 || len(proof) > 32768 {
			return identity.ForbiddenError{}
		}
		stored.Proof = bytes.Clone(proof)
		return nil
	})
	if err != nil {
		return nil, err
	}
	plainBinding, err := providerLoginPayloadEncode(stored)
	if err != nil || len(plainBinding) > 49152 {
		clear(plainBinding)
		return nil, identity.UnavailableError{}
	}
	defer clear(plainBinding)
	baad, err := providerLoginPayloadAAD(input, "binding", 0)
	if err != nil {
		return nil, err
	}
	binding, err := c.seal(ctx, baad, plainBinding, 65536)
	if err != nil {
		return nil, err
	}
	out := providerLoginStoredOutput{Schema: 1, Generation: generation, Binding: binding, Verifier: encryptedVerifier, Checkpoint: checkpoint, Plan: stored.Plan, Admission: providerLoginStoredAdmission(admitted)}
	plain, err := providerLoginPayloadEncode(out)
	if err != nil || len(plain) > 768<<10 {
		clear(plain)
		return nil, identity.UnavailableError{}
	}
	defer clear(plain)
	return c.seal(ctx, aad, plain, 1<<20)
}

func (c providerLoginPayloadConfig) openBinding(ctx context.Context, input providerLoginPayloadInput, wire []byte) (providerLoginStoredBinding, error) {
	if input.validate() != nil {
		return providerLoginStoredBinding{}, identity.ForbiddenError{}
	}
	stored, err := c.openCommittedBinding(ctx, input.rowIdentity(), wire)
	if err != nil {
		return providerLoginStoredBinding{}, err
	}
	if !reflect.DeepEqual(stored.Metadata.Input, input) {
		clear(stored.Proof)
		return providerLoginStoredBinding{}, identity.ForbiddenError{}
	}
	return stored, nil
}

// This authenticates row custody only. A future callback owner still owns
// browser possession, expiry/current authority, one-use state reservation and
// canonical capability validation before any verifier release or exchange.
func (c providerLoginPayloadConfig) openCommittedBinding(ctx context.Context, row providerLoginRowIdentity, wire []byte) (providerLoginStoredBinding, error) {
	fail := func() (providerLoginStoredBinding, error) {
		return providerLoginStoredBinding{}, identity.ForbiddenError{}
	}
	if err := providerLoginPayloadContext(ctx); err != nil {
		return providerLoginStoredBinding{}, err
	}
	if !c.ready() {
		return fail()
	}
	aad, err := row.aad()
	if err != nil {
		return providerLoginStoredBinding{}, err
	}
	plain, err := c.open(ctx, aad, wire, 65536, 49152)
	if err != nil {
		return providerLoginStoredBinding{}, err
	}
	defer clear(plain)
	var stored providerLoginStoredBinding
	if providerLoginPayloadDecode(plain, &stored) != nil {
		clear(stored.Proof)
		return fail()
	}
	if !c.validProviderLoginPendingBinding(row, stored) {
		clear(stored.Proof)
		return fail()
	}
	return stored, nil
}

func (c providerLoginPayloadConfig) restore(ctx context.Context, input providerLoginPayloadInput, generation uint64, wire []byte) (providerLoginPayloadOutput, error) {
	if err := providerLoginPayloadContext(ctx); err != nil {
		return providerLoginPayloadOutput{}, err
	}
	if !c.ready() {
		return providerLoginPayloadOutput{}, identity.ForbiddenError{}
	}
	aad, err := providerLoginPayloadAAD(input, "output", generation)
	if err != nil {
		return providerLoginPayloadOutput{}, err
	}
	plain, err := c.open(ctx, aad, wire, 1<<20, 768<<10)
	if err != nil {
		return providerLoginPayloadOutput{}, err
	}
	defer clear(plain)
	var out providerLoginStoredOutput
	if providerLoginPayloadDecode(plain, &out) != nil || out.Schema != 1 || out.Generation != generation || len(out.Checkpoint) == 0 || len(out.Checkpoint) > 512<<10 || len(out.Verifier) == 0 || len(out.Verifier) > 4096 {
		return providerLoginPayloadOutput{}, identity.ForbiddenError{}
	}
	stored, err := c.openBinding(ctx, input, out.Binding)
	if err != nil {
		return providerLoginPayloadOutput{}, err
	}
	defer clear(stored.Proof)
	if !reflect.DeepEqual(stored.Plan, out.Plan) {
		return providerLoginPayloadOutput{}, identity.ForbiddenError{}
	}
	prepared, err := c.Codec.RestorePreparation(ctx, input.Command, generation, out.Plan.native(), out.Checkpoint)
	if err != nil {
		return providerLoginPayloadOutput{}, err
	}
	binding, err := envelope.ParseEnvelope(out.Binding)
	if err != nil {
		return providerLoginPayloadOutput{}, identity.ForbiddenError{}
	}
	verifier, err := envelope.ParseEnvelope(out.Verifier)
	if err != nil {
		return providerLoginPayloadOutput{}, identity.ForbiddenError{}
	}
	m := stored.Metadata
	state := providerLoginTransactionState{callbackCommand: m.CallbackCommand, stateKey: m.StateKey, pkceKey: m.PKCEKey, stateDigest: m.StateDigest, pkceCommitment: m.PKCECommitment, binding: binding, verifier: verifier, issuedAt: input.IssuedAt, expiresAt: input.ExpiresAt}
	return providerLoginPayloadOutput{State: state, Issuance: prepared, Risk: risk.PreparedAuthenticationAdmission(out.Admission)}, nil
}

// The native redirect owner must still check current preauth possession,
// provider/directory authority and the original exclusive expiry. Decryption
// authenticates original state; it does not refresh that live authority.
func (c providerLoginPayloadConfig) redirectState(ctx context.Context, input providerLoginPayloadInput, persistedBindingEnvelope []byte) (providerLoginPublicState, error) {
	if err := providerLoginPayloadContext(ctx); err != nil {
		return providerLoginPublicState{}, err
	}
	if !c.ready() {
		return providerLoginPublicState{}, identity.ForbiddenError{}
	}
	stored, err := c.openBinding(ctx, input, persistedBindingEnvelope)
	if err != nil {
		return providerLoginPublicState{}, err
	}
	defer clear(stored.Proof)
	return stored.Metadata.Public, nil
}

func (c providerLoginPayloadConfig) seal(ctx context.Context, aad envelope.Context, plain []byte, maximum int) ([]byte, error) {
	sealed, err := c.Envelope.Encrypt(ctx, envelope.EncryptRequest{Plaintext: plain, KeyReference: c.KeyReference, Context: aad})
	if err != nil {
		return nil, providerLoginPayloadFailure(ctx)
	}
	wire, err := sealed.MarshalBinary()
	if err != nil || len(wire) > maximum {
		clear(wire)
		return nil, identity.UnavailableError{}
	}
	if err := providerLoginPayloadContext(ctx); err != nil {
		clear(wire)
		return nil, err
	}
	return wire, nil
}

func (c providerLoginPayloadConfig) open(ctx context.Context, aad envelope.Context, wire []byte, maximumWire, maximumPlain int) ([]byte, error) {
	if len(wire) == 0 || len(wire) > maximumWire {
		return nil, identity.ForbiddenError{}
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return nil, identity.ForbiddenError{}
	}
	plain, err := c.Envelope.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	if err != nil || len(plain) > maximumPlain {
		clear(plain)
		if cancellation := providerLoginPayloadContext(ctx); cancellation != nil {
			return nil, cancellation
		}
		return nil, identity.ForbiddenError{}
	}
	if err := providerLoginPayloadContext(ctx); err != nil {
		clear(plain)
		return nil, err
	}
	return plain, nil
}

// Private encrypted storage is not HTML. Disabling HTML escaping preserves
// accepted URL/client bytes without multiplying their durable storage budget.
func providerLoginPayloadEncode(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		clear(buffer.Bytes())
		return nil, err
	}
	return buffer.Bytes(), nil
}

func providerLoginPayloadDecode(plain []byte, output any) error {
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	if decoder.Decode(output) != nil || decoder.Decode(new(any)) != io.EOF {
		return identity.ForbiddenError{}
	}
	return nil
}

func providerLoginPayloadContext(ctx context.Context) error {
	if ctx == nil {
		return identity.ForbiddenError{}
	}
	if ctx.Err() == context.Canceled {
		return identity.CancelledError{}
	}
	if ctx.Err() == context.DeadlineExceeded {
		return identity.DeadlineExceededError{}
	}
	return nil
}

func providerLoginPayloadFailure(ctx context.Context) error {
	if err := providerLoginPayloadContext(ctx); err != nil {
		return err
	}
	return identity.UnavailableError{}
}
