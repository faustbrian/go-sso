package sso_test

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
)

// The fixture wraps random data keys with real AES-GCM and binds the wrapping
// layer to both key identity and AAD, like a configured envelope key provider.
type credentialEnvelopeKeys struct{ cipher cipher.AEAD }

func (k credentialEnvelopeKeys) GenerateDataKey(ctx context.Context, key string, aad envelope.Context) (envelope.DataKey, error) {
	if err := ctx.Err(); err != nil {
		return envelope.DataKey{}, err
	}
	raw := make([]byte, envelope.DataKeySize)
	if _, err := rand.Read(raw); err != nil {
		return envelope.DataKey{}, err
	}
	nonce := make([]byte, k.cipher.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		clear(raw)
		return envelope.DataKey{}, err
	}
	return envelope.NewDataKey(raw, k.cipher.Seal(nonce, nonce, raw, append([]byte(key), aad.AdditionalData()...)), key)
}

func (k credentialEnvelopeKeys) DecryptDataKey(ctx context.Context, key string, wire []byte, aad envelope.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(wire) < k.cipher.NonceSize()+k.cipher.Overhead() {
		return nil, envelope.ErrInvalidRequest
	}
	return k.cipher.Open(nil, wire[:k.cipher.NonceSize()], wire[k.cipher.NonceSize():], append([]byte(key), aad.AdditionalData()...))
}

func newCredentialEnvelopeService(t testing.TB) *envelope.Service {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	clear(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	service, err := envelope.NewService(credentialEnvelopeKeys{cipher: aead})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func credentialReferenceContext() sso.CredentialReferenceContext {
	at := time.Date(2026, 11, 22, 8, 0, 0, 0, time.UTC)
	return sso.CredentialReferenceContext{
		TenantID: "tenant", OrganizationID: "organization", ProviderID: "provider",
		Protocol: "oidc", Purpose: "client-secret", Generation: 1, ProviderVersion: 1,
		Audience: "identity.sso.provider.credentials-rotate", EnvelopeKeyID: "configured-key",
		IssuedAt: at, ExpiresAt: at.Add(time.Minute),
	}
}

func credentialEnvelope(t testing.TB, service *envelope.Service, binding sso.CredentialReferenceContext) []byte {
	t.Helper()
	aad, err := binding.EncryptionContext()
	if err != nil {
		t.Fatal(err)
	}
	secret := make([]byte, 32)
	if _, err = rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	defer clear(secret)
	sealed, err := service.Encrypt(context.Background(), envelope.EncryptRequest{Plaintext: secret, KeyReference: binding.EnvelopeKeyID, Context: aad})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := sealed.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestCredentialReferenceAuthenticatesExactBoundedEnvelopeContext(t *testing.T) {
	service := newCredentialEnvelopeService(t)
	binding := credentialReferenceContext()
	sealed := credentialEnvelope(t, service, binding)
	reference, err := sso.NewEncryptedCredentialReference(context.Background(), service, sealed, binding)
	if err != nil || reference.ValidateAt(binding.IssuedAt) != nil || reference.Context() != binding {
		t.Fatal("authenticated reference rejected its original binding", err)
	}
	if !errors.Is(reference.ValidateAt(binding.ExpiresAt), sso.ErrForbidden) || !errors.Is(reference.ValidateAt(binding.IssuedAt.Add(-time.Microsecond)), sso.ErrForbidden) {
		t.Fatal("reference accepted outside its immutable lifetime")
	}
	want := sealed
	actual, err := reference.EncryptedEnvelope().MarshalBinary()
	if err != nil || !bytes.Equal(actual, want) {
		t.Fatal("reference changed the authenticated envelope", err)
	}
	for _, field := range []string{"tenant", "organization", "provider", "protocol", "purpose", "generation", "provider-version", "audience", "key", "issued", "expires"} {
		t.Run(field, func(t *testing.T) {
			changed := binding
			switch field {
			case "tenant":
				changed.TenantID = "foreign"
			case "organization":
				changed.OrganizationID = "foreign"
			case "provider":
				changed.ProviderID = "foreign"
			case "protocol":
				changed.Protocol = "saml"
			case "purpose":
				changed.Purpose = "signing-key"
			case "generation":
				changed.Generation++
			case "provider-version":
				changed.ProviderVersion++
			case "audience":
				changed.Audience = "identity.sso.provider.update"
			case "key":
				changed.EnvelopeKeyID = "foreign"
			case "issued":
				changed.IssuedAt = changed.IssuedAt.Add(time.Microsecond)
			case "expires":
				changed.ExpiresAt = changed.ExpiresAt.Add(time.Microsecond)
			}
			if _, err := sso.NewEncryptedCredentialReference(context.Background(), service, sealed, changed); err == nil {
				t.Fatal("changed binding authenticated an original reference")
			}
		})
	}
	wrongKeys := newCredentialEnvelopeService(t)
	if _, err := sso.NewEncryptedCredentialReference(context.Background(), wrongKeys, sealed, binding); !errors.Is(err, sso.ErrForbidden) {
		t.Fatal("unrelated key provider authenticated reference", err)
	}
	wire := bytes.Clone(sealed)
	wire[len(wire)-1] ^= 1
	_, err = envelope.ParseEnvelope(wire)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sso.NewEncryptedCredentialReference(context.Background(), service, wire, binding); !errors.Is(err, sso.ErrForbidden) {
		t.Fatal("tampered ciphertext authenticated reference", err)
	}
}

func TestCredentialReferenceAuthenticatesOAuth2WithoutOIDCSubstitution(t *testing.T) {
	ctx := context.Background()
	service := newCredentialEnvelopeService(t)
	oidcBinding := credentialReferenceContext()
	oauthBinding := oidcBinding
	oauthBinding.Protocol = "oauth2"

	oauthWire := credentialEnvelope(t, service, oauthBinding)
	reference, err := sso.NewEncryptedCredentialReference(ctx, service, oauthWire, oauthBinding)
	if err != nil || reference.Context() != oauthBinding || reference.ValidateAt(oauthBinding.IssuedAt) != nil {
		t.Fatal("OAuth client-secret ingress lost its original binding", err)
	}
	if _, err = sso.NewEncryptedCredentialReference(ctx, service, oauthWire, oidcBinding); !errors.Is(err, sso.ErrForbidden) {
		t.Fatal("OAuth ciphertext authenticated as OIDC", err)
	}
	oidcWire := credentialEnvelope(t, service, oidcBinding)
	if _, err = sso.NewEncryptedCredentialReference(ctx, service, oidcWire, oauthBinding); !errors.Is(err, sso.ErrForbidden) {
		t.Fatal("OIDC ciphertext authenticated as OAuth", err)
	}
	for _, protocol := range []string{"", "oauth", "OAuth2", "saml"} {
		alias := oauthBinding
		alias.Protocol = protocol
		if _, err = alias.EncryptionContext(); !errors.Is(err, sso.ErrInvalidInput) {
			t.Fatal("noncanonical credential protocol accepted", err)
		}
	}
}

func TestCredentialReferenceAuthenticatesSAMLSigningPurposeOnly(t *testing.T) {
	ctx := t.Context()
	service := newCredentialEnvelopeService(t)
	binding := credentialReferenceContext()
	binding.Protocol, binding.Purpose = "saml", "sp-signing-key"
	wire := credentialEnvelope(t, service, binding)
	ref, err := sso.NewEncryptedCredentialReference(ctx, service, wire, binding)
	if err != nil || ref.Context() != binding || ref.ValidateAt(binding.IssuedAt) != nil {
		t.Fatal("SAML signing envelope lost its original binding", err)
	}
	for _, protocol := range []string{"oidc", "oauth2"} {
		client := binding
		client.Protocol, client.Purpose = protocol, "client-secret"
		if _, err := sso.NewEncryptedCredentialReference(ctx, service, wire, client); !errors.Is(err, sso.ErrForbidden) {
			t.Fatal("signing ciphertext authenticated as a client secret", err)
		}
		client.Purpose = binding.Purpose
		if _, err := client.EncryptionContext(); !errors.Is(err, sso.ErrInvalidInput) {
			t.Fatal("client protocol acquired SAML signing purpose", err)
		}
	}
	for _, purpose := range []string{"client-secret", "signing-key", "sp-signing-key "} {
		other := binding
		other.Purpose = purpose
		if _, err := other.EncryptionContext(); !errors.Is(err, sso.ErrInvalidInput) {
			t.Fatal("SAML accepted an unrelated ingress purpose", err)
		}
	}
}

func TestCredentialReferenceRejectsZeroUnsupportedAndOversizedInput(t *testing.T) {
	service := newCredentialEnvelopeService(t)
	binding := credentialReferenceContext()
	sealed := credentialEnvelope(t, service, binding)
	if _, err := sso.NewEncryptedCredentialReference(context.Background(), nil, sealed, binding); !errors.Is(err, sso.ErrInvalidInput) {
		t.Fatal("missing authenticator accepted", err)
	}
	if _, err := sso.NewEncryptedCredentialReference(context.Background(), service, nil, binding); !errors.Is(err, sso.ErrInvalidInput) {
		t.Fatal("zero envelope accepted", err)
	}
	if err := (sso.EncryptedCredentialReference{}).ValidateAt(binding.IssuedAt); !errors.Is(err, sso.ErrInvalidInput) {
		t.Fatal("zero reference accepted", err)
	}
	for _, field := range []string{"zero", "tenant", "owner", "generation", "version", "lifetime", "time-precision", "oversized"} {
		t.Run(field, func(t *testing.T) {
			changed := binding
			switch field {
			case "zero":
				changed = sso.CredentialReferenceContext{}
			case "tenant":
				changed.TenantID = " tenant"
			case "owner":
				changed.OrganizationID = ""
			case "generation":
				changed.Generation = 0
			case "version":
				changed.ProviderVersion = 0
			case "lifetime":
				changed.ExpiresAt = changed.IssuedAt
			case "time-precision":
				changed.IssuedAt = changed.IssuedAt.Add(time.Nanosecond)
			case "oversized":
				changed.ProviderID = strings.Repeat("p", 129)
			}
			if _, err := changed.EncryptionContext(); !errors.Is(err, sso.ErrInvalidInput) {
				t.Fatal("malformed reference context accepted", err)
			}
		})
	}
	aad, _ := binding.EncryptionContext()
	large, err := service.Encrypt(context.Background(), envelope.EncryptRequest{Plaintext: make([]byte, 32768), KeyReference: binding.EnvelopeKeyID, Context: aad})
	if err != nil {
		t.Fatal(err)
	}
	largeWire, err := large.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sso.NewEncryptedCredentialReference(context.Background(), service, largeWire, binding); !errors.Is(err, sso.ErrInvalidInput) {
		t.Fatal("oversized reference accepted", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := sso.NewEncryptedCredentialReference(ctx, service, sealed, binding); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled reference authentication lost cancellation", err)
	}
}

func TestCredentialReferenceAndExplicitNoOverlapAreRedacted(t *testing.T) {
	service := newCredentialEnvelopeService(t)
	binding := credentialReferenceContext()
	reference, err := sso.NewEncryptedCredentialReference(context.Background(), service, credentialEnvelope(t, service, binding), binding)
	if err != nil {
		t.Fatal(err)
	}
	policy := sso.NewNoCredentialOverlapPolicy()
	if policy.Validate() != nil || !errors.Is((sso.CredentialOverlapPolicy{}).Validate(), sso.ErrInvalidInput) {
		t.Fatal("no-overlap selection is not explicit")
	}
	for _, value := range []any{reference, policy, sso.ProviderCredentialsRotateRequest{ProviderID: binding.ProviderID, ExpectedVersion: 1, CredentialReference: reference, OverlapPolicy: policy}} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			formatted := fmt.Sprintf(format, value)
			if strings.Contains(formatted, binding.TenantID) || strings.Contains(formatted, binding.ProviderID) || strings.Contains(formatted, binding.EnvelopeKeyID) {
				t.Fatal("implicit formatting disclosed reference data")
			}
		}
		if _, err := json.Marshal(value); !errors.Is(err, sso.ErrSensitiveSerialization) {
			t.Fatal("implicit credential serialization accepted", err)
		}
	}
}

func FuzzCredentialReferenceRejectsHostileWire(f *testing.F) {
	service := newCredentialEnvelopeService(f)
	binding := credentialReferenceContext()
	f.Add(credentialEnvelope(f, service, binding))
	f.Add([]byte{})
	f.Add([]byte("SEV1"))
	f.Fuzz(func(t *testing.T, wire []byte) {
		reference, err := sso.NewEncryptedCredentialReference(context.Background(), service, wire, binding)
		if err != nil {
			return
		}
		actual, err := reference.EncryptedEnvelope().MarshalBinary()
		if err != nil || !bytes.Equal(actual, wire) || reference.Context() != binding || reference.ValidateAt(binding.IssuedAt) != nil {
			t.Fatal("accepted hostile wire changed authenticated custody")
		}
	})
}
