package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
)

func TestProviderLoginCallbackBorrowsOnlyTheInstalledCredential(t *testing.T) {
	payload, input, now, _ := providerLoginPayloadFixture(t)
	binding := sso.CredentialReferenceContext{
		TenantID: string(input.Command.TenantID), OrganizationID: input.OrganizationID, ProviderID: input.ProviderID,
		Protocol: "oidc", Purpose: "client-secret", Audience: "identity.sso.provider.credentials-rotate",
		Generation: input.CredentialGeneration, ProviderVersion: 5, EnvelopeKeyID: payload.KeyReference,
		IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-59 * time.Minute),
	}
	aad, err := binding.EncryptionContext()
	if err != nil {
		t.Fatal(err)
	}
	secret := bytes.Repeat([]byte{'x'}, 35)
	sealed, err := payload.Envelope.Encrypt(t.Context(), envelope.EncryptRequest{Plaintext: secret, KeyReference: payload.KeyReference, Context: aad})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := sealed.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(wire)
	contextWire, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	var borrowed []byte
	called := 0
	borrow := func(_ context.Context, got []byte) error {
		called++
		borrowed = got
		if !bytes.Equal(got, secret) {
			t.Fatal("borrowed wrong installed secret")
		}
		return nil
	}
	use := func(ctx context.Context, tenant, organization, provider string, wire, contextWire []byte, generation, installed uint64, callback func(context.Context, []byte) error) error {
		return withAuthenticatedStoredProviderCredential(ctx, payload.Envelope, tenant, organization, provider, wire, contextWire, generation, installed, callback)
	}
	installed := binding.ProviderVersion + 1
	if err := use(t.Context(), binding.TenantID, binding.OrganizationID, binding.ProviderID, wire, contextWire, binding.Generation, installed, borrow); err != nil || called != 1 {
		t.Fatalf("expired ingress grant prevented using the exact installed credential: %v", err)
	}
	if !bytes.Equal(borrowed, make([]byte, len(secret))) {
		t.Fatal("plaintext backing bytes survived scoped callback")
	}
	brokenWire := bytes.Clone(wire)
	brokenWire[len(brokenWire)-1] ^= 1
	for _, attempt := range []struct {
		name                           string
		tenant, organization, provider string
		wire, context                  []byte
		generation, installed          uint64
	}{
		{"tenant", "other", binding.OrganizationID, binding.ProviderID, wire, contextWire, binding.Generation, installed},
		{"organization", binding.TenantID, "other", binding.ProviderID, wire, contextWire, binding.Generation, installed},
		{"provider", binding.TenantID, binding.OrganizationID, "other", wire, contextWire, binding.Generation, installed},
		{"generation", binding.TenantID, binding.OrganizationID, binding.ProviderID, wire, contextWire, binding.Generation + 1, installed},
		{"predecessor", binding.TenantID, binding.OrganizationID, binding.ProviderID, wire, contextWire, binding.Generation, installed + 1},
		{"context bytes", binding.TenantID, binding.OrganizationID, binding.ProviderID, wire, append(bytes.Clone(contextWire), '\n'), binding.Generation, installed},
		{"encrypted bytes", binding.TenantID, binding.OrganizationID, binding.ProviderID, brokenWire, contextWire, binding.Generation, installed},
	} {
		t.Run(attempt.name, func(t *testing.T) {
			if err := use(t.Context(), attempt.tenant, attempt.organization, attempt.provider, attempt.wire, attempt.context, attempt.generation, attempt.installed, borrow); err == nil || called != 1 {
				t.Fatal("foreign or mismatched installed custody reached the borrower")
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := use(ctx, binding.TenantID, binding.OrganizationID, binding.ProviderID, wire, contextWire, binding.Generation, installed, borrow); !errors.Is(err, context.Canceled) || called != 1 {
		t.Fatalf("cancelled custody reached the borrower: %v", err)
	}
	borrowErr := errors.New("test transport outcome")
	if err := use(t.Context(), binding.TenantID, binding.OrganizationID, binding.ProviderID, wire, contextWire, binding.Generation, installed, func(_ context.Context, got []byte) error {
		borrowed = got
		return borrowErr
	}); !errors.Is(err, borrowErr) || !bytes.Equal(borrowed, make([]byte, len(secret))) {
		t.Fatalf("borrower's outcome or plaintext cleanup lost: %v", err)
	}
}
