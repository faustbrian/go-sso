package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
)

func TestProviderLoginCallbackVerifierBorrowsOnlyMatchingOriginalSecret(t *testing.T) {
	ctx := t.Context()
	c, input, now, _ := providerLoginPayloadFixture(t)
	output, err := c.generate(ctx, input, 1, risk.PreparedAuthenticationAdmission{})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(output)
	restored, err := c.restore(ctx, input, 1, output)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := restored.State.binding.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(bound)
	stored, err := c.openBinding(ctx, input, bound)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(stored.Proof)
	wire, err := restored.State.verifier.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(wire)
	called := 0
	use := func(_ context.Context, verifier []byte) error {
		called++
		challenge := sha256.Sum256(verifier)
		if base64.RawURLEncoding.EncodeToString(challenge[:]) != stored.Metadata.Public.Challenge {
			t.Fatal("borrowed verifier does not match the original redirect")
		}
		return nil
	}
	if err := c.withCallbackVerifier(ctx, stored.Metadata, *now, wire, use); err != nil || called != 1 {
		t.Fatalf("original reserved material did not yield one scoped verifier use: %v", err)
	}

	for name, change := range map[string]func(*providerLoginBindingMetadata, *time.Time, []byte){
		"foreign nonce": func(m *providerLoginBindingMetadata, _ *time.Time, _ []byte) {
			m.Public.Nonce = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		},
		"commitment mismatch": func(m *providerLoginBindingMetadata, _ *time.Time, _ []byte) { m.PKCECommitment[0] ^= 1 },
		"retired key":         func(m *providerLoginBindingMetadata, _ *time.Time, _ []byte) { m.PKCEKey++ },
		"ciphertext invalid":  func(_ *providerLoginBindingMetadata, _ *time.Time, wire []byte) { wire[len(wire)-1] ^= 1 },
		"exclusive expiry":    func(m *providerLoginBindingMetadata, clock *time.Time, _ []byte) { *clock = m.Input.ExpiresAt },
		"before issuance": func(m *providerLoginBindingMetadata, clock *time.Time, _ []byte) {
			*clock = m.Input.IssuedAt.Add(-time.Microsecond)
		},
	} {
		t.Run(name, func(t *testing.T) {
			metadata, clock := stored.Metadata, *now
			ciphertext := append([]byte(nil), wire...)
			defer clear(ciphertext)
			change(&metadata, &clock, ciphertext)
			var denied identity.ForbiddenError
			if err := c.withCallbackVerifier(ctx, metadata, clock, ciphertext, use); !errors.As(err, &denied) || called != 1 {
				t.Fatalf("non-original or expired material reached verifier borrower: %v", err)
			}
		})
	}
	if err := c.withCallbackVerifier(ctx, stored.Metadata, *now, wire, func(context.Context, []byte) error { return context.Canceled }); !errors.Is(err, context.Canceled) {
		t.Fatalf("caller lost the exact verifier-use outcome: %v", err)
	}
}
