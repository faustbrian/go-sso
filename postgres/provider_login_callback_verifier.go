package postgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// withCallbackVerifier opens the existing recoverable verifier only for the
// callback's admitted generation borrower. Its call site must run after the
// native coordinator has acknowledged reservation. This custody operation
// checks the original cryptographic binding; it does not reserve or renew it.
func (c providerLoginPayloadConfig) withCallbackVerifier(ctx context.Context, metadata providerLoginBindingMetadata, now time.Time, wire []byte, use func(context.Context, []byte) error) error {
	if ctx == nil || c.Envelope == nil || use == nil || metadata.Input.Protocol != "" || now.IsZero() || now.Before(metadata.Input.IssuedAt) || !now.Before(metadata.Input.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	key, retained := c.PKCEKeys[metadata.PKCEKey]
	if !retained || key == ([32]byte{}) || metadata.PKCECommitment == ([32]byte{}) {
		return identity.ForbiddenError{}
	}
	aad, err := providerLoginVerifierAAD(metadata)
	if err != nil {
		return err
	}
	const verifierBytes = 43 // The native start encrypts canonical base64url of 32 random bytes.
	verifier, err := c.open(ctx, aad, wire, 4096, verifierBytes)
	defer clear(verifier)
	if err != nil {
		return err
	}
	var raw [32]byte
	defer clear(raw[:])
	if len(verifier) != verifierBytes {
		return identity.ForbiddenError{}
	}
	if n, err := base64.RawURLEncoding.Strict().Decode(raw[:], verifier); err != nil || n != len(raw) {
		return identity.ForbiddenError{}
	}
	input := metadata.Input
	commitment := providerLoginPayloadMAC(key, metadata.PKCEKey, "identity.sso.oidc.pkce-verifier.v1", aad.AdditionalData(), []byte(input.IssuedAt.Format(time.RFC3339Nano)), []byte(input.ExpiresAt.Format(time.RFC3339Nano)), verifier)
	challenge := sha256.Sum256(verifier)
	challengeText := base64.RawURLEncoding.EncodeToString(challenge[:])
	if !hmac.Equal(commitment[:], metadata.PKCECommitment[:]) || !hmac.Equal([]byte(challengeText), []byte(metadata.Public.Challenge)) {
		return identity.ForbiddenError{}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return use(ctx, verifier)
}
