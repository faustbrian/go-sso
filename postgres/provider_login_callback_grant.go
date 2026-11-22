package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"

	"github.com/faustbrian/go-capability/v2"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-sso"
)

// Verify the signed RP binding and recover the exact original replay plan.
// The coordinator, not this read-only check, owns reservation and consumption.
func (s *ProviderLoginService) prepareProviderLoginCallbackGrant(ctx context.Context, found providerLoginCallbackLookup) (kernel.CapabilityPlan, error) {
	if s == nil || ctx == nil || s.callbackVerifier == nil || s.payload.Issuer == nil || found.CompletedAt != nil {
		return kernel.CapabilityPlan{}, sso.ErrForbidden
	}
	ctx, cancel := context.WithTimeout(ctx, s.config.Coordinator.MaximumDuration)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return kernel.CapabilityPlan{}, err
	}
	stored := found.Binding
	proof, err := capability.ParseProof(string(stored.Proof), s.callbackLimits)
	if err != nil {
		return kernel.CapabilityPlan{}, sso.ErrForbidden
	}
	defer func() {
		_ = proof.Transfer(context.WithoutCancel(ctx), func(context.Context, []byte) error { return nil })
	}()
	grant, err := s.callbackVerifier.Verify(ctx, proof, providerOIDCCallback, s.payload.Audience)
	if err != nil {
		if ctx.Err() != nil {
			return kernel.CapabilityPlan{}, ctx.Err()
		}
		if errors.Is(err, capability.ErrInvalidConfiguration) || errors.Is(err, capability.ErrKeyResolution) || errors.Is(err, capability.ErrRevocationUnknown) {
			return kernel.CapabilityPlan{}, sso.ErrUnavailable
		}
		return kernel.CapabilityPlan{}, sso.ErrForbidden
	}
	metadata := stored.Metadata
	frame, err := providerLoginPayloadEncode(metadata)
	if err != nil {
		return kernel.CapabilityPlan{}, sso.ErrForbidden
	}
	digest := sha256.Sum256(frame)
	clear(frame)
	original := metadata.Input.Command
	payload := grant.Payload()
	use := capability.Use{
		Issuer: s.payload.CapabilityIssuer, Audience: s.payload.Audience,
		Subject: original.AnonymousFlowID, Tenant: string(s.config.TenantID),
		Resource: original.RecordID, Operation: providerOIDCCallback,
		Caveats: map[string]string{"identity.sso.rp.binding": base64.RawURLEncoding.EncodeToString(digest[:])},
	}
	if len(payload.Caveats) != 1 || !payload.IssuedAt.Equal(metadata.Input.IssuedAt) || !payload.ExpiresAt.Equal(metadata.Input.ExpiresAt) || grant.Authorize(use) != nil {
		return kernel.CapabilityPlan{}, sso.ErrForbidden
	}
	plan, err := s.payload.Issuer.PrepareSSOOIDCSigninConsumption(ctx, original, proof, stored.Plan.Grant.ReplayKeyVersion)
	if err != nil {
		return kernel.CapabilityPlan{}, providerError(ctx, err)
	}
	if plan != kernel.CapabilityPlan(stored.Plan.Grant) || plan.ProofFingerprint != grant.EnvelopeDigest() {
		return kernel.CapabilityPlan{}, sso.ErrForbidden
	}
	return plan, nil
}
