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
	metadata := stored.Metadata
	_, purposeText := providerLoginCryptoProtocol(found.Row.Protocol)
	if purposeText == "" || metadata.Input.Protocol != found.Row.Protocol ||
		metadata.Input.validate() != nil || found.Row != metadata.Input.rowIdentity() ||
		(found.Row.Protocol != "" && metadata.Input.Link != nil) {
		return kernel.CapabilityPlan{}, sso.ErrForbidden
	}
	purpose := capability.Purpose(purposeText)
	proof, err := capability.ParseProof(string(stored.Proof), s.callbackLimits)
	if err != nil {
		return kernel.CapabilityPlan{}, sso.ErrForbidden
	}
	defer func() {
		_ = proof.Transfer(context.WithoutCancel(ctx), func(context.Context, []byte) error { return nil })
	}()
	grant, err := s.callbackVerifier.Verify(ctx, proof, purpose, s.payload.Audience)
	if err != nil {
		if ctx.Err() != nil {
			return kernel.CapabilityPlan{}, ctx.Err()
		}
		if errors.Is(err, capability.ErrInvalidConfiguration) || errors.Is(err, capability.ErrKeyResolution) || errors.Is(err, capability.ErrRevocationUnknown) {
			return kernel.CapabilityPlan{}, sso.ErrUnavailable
		}
		return kernel.CapabilityPlan{}, sso.ErrForbidden
	}
	frame, err := providerLoginPayloadEncode(metadata)
	if err != nil {
		return kernel.CapabilityPlan{}, sso.ErrForbidden
	}
	digest := sha256.Sum256(frame)
	clear(frame)
	original := metadata.Input.Command
	payload := grant.Payload()
	subject := original.AnonymousFlowID
	prepare := s.payload.Issuer.PrepareSSOOIDCSigninConsumption
	switch found.Row.Protocol {
	case providerProtocolOAuth2:
		prepare = s.payload.Issuer.PrepareSSOOAuth2SigninConsumption
	case providerProtocolSAML:
		prepare = s.payload.Issuer.PrepareSSOSAMLSigninConsumption
	case "":
		if metadata.Input.Link != nil {
			subject = string(original.UserID)
			prepare = s.payload.Issuer.PrepareSSOOIDCExplicitLinkConsumption
		}
	default:
		return kernel.CapabilityPlan{}, sso.ErrForbidden
	}
	use := capability.Use{
		Issuer: s.payload.CapabilityIssuer, Audience: s.payload.Audience,
		Subject: subject, Tenant: string(s.config.TenantID),
		Resource: original.RecordID, Operation: purposeText,
		Caveats: map[string]string{"identity.sso.rp.binding": base64.RawURLEncoding.EncodeToString(digest[:])},
	}
	if len(payload.Caveats) != 1 || !payload.IssuedAt.Equal(metadata.Input.IssuedAt) || !payload.ExpiresAt.Equal(metadata.Input.ExpiresAt) || grant.Authorize(use) != nil {
		return kernel.CapabilityPlan{}, sso.ErrForbidden
	}
	plan, err := prepare(ctx, original, proof, stored.Plan.Grant.ReplayKeyVersion)
	if err != nil {
		return kernel.CapabilityPlan{}, providerError(ctx, err)
	}
	if plan != kernel.CapabilityPlan(stored.Plan.Grant) || plan.ProofFingerprint != grant.EnvelopeDigest() {
		return kernel.CapabilityPlan{}, sso.ErrForbidden
	}
	return plan, nil
}
