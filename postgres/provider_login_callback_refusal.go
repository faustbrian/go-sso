package postgres

import (
	"bytes"
	"context"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

const providerLoginRefusalKind = "sso-oidc-callback-refused-v1\x00"
const providerLoginRefusalPurpose = "oidc-callback-refused-v1"

// Refusal retains only timing and original terminal correlation, never the
// provider error/body, original proof or verifier, recipient, or token material.
type providerLoginCallbackRefusal struct {
	ObservedAt, EvidenceUntil, RefusedAt time.Time
	Terminal                             []byte
}

func (p *providerLoginCallbackPhase) sealProviderLoginCallbackRefusal(ctx context.Context, generation uint64) ([]byte, error) {
	now := p.service.router.config.Clock.Now().UTC().Truncate(time.Microsecond)
	if err := p.checkOriginal(now); err != nil {
		return nil, err
	}
	aad, err := p.callbackOutputContext(generation, providerLoginRefusalPurpose)
	if err != nil {
		return nil, err
	}
	terminal, err := p.service.payload.sealProviderLoginCallbackTerminal(ctx, p.found)
	if err != nil {
		return nil, err
	}
	defer clear(terminal)
	refused := providerLoginCallbackRefusal{ObservedAt: p.found.ObservedAt, EvidenceUntil: p.authority.deadline, RefusedAt: now, Terminal: terminal}
	plain, err := providerLoginPayloadEncode(refused)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	wire, err := p.service.payload.seal(ctx, aad, plain, providerLoginCallbackCipherLimit)
	if err != nil {
		return nil, err
	}
	defer clear(wire)
	return append([]byte(providerLoginRefusalKind), wire...), nil
}

func (p *providerLoginCallbackPhase) RestoreSSOOIDCPreparationRefusal(ctx context.Context, original identity.Command, generation uint64, wire []byte) (bool, error) {
	// The kind is only a dispatch hint. The dedicated authenticated context
	// must verify before it can select any irreversible terminal action.
	sealed, marked := bytes.CutPrefix(wire, []byte(providerLoginRefusalKind))
	if !marked {
		return false, nil
	}
	if p == nil || p.service == nil || p.refusal != nil || p.execution != nil || original != p.command {
		return false, identity.ForbiddenError{}
	}
	aad, err := p.callbackOutputContext(generation, providerLoginRefusalPurpose)
	if err != nil {
		return false, err
	}
	plain, err := p.service.payload.open(ctx, aad, sealed, providerLoginCallbackCipherLimit, providerLoginCallbackPlainLimit)
	if err != nil {
		return false, err
	}
	defer clear(plain)
	var refused providerLoginCallbackRefusal
	if err := providerLoginPayloadDecode(plain, &refused); err != nil {
		clear(refused.Terminal)
		return false, err
	}
	now := p.service.router.config.Clock.Now().UTC()
	row := p.found.Row
	if refused.ObservedAt.Before(row.IssuedAt) || refused.ObservedAt.After(p.found.ObservedAt) ||
		refused.RefusedAt.Before(refused.ObservedAt) || refused.RefusedAt.After(now) || !refused.RefusedAt.Before(refused.EvidenceUntil) ||
		refused.EvidenceUntil.After(refused.ObservedAt.Add(20*time.Second)) || refused.EvidenceUntil.After(row.ExpiresAt) {
		clear(refused.Terminal)
		return false, identity.ForbiddenError{}
	}
	terminal, err := p.service.payload.openProviderLoginCallbackTerminal(ctx, row, refused.Terminal)
	if err != nil || !equalProviderLoginBindingMetadata(terminal.Metadata, p.found.Binding.Metadata) {
		clear(refused.Terminal)
		return false, identity.ForbiddenError{}
	}
	p.refusal = &refused
	return true, nil
}

func (p *providerLoginCallbackPhase) CleanupSSOOIDCPreparationRefusal(ctx context.Context, w kernel.Work) error {
	if p == nil || p.service == nil || p.refusal == nil || p.execution != nil || ctx == nil {
		return identity.ForbiddenError{}
	}
	binding, feature, _, err := w.FeatureScope(p)
	if err != nil || feature.Contributor != p.Descriptor() || feature.Operation != p.operation() || binding.TenantID != p.service.config.TenantID ||
		!validProviderLoginCallbackDispositionScope(binding, p.found, p.authority.deadline) || !p.service.payload.validProviderLoginPendingBinding(p.found.Row, p.found.Binding) {
		return identity.ForbiddenError{}
	}
	// Erasing refused custody grants no access. It may reconcile after the
	// original evidence deadline, but never extend the original RP lifetime.
	return eraseProviderLoginCallbackCustody(ctx, w, p.found, p.found.Row.ExpiresAt, p.refusal.Terminal)
}

var _ kernel.SSOOIDCPreparationRefusalContributor = (*providerLoginCallbackPhase)(nil)
