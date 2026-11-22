package postgres

import (
	"context"
	"time"

	organization "github.com/faustbrian/go-organization"
	"github.com/faustbrian/go-sso"
)

type providerLoginCallbackAuthority struct {
	organization organization.CredentialAuthorityObservation
	deadline     time.Time
}

// Reobserve the exact original proof, not the original routing lease. Domain
// writers advance the organization version under its lock; callback Work must
// fence this version before relying on the proof. This actorless read grants
// neither selected-user membership authority nor permission to exchange.
func (s *ProviderLoginService) observeProviderLoginCallbackAuthority(ctx context.Context, found providerLoginCallbackLookup, original providerLoginStartInput) (providerLoginCallbackAuthority, error) {
	if s == nil || s.router == nil || s.router.organizations == nil || ctx == nil || found.CompletedAt != nil || found.ObservedAt.IsZero() {
		return providerLoginCallbackAuthority{}, sso.ErrForbidden
	}
	proof := original.Proof
	if proof.TenantID != found.Row.TenantID || proof.TenantID != s.config.TenantID || string(proof.OrganizationID) != found.Row.OrganizationID ||
		original.Command.CommandID != found.Row.StartCommandID || original.RoutePolicy != s.router.config.PolicyVersion ||
		!original.Expires.Equal(found.Row.ExpiresAt) {
		return providerLoginCallbackAuthority{}, sso.ErrForbidden
	}
	deadline := earlierLoginTime(found.ObservedAt.Add(20*time.Second), original.Expires)
	deadline = earlierLoginTime(deadline, proof.ExpiresAt)
	if !s.router.config.Clock.Now().Before(deadline) {
		return providerLoginCallbackAuthority{}, sso.ErrForbidden
	}
	ctx, cancel := context.WithTimeout(ctx, s.config.Coordinator.MaximumDuration)
	defer cancel()
	directory, err := s.directory.GetDirectoryAuthority(ctx, s.directoryQuery())
	if err != nil {
		return providerLoginCallbackAuthority{}, providerError(ctx, err)
	}
	if !directory.Enabled || directory.GlobalVersion != original.GlobalVersion || directory.TenantVersion != original.TenantVersion {
		return providerLoginCallbackAuthority{}, sso.ErrForbidden
	}
	owner, err := s.router.organizations.ObserveCredentialAuthority(ctx, organization.CredentialAuthorityQuery{TenantID: proof.TenantID, OrganizationID: proof.OrganizationID})
	if err != nil {
		return providerLoginCallbackAuthority{}, providerError(ctx, err)
	}
	current, err := s.router.organizations.GetDomainProof(ctx, proof)
	if err != nil {
		return providerLoginCallbackAuthority{}, providerError(ctx, err)
	}
	deadline = earlierLoginTime(deadline, owner.ValidUntil.UTC().Truncate(time.Microsecond))
	if current != organization.DomainProof(proof) || !s.router.config.Clock.Now().Before(deadline) {
		return providerLoginCallbackAuthority{}, sso.ErrForbidden
	}
	if err := ctx.Err(); err != nil {
		return providerLoginCallbackAuthority{}, err
	}
	return providerLoginCallbackAuthority{organization: owner, deadline: deadline}, nil
}
