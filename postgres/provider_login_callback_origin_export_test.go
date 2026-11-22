//go:build integration

package postgres

import (
	"context"
	"time"

	organization "github.com/faustbrian/go-organization"
)

func ReadProviderLoginCallbackOriginForTest(ctx context.Context, s *ProviderLoginService, state string, browser ProviderLoginBrowser) (organization.DomainProofKey, time.Time, error) {
	found, err := s.lookupProviderLoginCallback(ctx, state)
	if err != nil {
		return organization.DomainProofKey{}, time.Time{}, err
	}
	defer clear(found.Binding.Proof)
	flow, err := s.authenticateProviderLoginCallbackBrowser(ctx, found, browser)
	if err != nil {
		return organization.DomainProofKey{}, time.Time{}, err
	}
	origin, err := s.readProviderLoginCallbackOrigin(ctx, found, flow)
	return origin.Proof, origin.RouteObservedAt, err
}

func ObserveProviderLoginCallbackAuthorityForTest(ctx context.Context, s *ProviderLoginService, state string, browser ProviderLoginBrowser) (organization.CredentialAuthorityObservation, time.Time, error) {
	found, err := s.lookupProviderLoginCallback(ctx, state)
	if err != nil {
		return organization.CredentialAuthorityObservation{}, time.Time{}, err
	}
	defer clear(found.Binding.Proof)
	flow, err := s.authenticateProviderLoginCallbackBrowser(ctx, found, browser)
	if err != nil {
		return organization.CredentialAuthorityObservation{}, time.Time{}, err
	}
	origin, err := s.readProviderLoginCallbackOrigin(ctx, found, flow)
	if err != nil {
		return organization.CredentialAuthorityObservation{}, time.Time{}, err
	}
	authority, err := s.observeProviderLoginCallbackAuthority(ctx, found, origin)
	return authority.organization, authority.deadline, err
}
