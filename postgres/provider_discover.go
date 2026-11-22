package postgres

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
	organization "github.com/faustbrian/go-organization"
	"github.com/faustbrian/go-sso"
)

// ProviderDiscoveryAdvertisement opts one exact native route into public
// discovery. A matching ID in another organization or domain is not advertised.
// This is an independently chosen startup policy, not proof or enablement.
type ProviderDiscoveryAdvertisement struct {
	OrganizationID       organization.ID
	Domain               string
	ProviderID           sso.ProviderID
	RequiresConfirmation bool
}

// ProviderDiscoveryConfig binds one tenant and up to 1,024 advertisements to
// the trusted native router. Construction copies all policy values.
type ProviderDiscoveryConfig struct {
	TenantID       identity.TenantID
	Advertisements []ProviderDiscoveryAdvertisement
}

type advertisedProvider struct {
	organization organization.ID
	domain       string
	provider     sso.ProviderID
}

// ProviderDiscovery is an opt-in, concurrent-safe factory for invocation-scoped
// discovery over the real router and counted, audited anonymous risk. It owns
// no pool lifecycle, caches, sign-in or organization management authority.
type ProviderDiscovery struct {
	router         *ProviderRouter
	admission      risk.SSODiscoveryAdmission
	tenant         identity.TenantID
	advertisements map[advertisedProvider]bool
}

func (ProviderDiscovery) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "sso.postgres.ProviderDiscovery(redacted)")
}
func (ProviderDiscovery) MarshalJSON() ([]byte, error) { return nil, sso.ErrSensitiveSerialization }
func (ProviderDiscovery) MarshalText() ([]byte, error) { return nil, sso.ErrSensitiveSerialization }

// NewProviderDiscovery snapshots explicitly advertised choices. It requires
// the selected SSO risk evaluator and a live configured router but performs no
// startup query. Routing continues to check current organization proof and
// provider state on every matched attempt.
func NewProviderDiscovery(router *ProviderRouter, evaluation risk.Evaluator, config ProviderDiscoveryConfig) (*ProviderDiscovery, error) {
	if router == nil || router.pool == nil || !providerID(string(config.TenantID)) || len(config.Advertisements) == 0 || len(config.Advertisements) > 1024 {
		return nil, sso.ErrInvalidInput
	}
	admission, err := risk.NewSSODiscoveryAdmission(evaluation)
	if err != nil {
		return nil, sso.ErrInvalidInput
	}
	entries := make(map[advertisedProvider]bool, len(config.Advertisements))
	for _, entry := range config.Advertisements {
		if !providerID(string(entry.OrganizationID)) || entry.ProviderID == "" {
			return nil, sso.ErrInvalidInput
		}
		request, err := sso.NewDomainRouteRequest(config.TenantID, entry.Domain, entry.ProviderID)
		if err != nil {
			return nil, sso.ErrInvalidInput
		}
		lookup, err := request.Bindings()
		if err != nil {
			return nil, sso.ErrInvalidInput
		}
		key := advertisedProvider{entry.OrganizationID, lookup.Domain, lookup.ProviderID}
		if _, exists := entries[key]; exists {
			return nil, sso.ErrInvalidInput
		}
		entries[key] = entry.RequiresConfirmation
	}
	return &ProviderDiscovery{router: router, admission: admission, tenant: config.TenantID, advertisements: entries}, nil
}

// ForBrowser binds server-resolved peer and browser identity. These inputs
// must come from trusted transport/protected browser custody, not query
// fields, untrusted forwarding headers or caller-selected device IDs.
func (p *ProviderDiscovery) ForBrowser(peer netip.Addr, trustedDevice string) (*sso.Service, error) {
	if p == nil || p.router == nil || !peer.IsValid() || peer.Zone() != "" || !providerID(trustedDevice) {
		return nil, sso.ErrInvalidInput
	}
	peer = peer.Unmap()
	if peer.IsUnspecified() || peer.IsMulticast() {
		return nil, sso.ErrInvalidInput
	}
	return sso.NewDiscoveryService(p.router.config.MaximumDuration, &discoveryBrowser{owner: p, network: peer.String(), device: trustedDevice})
}

type discoveryBrowser struct {
	owner           *ProviderDiscovery
	network, device string
}

func (b *discoveryBrowser) DiscoverProvider(ctx context.Context, domain string) (sso.DiscoverResult, error) {
	p := b.owner
	permit, err := p.admission.Admit(ctx, p.tenant, b.network, b.device)
	if err != nil {
		return sso.DiscoverResult{}, discoveryAdmissionError(err)
	}
	request, err := sso.NewDomainRouteRequest(p.tenant, domain, "")
	if err != nil {
		return sso.DiscoverResult{}, sso.ErrUnavailable
	}
	route, routeErr := p.router.Route(ctx, request)
	if err := permit.Check(ctx); err != nil {
		return sso.DiscoverResult{}, discoveryAdmissionError(err)
	}
	if errors.Is(routeErr, sso.ErrForbidden) || errors.Is(routeErr, sso.ErrConflict) {
		return sso.DiscoverResult{}, nil
	}
	if routeErr != nil {
		return sso.DiscoverResult{}, routeErr
	}
	binding, err := route.Bindings()
	if err != nil || binding.Proof.Key.TenantID != p.tenant || binding.Proof.Key.Domain != domain {
		return sso.DiscoverResult{}, sso.ErrUnavailable
	}
	confirmed, advertised := p.advertisements[advertisedProvider{binding.Proof.Key.OrganizationID, domain, binding.ProviderID}]
	if !advertised {
		return sso.DiscoverResult{}, nil
	}
	now := p.router.config.Clock.Now()
	if now.Before(binding.ObservedAt) || !now.Before(binding.ValidUntil) {
		return sso.DiscoverResult{}, nil
	}
	return sso.DiscoverResult{Matched: true, ProviderID: string(binding.ProviderID), Protocol: "oidc", RequiresConfirmation: confirmed}, nil
}

func discoveryAdmissionError(err error) error {
	if errors.Is(err, risk.ErrInvalidAuthenticationAdmission) || errors.Is(err, risk.ErrInvalidCounterCommand) || errors.Is(err, risk.ErrInvalidContext) {
		return sso.ErrForbidden
	}
	return err
}
