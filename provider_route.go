package sso

import (
	"fmt"
	"time"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

// DomainRouteRequest locates a provider for an exact tenant and canonical DNS
// name. It selects no organization or provider authority by itself. Zero is
// invalid. Use the trusted native route boundary, not an anonymous directory.
type DomainRouteRequest struct {
	binding DomainRouteLookup
}

// DomainRouteLookup is a detached request projection. ProviderID is optional;
// when set, a failed explicit choice cannot fall back to another provider.
type DomainRouteLookup struct {
	TenantID   identity.TenantID
	Domain     string
	ProviderID ProviderID
}

// NewDomainRouteRequest validates the tenant and optional provider ID and
// normalizes only the organization owner's ASCII DNS grammar. It does not
// accept an email, URL, IP literal, suffix selector, or inferred tenant.
func NewDomainRouteRequest(tenant identity.TenantID, domain string, provider ProviderID) (DomainRouteRequest, error) {
	if !providerClaimName(string(tenant)) || provider != "" && !providerClaimName(string(provider)) {
		return DomainRouteRequest{}, ErrInvalidInput
	}
	canonical, err := organization.CanonicalDomain(domain)
	if err != nil {
		return DomainRouteRequest{}, ErrInvalidInput
	}
	return DomainRouteRequest{binding: DomainRouteLookup{TenantID: tenant, Domain: canonical, ProviderID: provider}}, nil
}

// Bindings projects the exact typed selector for native routing. A zero request
// returns ErrInvalidInput. It never derives the expected organization.
func (r DomainRouteRequest) Bindings() (DomainRouteLookup, error) {
	if r.binding.TenantID == "" {
		return DomainRouteLookup{}, ErrInvalidInput
	}
	return r.binding, nil
}

func (DomainRouteRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("sso.DomainRouteRequest(redacted)"))
}
func (DomainRouteRequest) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (DomainRouteRequest) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// DomainRouteBinding identifies the exact static provider, installed
// credential generation, configured routing policy and organization-owned
// proof seen within one bounded route operation. ObservedAt is the original
// read start, not the time the provider was selected. A native login owner
// must recheck the binding; it is not an authentication or provisioning grant.
// The enclosing DomainRoute retains the selected protocol.
type DomainRouteBinding struct {
	ProviderID           ProviderID
	ProviderVersion      uint64
	CredentialGeneration uint64
	PolicyVersion        uint64
	Proof                DomainProofCheckpoint
	ObservedAt           time.Time
	ValidUntil           time.Time
}

// DomainRoute is a native snapshot, not a public discovery response. Value is
// a copy of its provider ID; changing it invalidates the projected binding.
// Copying a route preserves the original, exclusive expiry. Zero is invalid.
type DomainRoute struct {
	Value    string
	binding  DomainRouteBinding
	protocol string
}

// NewDomainRoute selects the static OIDC protocol and validates native shape, with a maximum
// lifetime of 20 seconds from the original read start and never past proof
// expiry. It does not check the repository or establish current authority.
func NewDomainRoute(b DomainRouteBinding) (DomainRoute, error) {
	return newDomainRoute(b, "oidc")
}

// NewOAuth2DomainRoute selects the static OAuth 2.0 protocol for the same
// original bounded route evidence. It performs no I/O or authority check.
func NewOAuth2DomainRoute(b DomainRouteBinding) (DomainRoute, error) {
	return newDomainRoute(b, "oauth2")
}

func newDomainRoute(b DomainRouteBinding, protocol string) (DomainRoute, error) {
	if !providerClaimName(string(b.ProviderID)) || b.ProviderVersion == 0 || b.CredentialGeneration == 0 || b.PolicyVersion == 0 || b.Proof.validate() != nil {
		return DomainRoute{}, ErrInvalidInput
	}
	if !credentialReferenceTime(b.ObservedAt) || !credentialReferenceTime(b.ValidUntil) || !b.ValidUntil.After(b.ObservedAt) || b.ValidUntil.After(b.Proof.Key.ExpiresAt) || b.ObservedAt.Before(b.Proof.Key.ObservedAt) || b.ValidUntil.Sub(b.ObservedAt) > 20*time.Second {
		return DomainRoute{}, ErrInvalidInput
	}
	return DomainRoute{Value: string(b.ProviderID), binding: b, protocol: protocol}, nil
}

// Protocol returns the exact selected protocol, or empty for an invalid copy.
// It does not establish current routing, credential, or session authority.
func (r DomainRoute) Protocol() string {
	if _, err := r.Bindings(); err != nil {
		return ""
	}
	return r.protocol
}

// Bindings returns a detached copy for trusted native continuation, without a
// clock read, I/O, proof renewal, or non-native serialization.
func (r DomainRoute) Bindings() (DomainRouteBinding, error) {
	if r.protocol == "" || r.binding.ProviderID == "" || r.Value != string(r.binding.ProviderID) {
		return DomainRouteBinding{}, ErrInvalidInput
	}
	return r.binding, nil
}

func (DomainRoute) Format(s fmt.State, _ rune)   { _, _ = s.Write([]byte("sso.DomainRoute(redacted)")) }
func (DomainRoute) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (DomainRoute) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// SelectDomainRoute chooses an explicit provider, then a deployment-selected
// default, or an unambiguous single eligible provider. A missing explicit or
// configured preferred provider does not fall back. Route bindings must agree
// on the exact current proof, read scope and protocol. This is selection, not a proof
// check against storage. The caller cannot use a selected route as authority.
func SelectDomainRoute(request DomainRouteRequest, preferred ProviderID, choices []DomainRoute, at time.Time) (DomainRoute, error) {
	lookup, err := request.Bindings()
	if err != nil || at.IsZero() || preferred != "" && !providerClaimName(string(preferred)) {
		return DomainRoute{}, ErrInvalidInput
	}
	if len(choices) > 128 {
		return DomainRoute{}, ErrConflict
	}
	target := lookup.ProviderID
	if target == "" {
		target = preferred
	}
	seen := make(map[ProviderID]struct{}, len(choices))
	var first DomainRouteBinding
	var protocol string
	var result DomainRoute
	var eligible int
	for _, choice := range choices {
		b, err := choice.Bindings()
		if err != nil || b.Proof.Key.TenantID != lookup.TenantID || b.Proof.Key.Domain != lookup.Domain || at.Before(b.ObservedAt) || !at.Before(b.ValidUntil) {
			return DomainRoute{}, ErrForbidden
		}
		if len(seen) == 0 {
			first = b
			protocol = choice.protocol
		} else if choice.protocol != protocol || b.Proof != first.Proof || b.PolicyVersion != first.PolicyVersion || b.ObservedAt != first.ObservedAt || b.ValidUntil != first.ValidUntil {
			return DomainRoute{}, ErrForbidden
		}
		if _, duplicate := seen[b.ProviderID]; duplicate {
			return DomainRoute{}, ErrConflict
		}
		seen[b.ProviderID] = struct{}{}
		if target == "" || b.ProviderID == target {
			result = choice
			eligible++
		}
	}
	if eligible == 0 {
		return DomainRoute{}, ErrForbidden
	}
	if eligible != 1 {
		return DomainRoute{}, ErrConflict
	}
	return result, nil
}
