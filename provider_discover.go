package sso

import (
	"context"
	"errors"
	"time"
)

// DiscoveryOwner is the trusted adapter boundary for public discovery. The
// owner binds startup and server invocation scope, performs abuse admission,
// checks current domain/provider authority, and returns only an opted-in
// public projection. It receives the canonical domain, never an account hint.
// Use the provided native adapter for durable authority.
type DiscoveryOwner interface {
	DiscoverProvider(context.Context, string) (DiscoverResult, error)
}

type discoveryWorkflow struct {
	owner   DiscoveryOwner
	timeout time.Duration
}

// NewDiscoveryService selects only public SSO discovery. It borrows the
// trusted owner and does no I/O. The owner must honor the bounded operation
// context; the service returns no result after cancellation or expiry.
func NewDiscoveryService(timeout time.Duration, owner DiscoveryOwner) (*Service, error) {
	if owner == nil || timeout <= 0 || timeout > 5*time.Second {
		return nil, ErrInvalidInput
	}
	return &Service{discovery: &discoveryWorkflow{owner: owner, timeout: timeout}}, nil
}

// Discover looks up only the canonical domain after discarding any email
// local part. Its public result grants no authentication or sign-in authority.
// Unsupported workflows, canceled operations and unsafe owner output yield no
// partial result. A successful no-match has no provider or organization data.
func (s *Service) Discover(ctx context.Context, request DiscoverRequest) (out DiscoverResult, err error) {
	if ctx == nil {
		return DiscoverResult{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return DiscoverResult{}, err
	}
	if s == nil || s.discovery == nil {
		return DiscoverResult{}, ErrUnavailable
	}
	domain, err := discoveryDomain(request)
	if err != nil {
		return DiscoverResult{}, err
	}
	bounded, cancel := context.WithTimeout(ctx, s.discovery.timeout)
	defer cancel()
	defer func() {
		if recover() != nil {
			out, err = DiscoverResult{}, ErrUnavailable
		}
	}()
	result, err := s.discovery.owner.DiscoverProvider(bounded, domain)
	if err := bounded.Err(); err != nil {
		return DiscoverResult{}, err
	}
	if errors.Is(err, ErrForbidden) {
		return DiscoverResult{}, ErrForbidden
	}
	if err != nil || !validPublicDiscoveryResult(result) {
		return DiscoverResult{}, ErrUnavailable
	}
	return result, nil
}

func validPublicDiscoveryResult(result DiscoverResult) bool {
	if !result.Matched {
		return result == (DiscoverResult{})
	}
	return providerClaimName(result.ProviderID) && result.Protocol == "oidc"
}
