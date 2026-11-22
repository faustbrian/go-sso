package sso

import (
	"context"
	"errors"
	"testing"
	"time"

	organization "github.com/faustbrian/go-organization"
)

type discoveryOwnerFunc func(context.Context, string) (DiscoverResult, error)

func (f discoveryOwnerFunc) DiscoverProvider(ctx context.Context, domain string) (DiscoverResult, error) {
	return f(ctx, domain)
}

func TestDiscoverUsesCanonicalDomainOnly(t *testing.T) {
	want := DiscoverResult{Matched: true, ProviderID: "static-oidc", Protocol: "oidc", RequiresConfirmation: true}
	calls := 0
	s, err := NewDiscoveryService(time.Second, discoveryOwnerFunc(func(ctx context.Context, domain string) (DiscoverResult, error) {
		if _, bounded := ctx.Deadline(); !bounded || domain != "example.test" {
			t.Fatal("discovery owner did not receive only bounded canonical domain")
		}
		calls++
		return want, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	for _, request := range []DiscoverRequest{{"EXAMPLE.test."}, {"unknown+alias@EXAMPLE.test"}, {"known@EXAMPLE.test"}} {
		got, err := s.Discover(context.Background(), request)
		if err != nil || got != want {
			t.Fatal("account names affected a domain-only match", err)
		}
	}
	if got, err := s.Discover(context.Background(), DiscoverRequest{"display name <user@EXAMPLE.test>"}); got != (DiscoverResult{}) || !errors.Is(err, ErrInvalidInput) || calls != 3 {
		t.Fatal("malformed input reached authority", err)
	}
	if _, err := s.GetDomainProof(context.Background(), organization.DomainProofKey{OrganizationID: "org", ClaimID: "claim"}); err == nil {
		t.Fatal("public discovery instance acquired domain-management authority")
	}
}

func TestDiscoverWithholdsInvalidOrFailedOwnerResponses(t *testing.T) {
	for _, item := range []struct {
		name     string
		owner    DiscoverResult
		ownerErr error
		wantErr  error
	}{
		{"no match", DiscoverResult{}, nil, nil},
		{"no match with a hint", DiscoverResult{ProviderID: "private"}, nil, ErrUnavailable},
		{"invalid provider", DiscoverResult{Matched: true, ProviderID: "private provider", Protocol: "oidc"}, nil, ErrUnavailable},
		{"unsupported protocol", DiscoverResult{Matched: true, ProviderID: "provider", Protocol: "private"}, nil, ErrUnavailable},
		{"denied", DiscoverResult{Matched: true, ProviderID: "provider", Protocol: "oidc"}, ErrForbidden, ErrForbidden},
		{"private error", DiscoverResult{Matched: true, ProviderID: "provider", Protocol: "oidc"}, errors.New("unsafe storage details"), ErrUnavailable},
	} {
		t.Run(item.name, func(t *testing.T) {
			s, err := NewDiscoveryService(time.Second, discoveryOwnerFunc(func(context.Context, string) (DiscoverResult, error) { return item.owner, item.ownerErr }))
			if err != nil {
				t.Fatal(err)
			}
			got, err := s.Discover(context.Background(), DiscoverRequest{"example.test"})
			if got != (DiscoverResult{}) || err != item.wantErr {
				t.Fatal("owner returned a partial response or private failure", err)
			}
		})
	}
	if _, err := new(Service).Discover(context.Background(), DiscoverRequest{"example.test"}); err != ErrUnavailable {
		t.Fatal("unconfigured discovery did not fail closed", err)
	}
	if _, err := NewDiscoveryService(0, nil); err != ErrInvalidInput {
		t.Fatal("unbounded discovery owner admitted", err)
	}
}

func TestDiscoverDiscardsPositiveResultAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, err := NewDiscoveryService(time.Second, discoveryOwnerFunc(func(context.Context, string) (DiscoverResult, error) {
		cancel()
		return DiscoverResult{Matched: true, ProviderID: "provider", Protocol: "oidc"}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.Discover(ctx, DiscoverRequest{"example.test"}); got != (DiscoverResult{}) || err != context.Canceled {
		t.Fatal("late positive result was disclosed", err)
	}
}
