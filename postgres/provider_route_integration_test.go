//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	database "github.com/faustbrian/go-postgres"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func enableRouteFixture(t *testing.T, x providerEnableFixture, second bool) sso.ProviderID {
	t.Helper()
	request := x.request
	if second {
		registration := providerRequest(t, "https://alternate-oidc.example.com", "route-secondary-registration")
		registered, err := x.base.ProviderRegisterOidc(x.f.ctx, registration)
		if err != nil {
			t.Fatal("register second provider", err)
		}
		id := registered.Provider.ID
		credentials := nativeCredentialService(t, x.base)
		rotated, err := credentials.ProviderCredentialsRotate(x.f.ctx, nativeCredentialRequest(t, x.f, x.config, id, 1, 1))
		if err != nil || rotated.Version != 2 {
			t.Fatal("prepare second provider credential", err)
		}
		request.CredentialCheckpoint, err = x.service.ObserveProviderCredentialCheckpoint(x.f.ctx, id, 2)
		if err != nil {
			t.Fatal("observe second provider credential", err)
		}
		request.IdempotencyKey, err = identity.NewIdempotencyKey([]byte("route-secondary-enable"))
		if err != nil {
			t.Fatal(err)
		}
		request.ProviderID = id
	}
	enabled, err := x.service.ProviderEnable(x.f.ctx, request)
	if err != nil || !enabled.Provider.Enabled || enabled.Provider.Version != 3 {
		t.Fatal("enable initial provider for routing", err)
	}
	return sso.ProviderID(enabled.Provider.ID)
}

func newProviderRouter(t *testing.T, x providerEnableFixture, limit uint32, defaults ...ssopg.ProviderRouteDefault) *ssopg.ProviderRouter {
	t.Helper()
	router, err := ssopg.NewProviderRouter(x.f.pool, ssopg.ProviderRouterConfig{Clock: clock.System{}, Envelope: x.config.Envelope, MaximumDuration: 3 * time.Second, Lifetime: 8 * time.Second, PolicyVersion: 1, MaximumProviders: limit, Defaults: defaults})
	if err != nil {
		t.Fatal("configure trusted native routing", err)
	}
	return router
}

func assertRoute(t *testing.T, x providerEnableFixture, router *ssopg.ProviderRouter, domain string, explicit, want sso.ProviderID, expected error) {
	t.Helper()
	request, err := sso.NewDomainRouteRequest(x.proof.TenantID, domain, explicit)
	if err != nil {
		t.Fatal(err)
	}
	got, err := router.Route(x.f.ctx, request)
	if !errors.Is(err, expected) || got.Value != string(want) {
		t.Fatal("wrong native routing result", err)
	}
	if want == "" {
		return
	}
	b, err := got.Bindings()
	if err != nil || b.ProviderID != want || b.ProviderVersion != 3 || b.CredentialGeneration != 1 || b.PolicyVersion != 1 || b.Proof.Key != organization.DomainProofKey(x.proof) || b.ValidUntil.After(x.proof.ExpiresAt) || b.ValidUntil.Sub(b.ObservedAt) > 8*time.Second {
		t.Fatal("selected route lost native provider, credential, proof or deadline binding", err)
	}
}

func TestNativeProviderRouteSelectsCurrentProofAndDeterministicEligibleChoice(t *testing.T) {
	x := newProviderEnableFixture(t)
	router := newProviderRouter(t, x, 4)
	assertRoute(t, x, router, x.proof.Domain, "", "", sso.ErrForbidden)
	primary := enableRouteFixture(t, x, false)
	assertRoute(t, x, router, x.proof.Domain, "", primary, nil)
	assertRoute(t, x, router, "unproved.example.test", primary, "", sso.ErrForbidden)
	second := enableRouteFixture(t, x, true)
	assertRoute(t, x, router, x.proof.Domain, "", "", sso.ErrConflict)
	defaulted := newProviderRouter(t, x, 4, ssopg.ProviderRouteDefault{TenantID: x.proof.TenantID, OrganizationID: x.proof.OrganizationID, Domain: x.proof.Domain, ProviderID: second})
	assertRoute(t, x, defaulted, x.proof.Domain, "", second, nil)
	assertRoute(t, x, defaulted, x.proof.Domain, primary, primary, nil)
	assertRoute(t, x, defaulted, x.proof.Domain, "other-provider", "", sso.ErrForbidden)
	brokenDefault := newProviderRouter(t, x, 4, ssopg.ProviderRouteDefault{TenantID: x.proof.TenantID, OrganizationID: x.proof.OrganizationID, Domain: x.proof.Domain, ProviderID: "unavailable"})
	assertRoute(t, x, brokenDefault, x.proof.Domain, "", "", sso.ErrForbidden)
	limited := newProviderRouter(t, x, 1)
	assertRoute(t, x, limited, x.proof.Domain, "", "", sso.ErrConflict)
	assertRoute(t, x, limited, x.proof.Domain, primary, primary, nil)
}

func TestNativeProviderRouteRejectsForeignRevokedAndUnreadyProvider(t *testing.T) {
	x := newProviderEnableFixture(t)
	provider := enableRouteFixture(t, x, false)
	router := newProviderRouter(t, x, 4)
	foreign, err := sso.NewDomainRouteRequest("org-test-other", x.proof.Domain, provider)
	if err != nil {
		t.Fatal(err)
	}
	if route, err := router.Route(x.f.ctx, foreign); !errors.Is(err, sso.ErrForbidden) || route.Value != "" {
		t.Fatal("foreign tenant received provider route", err)
	}
	assertRoute(t, x, router, x.proof.Domain, provider, provider, nil)
	for _, generation := range []int{2, 1} {
		// Isolated storage fixture for a successor not coupled to the exact
		// enabled snapshot. No valid administration path can create this state.
		if _, err := x.f.pool.Raw().Exec(x.f.ctx, `UPDATE sso_providers.credentials SET generation=$1::numeric WHERE tenant_id=$2 AND organization_id=$3 AND provider_id=$4`, generation, string(x.proof.TenantID), string(x.proof.OrganizationID), string(provider)); err != nil {
			t.Fatal("fixture credential generation", err)
		}
		if generation == 2 {
			assertRoute(t, x, router, x.proof.Domain, provider, "", sso.ErrForbidden)
		}
	}
	assertRoute(t, x, router, x.proof.Domain, provider, provider, nil)
	revokeEnableTestProof(t, x)
	assertRoute(t, x, router, x.proof.Domain, provider, "", sso.ErrForbidden)
}

func TestNativeProviderRouteRechecksProofAfterInitialSelection(t *testing.T) {
	x := newProviderEnableFixture(t)
	provider := enableRouteFixture(t, x, false)
	pause := &enableProofPause{arrived: make(chan struct{}), resume: make(chan struct{})}
	var release sync.Once
	defer release.Do(func() { close(pause.resume) })
	pool, err := database.Connect(x.f.ctx, database.Config{DSN: x.f.dsn, MaxConns: 2, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database = x.f.database
		c.ConnConfig.Tracer = pause
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := pool.Close(ctx); err != nil {
			t.Error("close proof-race pool", err)
		}
	})
	router, err := ssopg.NewProviderRouter(pool, ssopg.ProviderRouterConfig{Clock: clock.System{}, Envelope: x.config.Envelope, MaximumDuration: 4 * time.Second, Lifetime: 8 * time.Second, PolicyVersion: 1, MaximumProviders: 4})
	if err != nil {
		t.Fatal(err)
	}
	request, err := sso.NewDomainRouteRequest(x.proof.TenantID, x.proof.Domain, provider)
	if err != nil {
		t.Fatal(err)
	}
	type reply struct {
		route sso.DomainRoute
		err   error
	}
	result := make(chan reply, 1)
	go func() {
		route, err := router.Route(x.f.ctx, request)
		result <- reply{route, err}
	}()
	select {
	case <-pause.arrived:
	case ended := <-result:
		t.Fatal("route never reached selected credential read", ended.err)
	case <-x.f.ctx.Done():
		t.Fatal("timed out awaiting selected credential read")
	}
	revokeEnableTestProof(t, x)
	release.Do(func() { close(pause.resume) })
	ended := <-result
	if !errors.Is(ended.err, sso.ErrForbidden) || ended.route.Value != "" {
		t.Fatal("routing returned a provider after the selected proof was revoked", ended.err)
	}
}
