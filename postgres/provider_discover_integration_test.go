//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

const discoveryFixtureTenant = identity.TenantID("01ARZ3NDEKTSV4RRFFQ69G5FAW")

func TestNativeProviderDiscoveryBindsResolvedTenant(t *testing.T) {
	const schema = "organization_discovery_risk"
	x := newProviderEnableFixtureForTenant(t, discoveryFixtureTenant, riskpg.DurableCounterMigrationSource{Schema: schema, Version: 318})
	provider := enableRouteFixture(t, x, false)
	discovery, err := ssopg.NewProviderDiscovery(newProviderRouter(t, x, 4), providerDiscoveryEvaluator(t, x, schema), ssopg.ProviderDiscoveryConfig{
		TenantID:       x.proof.TenantID,
		Advertisements: []ssopg.ProviderDiscoveryAdvertisement{{OrganizationID: x.proof.OrganizationID, Domain: x.proof.Domain, ProviderID: provider}},
	})
	if err != nil {
		t.Fatal(err)
	}
	peer := netip.MustParseAddr("192.0.2.83")
	for _, tenant := range []identity.TenantID{"", "01ARZ3NDEKTSV4RRFFQ69G5FAX"} {
		for _, address := range []netip.Addr{peer, {}} {
			service, err := discovery.ForTenantBrowser(tenant, address, "verified-test-browser")
			if !errors.Is(err, sso.ErrForbidden) || service != nil {
				t.Fatal("unmatched tenant received discovery authority", err)
			}
		}
	}
	if service, err := discovery.ForTenantBrowser(x.proof.TenantID, netip.Addr{}, "verified-test-browser"); !errors.Is(err, sso.ErrInvalidInput) || service != nil {
		t.Fatal("matching tenant bypassed browser validation", err)
	}
	service, err := discovery.ForTenantBrowser(x.proof.TenantID, peer, "verified-test-browser")
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := discovery.ForBrowser(peer, "verified-test-browser")
	if err != nil {
		t.Fatal("single-tenant browser binding failed", err)
	}
	want := sso.DiscoverResult{Matched: true, ProviderID: string(provider), Protocol: "oidc"}
	for _, browser := range []*sso.Service{service, legacy} {
		got, err := browser.Discover(x.f.ctx, sso.DiscoverRequest{EmailOrDomain: x.proof.Domain})
		if err != nil || got != want {
			t.Fatal("matching tenant did not discover its advertised provider", err)
		}
	}
}

func TestNativeProviderDiscoveryRejectsUnconfiguredTenantBinding(t *testing.T) {
	for _, discovery := range []*ssopg.ProviderDiscovery{nil, {}} {
		for _, tenant := range []identity.TenantID{"", discoveryFixtureTenant} {
			service, err := discovery.ForTenantBrowser(tenant, netip.MustParseAddr("192.0.2.83"), "verified-test-browser")
			if !errors.Is(err, sso.ErrInvalidInput) || service != nil {
				t.Fatal("unconfigured discovery did not preserve invalid input", err)
			}
		}
	}
}

func TestNativeProviderDiscoveryDisclosesOnlyAnAdvertisedCurrentRoute(t *testing.T) {
	const tenant = discoveryFixtureTenant
	const schema = "organization_discovery_risk"
	x := newProviderEnableFixtureForTenant(t, tenant, riskpg.DurableCounterMigrationSource{Schema: schema, Version: 318})
	provider := enableRouteFixture(t, x, false)
	router := newProviderRouter(t, x, 4)
	evaluator := providerDiscoveryEvaluator(t, x, schema)
	advertise := ssopg.ProviderDiscoveryAdvertisement{OrganizationID: x.proof.OrganizationID, Domain: x.proof.Domain, ProviderID: provider, RequiresConfirmation: true}
	config := ssopg.ProviderDiscoveryConfig{TenantID: tenant, Advertisements: []ssopg.ProviderDiscoveryAdvertisement{advertise}}
	if _, err := ssopg.NewProviderDiscovery(router, risk.Evaluator{}, config); !errors.Is(err, sso.ErrInvalidInput) {
		t.Fatal("unaudited discovery configured", err)
	}
	service := providerBrowserDiscovery(t, router, evaluator, config)
	config.Advertisements[0].ProviderID = "other-provider"
	unadvertised := providerBrowserDiscovery(t, router, evaluator, config)
	config.Advertisements[0] = advertise
	config.Advertisements[0].OrganizationID = "another-organization"
	foreign := providerBrowserDiscovery(t, router, evaluator, config)
	want := sso.DiscoverResult{Matched: true, ProviderID: string(provider), Protocol: "oidc", RequiresConfirmation: true}
	for _, input := range []string{x.proof.Domain, "missing-account@" + x.proof.Domain, "owner@" + x.proof.Domain} {
		got, err := service.Discover(x.f.ctx, sso.DiscoverRequest{EmailOrDomain: input})
		if err != nil || got != want {
			t.Fatal("current advertised provider was not matched independently of local account", err)
		}
	}
	for _, sample := range []struct {
		service *sso.Service
		input   string
	}{{service, "unproved.example.test"}, {unadvertised, x.proof.Domain}, {foreign, x.proof.Domain}} {
		got, err := sample.service.Discover(x.f.ctx, sso.DiscoverRequest{EmailOrDomain: sample.input})
		if err != nil || got != (sso.DiscoverResult{}) {
			t.Fatal("unproved or unadvertised authority leaked provider data", err)
		}
	}
	for i := 0; i < 4; i++ {
		got, err := service.Discover(x.f.ctx, sso.DiscoverRequest{EmailOrDomain: x.proof.Domain})
		if err != nil || got != want {
			t.Fatal("discovery budget expired early", err)
		}
	}
	if got, err := service.Discover(x.f.ctx, sso.DiscoverRequest{EmailOrDomain: x.proof.Domain}); !errors.Is(err, sso.ErrForbidden) || got != (sso.DiscoverResult{}) {
		t.Fatal("throttled browser still received positive discovery", err)
	}
}

func TestNativeProviderDiscoveryDoesNotRetainARevokedMatch(t *testing.T) {
	const schema = "organization_discovery_risk"
	x := newProviderEnableFixtureForTenant(t, discoveryFixtureTenant, riskpg.DurableCounterMigrationSource{Schema: schema, Version: 318})
	provider := enableRouteFixture(t, x, false)
	service := providerBrowserDiscovery(t, newProviderRouter(t, x, 4), providerDiscoveryEvaluator(t, x, schema), ssopg.ProviderDiscoveryConfig{TenantID: x.proof.TenantID, Advertisements: []ssopg.ProviderDiscoveryAdvertisement{{OrganizationID: x.proof.OrganizationID, Domain: x.proof.Domain, ProviderID: provider}}})
	request := sso.DiscoverRequest{EmailOrDomain: x.proof.Domain}
	if got, err := service.Discover(x.f.ctx, request); err != nil || !got.Matched || got.RequiresConfirmation {
		t.Fatal("precondition: configured verified provider did not match", err)
	}
	revokeEnableTestProof(t, x)
	if got, err := service.Discover(x.f.ctx, request); err != nil || got != (sso.DiscoverResult{}) {
		t.Fatal("previous discovery result survived primary proof revocation", err)
	}
}

func providerBrowserDiscovery(t *testing.T, router *ssopg.ProviderRouter, evaluator risk.Evaluator, config ssopg.ProviderDiscoveryConfig) *sso.Service {
	t.Helper()
	discovery, err := ssopg.NewProviderDiscovery(router, evaluator, config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := discovery.ForBrowser(netip.MustParseAddr("192.0.2.81"), ""); !errors.Is(err, sso.ErrInvalidInput) {
		t.Fatal("discovery accepted an absent browser binding", err)
	}
	for _, invalid := range []string{"::ffff:0.0.0.0", "::ffff:224.0.0.1", "fe80::1%untrusted"} {
		if _, err := discovery.ForBrowser(netip.MustParseAddr(invalid), "verified-test-browser"); !errors.Is(err, sso.ErrInvalidInput) {
			t.Fatal("discovery accepted invalid network binding", err)
		}
	}
	service, err := discovery.ForBrowser(netip.MustParseAddr("192.0.2.82"), "verified-test-browser")
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func providerDiscoveryEvaluator(t *testing.T, x providerEnableFixture, schema string) risk.Evaluator {
	t.Helper()
	policy, err := risk.NewSSODiscoveryPolicy(risk.PolicyConfig{Version: 1, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}, Profiles: []risk.Profile{
		{Class: risk.Authentication, Phase: risk.BeforeCredential, Dimensions: []risk.Dimension{risk.TenantDimension, risk.NetworkDimension, risk.DeviceDimension, risk.IdentifierDimension}, Window: 5 * time.Minute, Limit: 10, ThresholdAction: risk.Throttle, EvidenceTTL: 20 * time.Second, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status", "velocity"}},
		{Class: risk.CredentialMutation, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectDimension, risk.SessionDimension, risk.NetworkDimension}, Window: 15 * time.Minute, Limit: 5, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status", "velocity"}},
		{Class: risk.Privileged, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.ActorDimension, risk.ResourceDimension, risk.NetworkDimension}, Window: time.Hour, Limit: 20, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status", "velocity"}},
		{Class: risk.StateNeutralRead, Phase: risk.BeforeReturn, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectOrNetworkDimension}, Window: time.Minute, Limit: 120, ThresholdAction: risk.Throttle, EvidenceTTL: time.Minute, Unknown: risk.StepUpWithIndependentFactor, MaxCounters: 2, RequiredSignals: []string{"status", "velocity"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	key, err := risk.NewCounterDigestKey(1, bytes.Repeat([]byte{0x43}, 32))
	if err != nil {
		t.Fatal(err)
	}
	keys := []risk.CounterDigestKey{key}
	counters, err := riskpg.NewDurableCounterStore(riskpg.DurableCounterConfig{Pool: x.f.pool, Schema: schema, Namespace: "native-discovery", Policy: policy, Keys: keys, ReplayKey: bytes.Repeat([]byte{0x44}, 32), Tenants: []string{string(x.proof.TenantID)}, MaximumRecords: 64, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	wall := func() time.Time { return time.Now().UTC() }
	coordinator, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: policy, Store: counters, Clock: wall, Keys: keys, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	store, err := auditpg.New(x.f.pool.Raw(), auditpg.Config{})
	if err != nil {
		t.Fatal(err)
	}
	evaluator, err := risk.NewEvaluator(risk.EvaluatorConfig{Policy: policy, Clock: wall, Timeout: 2 * time.Second, Counters: &coordinator,
		Sources: []risk.Source{{Name: "status", Timeout: time.Second, Read: func(_ context.Context, c risk.Context) (risk.Signal, error) {
			return risk.Signal{Tenant: c.Tenant, Operation: c.Operation, Attempt: c.Attempt, Name: "status", State: risk.SignalClean, Trust: risk.ServerVerified, ObservedAt: c.Now, ExpiresAt: c.Now.Add(20 * time.Second)}, nil
		}}},
		DecisionAudit: &risk.DecisionAuditConfig{PolicyID: string(x.proof.TenantID), Timeout: time.Second, Delivery: audit.RecorderConfig{Sink: store, Mode: audit.DeliveryFailClosed}, OnLoss: func(context.Context, risk.DecisionDelivery) error { return errors.New("unexpected audit loss") }},
	})
	if err != nil {
		t.Fatal(err)
	}
	return evaluator
}
