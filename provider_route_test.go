package sso_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	organization "github.com/faustbrian/go-organization"
	"github.com/faustbrian/go-sso"
)

var routeTime = time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)

func routeBinding(provider sso.ProviderID) sso.DomainRouteBinding {
	proof := organization.DomainProofKey{TenantID: "tenant-a", OrganizationID: "org-a", ClaimID: "claim-a", Domain: "example.test", ClaimVersion: 1, ProofVersion: 1, Method: organization.DomainDNS, ObservedAt: routeTime.Add(-time.Minute), ExpiresAt: routeTime.Add(time.Minute)}
	return sso.DomainRouteBinding{ProviderID: provider, ProviderVersion: 3, CredentialGeneration: 1, PolicyVersion: 7, Proof: sso.DomainProofCheckpoint{Key: proof, ProofVersion: 1}, ObservedAt: routeTime, ValidUntil: routeTime.Add(5 * time.Second)}
}

func makeRoute(t *testing.T, provider sso.ProviderID) sso.DomainRoute {
	t.Helper()
	route, err := sso.NewDomainRoute(routeBinding(provider))
	if err != nil {
		t.Fatal(err)
	}
	return route
}

func TestDomainRouteRequestCanonicalizesOnlyExactDNSName(t *testing.T) {
	r, err := sso.NewDomainRouteRequest("tenant-a", "EXAMPLE.Test.", "provider-a")
	if err != nil {
		t.Fatal(err)
	}
	b, err := r.Bindings()
	if err != nil || b.TenantID != "tenant-a" || b.Domain != "example.test" || b.ProviderID != "provider-a" {
		t.Fatalf("unexpected scope: %v", err)
	}
	for _, input := range []string{"user@example.test", "*.example.test", " example.test", "https://example.test", "127.0.0.1", "éxample.test"} {
		if _, err = sso.NewDomainRouteRequest("tenant-a", input, ""); !errors.Is(err, sso.ErrInvalidInput) {
			t.Fatalf("non-domain input accepted: %q", input)
		}
	}
	if _, err = sso.NewDomainRouteRequest("", "example.test", "provider-a"); !errors.Is(err, sso.ErrInvalidInput) {
		t.Fatal("absent tenant accepted")
	}
	if strings.Contains(fmt.Sprintf("%#v", r), "example.test") {
		t.Fatal("route request leaked its lookup scope")
	}
}

func TestDomainRouteSelectionRequiresExplicitDefaultOrOneExactEligibleChoice(t *testing.T) {
	a, b := makeRoute(t, "provider-a"), makeRoute(t, "provider-b")
	for _, tc := range []struct {
		name               string
		explicit, fallback sso.ProviderID
		choices            []sso.DomainRoute
		want               sso.ProviderID
		err                error
	}{
		{"unique", "", "", []sso.DomainRoute{a}, "provider-a", nil},
		{"ambiguous", "", "", []sso.DomainRoute{a, b}, "", sso.ErrConflict},
		{"default", "", "provider-b", []sso.DomainRoute{a, b}, "provider-b", nil},
		{"explicit overrides default", "provider-a", "provider-b", []sso.DomainRoute{b, a}, "provider-a", nil},
		{"default not eligible", "", "provider-b", []sso.DomainRoute{a}, "", sso.ErrForbidden},
		{"explicit not eligible", "provider-b", "provider-a", []sso.DomainRoute{a}, "", sso.ErrForbidden},
		{"duplicate route", "provider-a", "", []sso.DomainRoute{a, a}, "", sso.ErrConflict},
		{"no route", "", "", nil, "", sso.ErrForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request, err := sso.NewDomainRouteRequest("tenant-a", "example.test", tc.explicit)
			if err != nil {
				t.Fatal(err)
			}
			got, err := sso.SelectDomainRoute(request, tc.fallback, tc.choices, routeTime)
			if !errors.Is(err, tc.err) || got.Value != string(tc.want) {
				t.Fatalf("wrong selected route or outcome: %v", err)
			}
		})
	}
	request, _ := sso.NewDomainRouteRequest("other-tenant", "example.test", "provider-a")
	if got, err := sso.SelectDomainRoute(request, "", []sso.DomainRoute{a}, routeTime); !errors.Is(err, sso.ErrForbidden) || got.Value != "" {
		t.Fatal("cross-tenant candidate was selected")
	}
}

func TestDomainRouteSnapshotNeverRenewsOrDisclosesRawProof(t *testing.T) {
	a := makeRoute(t, "provider-a")
	request, _ := sso.NewDomainRouteRequest("tenant-a", "example.test", "")
	if _, err := sso.SelectDomainRoute(request, "", []sso.DomainRoute{a}, routeTime.Add(5*time.Second)); !errors.Is(err, sso.ErrForbidden) {
		t.Fatal("expiration was not exclusive")
	}
	if _, err := sso.SelectDomainRoute(request, "", []sso.DomainRoute{a}, routeTime.Add(-time.Microsecond)); !errors.Is(err, sso.ErrForbidden) {
		t.Fatal("future observation was used")
	}
	wrong := routeBinding("provider-a")
	wrong.ValidUntil = routeTime.Add(21 * time.Second)
	if _, err := sso.NewDomainRoute(wrong); !errors.Is(err, sso.ErrInvalidInput) {
		t.Fatal("longer than 20-second routing evidence accepted")
	}
	wrong = routeBinding("provider-a")
	wrong.Proof.Key.ExpiresAt = routeTime.Add(time.Second)
	if _, err := sso.NewDomainRoute(wrong); !errors.Is(err, sso.ErrInvalidInput) {
		t.Fatal("snapshot outlives proof")
	}
	if _, err := json.Marshal(a); !errors.Is(err, sso.ErrSensitiveSerialization) {
		t.Fatal("native route accepted implicit serialization")
	}
	if strings.Contains(fmt.Sprintf("%#v", a), "claim-a") {
		t.Fatal("native route logged raw proof")
	}
	a.Value = "provider-b"
	if _, err := a.Bindings(); !errors.Is(err, sso.ErrInvalidInput) {
		t.Fatal("copied display value changed route binding")
	}
}

func TestDomainRouteRetainsProtocolAndRejectsMixedChoices(t *testing.T) {
	binding := routeBinding("oauth-provider")
	oauth, err := sso.NewOAuth2DomainRoute(binding)
	if err != nil || oauth.Protocol() != "oauth2" {
		t.Fatal("OAuth route lost its explicit protocol", err)
	}
	got, err := oauth.Bindings()
	if err != nil || got != binding {
		t.Fatal("OAuth route changed the exact original evidence", err)
	}
	oidc := makeRoute(t, "oidc-provider")
	request, _ := sso.NewDomainRouteRequest("tenant-a", "example.test", binding.ProviderID)
	if selected, err := sso.SelectDomainRoute(request, "", []sso.DomainRoute{oauth}, routeTime); err != nil || selected != oauth || oidc.Protocol() != "oidc" {
		t.Fatal("selection reclassified a protocol", err)
	}
	if selected, err := sso.SelectDomainRoute(request, "", []sso.DomainRoute{oauth, oidc}, routeTime); !errors.Is(err, sso.ErrForbidden) || selected.Protocol() != "" {
		t.Fatal("mixed evidence entered a single protocol selection", err)
	}
	oauth.Value = "oidc-provider"
	if oauth.Protocol() != "" {
		t.Fatal("modified route exposed apparently valid protocol evidence")
	}
}

func TestSAMLDomainRoutePreservesExactEvidenceAndNeverFallsBack(t *testing.T) {
	binding := routeBinding("saml-provider")
	saml, err := sso.NewSAMLDomainRoute(binding)
	if err != nil || saml.Protocol() != "saml" {
		t.Fatal("SAML route lost its distinct protocol", err)
	}
	if got, err := saml.Bindings(); err != nil || got != binding {
		t.Fatal("SAML route changed the exact original evidence", err)
	}
	request, err := sso.NewDomainRouteRequest("tenant-a", "example.test", binding.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := sso.SelectDomainRoute(request, "unrelated-default", []sso.DomainRoute{saml}, routeTime); err != nil || got != saml {
		t.Fatal("exact selection did not preserve the SAML route", err)
	}
	oidc := makeRoute(t, "oidc-provider")
	if got, err := sso.SelectDomainRoute(request, "oidc-provider", []sso.DomainRoute{oidc}, routeTime); !errors.Is(err, sso.ErrForbidden) || got.Protocol() != "" {
		t.Fatal("a missing explicit SAML provider fell back to an OIDC default", err)
	}
	if got, err := sso.SelectDomainRoute(request, "", []sso.DomainRoute{saml, oidc}, routeTime); !errors.Is(err, sso.ErrForbidden) || got.Protocol() != "" {
		t.Fatal("different protocols were mixed in one route selection", err)
	}
	if got, err := sso.SelectDomainRoute(request, "", []sso.DomainRoute{saml}, binding.ValidUntil); !errors.Is(err, sso.ErrForbidden) || got.Protocol() != "" {
		t.Fatal("route reached its original exclusive cutoff without denial", err)
	}
	binding.ValidUntil = binding.ObservedAt.Add(20*time.Second + time.Microsecond)
	if _, err := sso.NewSAMLDomainRoute(binding); !errors.Is(err, sso.ErrInvalidInput) {
		t.Fatal("SAML route accepted more than twenty seconds of evidence", err)
	}
}

func FuzzDomainRouteRequest(f *testing.F) {
	for _, domain := range []string{"EXAMPLE.Test.", "*.example.test", "user@example.test", "127.0.0.1", "a.test"} {
		f.Add(domain)
	}
	f.Fuzz(func(t *testing.T, domain string) {
		route, err := sso.NewDomainRouteRequest("tenant-a", domain, "provider-a")
		if err != nil {
			if !errors.Is(err, sso.ErrInvalidInput) {
				t.Fatal("unexpected error category", err)
			}
			return
		}
		binding, err := route.Bindings()
		if err != nil || binding.TenantID != "tenant-a" || binding.ProviderID != "provider-a" {
			t.Fatal("route changed its tenant or explicit provider", err)
		}
		canonical, err := organization.CanonicalDomain(binding.Domain)
		if err != nil || canonical != binding.Domain {
			t.Fatal("route emitted a noncanonical domain", err)
		}
	})
}
