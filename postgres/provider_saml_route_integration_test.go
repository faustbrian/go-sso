//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestNativeSAMLProviderRouteRequiresSelectedCurrentSignerAndExactProvider(t *testing.T) {
	x := newProviderSAMLActivationFixture(t)
	enabled, err := x.service.ProviderEnable(x.f.ctx, x.request)
	if err != nil || enabled.Completion.Outcome != identity.CommitOutcomeCommitted || !enabled.Provider.Enabled || enabled.Provider.Protocol != "saml" || enabled.Provider.Version != 3 {
		t.Fatal("activate the installed SAML provider before routing", err)
	}
	provider := sso.ProviderID(enabled.Provider.ID)
	request, err := sso.NewDomainRouteRequest(x.proof.TenantID, x.proof.Domain, provider)
	if err != nil {
		t.Fatal(err)
	}
	observedAt := time.Now().UTC().Truncate(time.Microsecond)
	certificateExpiry := observedAt.Add(2 * time.Second)
	config := ssopg.ProviderRouterConfig{
		Clock: fixedClock{at: observedAt}, Envelope: x.config.Envelope,
		MaximumDuration: 3 * time.Second, Lifetime: 8 * time.Second,
		PolicyVersion: 1, MaximumProviders: 4,
		Defaults: []ssopg.ProviderRouteDefault{{TenantID: x.proof.TenantID,
			OrganizationID: x.proof.OrganizationID, Domain: x.proof.Domain, ProviderID: provider}},
	}
	legacy, err := ssopg.NewProviderRouter(x.f.pool, config)
	if err != nil {
		t.Fatal(err)
	}
	protocolAware, err := legacy.WithProtocolRegistry()
	if err != nil || protocolAware == legacy {
		t.Fatal("select an independent protocol-aware router", err)
	}
	expectedSigner := bytes.Repeat([]byte("fixture-activation-SP-signing/"), 2)
	defer clear(expectedSigner)
	var validationInstants []time.Time
	validate := sso.SAMLSigningCredentialValidator(func(ctx context.Context, bundle []byte, at time.Time) (time.Time, error) {
		if _, bounded := ctx.Deadline(); !bounded || ctx.Err() != nil || !bytes.Equal(bundle, expectedSigner) {
			t.Error("route validator did not receive bounded access to the installed signer")
			return time.Time{}, sso.ErrInvalidInput
		}
		validationInstants = append(validationInstants, at)
		return certificateExpiry, nil
	})
	router, err := protocolAware.WithSAMLRouteValidation(validate)
	if err != nil || router == nil || router == protocolAware {
		t.Fatal("select SAML route validation on an independent router", err)
	}

	for _, unselected := range []*ssopg.ProviderRouter{legacy, protocolAware} {
		if route, err := unselected.RouteSAML(x.f.ctx, request); !errors.Is(err, sso.ErrForbidden) || route.Value != "" {
			t.Fatal("SAML opt-in changed an unselected router", err)
		}
	}
	for _, sibling := range []struct {
		name string
		call func(context.Context, sso.DomainRouteRequest) (sso.DomainRoute, error)
	}{{"oidc", router.Route}, {"oauth2", router.RouteOAuth2}} {
		t.Run("reject-"+sibling.name+"-route", func(t *testing.T) {
			if route, err := sibling.call(x.f.ctx, request); !errors.Is(err, sso.ErrForbidden) || route.Value != "" {
				t.Fatal("sibling route selected an enabled SAML provider", err)
			}
		})
	}
	for _, explicit := range []sso.ProviderID{"", "missing-saml-provider"} {
		missing, err := sso.NewDomainRouteRequest(x.proof.TenantID, x.proof.Domain, explicit)
		if err != nil {
			t.Fatal(err)
		}
		if route, err := router.RouteSAML(x.f.ctx, missing); !errors.Is(err, sso.ErrForbidden) || route.Value != "" {
			t.Fatal("SAML route fell back without an existing explicit provider", err)
		}
	}

	route, err := router.RouteSAML(x.f.ctx, request)
	if err != nil || route.Value != string(provider) || route.Protocol() != "saml" {
		t.Fatal("route the exact installed active SAML provider", err)
	}
	binding, err := route.Bindings()
	wantProof := sso.DomainProofCheckpoint{Key: organization.DomainProofKey(x.proof), ProofVersion: x.proof.ProofVersion}
	if err != nil || binding.ProviderID != provider || binding.ProviderVersion != enabled.Provider.Version || binding.CredentialGeneration != 1 ||
		binding.PolicyVersion != config.PolicyVersion || binding.Proof != wantProof || binding.ObservedAt != observedAt || binding.ValidUntil != certificateExpiry ||
		!binding.ValidUntil.Before(observedAt.Add(config.Lifetime)) {
		t.Fatal("SAML route lost the original proof, signer generation or exclusive certificate cutoff", err)
	}
	if len(validationInstants) == 0 {
		t.Fatal("SAML route did not validate the installed signing credential")
	}
	for _, at := range validationInstants {
		if at != observedAt {
			t.Fatal("SAML route renewed its original credential observation")
		}
	}
	if _, err := sso.SelectDomainRoute(request, provider, []sso.DomainRoute{route}, certificateExpiry.Add(-time.Microsecond)); err != nil {
		t.Fatal("SAML route expired before the exclusive certificate cutoff", err)
	}
	if retained, err := sso.SelectDomainRoute(request, provider, []sso.DomainRoute{route}, certificateExpiry); !errors.Is(err, sso.ErrForbidden) || retained.Value != "" {
		t.Fatal("retained SAML route remained usable at its exclusive certificate cutoff", err)
	}

	failed, err := protocolAware.WithSAMLRouteValidation(func(context.Context, []byte, time.Time) (time.Time, error) {
		return time.Time{}, sso.ErrUnavailable
	})
	if err != nil {
		t.Fatal(err)
	}
	if route, err := failed.RouteSAML(x.f.ctx, request); !errors.Is(err, sso.ErrForbidden) || route.Value != "" {
		t.Fatal("SAML route survived signing validator failure", err)
	}
	config.Clock = fixedClock{at: certificateExpiry}
	expired, err := ssopg.NewProviderRouter(x.f.pool, config)
	if err != nil {
		t.Fatal(err)
	}
	expired, err = expired.WithProtocolRegistry()
	if err != nil {
		t.Fatal(err)
	}
	expired, err = expired.WithSAMLRouteValidation(validate)
	if err != nil {
		t.Fatal(err)
	}
	if route, err := expired.RouteSAML(x.f.ctx, request); !errors.Is(err, sso.ErrForbidden) || route.Value != "" {
		t.Fatal("new SAML route accepted the signer at its exclusive certificate expiry", err)
	}

	disposition, err := sso.NewActiveTransactionDisposition(provider, enabled.Provider.Version, sso.ActiveTransactionRevoke)
	if err != nil {
		t.Fatal(err)
	}
	disabled, err := x.service.ProviderDisableSAML(x.f.ctx, sso.ProviderDisableRequest{
		ProviderID: string(provider), ExpectedVersion: enabled.Provider.Version,
		Reason: "Stop routing new SAML sign-ins", ActiveTransactionDisposition: disposition,
	})
	if err != nil || disabled.Completion.Outcome != identity.CommitOutcomeCommitted || !disabled.Disabled {
		t.Fatal("disable SAML through its native lifecycle before routing again", err)
	}
	if route, err := router.RouteSAML(x.f.ctx, request); !errors.Is(err, sso.ErrForbidden) || route.Value != "" {
		t.Fatal("SAML route ignored native provider disablement", err)
	}
	currentProof, err := x.config.Organizations.GetDomainProof(x.f.ctx, organization.DomainProofKey(x.proof))
	if err != nil || currentProof != x.proof {
		t.Fatal("route denial replaced the organization-owned proof", err)
	}
}
