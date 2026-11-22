//go:build integration

package postgres_test

import (
	"errors"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestNativeProviderRouteProtocolRegistryIsExplicitAndImmutable(t *testing.T) {
	x := newProviderEnableFixture(t)
	oidc := enableRouteFixture(t, x, false)
	legacy := newProviderRouter(t, x, 4)
	selected, err := legacy.WithProtocolRegistry()
	if err != nil || selected == nil || selected == legacy {
		t.Fatal("select independent migrated-registry reader without schema I/O", err)
	}
	assertRoute(t, x, legacy, x.proof.Domain, "", oidc, nil)
	assertRoute(t, x, selected, x.proof.Domain, oidc, "", sso.ErrUnavailable)

	installProviderRouteProtocolHistory(t, x.f)
	oauth := insertUnusableOAuthRouteFixture(t, x)
	assertRoute(t, x, selected, x.proof.Domain, "", oidc, nil)
	assertRoute(t, x, selected, x.proof.Domain, oidc, oidc, nil)
	assertRoute(t, x, selected, x.proof.Domain, oauth, "", sso.ErrForbidden)
	assertRoute(t, x, legacy, x.proof.Domain, oidc, oidc, nil)
	assertRoute(t, x, legacy, x.proof.Domain, "", "", sso.ErrUnavailable)

	defaulted := newProviderRouter(t, x, 4, ssopg.ProviderRouteDefault{
		TenantID: x.proof.TenantID, OrganizationID: x.proof.OrganizationID,
		Domain: x.proof.Domain, ProviderID: oauth,
	})
	defaulted, err = defaulted.WithProtocolRegistry()
	if err != nil {
		t.Fatal(err)
	}
	assertRoute(t, x, defaulted, x.proof.Domain, "", "", sso.ErrForbidden)
	assertRoute(t, x, defaulted, x.proof.Domain, oidc, oidc, nil)
}

func TestNativeProviderRouteProtocolRegistryBoundsAllProtocols(t *testing.T) {
	x := newProviderEnableFixture(t)
	oidc := enableRouteFixture(t, x, false)
	installProviderRouteProtocolHistory(t, x.f)
	oauth := insertUnusableOAuthRouteFixture(t, x)
	limited, err := newProviderRouter(t, x, 1).WithProtocolRegistry()
	if err != nil {
		t.Fatal(err)
	}
	assertRoute(t, x, limited, x.proof.Domain, "", "", sso.ErrConflict)
	assertRoute(t, x, limited, x.proof.Domain, oidc, oidc, nil)
	assertRoute(t, x, limited, x.proof.Domain, oauth, "", sso.ErrForbidden)
	if _, err := x.f.pool.Raw().Exec(x.f.ctx, `UPDATE sso_providers.providers SET enabled=false,enablement_proof=NULL,enablement_credential_generation=NULL WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`,
		string(x.proof.TenantID), string(x.proof.OrganizationID), string(oauth)); err != nil {
		t.Fatal("disable isolated foreign row", err)
	}
	assertRoute(t, x, limited, x.proof.Domain, "", "", sso.ErrConflict)
}

func TestNativeProviderRouteProtocolRegistryDoesNotSkipMalformedOIDC(t *testing.T) {
	x := newProviderEnableFixture(t)
	oidc := enableRouteFixture(t, x, false)
	installProviderRouteProtocolHistory(t, x.f)
	foreign := insertUnusableOAuthRouteFixture(t, x)
	router, err := newProviderRouter(t, x, 4).WithProtocolRegistry()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x.f.pool.Raw().Exec(x.f.ctx, `UPDATE sso_providers.providers SET protocol='oidc' WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`,
		string(x.proof.TenantID), string(x.proof.OrganizationID), string(foreign)); err != nil {
		t.Fatal("fixture malformed OIDC enablement proof", err)
	}
	assertRoute(t, x, router, x.proof.Domain, "", "", sso.ErrUnavailable)
	assertRoute(t, x, router, x.proof.Domain, foreign, "", sso.ErrUnavailable)
	assertRoute(t, x, router, x.proof.Domain, oidc, oidc, nil)

	if _, err := x.f.pool.Raw().Exec(x.f.ctx, `ALTER TABLE sso_providers.providers DROP CONSTRAINT sso_providers_protocol_check`); err != nil {
		t.Fatal("allow isolated unsupported protocol corruption", err)
	}
	if _, err := x.f.pool.Raw().Exec(x.f.ctx, `UPDATE sso_providers.providers SET protocol='unsupported' WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`,
		string(x.proof.TenantID), string(x.proof.OrganizationID), string(foreign)); err != nil {
		t.Fatal("fixture unsupported registry protocol", err)
	}
	assertRoute(t, x, router, x.proof.Domain, "", "", sso.ErrUnavailable)
	assertRoute(t, x, router, x.proof.Domain, foreign, "", sso.ErrUnavailable)
}

func TestNativeProviderRouteProtocolRegistryRejectsUnconfiguredRouter(t *testing.T) {
	for _, router := range []*ssopg.ProviderRouter{nil, {}} {
		if selected, err := router.WithProtocolRegistry(); !errors.Is(err, sso.ErrInvalidInput) || selected != nil {
			t.Fatal("unconfigured router selected protocol registry", err)
		}
	}
}

// The OAuth row deliberately has no usable enablement proof or credential.
// Routing must reject its recorded protocol before treating either as OIDC.
// Native OAuth enable/disable lifecycle proof belongs to its administration tests.
func insertUnusableOAuthRouteFixture(t *testing.T, x providerEnableFixture) sso.ProviderID {
	t.Helper()
	service, err := x.base.WithOAuthRegistration()
	if err != nil {
		t.Fatal(err)
	}
	request := providerOAuthRegistrationRequest(t, string(x.proof.OrganizationID))
	registered, err := service.ProviderRegisterOauth(x.f.ctx, request)
	if err != nil || registered.Provider.Protocol != "oauth2" || registered.Provider.Enabled {
		t.Fatal("register isolated foreign-protocol route row", err)
	}
	if _, err := x.f.pool.Raw().Exec(x.f.ctx, `UPDATE sso_providers.providers SET enabled=true,enablement_proof=$4,enablement_credential_generation=1 WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`,
		string(x.proof.TenantID), string(x.proof.OrganizationID), registered.Provider.ID, []byte{0xff}); err != nil {
		t.Fatal("fixture foreign enablement without an OIDC proof", err)
	}
	return sso.ProviderID(registered.Provider.ID)
}

func installProviderRouteProtocolHistory(t *testing.T, f *orgFixture) {
	t.Helper()
	config, err := pgx.ParseConfig(f.dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.Database = f.database
	db := stdlib.OpenDB(*config)
	defer db.Close()
	backend, err := migrationpg.New(db)
	if err != nil {
		t.Fatal(err)
	}
	history := append(migrationList(nil), f.history...)
	for _, source := range []migrations.Source{
		ssopg.ProviderUpdateMigrationSource{Version: 321},
		ssopg.ProviderCredentialsMigrationSource{Version: 322},
		ssopg.ProviderEnableMigrationSource{Version: 323},
		ssopg.ProviderProtocolMigrationSource{Version: 324, ValidationVersion: 325},
	} {
		loaded, err := source.Load(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		history = append(history, loaded...)
	}
	runner, err := migrations.NewRunner(history, backend)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := runner.Up(f.ctx); err != nil {
			t.Fatal("install additive protocol history after populated OIDC enablement", err)
		}
	}
}
