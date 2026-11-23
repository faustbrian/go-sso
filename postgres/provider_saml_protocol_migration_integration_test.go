//go:build integration

package postgres_test

import (
	"errors"
	"reflect"
	"testing"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestNativeSAMLProviderProtocolExpandsPopulatedRegistry(t *testing.T) {
	f, legacy, _ := newProviderFixture(t)
	request := providerRequest(t, "https://existing-oidc.example.com", "existing-oidc-before-saml-migration")
	oidc, err := legacy.ProviderRegisterOidc(f.ctx, request)
	if err != nil || oidc.Completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("seed genuine OIDC provider", err)
	}
	installProviderProtocolHistory(t, f)
	mixed, err := legacy.WithOAuthRegistration()
	if err != nil {
		t.Fatal("select currently supported mixed reader", err)
	}
	oauth, err := mixed.ProviderRegisterOauth(f.ctx, providerOAuthRegistrationRequest(t, request.OrganizationID))
	if err != nil || oauth.Completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("seed genuine OAuth2 provider", err)
	}
	var fileBefore uint32
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT pg_relation_filenode('sso_providers.providers')`).Scan(&fileBefore); err != nil || fileBefore == 0 {
		t.Fatal("read original provider storage identity", err)
	}

	probe := func(protocol string, wantValid bool) {
		t.Helper()
		// A rolled-back discriminator update tests the CHECK only. This never
		// installs an actual provider or permits routing an existing OAuth row.
		tx, err := f.pool.Raw().Begin(f.ctx)
		if err != nil {
			t.Fatal("begin isolated discriminator probe", err)
		}
		defer tx.Rollback(f.ctx)
		tag, err := tx.Exec(f.ctx, `UPDATE sso_providers.providers SET protocol=$1 WHERE tenant_id=$2 AND organization_id=$3 AND provider_id=$4`, protocol, "org-test-basic", request.OrganizationID, oauth.Provider.ID)
		if wantValid {
			if err != nil || tag.RowsAffected() != 1 {
				t.Fatal("expanded schema did not accept exact selected discriminator", err)
			}
			return
		}
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23514" || pgErr.ConstraintName != "sso_providers_protocol_check" {
			t.Fatal("closed schema did not reject unsupported discriminator", err)
		}
	}
	probe("saml", false)

	previousUpdates, err := (ssopg.ProviderUpdateMigrationSource{Version: 321}).Load(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	previousProtocols, err := (ssopg.ProviderProtocolMigrationSource{Version: 322, ValidationVersion: 323}).Load(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	added, err := (ssopg.ProviderSAMLProtocolMigrationSource{Version: 324, ValidationVersion: 325}).Load(f.ctx)
	if err != nil || len(added) != 2 {
		t.Fatal("load forward SAML history", err)
	}
	history := append(migrationList(nil), f.history...)
	history = append(history, previousUpdates...)
	history = append(history, previousProtocols...)
	cfg, err := pgx.ParseConfig(f.dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Database = f.database
	db := stdlib.OpenDB(*cfg)
	defer db.Close()
	backend, err := migrationpg.New(db)
	if err != nil {
		t.Fatal(err)
	}
	for index, migration := range added {
		history = append(history, migration)
		runner, err := migrations.NewRunner(history, backend)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := runner.Up(f.ctx); err != nil {
			t.Fatal("apply SAML provider schema phase", index, err)
		}
		var validated bool
		var fileAfter uint32
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT convalidated,pg_relation_filenode(conrelid) FROM pg_constraint WHERE conrelid='sso_providers.providers'::regclass AND conname='sso_providers_protocol_check'`).Scan(&validated, &fileAfter); err != nil || validated != (index == 1) || fileAfter != fileBefore {
			t.Fatal("schema transition rewrote provider rows or skipped separate validation", index, err)
		}
		probe("saml", true)
		probe("unexpected", false)
		for _, original := range []sso.Provider{oidc.Provider, oauth.Provider} {
			got, err := mixed.ProviderGet(f.ctx, sso.ProviderGetRequest{OrganizationID: original.OrganizationID, ProviderID: sso.ProviderID(original.ID)})
			if err != nil || !reflect.DeepEqual(got.Provider, original) {
				t.Fatal("existing provider metadata changed during expansion", err)
			}
		}
	}
}
