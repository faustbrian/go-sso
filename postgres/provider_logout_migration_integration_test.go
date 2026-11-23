//go:build integration

package postgres_test

import (
	"bytes"
	"errors"
	"testing"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
)

func installProviderLogoutMigration(t *testing.T, f *orgFixture) {
	t.Helper()
	configuration, err := pgx.ParseConfig(f.dsn)
	if err != nil {
		t.Fatal(err)
	}
	configuration.Database = f.database
	db := stdlib.OpenDB(*configuration)
	defer db.Close()
	backend, err := migrationpg.New(db)
	if err != nil {
		t.Fatal(err)
	}
	addition, err := (ssopg.ProviderLogoutMigrationSource{Version: 360}).Load(f.ctx)
	if err != nil {
		t.Fatal("load additive logout custody migration", err)
	}
	history := append(append(migrationList(nil), f.history...), addition...)
	runner, err := migrations.NewRunner(history, backend)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := runner.Up(f.ctx); err != nil {
			t.Fatal("install or replay additive logout custody migration", err)
		}
	}
}

func TestNativeProviderLogoutMigrationPreservesHistoryAndEnforcesCustody(t *testing.T) {
	f, service, _ := newProviderFixtureWithUpdates(t, false)
	registered, err := service.ProviderRegisterOidc(f.ctx, providerRequest(t, "https://logout.example.test", "logout-migration-provider"))
	if err != nil || registered.Completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("seed a real registered provider before the additive migration", err)
	}
	snapshot := func() []byte {
		t.Helper()
		var state []byte
		err := f.pool.Raw().QueryRow(f.ctx, `SELECT jsonb_build_object(
 'providers',(SELECT jsonb_agg(to_jsonb(p) ORDER BY tenant_id,organization_id,provider_id) FROM sso_providers.providers p),
 'effects',(SELECT jsonb_agg(to_jsonb(e) ORDER BY command_id) FROM sso_providers.command_effects e),
 'commands',(SELECT jsonb_agg(to_jsonb(c) ORDER BY tenant_id,purpose,command_id) FROM identity.commands c),
 'claims',(SELECT jsonb_agg(to_jsonb(c) ORDER BY command_id) FROM identity.identity_command_id_claims c),
 'history',(SELECT jsonb_agg(to_jsonb(m) ORDER BY version) FROM public.migrations m WHERE version<360),
 'provider_relation',pg_relation_filenode('sso_providers.providers'::regclass)
)::text`).Scan(&state)
		if err != nil {
			t.Fatal("snapshot existing provider, command provenance and migration history", err)
		}
		return state
	}
	before := snapshot()
	installProviderLogoutMigration(t, f)
	if !bytes.Equal(before, snapshot()) {
		t.Fatal("logout migration or replay changed existing provider data, command provenance or migration history")
	}
	var count int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM sso_providers.logout_transactions`).Scan(&count); err != nil || count != 0 {
		t.Fatal("logout migration did not create empty custody", count, err)
	}

	// These rows exercise the actual native claim/journal foreign keys, without
	// claiming that a normal caller can manufacture command authority.
	for _, command := range []struct{ hex, tenant, purpose string }{
		{"11", "org-test-basic", "identity.sso.oidc-logout"},
		{"22", "org-test-basic", "identity.sso.oidc-logout"},
		{"33", "org-test-basic", "identity.sso.oidc-logout-complete"},
		{"44", "org-test-basic", "identity.sso.oidc-logout"},
		{"55", "org-test-other", "identity.sso.oidc-logout-complete"},
		{"66", "org-test-basic", "identity.sso.oidc-logout-complete"},
		{"77", "org-test-other", "identity.sso.oidc-logout"},
	} {
		if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields)
 VALUES(decode(repeat($1,16),'hex'),$2,$3,decode(repeat('01',32),'hex'),1,decode('01','hex'))`, command.hex, command.tenant, command.purpose); err != nil {
			t.Fatal("seed native command claim", err)
		}
		if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES(decode(repeat($1,16),'hex'),$2,$3)`, command.hex, command.tenant, command.purpose); err != nil {
			t.Fatal("seed native command journal", err)
		}
	}
	for _, hex := range []string{"11", "22"} {
		if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO sso_providers.logout_transactions
 (tenant_id,state_key_version,state_digest,start_command_id,issued_at,expires_at,binding_envelope)
 VALUES('org-test-basic',1,decode(repeat($1,32),'hex'),decode(repeat($1,16),'hex'),'2026-11-23T10:00:00Z','2026-11-23T10:10:00Z',decode('01','hex'))`, hex); err != nil {
			t.Fatal("valid pending encrypted logout custody rejected", err)
		}
	}

	const terminal = `completed_at='2026-11-23T10:11:00Z',completion_command_id=decode(repeat('33',16),'hex'),completion_kind='provider_complete'`
	cases := []struct{ name, assignment, code string }{
		{"empty tenant", `tenant_id=''`, "23514"},
		{"oversized tenant", `tenant_id=repeat('t',129)`, "23514"},
		{"foreign start tenant", `start_command_id=decode(repeat('77',16),'hex')`, "23503"},
		{"foreign start purpose", `start_command_id=decode(repeat('66',16),'hex')`, "23503"},
		{"unknown start command", `start_command_id=decode(repeat('88',16),'hex')`, "23503"},
		{"short start command", `start_command_id=decode(repeat('22',15),'hex')`, "23514"},
		{"long start command", `start_command_id=decode(repeat('22',17),'hex')`, "23514"},
		{"wrong start purpose", `start_purpose='identity.sso.oidc-logout-complete'`, "23514"},
		{"zero state key", `state_key_version=0`, "23514"},
		{"overflow state key", `state_key_version=4294967296`, "23514"},
		{"short digest", `state_digest=decode(repeat('22',31),'hex')`, "23514"},
		{"long digest", `state_digest=decode(repeat('22',33),'hex')`, "23514"},
		{"empty envelope", `binding_envelope=decode('','hex')`, "23514"},
		{"oversized envelope", `binding_envelope=decode(repeat('01',65537),'hex')`, "23514"},
		{"infinite issuance", `issued_at='-infinity'`, "23514"},
		{"infinite expiry", `expires_at='infinity'`, "23514"},
		{"expiry at issuance", `expires_at=issued_at`, "23514"},
		{"expiry beyond ten minutes", `expires_at=issued_at+interval '10 minutes 1 microsecond'`, "23514"},
		{"completion timestamp alone", `completed_at=issued_at`, "23514"},
		{"completion command alone", `completion_command_id=decode(repeat('33',16),'hex')`, "23514"},
		{"completion kind alone", `completion_kind='provider_error'`, "23514"},
		{"missing completion timestamp", `completion_command_id=decode(repeat('33',16),'hex'),completion_kind='timeout'`, "23514"},
		{"missing completion command", `completed_at=issued_at,completion_kind='timeout'`, "23514"},
		{"missing completion kind", `completed_at=issued_at,completion_command_id=decode(repeat('33',16),'hex')`, "23514"},
		{"infinite completion", `completed_at='infinity',completion_command_id=decode(repeat('33',16),'hex'),completion_kind='timeout'`, "23514"},
		{"completion before issuance", `completed_at=issued_at-interval '1 microsecond',completion_command_id=decode(repeat('33',16),'hex'),completion_kind='timeout'`, "23514"},
		{"short completion command", `completed_at=issued_at,completion_command_id=decode(repeat('33',15),'hex'),completion_kind='timeout'`, "23514"},
		{"long completion command", `completed_at=issued_at,completion_command_id=decode(repeat('33',17),'hex'),completion_kind='timeout'`, "23514"},
		{"same start and completion command", `completed_at=issued_at,completion_command_id=start_command_id,completion_kind='timeout'`, "23514"},
		{"wrong completion purpose", terminal + `,completion_purpose='identity.sso.oidc-logout'`, "23514"},
		{"foreign completion tenant", `completed_at=issued_at,completion_command_id=decode(repeat('55',16),'hex'),completion_kind='timeout'`, "23503"},
		{"foreign completion purpose", `completed_at=issued_at,completion_command_id=decode(repeat('44',16),'hex'),completion_kind='timeout'`, "23503"},
		{"unknown completion command", `completed_at=issued_at,completion_command_id=decode(repeat('88',16),'hex'),completion_kind='timeout'`, "23503"},
		{"unknown completion kind", `completed_at=issued_at,completion_command_id=decode(repeat('33',16),'hex'),completion_kind='unknown'`, "23514"},
		{"duplicate state custody", `state_digest=decode(repeat('11',32),'hex')`, "23505"},
		{"duplicate start command", `start_command_id=decode(repeat('11',16),'hex')`, "23505"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := f.pool.Raw().Exec(f.ctx, `UPDATE sso_providers.logout_transactions SET `+tc.assignment+` WHERE state_digest=decode(repeat('22',32),'hex')`)
			var databaseError *pgconn.PgError
			if !errors.As(err, &databaseError) || databaseError.Code != tc.code {
				t.Fatal("invalid logout custody did not fail at the expected database constraint", tc.code, err)
			}
		})
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE sso_providers.logout_transactions SET state_key_version=4294967295,binding_envelope=decode(repeat('01',65536),'hex') WHERE state_digest=decode(repeat('22',32),'hex')`); err != nil {
		t.Fatal("maximum bounded key and opaque envelope rejected", err)
	}
	for _, kind := range []string{"provider_complete", "provider_error", "timeout"} {
		if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE sso_providers.logout_transactions SET completed_at=issued_at,completion_command_id=decode(repeat('33',16),'hex'),completion_kind=$1 WHERE state_digest=decode(repeat('11',32),'hex')`, kind); err != nil {
			t.Fatal("valid typed terminal outcome at issuance rejected", kind, err)
		}
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE sso_providers.logout_transactions SET completed_at='2026-11-23T10:11:00Z' WHERE state_digest=decode(repeat('11',32),'hex')`); err != nil {
		t.Fatal("terminal reconciliation after expiry rejected", err)
	}
	_, err = f.pool.Raw().Exec(f.ctx, `UPDATE sso_providers.logout_transactions SET `+terminal+` WHERE state_digest=decode(repeat('22',32),'hex')`)
	var databaseError *pgconn.PgError
	if !errors.As(err, &databaseError) || databaseError.Code != "23505" {
		t.Fatal("one native completion command was allowed to consume two logout transactions", err)
	}
}
