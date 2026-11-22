//go:build integration

package postgres_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
)

func installLoginTransactionMigration(t *testing.T, f *orgFixture) {
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
	history := append(migrationList{}, f.history...)
	for _, source := range []migrations.Source{
		ssopg.ProviderUpdateMigrationSource{Version: 321},
		ssopg.ProviderCredentialsMigrationSource{Version: 322},
		ssopg.ProviderEnableMigrationSource{Version: 323},
		ssopg.LoginTransactionMigrationSource{Version: 324},
	} {
		loaded, err := source.Load(f.ctx)
		if err != nil {
			t.Fatal("load additive login transaction migration", err)
		}
		history = append(history, loaded...)
	}
	runner, err := migrations.NewRunner(history, backend)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err = runner.Up(f.ctx); err != nil {
			t.Fatal("install or replay login transaction migration", err)
		}
	}
}

func TestNativeLoginTransactionMigrationPreservesProvidersAndEnforcesCustody(t *testing.T) {
	x := newProviderEnableFixture(t)
	f := x.f
	if enabled, err := x.service.ProviderEnable(f.ctx, x.request); err != nil || !enabled.Provider.Enabled {
		t.Fatal("establish enabled provider before schema expansion", err)
	}
	providerSnapshot := func() []byte {
		t.Helper()
		var snapshot []byte
		err := f.pool.Raw().QueryRow(f.ctx, `SELECT jsonb_build_object(
 'provider',to_jsonb(p),'credential',to_jsonb(c),
 'effects',(SELECT jsonb_agg(to_jsonb(e) ORDER BY command_id) FROM sso_providers.command_effects e),
 'credential_effects',(SELECT jsonb_agg(to_jsonb(e) ORDER BY command_id) FROM sso_providers.credential_effects e),
 'enable_receipts',(SELECT jsonb_agg(to_jsonb(e) ORDER BY command_id) FROM sso_providers.enable_receipts e)
)::text FROM sso_providers.providers p JOIN sso_providers.credentials c USING(tenant_id,organization_id,provider_id)
WHERE p.tenant_id=$1 AND p.organization_id=$2 AND p.provider_id=$3`, string(x.proof.TenantID), string(x.proof.OrganizationID), x.request.ProviderID).Scan(&snapshot)
		if err != nil {
			t.Fatal("read existing provider snapshot", err)
		}
		return snapshot
	}
	before := providerSnapshot()
	installLoginTransactionMigration(t, f)
	if !bytes.Equal(before, providerSnapshot()) {
		t.Fatal("schema expansion changed existing enabled provider data")
	}
	var logins, dispositions int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM sso_providers.login_transactions),(SELECT count(*) FROM sso_providers.provider_login_dispositions)`).Scan(&logins, &dispositions); err != nil || logins != 0 || dispositions != 0 {
		t.Fatal("migration did not create empty custody tables", logins, dispositions, err)
	}

	const columns = `tenant_id,organization_id,provider_id,provider_version,credential_generation,mapping_version,start_command_id,callback_command_id,protocol,state_key_version,state_digest,pkce_key_version,pkce_commitment,binding_envelope,verifier_envelope,issued_at,expires_at,completed_at`
	valid := []string{"$1", "$2", "$3", "3", "1", "1", "'start-1'", "'callback-1'", "'oidc'", "1", "decode(repeat('11',32),'hex')", "1", "decode(repeat('22',32),'hex')", "decode('33','hex')", "decode('44','hex')", "'2026-11-22T10:00:00Z'::timestamptz", "'2026-11-22T10:10:00Z'::timestamptz", "NULL"}
	insert := func(values []string) string {
		return "INSERT INTO sso_providers.login_transactions (" + columns + ") VALUES (" + strings.Join(values, ",") + ")"
	}
	args := []any{string(x.proof.TenantID), string(x.proof.OrganizationID), x.request.ProviderID}
	if _, err := f.pool.Raw().Exec(f.ctx, insert(valid), args...); err != nil {
		t.Fatal("valid pending encrypted transaction rejected", err)
	}

	cases := []struct {
		name, value, code string
		column            int
	}{
		{"foreign tenant", "other-tenant", "23503", 0},
		{"foreign organization", "other-organization", "23503", 1},
		{"foreign provider", "other-provider", "23503", 2},
		{"zero provider version", "0", "23514", 3},
		{"overflow provider version", "18446744073709551616", "23514", 3},
		{"zero credential generation", "0", "23514", 4},
		{"overflow credential generation", "18446744073709551616", "23514", 4},
		{"zero mapping version", "0", "23514", 5},
		{"overflow mapping version", "18446744073709551616", "23514", 5},
		{"empty start command", "''", "23514", 6},
		{"oversized start command", "repeat('s',129)", "23514", 6},
		{"empty callback command", "''", "23514", 7},
		{"oversized callback command", "repeat('c',129)", "23514", 7},
		{"same start and callback command", "'candidate-start'", "23514", 7},
		{"unsupported protocol", "'saml'", "23514", 8},
		{"zero state key", "0", "23514", 9},
		{"overflow state key", "4294967296", "23514", 9},
		{"short state digest", "decode(repeat('11',31),'hex')", "23514", 10},
		{"oversized state digest", "decode(repeat('11',33),'hex')", "23514", 10},
		{"zero PKCE key", "0", "23514", 11},
		{"overflow PKCE key", "4294967296", "23514", 11},
		{"short PKCE commitment", "decode(repeat('22',31),'hex')", "23514", 12},
		{"oversized PKCE commitment", "decode(repeat('22',33),'hex')", "23514", 12},
		{"empty binding envelope", "decode('','hex')", "23514", 13},
		{"oversized binding envelope", "decode(repeat('33',65537),'hex')", "23514", 13},
		{"missing pending verifier", "NULL", "23514", 14},
		{"empty verifier envelope", "decode('','hex')", "23514", 14},
		{"oversized verifier envelope", "decode(repeat('44',4097),'hex')", "23514", 14},
		{"infinite issuance", "'-infinity'::timestamptz", "23514", 15},
		{"infinite expiry", "'infinity'::timestamptz", "23514", 16},
		{"expiry at issuance", valid[15], "23514", 16},
		{"expiry beyond protocol lifetime", "'2026-11-22T10:10:00.000001Z'::timestamptz", "23514", 16},
		{"infinite completion", "'infinity'::timestamptz", "23514", 17},
		{"completion before issuance", "'2026-11-22T09:59:59Z'::timestamptz", "23514", 17},
		{"terminal retains verifier", "'2026-11-22T10:05:00Z'::timestamptz", "23514", 17},
		{"duplicate state custody", valid[10], "23505", 10},
		{"global duplicate start command", valid[6], "23505", 6},
		{"global duplicate callback command", valid[7], "23505", 7},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			values := append([]string(nil), valid...)
			values[6], values[7], values[10] = "'candidate-start'", "'candidate-callback'", "decode(repeat('55',32),'hex')"
			bound := append([]any(nil), args...)
			if tc.column < len(bound) {
				bound[tc.column] = tc.value
			} else {
				values[tc.column] = tc.value
			}
			_, err := f.pool.Raw().Exec(f.ctx, insert(values), bound...)
			var databaseError *pgconn.PgError
			if !errors.As(err, &databaseError) || databaseError.Code != tc.code {
				t.Fatal("invalid custody did not fail with expected database constraint", tc.code, err)
			}
		})
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE sso_providers.login_transactions SET completed_at='2026-11-22T10:11:00Z',verifier_envelope=NULL WHERE start_command_id='start-1'`); err != nil {
		t.Fatal("terminal cleanup after expiry rejected", err)
	}
	var verifierErased bool
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT verifier_envelope IS NULL FROM sso_providers.login_transactions WHERE start_command_id='start-1'`).Scan(&verifierErased); err != nil || !verifierErased {
		t.Fatal("terminal transaction retained recoverable verifier", err)
	}
	values := append([]string(nil), valid...)
	values[6], values[7], values[10] = "'maximum-start'", "'maximum-callback'", "decode(repeat('66',32),'hex')"
	values[3], values[4], values[5] = "18446744073709551615", "18446744073709551615", "18446744073709551615"
	values[9], values[11] = "4294967295", "4294967295"
	values[13], values[14] = "decode(repeat('33',65536),'hex')", "decode(repeat('44',4096),'hex')"
	if _, err := f.pool.Raw().Exec(f.ctx, insert(values), args...); err != nil {
		t.Fatal("valid maximum bounded encrypted custody rejected", err)
	}

	var effectCommand string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT command_id FROM sso_providers.command_effects WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 ORDER BY generation DESC LIMIT 1`, args...).Scan(&effectCommand); err != nil {
		t.Fatal("read existing atomic command effect", err)
	}
	const disposition = `INSERT INTO sso_providers.provider_login_dispositions (tenant_id,organization_id,provider_id,provider_version,mode,command_id,active_transaction_count,recorded_at) VALUES ($1,$2,$3,3,'drain',$4,1,'2026-11-22T10:00:00Z')`
	if _, err := f.pool.Raw().Exec(f.ctx, disposition, append(args, effectCommand)...); err != nil {
		t.Fatal("valid bounded disposition rejected", err)
	}
	t.Run("disposition foreign provider", func(t *testing.T) {
		tx, err := f.pool.Raw().Begin(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(f.ctx)
		if _, err = tx.Exec(f.ctx, `DELETE FROM sso_providers.provider_login_dispositions`); err != nil {
			t.Fatal("isolate rejected disposition from existing receipt", err)
		}
		_, err = tx.Exec(f.ctx, disposition, args[0], args[1], "other-provider", effectCommand)
		var databaseError *pgconn.PgError
		if !errors.As(err, &databaseError) || databaseError.Code != "23503" {
			t.Fatal("foreign disposition scope did not fail with the expected foreign key", err)
		}
	})
	dispositionCases := []struct{ name, from, to, code string }{
		{"zero provider version", "$3,3", "$3,0", "23514"},
		{"overflow provider version", "$3,3", "$3,18446744073709551616", "23514"},
		{"unknown mode", "'drain'", "'ignore'", "23514"},
		{"missing command effect", "$4", "'missing-effect'", "23503"},
		{"empty command", "$4", "''", "23514"},
		{"oversized command", "$4", "repeat('c',129)", "23514"},
		{"negative active count", ",$4,1,", ",$4,-1,", "23514"},
		{"oversized active count", ",$4,1,", ",$4,1000001,", "23514"},
		{"infinite recorded time", "'2026-11-22T10:00:00Z'", "'infinity'", "23514"},
	}
	for _, tc := range dispositionCases {
		t.Run(tc.name, func(t *testing.T) {
			tx, err := f.pool.Raw().Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(f.ctx)
			if _, err = tx.Exec(f.ctx, `DELETE FROM sso_providers.provider_login_dispositions`); err != nil {
				t.Fatal("isolate rejected disposition from existing receipt", err)
			}
			query := strings.Replace(disposition, tc.from, tc.to, 1)
			queryArgs := append([]any(nil), args...)
			if strings.Contains(query, "$4") {
				queryArgs = append(queryArgs, effectCommand)
			}
			_, err = tx.Exec(f.ctx, query, queryArgs...)
			var databaseError *pgconn.PgError
			if !errors.As(err, &databaseError) || databaseError.Code != tc.code {
				t.Fatal("invalid disposition did not fail with expected database constraint", tc.code, err)
			}
		})
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE sso_providers.provider_login_dispositions SET mode='revoke',active_transaction_count=1000000`); err != nil {
		t.Fatal("valid maximum revocation disposition rejected", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE sso_providers.provider_login_dispositions SET active_transaction_count=0`); err != nil {
		t.Fatal("valid empty revocation disposition rejected", err)
	}
}
