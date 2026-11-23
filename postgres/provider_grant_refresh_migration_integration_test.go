//go:build integration

package postgres_test

import (
	"crypto/sha256"
	"errors"
	"testing"

	identity "github.com/faustbrian/go-identity"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestProviderGrantRefreshMigrationExpandsPopulatedOAuth2Vault(t *testing.T) {
	x := newNativeOAuth2JourneyFixture(t, "restorable-vault")
	f := x.start.enable.f
	login, err := x.completion.SigninCallbackOAuth2(f.ctx, x.request)
	if err != nil || login.Completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("establish a committed pre-refresh OAuth2 grant", err)
	}
	callback := string(login.Completion.Binding.CommandID)
	const readGrant = `SELECT token_version::text, sha256(token_ciphertext) FROM sso_providers.provider_login_token_sets WHERE callback_command_id=$1`
	var version string
	var before []byte
	if err := f.pool.Raw().QueryRow(f.ctx, readGrant, callback).Scan(&version, &before); err != nil || version != "1" || len(before) != sha256.Size {
		t.Fatal("missing original generation-one encrypted custody", err)
	}
	const bump = `UPDATE sso_providers.provider_login_token_sets SET token_version=2 WHERE callback_command_id=$1`
	_, err = f.pool.Raw().Exec(f.ctx, bump, callback)
	var check *pgconn.PgError
	if !errors.As(err, &check) || check.Code != "23514" || check.ConstraintName != "provider_login_token_sets_token_version_check" {
		t.Fatal("predecessor did not enforce the expected exact version constraint", err)
	}
	fence, err := (ssopg.ProviderGrantFenceMigrationSource{Version: 355}).Load(f.ctx)
	if err != nil || len(fence) != 1 {
		t.Fatal("load the existing grant fence", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, fence[0].UpSQL()); err != nil {
		t.Fatal("install the existing grant fence", err)
	}
	steps, err := (ssopg.ProviderGrantRefreshMigrationSource{Version: 356, ValidationVersion: 357, ReceiptVersion: 358}).Load(f.ctx)
	if err != nil || len(steps) != 3 {
		t.Fatal("load the forward-only refresh history", err)
	}
	for i, step := range steps {
		if _, err := f.pool.Raw().Exec(f.ctx, step.UpSQL()); err != nil {
			t.Fatal("apply refresh schema step", i, err)
		}
		var validated bool
		err := f.pool.Raw().QueryRow(f.ctx, `SELECT convalidated FROM pg_constraint WHERE conrelid='sso_providers.provider_login_token_sets'::regclass AND conname='provider_login_token_sets_token_version_check'`).Scan(&validated)
		if err != nil || validated != (i >= 1) {
			t.Fatal("refresh validation did not remain a separate migration", i, err)
		}
	}
	var after []byte
	if err := f.pool.Raw().QueryRow(f.ctx, readGrant, callback).Scan(&version, &after); err != nil || version != "1" || string(before) != string(after) {
		t.Fatal("schema changed existing encrypted custody", err)
	}
	tx, err := f.pool.Raw().Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.ctx)
	if tag, err := tx.Exec(f.ctx, bump, callback); err != nil || tag.RowsAffected() != 1 {
		t.Fatal("expanded schema did not admit a successor for OAuth2", err)
	}
	if err := tx.Rollback(f.ctx); err != nil {
		t.Fatal("discard test-only generation change", err)
	}
}
