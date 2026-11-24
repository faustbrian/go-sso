//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestSAMLLogoutSubjectMigrationRejectsInvalidHistory(t *testing.T) {
	for _, version := range []migrations.Version{0, migrations.Version(math.MaxInt64) + 1} {
		if history, err := (ssopg.SAMLLogoutSubjectMigrationSource{Version: version}).Load(context.Background()); !errors.Is(err, sso.ErrInvalidInput) || history != nil {
			t.Fatal("invalid version returned logout subject history", err)
		}
	}
	source := ssopg.SAMLLogoutSubjectMigrationSource{Version: 394}
	if history, err := source.Load(nil); !errors.Is(err, sso.ErrInvalidInput) || history != nil {
		t.Fatal("nil context returned logout subject history", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if history, err := source.Load(ctx); !errors.Is(err, context.Canceled) || history != nil {
		t.Fatal("cancelled source returned partial history", err)
	}
	history, err := source.Load(context.Background())
	if err != nil || len(history) != 1 || history[0].Version() != 394 || history[0].DownSQL() != "" || history[0].TransactionMode() != migrations.TransactionModeDefault {
		t.Fatal("logout subject source is not caller-versioned forward-only transactional history", err)
	}
}

func TestNativeSAMLLogoutSubjectMigrationPreservesUpstreamAndEnforcesCustody(t *testing.T) {
	x := newProviderEnableFixture(t)
	f, tenant, org, provider := x.f, x.proof.TenantID, x.proof.OrganizationID, x.request.ProviderID
	const sp, idp = "identity.sso.saml-acs", "identity.sso.saml-idp-init"
	spCommand := samlIDPMigrationCommandBytes(t, f, tenant, sp)
	idpCommand := samlIDPMigrationCommandBytes(t, f, tenant, idp)
	unusedCommand := samlIDPMigrationCommandBytes(t, f, tenant, sp)
	wrongCommand := samlIDPMigrationCommandBytes(t, f, tenant, "identity.sso.saml-idp-prepare")
	foreignCommand := samlIDPMigrationCommandBytes(t, f, identity.TenantID("foreign-tenant"), sp)
	snapshot := func() []byte {
		t.Helper()
		var raw []byte
		err := f.pool.Raw().QueryRow(f.ctx, `SELECT jsonb_build_object(
 'providers',(SELECT jsonb_agg(to_jsonb(p) ORDER BY tenant_id,organization_id,provider_id) FROM sso_providers.providers p),
 'commands',(SELECT jsonb_agg(to_jsonb(c) ORDER BY command_id) FROM identity.commands c),
 'provider_relation',pg_relation_filenode('sso_providers.providers'::regclass),
 'command_relation',pg_relation_filenode('identity.commands'::regclass),
 'history',(SELECT jsonb_agg(to_jsonb(m) ORDER BY version) FROM public.migrations m WHERE version<394)
)::text`).Scan(&raw)
		if err != nil {
			t.Fatal("snapshot populated upstream provider and command history", err)
		}
		return raw
	}
	before := snapshot()
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
	history := append(migrationList(nil), f.history...)
	for _, source := range []migrations.Source{
		ssopg.ProviderUpdateMigrationSource{Version: 321},
		ssopg.ProviderCredentialsMigrationSource{Version: 322},
		ssopg.ProviderEnableMigrationSource{Version: 323},
		ssopg.SAMLLogoutSubjectMigrationSource{Version: 394},
	} {
		loaded, err := source.Load(f.ctx)
		if err != nil {
			t.Fatal("load additive logout subject history", err)
		}
		history = append(history, loaded...)
	}
	runner, err := migrations.NewRunner(history, backend)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := runner.Up(f.ctx); err != nil {
			t.Fatal("install or replay subject history", err)
		}
	}
	if !bytes.Equal(before, snapshot()) {
		t.Fatal("logout subject expansion changed populated upstream history")
	}
	var count, indexes, foreignKeys int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT count(*) FROM sso_providers.saml_logout_subjects),
 (SELECT count(*) FROM pg_index WHERE indrelid='sso_providers.saml_logout_subjects'::regclass AND indisvalid),
 (SELECT count(*) FROM pg_constraint WHERE conrelid='sso_providers.saml_logout_subjects'::regclass AND contype='f')`).Scan(&count, &indexes, &foreignKeys); err != nil || count != 0 || indexes != 3 || foreignKeys != 2 {
		t.Fatal("schema did not install empty custody with exactly the scoped index and two native foreign keys", count, indexes, foreignKeys, err)
	}
	issued := time.Now().UTC().Truncate(time.Microsecond)
	// The original session's absolute expiry may exceed a deployment's usual
	// duration. This storage boundary must not invent a separate age policy.
	expires := issued.AddDate(5, 0, 0)
	digest, index, sealed := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), []byte("synthetic-encrypted-original-subject")
	const insert = `INSERT INTO sso_providers.saml_logout_subjects
 (tenant_id,organization_id,provider_id,user_id,session_id,family_id,issuance_command_id,issuance_purpose,issued_at,expires_at,match_key_version,subject_digest,session_index_digest,subject_envelope)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`
	valid := []any{string(tenant), string(org), provider, "linked-user", "session-sp", "family-original", spCommand, sp, issued, expires, int64(1), digest, index, sealed}
	if _, err := f.pool.Raw().Exec(f.ctx, insert, valid...); err != nil {
		t.Fatal("store original SP logout subject without requiring a session schema or user row", err)
	}
	idpRow := append([]any(nil), valid...)
	idpRow[4], idpRow[6], idpRow[7], idpRow[10], idpRow[12] = "session-idp", idpCommand, idp, int64(math.MaxUint32), nil
	if _, err := f.pool.Raw().Exec(f.ctx, insert, idpRow...); err != nil {
		t.Fatal("store IdP subject with absent original session index and maximum key version", err)
	}
	for _, tc := range []struct {
		name   string
		column int
		value  any
		state  string
	}{
		{"foreign tenant", 0, "foreign-tenant", "23503"},
		{"foreign organization", 1, "foreign-organization", "23503"},
		{"foreign provider", 2, "foreign-provider", "23503"},
		{"foreign command tenant", 6, foreignCommand, "23503"},
		{"wrong command operation", 6, wrongCommand, "23503"},
		{"unsupported operation", 7, "identity.sso.saml-idp-prepare", "23514"},
		{"short command", 6, bytes.Repeat([]byte{3}, 15), "23514"},
		{"empty session", 4, "", "23514"},
		{"long session", 4, strings.Repeat("s", 129), "23514"},
		{"empty family", 5, "", "23514"},
		{"long family", 5, strings.Repeat("f", 129), "23514"},
		{"zero key", 10, int64(0), "23514"},
		{"overflow key", 10, int64(math.MaxUint32) + 1, "23514"},
		{"short subject digest", 11, bytes.Repeat([]byte{1}, 31), "23514"},
		{"short optional index", 12, bytes.Repeat([]byte{2}, 31), "23514"},
		{"empty envelope", 13, []byte{}, "23514"},
		{"oversized envelope", 13, bytes.Repeat([]byte{3}, 65537), "23514"},
		{"nonfinite issue", 8, pgtype.Timestamptz{Valid: true, InfinityModifier: pgtype.NegativeInfinity}, "23514"},
		{"nonfinite expiry", 9, pgtype.Timestamptz{Valid: true, InfinityModifier: pgtype.Infinity}, "23514"},
		{"equal expiry", 9, issued, "23514"},
		{"earlier expiry", 9, issued.Add(-time.Microsecond), "23514"},
		{"duplicate session", 4, "session-sp", "23505"},
		{"duplicate issuance", 6, spCommand, "23505"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row := append([]any(nil), valid...)
			row[4], row[6] = "constraint-target", unusedCommand
			row[tc.column] = tc.value
			_, err := f.pool.Raw().Exec(f.ctx, insert, row...)
			assertSAMLIDPStorageSQLState(t, tc.state, err)
		})
	}
	var unchanged, absent bool
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT subject_envelope=$2 AND subject_digest=$3 AND session_index_digest=$4 AND issued_at=$5 AND expires_at=$6
 FROM sso_providers.saml_logout_subjects WHERE tenant_id=$1 AND session_id='session-sp'),
 (SELECT session_index_digest IS NULL FROM sso_providers.saml_logout_subjects WHERE tenant_id=$1 AND session_id='session-idp')`,
		string(tenant), sealed, digest, index, issued, expires).Scan(&unchanged, &absent); err != nil || !unchanged || !absent {
		t.Fatal("constraint failures replaced original custody or invented absent index", err)
	}
}
