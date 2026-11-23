//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"testing"
	"time"

	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestLoginTransactionSAMLProtocolMigrationRejectsInvalidHistory(t *testing.T) {
	for _, source := range []ssopg.LoginTransactionSAMLProtocolMigrationSource{
		{Version: 0, ValidationVersion: 2},
		{Version: 1, ValidationVersion: 0},
		{Version: 2, ValidationVersion: 2},
		{Version: 2, ValidationVersion: 1},
		{Version: migrations.Version(math.MaxInt64), ValidationVersion: migrations.Version(math.MaxInt64) + 1},
		{Version: migrations.Version(math.MaxUint64), ValidationVersion: migrations.Version(math.MaxUint64)},
	} {
		if history, err := source.Load(context.Background()); !errors.Is(err, sso.ErrInvalidInput) || history != nil {
			t.Fatal("invalid version pair returned history", source, err)
		}
	}
	source := ssopg.LoginTransactionSAMLProtocolMigrationSource{Version: 329, ValidationVersion: 330}
	if history, err := source.Load(nil); !errors.Is(err, sso.ErrInvalidInput) || history != nil {
		t.Fatal("nil context returned history", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if history, err := source.Load(ctx); !errors.Is(err, context.Canceled) || history != nil {
		t.Fatal("cancellation returned partial history", err)
	}
	if history, err := (ssopg.LoginTransactionSAMLProtocolMigrationSource{
		Version: migrations.Version(math.MaxInt64) - 1, ValidationVersion: migrations.Version(math.MaxInt64),
	}).Load(context.Background()); err != nil || len(history) != 2 {
		t.Fatal("maximum supported ordered versions rejected", err)
	}
}

func TestNativeLoginTransactionSAMLProtocolMigrationPreservesPopulatedCustody(t *testing.T) {
	x := newProviderEnableFixture(t)
	f := x.f
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
		ssopg.LoginTransactionMigrationSource{Version: 324},
		ssopg.ProviderProtocolMigrationSource{Version: 325, ValidationVersion: 326},
		ssopg.LoginTransactionProtocolMigrationSource{Version: 327, ValidationVersion: 328},
	} {
		loaded, err := source.Load(f.ctx)
		if err != nil {
			t.Fatal("load installed caller-selected history", err)
		}
		history = append(history, loaded...)
	}
	apply := func() {
		t.Helper()
		runner, err := migrations.NewRunner(history, backend)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := runner.Up(f.ctx); err != nil {
			t.Fatal("apply unchanged prefix and selected additive history", err)
		}
	}
	apply()

	issuedAt := time.Date(2026, time.November, 22, 10, 0, 0, 0, time.UTC)
	completedAt := issuedAt.Add(time.Minute)
	pkceKeyVersion := int64(1)
	type custody struct {
		protocol   string
		keyVersion *int64
		commitment []byte
		verifier   []byte
		expiresAt  time.Time
		completed  *time.Time
	}
	pending := func(protocol string) custody {
		return custody{
			protocol: protocol, keyVersion: &pkceKeyVersion,
			commitment: bytes.Repeat([]byte{0x22}, 32), verifier: []byte{0x44, 0x45, 0x46},
			expiresAt: issuedAt.Add(10 * time.Minute),
		}
	}
	saml := func() custody {
		return custody{protocol: "saml", expiresAt: issuedAt.Add(5 * time.Minute)}
	}
	sequence := 0
	insert := func(command string, row custody) error {
		sequence++
		_, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO sso_providers.login_transactions
 (tenant_id,organization_id,provider_id,provider_version,credential_generation,mapping_version,
 start_command_id,callback_command_id,protocol,state_key_version,state_digest,pkce_key_version,
 pkce_commitment,binding_envelope,verifier_envelope,issued_at,expires_at,completed_at)
 VALUES ($1,$2,$3,3,1,1,$4,$5,$6,1,$7,$8,$9,$10,$11,$12,$13,$14)`,
			string(x.proof.TenantID), string(x.proof.OrganizationID), x.request.ProviderID,
			command+"-start", command+"-callback", row.protocol, bytes.Repeat([]byte{byte(sequence)}, 32),
			row.keyVersion, row.commitment, []byte{0x33, 0x34, 0x35}, row.verifier,
			issuedAt, row.expiresAt, row.completed)
		return err
	}
	for _, protocol := range []string{"oidc", "oauth2"} {
		row := pending(protocol)
		if err := insert("legacy-"+protocol+"-pending", row); err != nil {
			t.Fatal("seed existing pending PKCE custody", protocol, err)
		}
		row.completed, row.verifier = &completedAt, nil
		if err := insert("legacy-"+protocol+"-completed", row); err != nil {
			t.Fatal("seed existing completed PKCE custody", protocol, err)
		}
	}
	if err := insert("before-saml-expansion", saml()); err == nil {
		t.Fatal("predecessor schema unexpectedly accepts no-PKCE SAML custody")
	}
	snapshot := func(query string) []byte {
		t.Helper()
		var result []byte
		if err := f.pool.Raw().QueryRow(f.ctx, query).Scan(&result); err != nil {
			t.Fatal("snapshot retained custody schema or history", err)
		}
		return result
	}
	const rowsQuery = `SELECT jsonb_agg(to_jsonb(t) ORDER BY start_command_id)::text
 FROM sso_providers.login_transactions t WHERE start_command_id LIKE 'legacy-%'`
	const indexesQuery = `SELECT jsonb_agg(to_jsonb(i) ORDER BY indexrelid)::text
 FROM pg_index i WHERE indrelid='sso_providers.login_transactions'::regclass`
	// PostgreSQL 18 records NOT NULL in pg_constraint (contype='n'). These
	// two intended removals are checked separately through pg_attribute.
	const constraintsQuery = `SELECT jsonb_agg(to_jsonb(c) ORDER BY oid)::text FROM pg_constraint c
 WHERE conrelid='sso_providers.login_transactions'::regclass
 AND NOT (contype='n' AND conkey && ARRAY(SELECT attnum FROM pg_attribute
  WHERE attrelid=c.conrelid AND attname IN ('pkce_key_version','pkce_commitment')))
 AND conname NOT IN ('login_transactions_protocol_check','login_transactions_check3',
 'login_transactions_pkce_check','login_transactions_saml_lifetime_check')`
	const ledgerQuery = `SELECT jsonb_agg(to_jsonb(m) ORDER BY version)::text
 FROM public.migrations m WHERE version <= 328`
	assertPKCENullability := func(notNull bool) {
		t.Helper()
		var count int
		var matches bool
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*),bool_and(attnotnull=$1)
 FROM pg_attribute WHERE attrelid='sso_providers.login_transactions'::regclass
 AND attname IN ('pkce_key_version','pkce_commitment')`, notNull).Scan(&count, &matches); err != nil || count != 2 || !matches {
			t.Fatal("PKCE nullability differs from the selected schema phase", count, notNull, err)
		}
	}
	assertPKCENullability(true)
	beforeRows, beforeIndexes := snapshot(rowsQuery), snapshot(indexesQuery)
	beforeConstraints, beforeHistory := snapshot(constraintsQuery), snapshot(ledgerQuery)
	var beforeFile uint32
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT pg_relation_filenode('sso_providers.login_transactions'::regclass)`).Scan(&beforeFile); err != nil {
		t.Fatal("snapshot physical custody relation", err)
	}
	expansion, err := (ssopg.LoginTransactionSAMLProtocolMigrationSource{Version: 329, ValidationVersion: 330}).Load(f.ctx)
	if err != nil || len(expansion) != 2 {
		t.Fatal("load separate SAML expansion and validation", err)
	}
	for phase, migration := range expansion {
		history = append(history, migration)
		apply()
		assertPKCENullability(false)
		var constraintCount int
		var validated bool
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*),bool_and(convalidated)
 FROM pg_constraint WHERE conrelid='sso_providers.login_transactions'::regclass
 AND conname IN ('login_transactions_protocol_check','login_transactions_pkce_check','login_transactions_saml_lifetime_check')`).Scan(&constraintCount, &validated); err != nil || constraintCount != 3 || validated != (phase == 1) {
			t.Fatal("replacement checks must be enforced before their separate validation", constraintCount, validated, err)
		}
		for _, protocol := range []string{"oidc", "oauth2", "saml"} {
			row := pending(protocol)
			if protocol == "saml" {
				row = saml()
			}
			for _, completed := range []bool{false, true} {
				if completed {
					row.completed, row.verifier = &completedAt, nil
				}
				if err := insert(fmt.Sprintf("phase-%d-%s-completed-%t", phase, protocol, completed), row); err != nil {
					t.Fatal("expanded schema rejected valid protocol-specific custody", protocol, completed, err)
				}
			}
		}
		type rejection struct {
			name string
			row  custody
		}
		var rejected []rejection
		for _, completed := range []bool{false, true} {
			base := saml()
			if completed {
				base.completed = &completedAt
			}
			withKey, withCommitment, withVerifier := base, base, base
			withKey.keyVersion = &pkceKeyVersion
			withCommitment.commitment = bytes.Repeat([]byte{0x22}, 32)
			withVerifier.verifier = []byte{0x44}
			rejected = append(rejected,
				rejection{fmt.Sprintf("saml-key-completed-%t", completed), withKey},
				rejection{fmt.Sprintf("saml-commitment-completed-%t", completed), withCommitment},
				rejection{fmt.Sprintf("saml-verifier-completed-%t", completed), withVerifier})
		}
		tooLong, zeroLifetime := saml(), saml()
		tooLong.expiresAt = issuedAt.Add(5*time.Minute + time.Microsecond)
		zeroLifetime.expiresAt = issuedAt
		rejected = append(rejected, rejection{"saml-over-five-minutes", tooLong}, rejection{"saml-zero-lifetime", zeroLifetime})
		for _, protocol := range []string{"oidc", "oauth2"} {
			missingKey, missingCommitment, missingVerifier := pending(protocol), pending(protocol), pending(protocol)
			missingKey.keyVersion, missingCommitment.commitment, missingVerifier.verifier = nil, nil, nil
			terminalVerifier := pending(protocol)
			terminalVerifier.completed = &completedAt
			badKey, badCommitment, badVerifier := pending(protocol), pending(protocol), pending(protocol)
			zeroKeyVersion := int64(0)
			badKey.keyVersion, badCommitment.commitment, badVerifier.verifier = &zeroKeyVersion, []byte{0x22}, []byte{}
			for _, invalid := range []rejection{
				{"missing-key", missingKey}, {"missing-commitment", missingCommitment},
				{"missing-pending-verifier", missingVerifier}, {"terminal-verifier-retained", terminalVerifier},
				{"invalid-key-bounds", badKey}, {"invalid-commitment-bounds", badCommitment}, {"invalid-verifier-bounds", badVerifier},
			} {
				invalid.name = protocol + "-" + invalid.name
				rejected = append(rejected, invalid)
			}
		}
		unknown := pending("unknown")
		rejected = append(rejected, rejection{"unsupported-protocol", unknown})
		for _, invalid := range rejected {
			t.Run(fmt.Sprintf("phase-%d/%s", phase, invalid.name), func(t *testing.T) {
				var databaseError *pgconn.PgError
				err := insert(fmt.Sprintf("rejected-%d-%s", phase, invalid.name), invalid.row)
				if !errors.As(err, &databaseError) || databaseError.Code != "23514" {
					t.Fatal("invalid custody did not fail at an enforced CHECK", err)
				}
			})
		}
		var afterFile uint32
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT pg_relation_filenode('sso_providers.login_transactions'::regclass)`).Scan(&afterFile); err != nil {
			t.Fatal("read retained physical relation", err)
		}
		if !bytes.Equal(beforeRows, snapshot(rowsQuery)) || beforeFile != afterFile || !bytes.Equal(beforeIndexes, snapshot(indexesQuery)) {
			t.Fatal("SAML expansion rewrote existing OIDC/OAuth2 custody, physical relation, or indexes")
		}
		if !bytes.Equal(beforeConstraints, snapshot(constraintsQuery)) {
			t.Fatal("SAML expansion changed unrelated constraints")
		}
		if !bytes.Equal(beforeHistory, snapshot(ledgerQuery)) {
			t.Fatal("SAML expansion changed installed migration history")
		}
	}
	apply()
}
