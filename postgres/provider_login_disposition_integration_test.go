//go:build integration

package postgres_test

import (
	"errors"
	"strconv"
	"testing"
	"time"

	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/jackc/pgx/v5"
)

func TestNativeProviderLoginFenceDispositionCountsOnlyLiveExactGeneration(t *testing.T) {
	x := newProviderEnableFixture(t)
	provider := enableRouteFixture(t, x, false)
	installLoginTransactionMigration(t, x.f)
	ctx := x.f.ctx
	pool := x.f.pool.Raw()
	tenant, organization, id := string(x.proof.TenantID), string(x.proof.OrganizationID), string(provider)
	const seed = `INSERT INTO sso_providers.login_transactions
 (tenant_id,organization_id,provider_id,provider_version,credential_generation,mapping_version,
 start_command_id,callback_command_id,protocol,state_key_version,state_digest,pkce_key_version,
 pkce_commitment,binding_envelope,verifier_envelope,issued_at,expires_at,completed_at)
 VALUES ($1,$2,$3,$4::numeric,1,1,$5,$6,'oidc',1,$7,1,$7,$8,$9,$10,$11,$12)`
	var now time.Time
	if err := pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal("read primary time", err)
	}
	for index, spec := range []struct {
		version string
		expires time.Time
		done    *time.Time
	}{
		{"3", now.Add(time.Minute), nil},
		{"3", now.Add(time.Minute), nil},
		{"2", now.Add(time.Minute), nil},
		{"3", now.Add(-time.Minute), nil},
		{"3", now.Add(time.Minute), &now},
	} {
		var verifier []byte
		if spec.done == nil {
			verifier = []byte{0x42}
		}
		digest := make([]byte, 32)
		digest[0] = byte(index + 1)
		suffix := strconv.Itoa(index)
		if _, err := pool.Exec(ctx, seed, tenant, organization, id, spec.version, "count-start-"+suffix, "count-callback-"+suffix, digest, []byte{0x43}, verifier, now.Add(-2*time.Minute), spec.expires, spec.done); err != nil {
			t.Fatal("seed real transaction custody", index, err)
		}
	}
	var effect string
	if err := pool.QueryRow(ctx, `SELECT command_id FROM sso_providers.command_effects WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 ORDER BY command_id LIMIT 1`, tenant, organization, id).Scan(&effect); err != nil {
		t.Fatal("read existing scoped command-effect fixture", err)
	}
	var count int32
	if err := pool.QueryRow(ctx, ssopg.ProviderLoginDispositionForTest, tenant, organization, id, "3", "drain", effect).Scan(&count); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("enabled provider acquired a disablement receipt", err)
	}
	disable, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = disable.Rollback(ctx) }()
	if _, err := disable.Exec(ctx, `UPDATE sso_providers.providers SET enabled=false,metadata_version=4,enablement_proof=NULL,enablement_credential_generation=NULL WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`, tenant, organization, id); err != nil {
		t.Fatal("advance the disabled provider predecessor", err)
	}
	if err := disable.QueryRow(ctx, ssopg.ProviderLoginDispositionForTest, tenant, "foreign-organization", id, "3", "revoke", effect).Scan(&count); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("foreign command-effect scope wrote disposition", err)
	}
	if err := disable.QueryRow(ctx, ssopg.ProviderLoginDispositionForTest, tenant, organization, id, "3", "drain", effect).Scan(&count); err != nil || count != 2 {
		t.Fatal("disposition counted the wrong active rows", count, err)
	}
	if err := disable.Commit(ctx); err != nil {
		t.Fatal("commit disposition", err)
	}
	var mode string
	if err := pool.QueryRow(ctx, `SELECT mode,active_transaction_count FROM sso_providers.provider_login_dispositions WHERE command_id=$1`, effect).Scan(&mode, &count); err != nil || mode != "drain" || count != 2 {
		t.Fatal("disposition did not retain its original count", mode, count, err)
	}
}
