//go:build integration

package postgres_test

import (
	"context"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestNativeProviderGrantFenceSerializesRestoredGrantAcrossOperations(t *testing.T) {
	x := newNativeOAuth2JourneyFixture(t, "restorable-vault")
	f := x.start.enable.f
	result, err := x.completion.SigninCallbackOAuth2(f.ctx, x.request)
	if err != nil || result.Completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("commit original enterprise grant", err)
	}
	history, err := (ssopg.ProviderGrantFenceMigrationSource{Version: 355}).Load(f.ctx)
	if err != nil || len(history) != 1 {
		t.Fatal("load exact additive grant fence", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, history[0].UpSQL()); err != nil {
		t.Fatal("install additive grant fence on populated callback history", err)
	}
	tenant, callback := result.Completion.Binding.TenantID, result.Completion.Binding.CommandID
	var digest []byte
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT sha256(token_ciphertext) FROM sso_providers.provider_login_token_sets
WHERE tenant_id=$1 AND callback_command_id=$2`, string(tenant), string(callback)).Scan(&digest); err != nil || len(digest) != 32 {
		t.Fatal("read exact committed grant fingerprint", err)
	}
	newClaim := func(purpose string) ssopg.ProviderGrantFenceClaimForTest {
		return ssopg.ProviderGrantFenceClaimForTest{
			Tenant: tenant, Callback: callback, TokenVersion: 1, CiphertextDigest: [32]byte(digest),
			Attempt: seedProviderGrantAttemptForTest(t, f, tenant, purpose), Operation: purpose, Generation: 1,
		}
	}
	revoke := newClaim("identity.sso.provider-token.revoke")
	alternateRevoke := newClaim("identity.sso.provider-token.revoke")
	refresh := newClaim("identity.sso.provider-token.refresh")
	wrongDigest, wrongVersion := revoke, revoke
	wrongDigest.CiphertextDigest[0] ^= 1
	wrongVersion.TokenVersion++
	for _, mismatch := range []ssopg.ProviderGrantFenceClaimForTest{wrongDigest, wrongVersion} {
		if err := ssopg.ClaimProviderGrantFenceForTest(f.ctx, f.pool.Raw(), mismatch); !errors.Is(err, identity.ConflictError{}) {
			t.Fatal("changed custody or generation obtained the provider-attempt fence", err)
		}
	}

	start := make(chan struct{})
	type vote struct {
		claim ssopg.ProviderGrantFenceClaimForTest
		err   error
	}
	claims := []ssopg.ProviderGrantFenceClaimForTest{revoke, revoke, alternateRevoke, refresh}
	votes := make(chan vote, len(claims))
	var group sync.WaitGroup
	for _, claim := range claims {
		group.Go(func() {
			ctx, cancel := context.WithTimeout(f.ctx, 5*time.Second)
			defer cancel()
			<-start
			votes <- vote{claim, ssopg.ClaimProviderGrantFenceForTest(ctx, f.pool.Raw(), claim)}
		})
	}
	close(start)
	group.Wait()
	close(votes)
	var winners int
	var winner ssopg.ProviderGrantFenceClaimForTest
	for result := range votes {
		switch {
		case result.err == nil:
			winners++
			winner = result.claim
		case errors.Is(result.err, identity.ConflictError{}):
		default:
			t.Fatal("competing grant attempt produced an unexpected outcome", result.err)
		}
	}
	if winners != 1 {
		t.Fatalf("wanted one acknowledged attempt across competing commands, got %d", winners)
	}
	if err := ssopg.ClaimProviderGrantFenceForTest(f.ctx, f.pool.Raw(), winner); !errors.Is(err, identity.ConflictError{}) {
		t.Fatal("historical acknowledgement authorized a second attempt", err)
	}

	var command []byte
	var operation string
	var generation uint64
	err = f.pool.Raw().QueryRow(f.ctx, `SELECT f.attempt_command_id,f.attempt_purpose,f.attempt_generation::text::bigint
FROM sso_providers.provider_grant_fences f JOIN sso_providers.provider_login_token_sets v
 ON v.tenant_id=f.tenant_id AND v.origin_command_id=f.grant_command_id AND v.token_version=f.token_version
WHERE v.tenant_id=$1 AND v.callback_command_id=$2`, string(tenant), string(callback)).Scan(&command, &operation, &generation)
	if err != nil || base64.RawURLEncoding.EncodeToString(command) != string(winner.Attempt) || operation != winner.Operation || generation != winner.Generation ||
		x.posts.Load() != 1 || x.identities.Load() != 1 {
		t.Fatal("durable grant fence did not retain the sole winning command without touching provider custody", err)
	}
}

func seedProviderGrantAttemptForTest(t *testing.T, f *orgFixture, tenant identity.TenantID, purpose string) identity.CommandID {
	t.Helper()
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	wire, err := base64.RawURLEncoding.Strict().DecodeString(string(id))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `WITH claim AS (
 INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields)
 VALUES($1,$2,$3,sha256($1),1,decode('01','hex')) RETURNING command_id,tenant_id,purpose
) INSERT INTO identity.commands(command_id,tenant_id,purpose) SELECT command_id,tenant_id,purpose FROM claim`, wire, string(tenant), purpose); err != nil {
		t.Fatal("seed distinct native command provenance for storage-only test", err)
	}
	return id
}
