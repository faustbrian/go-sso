//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

// This exercises replay storage with real provider and command ownership. It
// does not register a SAML provider or complete a browser callback or session.
func TestNativeSAMLReplayStorageReservesPairsAndRecoversOnlyExactClaims(t *testing.T) {
	f, providers, _ := newProviderFixtureWithUpdates(t, false)
	registration := providerRequest(t, "https://replay-storage.example.com", "saml-replay-storage-provider")
	registered, err := providers.ProviderRegisterOidc(f.ctx, registration)
	if err != nil || registered.Completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("populate real provider ownership before installing replay storage", err)
	}
	const tenant identity.TenantID = "org-test-basic"
	var issuer, providerBefore []byte
	err = f.pool.Raw().QueryRow(f.ctx, `SELECT issuer_digest,to_jsonb(p)::text::bytea
FROM sso_providers.providers p WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`,
		string(tenant), registration.OrganizationID, registered.Provider.ID).Scan(&issuer, &providerBefore)
	if err != nil || len(issuer) != sha256.Size {
		t.Fatal("read exact populated provider ownership", err)
	}
	history, err := (ssopg.SAMLReplayMigrationSource{Version: 390}).Load(f.ctx)
	if err != nil || len(history) != 1 {
		t.Fatal("load additive replay-member migration", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, history[0].UpSQL()); err != nil {
		t.Fatal("install replay-member migration on populated provider schema", err)
	}
	var providerAfter []byte
	err = f.pool.Raw().QueryRow(f.ctx, `SELECT to_jsonb(p)::text::bytea FROM sso_providers.providers p
WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`,
		string(tenant), registration.OrganizationID, registered.Provider.ID).Scan(&providerAfter)
	if err != nil || !bytes.Equal(providerBefore, providerAfter) {
		t.Fatal("replay migration changed existing provider ownership", err)
	}

	newClaim := func(label string) ssopg.SAMLReplayClaimForTest {
		t.Helper()
		return ssopg.SAMLReplayClaimForTest{
			Tenant: tenant, OrganizationID: registration.OrganizationID, ProviderID: registered.Provider.ID,
			IssuerDigest: [32]byte(issuer), ResponseDigest: sha256.Sum256([]byte(label + "/response")),
			AssertionDigest: sha256.Sum256([]byte(label + "/assertion")), Fingerprint: sha256.Sum256([]byte(label + "/execution")),
			CommandID:  seedProviderGrantAttemptForTest(t, f, tenant, "identity.sso.saml-acs"),
			Generation: 1, RetainUntil: time.Now().UTC().Truncate(time.Microsecond).Add(time.Hour),
		}
	}
	reserveAndCommit := func(ctx context.Context, claim ssopg.SAMLReplayClaimForTest) error {
		tx, err := f.pool.Raw().Begin(ctx)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if err := ssopg.ReserveSAMLReplayForTest(ctx, tx, claim); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	assertAbsent := func(t *testing.T, digest [32]byte) {
		t.Helper()
		var count int
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM sso_providers.saml_replay_members WHERE member_digest=$1`, digest[:]).Scan(&count); err != nil || count != 0 {
			t.Fatal("rejected pair left its previously unclaimed member durable", count, err)
		}
	}
	claim := newClaim("original")
	if err := reserveAndCommit(f.ctx, claim); err != nil {
		t.Fatal("reserve and commit both replay members", err)
	}
	assertSAMLReplayPairForTest(t, f, claim)
	if found, err := ssopg.ObserveSAMLReplayForTest(f.ctx, f.pool.Raw(), claim); err != nil || !found {
		t.Fatal("exact durable replay pair was not recoverable", found, err)
	}
	if err := reserveAndCommit(f.ctx, claim); !errors.Is(err, identity.ConflictError{}) {
		t.Fatal("exact recovery claim authorized a second replay reservation", err)
	}
	assertSAMLReplayPairForTest(t, f, claim)

	t.Run("either previously claimed role rejects the whole new pair", func(t *testing.T) {
		for _, collision := range []struct {
			name       string
			response   bool
			previousID [32]byte
		}{
			{"response-response", true, claim.ResponseDigest},
			{"assertion-assertion", false, claim.AssertionDigest},
			{"response-assertion", true, claim.AssertionDigest},
			{"assertion-response", false, claim.ResponseDigest},
		} {
			t.Run(collision.name, func(t *testing.T) {
				competing := newClaim(collision.name)
				fresh := competing.ResponseDigest
				if collision.response {
					competing.ResponseDigest = collision.previousID
					fresh = competing.AssertionDigest
				} else {
					competing.AssertionDigest = collision.previousID
				}
				tx, err := f.pool.Raw().Begin(f.ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = tx.Rollback(f.ctx) }()
				err = ssopg.ReserveSAMLReplayForTest(f.ctx, tx, competing)
				if !errors.Is(err, identity.ConflictError{}) {
					t.Fatal("previously claimed member did not reject competing pair", err)
				}
				if err := tx.Rollback(f.ctx); err != nil {
					t.Fatal("roll back denied pair", err)
				}
				assertAbsent(t, fresh)
				assertSAMLReplayPairForTest(t, f, claim)
			})
		}
	})

	t.Run("recovery binds both roles and the complete execution scope", func(t *testing.T) {
		other := newClaim("other-command")
		for _, mismatch := range []struct {
			name   string
			change func(*ssopg.SAMLReplayClaimForTest)
		}{
			{"tenant", func(c *ssopg.SAMLReplayClaimForTest) { c.Tenant = "org-test-other" }},
			{"organization", func(c *ssopg.SAMLReplayClaimForTest) { c.OrganizationID += "-other" }},
			{"provider", func(c *ssopg.SAMLReplayClaimForTest) { c.ProviderID += "-other" }},
			{"issuer", func(c *ssopg.SAMLReplayClaimForTest) { c.IssuerDigest[0] ^= 1 }},
			{"response", func(c *ssopg.SAMLReplayClaimForTest) { c.ResponseDigest[0] ^= 1 }},
			{"assertion", func(c *ssopg.SAMLReplayClaimForTest) { c.AssertionDigest[0] ^= 1 }},
			{"swapped roles", func(c *ssopg.SAMLReplayClaimForTest) {
				c.ResponseDigest, c.AssertionDigest = c.AssertionDigest, c.ResponseDigest
			}},
			{"fingerprint", func(c *ssopg.SAMLReplayClaimForTest) { c.Fingerprint[0] ^= 1 }},
			{"command", func(c *ssopg.SAMLReplayClaimForTest) { c.CommandID = other.CommandID }},
			{"generation", func(c *ssopg.SAMLReplayClaimForTest) { c.Generation++ }},
			{"retention", func(c *ssopg.SAMLReplayClaimForTest) { c.RetainUntil = c.RetainUntil.Add(time.Microsecond) }},
		} {
			t.Run(mismatch.name, func(t *testing.T) {
				changed := claim
				mismatch.change(&changed)
				if found, err := ssopg.ObserveSAMLReplayForTest(f.ctx, f.pool.Raw(), changed); err != nil || found {
					t.Fatal("nonmatching replay pair was accepted as exact recovery", found, err)
				}
			})
		}
		if found, err := ssopg.ObserveSAMLReplayForTest(f.ctx, f.pool.Raw(), other); err != nil || found {
			t.Fatal("command provenance alone was accepted as durable replay reservation", found, err)
		}
		for _, kind := range []int{1, 2} {
			tx, err := f.pool.Raw().Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(f.ctx) }()
			digest := claim.ResponseDigest
			if kind == 2 {
				digest = claim.AssertionDigest
			}
			if tag, err := tx.Exec(f.ctx, `DELETE FROM sso_providers.saml_replay_members WHERE member_digest=$1 AND member_kind=$2`, digest[:], kind); err != nil || tag.RowsAffected() != 1 {
				t.Fatal("stage one missing replay member", kind, err)
			}
			if found, err := ssopg.ObserveSAMLReplayForTest(f.ctx, tx, claim); err != nil || found {
				t.Fatal("one surviving member was accepted as a recoverable pair", kind, found, err)
			}
			if err := tx.Rollback(f.ctx); err != nil {
				t.Fatal("restore complete durable replay pair", err)
			}
		}
		for _, binding := range []struct {
			name  string
			query string
			value any
		}{
			{"fingerprint", `UPDATE sso_providers.saml_replay_members SET execution_fingerprint=$1 WHERE member_digest=$2`, other.Fingerprint[:]},
			{"generation", `UPDATE sso_providers.saml_replay_members SET execution_generation=$1 WHERE member_digest=$2`, "2"},
			{"retention", `UPDATE sso_providers.saml_replay_members SET retain_until=$1 WHERE member_digest=$2`, claim.RetainUntil.Add(time.Microsecond)},
		} {
			for _, digest := range [][32]byte{claim.ResponseDigest, claim.AssertionDigest} {
				tx, err := f.pool.Raw().Begin(f.ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = tx.Rollback(f.ctx) }()
				if tag, err := tx.Exec(f.ctx, binding.query, binding.value, digest[:]); err != nil || tag.RowsAffected() != 1 {
					t.Fatal("stage a differently bound member in the isolated fixture", binding.name, err)
				}
				if found, err := ssopg.ObserveSAMLReplayForTest(f.ctx, tx, claim); err != nil || found {
					t.Fatal("one correctly bound member concealed its differently bound partner", binding.name, found, err)
				}
				if err := tx.Rollback(f.ctx); err != nil {
					t.Fatal("restore exact member binding", err)
				}
			}
		}
		assertSAMLReplayPairForTest(t, f, claim)
	})

	t.Run("overlapping concurrent pairs have one durable winner", func(t *testing.T) {
		left, right := newClaim("race-left"), newClaim("race-right")
		right.AssertionDigest = left.ResponseDigest
		start := make(chan struct{})
		type vote struct {
			claim ssopg.SAMLReplayClaimForTest
			err   error
		}
		votes := make(chan vote, 2)
		var group sync.WaitGroup
		for _, candidate := range []ssopg.SAMLReplayClaimForTest{left, right} {
			group.Go(func() {
				ctx, cancel := context.WithTimeout(f.ctx, 5*time.Second)
				defer cancel()
				<-start
				votes <- vote{candidate, reserveAndCommit(ctx, candidate)}
			})
		}
		close(start)
		group.Wait()
		close(votes)
		var winners int
		for result := range votes {
			if result.err == nil {
				winners++
				assertSAMLReplayPairForTest(t, f, result.claim)
				continue
			}
			if !errors.Is(result.err, identity.ConflictError{}) {
				t.Fatal("overlapping pair produced unexpected storage failure", result.err)
			}
			fresh := result.claim.AssertionDigest
			if result.claim.CommandID == right.CommandID {
				fresh = right.ResponseDigest
			}
			assertAbsent(t, fresh)
		}
		if winners != 1 {
			t.Fatal("overlapping pairs did not have exactly one committed winner", winners)
		}
		var total int
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM sso_providers.saml_replay_members`).Scan(&total); err != nil || total != 4 {
			t.Fatal("original pair and sole race winner did not account for every durable member", total, err)
		}
	})

	t.Run("lost commit response recovers only the durable original pair", func(t *testing.T) {
		lostClaim := newClaim("lost-acknowledgement")
		pool, fault := providerLossPool(t, f, "INSERT INTO sso_providers.saml_replay_members")
		tx, err := pool.Raw().Begin(f.ctx)
		if err != nil {
			t.Fatal("begin isolated replay claim", err)
		}
		defer func() { _ = tx.Rollback(f.ctx) }()
		if err := ssopg.ReserveSAMLReplayForTest(f.ctx, tx, lostClaim); err != nil {
			t.Fatal("apply both members before requesting commit", err)
		}
		if err := tx.Commit(f.ctx); err == nil || !fault.seen.Load() || !fault.lost.Load() {
			t.Fatal("did not withhold the actual successful PostgreSQL commit response", err)
		}
		if found, err := ssopg.ObserveSAMLReplayForTest(f.ctx, f.pool.Raw(), lostClaim); err != nil || !found {
			t.Fatal("fresh connection could not recover the exact pair after unknown", err)
		}
		assertSAMLReplayPairForTest(t, f, lostClaim)
		for _, member := range [][32]byte{lostClaim.ResponseDigest, lostClaim.AssertionDigest} {
			retry := newClaim("different-command-after-lost-ack")
			retry.AssertionDigest = member
			if err := reserveAndCommit(f.ctx, retry); !errors.Is(err, identity.ConflictError{}) {
				t.Fatal("uncertain acknowledgement released a consumed ID", err)
			}
			assertAbsent(t, retry.ResponseDigest)
		}
	})
}

func assertSAMLReplayPairForTest(t *testing.T, f *orgFixture, claim ssopg.SAMLReplayClaimForTest) {
	t.Helper()
	command, err := base64.RawURLEncoding.Strict().DecodeString(string(claim.CommandID))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := f.pool.Raw().Query(f.ctx, `SELECT tenant_id,organization_id,provider_id,issuer_digest,member_digest,member_kind,
callback_command_id,callback_purpose,execution_fingerprint,execution_generation::text,retain_until
FROM sso_providers.saml_replay_members WHERE callback_command_id=$1 ORDER BY member_kind`, command)
	if err != nil {
		t.Fatal("query committed replay pair independently of recovery helper", err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var tenant, organization, provider, purpose, generation string
		var issuer, digest, callback, fingerprint []byte
		var kind int
		var retainUntil time.Time
		if err := rows.Scan(&tenant, &organization, &provider, &issuer, &digest, &kind, &callback, &purpose, &fingerprint, &generation, &retainUntil); err != nil {
			t.Fatal("scan durable replay member", err)
		}
		count++
		expectedDigest := claim.ResponseDigest
		if kind == 2 {
			expectedDigest = claim.AssertionDigest
		}
		if kind != count || count > 2 || tenant != string(claim.Tenant) || organization != claim.OrganizationID || provider != claim.ProviderID ||
			!bytes.Equal(issuer, claim.IssuerDigest[:]) || !bytes.Equal(digest, expectedDigest[:]) || !bytes.Equal(callback, command) ||
			purpose != "identity.sso.saml-acs" || !bytes.Equal(fingerprint, claim.Fingerprint[:]) ||
			generation != strconv.FormatUint(claim.Generation, 10) || !retainUntil.Equal(claim.RetainUntil) {
			t.Fatal("durable replay member differs from its exact role, owner or execution binding", kind)
		}
	}
	if err := rows.Err(); err != nil || count != 2 {
		t.Fatal("committed claim did not persist exactly one response and one assertion member", count, err)
	}
}
