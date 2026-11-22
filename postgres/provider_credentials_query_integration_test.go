//go:build integration

package postgres_test

import (
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-sso"
)

// Cost-only synthetic rows retain no semantic authority. Measurements replay
// captured native Work SQL/OIDs and ordinary pgx binding types without printing
// bytea/context arguments, against 100k skewed providers and credential/effect
// rows. Every mutating EXPLAIN runs in an isolated rollback-only transaction.
func TestNativeProviderCredentialsQueryScale(t *testing.T) {
	f, base, config := newProviderFixture(t)
	created, err := base.ProviderRegisterOidc(f.ctx, providerRequest(t, "https://credentials-scale.example.com", "credentials-scale-registration"))
	if err != nil {
		t.Fatal(err)
	}
	installProviderCredentials(t, f)
	trace := new(providerTrace)
	base = tracedProviderService(t, f, config, trace)
	base, _ = base.ForOrganization(created.Provider.OrganizationID)
	service := nativeCredentialService(t, base)
	first := nativeCredentialRequest(t, f, config, created.Provider.ID, 1, 1)
	if _, err = service.ProviderCredentialsRotate(f.ctx, first); err != nil {
		t.Fatal(err)
	}
	populateProviderQueryRows(t, f, created.Provider.ID)
	if _, err = f.pool.Raw().Exec(f.ctx, `INSERT INTO sso_providers.credentials(tenant_id,organization_id,provider_id,generation,provider_version,envelope,credential_context) SELECT p.tenant_id,p.organization_id,p.provider_id,c.generation,c.provider_version,c.envelope,c.credential_context FROM sso_providers.providers p CROSS JOIN sso_providers.credentials c WHERE p.provider_id LIKE 'scale-%' AND c.provider_id=$1`, created.Provider.ID); err != nil {
		t.Fatal("cost-only credential population", err)
	}
	if _, err = f.pool.Raw().Exec(f.ctx, `INSERT INTO sso_providers.credential_effects(command_id,tenant_id,organization_id,provider_id,binding,fingerprint,generation) SELECT 'scale-credential-'||p.provider_id,p.tenant_id,p.organization_id,p.provider_id,e.binding,e.fingerprint,1 FROM sso_providers.providers p CROSS JOIN sso_providers.credential_effects e WHERE p.provider_id LIKE 'scale-%' AND e.provider_id=$1`, created.Provider.ID); err != nil {
		t.Fatal("cost-only credential effect population", err)
	}
	if _, err = f.pool.Raw().Exec(f.ctx, `ANALYZE sso_providers.credentials; ANALYZE sso_providers.credential_effects`); err != nil {
		t.Fatal(err)
	}
	var elapsed []time.Duration
	for version := uint64(2); version <= 8; version++ {
		request := nativeCredentialRequest(t, f, config, created.Provider.ID, version, version)
		start := time.Now()
		out, callErr := service.ProviderCredentialsRotate(f.ctx, request)
		elapsed = append(elapsed, time.Since(start))
		if callErr != nil || out.Version != version+1 || !out.Active {
			t.Fatal("scaled credential successor", callErr)
		}
	}
	missing := nativeCredentialRequest(t, f, config, "missing", 1, 1)
	if _, err = service.ProviderCredentialsRotate(f.ctx, missing); !errors.Is(err, sso.ErrForbidden) {
		t.Fatal("scaled no-match changed denial", err)
	}
	if _, err = service.ProviderCredentialsRotate(f.ctx, nativeCredentialRequest(t, f, config, created.Provider.ID, 1, 1)); !errors.Is(err, sso.ErrConflict) {
		t.Fatal("scaled stale predecessor accepted", err)
	}
	// Trigger the actual pending recovery participant rather than substitute an
	// application query. Only this real original lease is expired; no journal
	// identity, plan, receipt, state or effect is fabricated.
	lossy, fault := providerLossService(t, f, config, "INSERT INTO sso_providers.credentials")
	fault.beforeCommit.Store(true)
	lossy, _ = lossy.ForOrganization(created.Provider.OrganizationID)
	lostRequest := nativeCredentialRequest(t, f, config, created.Provider.ID, 9, 9)
	lost, lostErr := nativeCredentialService(t, lossy).ProviderCredentialsRotate(f.ctx, lostRequest)
	if !fault.lost.Load() || lostErr == nil || lost.Completion.Outcome != identity.CommitOutcomeUnknown {
		t.Fatal("scaled pending fixture unavailable", lostErr)
	}
	id, _ := base64.RawURLEncoding.Strict().DecodeString(string(lost.Completion.Binding.CommandID))
	if tag, err := f.pool.Raw().Exec(f.ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 microsecond' WHERE command_id=$1 AND tenant_id=$2 AND purpose='identity.sso.provider.credentials-rotate' AND state='pending' AND command_plan IS NOT NULL AND preparation_ciphertext IS NOT NULL`, id, "org-test-basic"); err != nil || tag.RowsAffected() != 1 {
		t.Fatal("scaled original lease unavailable", err)
	}
	if recovered, recoveryErr := service.ProviderCredentialsRotate(f.ctx, lostRequest); !errors.Is(recoveryErr, sso.ErrUnavailable) || recovered.Completion.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("scaled original recovery", recovered.Completion.Outcome, recoveryErr)
	}
	var providers, hot, credentials, effects int
	var server string
	if err = f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM sso_providers.providers),(SELECT count(*) FROM sso_providers.providers WHERE tenant_id='org-test-basic'),(SELECT count(*) FROM sso_providers.credentials),(SELECT count(*) FROM sso_providers.credential_effects),current_setting('server_version')`).Scan(&providers, &hot, &credentials, &effects, &server); err != nil || providers != 100001 || hot != 10001 || credentials != 100001 || effects != 100008 {
		t.Fatal("representative credential distribution changed", providers, hot, credentials, effects, err)
	}
	sort.Slice(elapsed, func(i, j int) bool { return elapsed[i] < elapsed[j] })
	t.Logf("isolated PostgreSQL %s; providers=%d hot tenant=%d credentials=%d effects=%d; 7 complete native rotations median=%s max=%s, including authority/key/counter/envelope/commit work; warmed, no concurrent load; C-collated exact tenant/organization/provider and command primary keys", server, providers, hot, credentials, effects, elapsed[3], elapsed[6])
	trace.mu.Lock()
	queries := append([]providerQuery(nil), trace.queries...)
	traceErr := trace.err
	trace.mu.Unlock()
	if traceErr != nil {
		t.Fatal(traceErr)
	}
	seen := map[string]bool{}
	for _, query := range queries {
		partition := query.sql
		initialCredential := strings.HasPrefix(query.sql, "INSERT INTO sso_providers.credentials(") && len(query.args) > 3 && query.args[3] == "1"
		if initialCredential {
			partition += "/initial"
		}
		if strings.HasPrefix(query.sql, "SELECT") && len(query.args) > 2 && query.args[2] == "missing" {
			partition += "/no-match"
		}
		if seen[partition] {
			continue
		}
		seen[partition] = true
		types := make([]string, len(query.args))
		for i, arg := range query.args {
			types[i] = fmt.Sprintf("%T", arg)
		}
		for range 3 {
			tx, beginErr := f.pool.Raw().Begin(f.ctx)
			if beginErr != nil {
				t.Fatal(beginErr)
			}
			err = nil
			if strings.HasPrefix(query.sql, "UPDATE sso_providers.providers") {
				if query.args[6] == "1" {
					_, err = tx.Exec(f.ctx, `UPDATE sso_providers.providers SET metadata_version=1,metadata_configuration_envelope=NULL,metadata_mapping_version=NULL WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`, query.args[0], query.args[1], query.args[2])
				} else {
					_, err = tx.Exec(f.ctx, `UPDATE sso_providers.providers SET metadata_version=$4::numeric WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`, query.args[0], query.args[1], query.args[2], query.args[6])
				}
			} else if strings.HasPrefix(query.sql, "INSERT INTO sso_providers.credentials(") {
				if initialCredential {
					_, err = tx.Exec(f.ctx, `DELETE FROM sso_providers.credentials WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`, query.args[0], query.args[1], query.args[2])
				} else {
					_, err = tx.Exec(f.ctx, `UPDATE sso_providers.credentials SET generation=$4::numeric WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`, query.args[0], query.args[1], query.args[2], query.args[7])
				}
			} else if strings.HasPrefix(query.sql, "INSERT INTO sso_providers.credential_effects") {
				_, err = tx.Exec(f.ctx, `DELETE FROM sso_providers.credential_effects WHERE command_id=$1`, query.args[0])
			}
			var plan []byte
			if err == nil {
				if len(query.oids) > 0 {
					result := tx.Conn().PgConn().ExecParams(f.ctx, "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) "+query.sql, query.values, query.oids, query.formats, nil).Read()
					err = result.Err
					if err == nil {
						if len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
							err = fmt.Errorf("invalid captured credential plan")
						} else {
							plan = result.Rows[0][0]
						}
					}
				} else {
					err = tx.QueryRow(f.ctx, "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) "+query.sql, query.args...).Scan(&plan)
				}
			}
			rollbackErr := tx.Rollback(f.ctx)
			if err != nil || rollbackErr != nil {
				t.Fatal("actual credential SQL/binding plan", err, rollbackErr)
			}
			t.Logf("actual SQL=%s; binding types=%v native-OIDs=%v native-formats=%v; plan=%s", query.sql, types, query.oids, query.formats, string(plan))
		}
	}
	if len(seen) < 8 {
		t.Fatal("missing native read/no-match/lock/write/recovery query partitions", len(seen))
	}
}
