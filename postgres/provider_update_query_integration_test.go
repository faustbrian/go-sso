//go:build integration

package postgres_test

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-sso"
)

// Measurements use the actual driver's captured SQL and bindings against the
// same skewed 100k-row fixture as registration. Copies are cost-only rows, not
// accepted encrypted configuration or manufactured organization authority.
func TestNativeProviderUpdateQueryScale(t *testing.T) {
	f, service, config := newProviderFixture(t)
	registration := providerRequest(t, "https://update-scale.example.com", "update-scale-registration")
	created, err := service.ProviderRegisterOidc(f.ctx, registration)
	if err != nil {
		t.Fatal(err)
	}
	populateProviderQueryRows(t, f, created.Provider.ID)
	trace := new(providerTrace)
	service = tracedProviderService(t, f, config, trace)
	service, err = service.ForOrganization(registration.OrganizationID)
	if err != nil {
		t.Fatal(err)
	}
	var elapsed []time.Duration
	for version := uint64(1); version <= 7; version++ {
		request := providerUpdateRequest(t, registration, created.Provider.ID, version, fmt.Sprintf("update-scale-%d", version))
		started := time.Now()
		out, updateErr := service.ProviderUpdate(f.ctx, request)
		elapsed = append(elapsed, time.Since(started))
		if updateErr != nil || out.Provider.Version != version+1 {
			t.Fatal("scaled native successor", updateErr)
		}
	}
	sort.Slice(elapsed, func(i, j int) bool { return elapsed[i] < elapsed[j] })
	var rows, hot int
	var server string
	if err = f.pool.Raw().QueryRow(f.ctx, `SELECT count(*),count(*) FILTER(WHERE tenant_id='org-test-basic'),current_setting('server_version') FROM sso_providers.providers`).Scan(&rows, &hot, &server); err != nil || rows != 100001 || hot != 10001 {
		t.Fatal("scale distribution changed", err)
	}
	t.Logf("isolated PostgreSQL %s; providers=%d hot organization=%d; 7 native successor calls median=%s max=%s including authority/key/counter/envelope/commit work; warm fixture, no concurrent load", server, rows, hot, elapsed[3], elapsed[6])
	missing := providerUpdateRequest(t, registration, "missing", 1, "update-scale-missing")
	if _, err = service.ProviderUpdate(f.ctx, missing); !errors.Is(err, sso.ErrForbidden) {
		t.Fatal("scaled no-match disclosure", err)
	}
	stale := providerUpdateRequest(t, registration, created.Provider.ID, 1, "update-scale-stale")
	if _, err = service.ProviderUpdate(f.ctx, stale); !errors.Is(err, sso.ErrConflict) {
		t.Fatal("scaled stale accepted", err)
	}
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
			err = nil
			tx, beginErr := f.pool.Raw().Begin(f.ctx)
			if beginErr != nil {
				t.Fatal(beginErr)
			}
			if strings.HasPrefix(query.sql, "UPDATE sso_providers.providers") {
				// Replay the captured first successor against its real v1 source
				// projection in this rollback-only measurement transaction.
				_, err = tx.Exec(f.ctx, `UPDATE sso_providers.providers SET metadata_version=1,metadata_configuration_envelope=NULL,metadata_mapping_version=NULL WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`, query.args[0], query.args[1], query.args[2])
			} else if strings.HasPrefix(query.sql, "INSERT INTO sso_providers.command_effects") {
				_, err = tx.Exec(f.ctx, `DELETE FROM sso_providers.command_effects WHERE command_id=$1`, query.args[0])
			}
			var plan []byte
			if err == nil {
				if len(query.oids) > 0 {
					result := tx.Conn().PgConn().ExecParams(f.ctx, "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) "+query.sql, query.values, query.oids, query.formats, nil).Read()
					err = result.Err
					if err == nil {
						if len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
							err = fmt.Errorf("invalid captured update plan")
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
				t.Fatal("actual update SQL/binding plan", err, rollbackErr)
			}
			t.Logf("actual SQL=%s; binding types=%v native-OIDs=%v native-formats=%v; plan=%s", query.sql, types, query.oids, query.formats, string(plan))
		}
	}
	if len(seen) < 4 {
		t.Fatal("missing matched/no-match/read/write/effect partitions", len(seen))
	}
}
