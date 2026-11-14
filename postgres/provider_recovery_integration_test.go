//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

type providerCommitFault struct {
	target       string
	seen, lost   atomic.Bool
	beforeCommit atomic.Bool
}
type providerLossConn struct {
	net.Conn
	fault   *providerCommitFault
	pending []byte
}

func (c *providerLossConn) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte(c.fault.target)) {
		c.fault.seen.Store(true)
	}
	if c.fault.beforeCommit.Load() && c.fault.seen.Load() && len(p) >= 5 && p[0] == 'Q' && (bytes.Equal(p[5:], []byte("commit\x00")) || bytes.Equal(p[5:], []byte("COMMIT\x00"))) && c.fault.lost.CompareAndSwap(false, true) {
		// This fixture withholds the final COMMIT request itself, after actual
		// feature SQL ran. Closing the real connection rolls back that work;
		// the already-attached native command journal remains pending.
		_ = c.Conn.Close()
		return 0, io.ErrClosedPipe
	}
	return c.Conn.Write(p)
}

func (c *providerLossConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(c.pending) == 0 {
		var header [5]byte
		if _, err := io.ReadFull(c.Conn, header[:]); err != nil {
			return 0, err
		}
		size := binary.BigEndian.Uint32(header[1:])
		if size < 4 || size > 16<<20 {
			return 0, errors.New("invalid fixture PostgreSQL frame")
		}
		frame := make([]byte, int(size)+1)
		copy(frame, header[:])
		if _, err := io.ReadFull(c.Conn, frame[5:]); err != nil {
			return 0, err
		}
		// The exact server CommandComplete proves COMMIT succeeded before this
		// fixture loses its response. No alternate coordinator or journal runs.
		if !c.fault.beforeCommit.Load() && header[0] == 'C' && string(frame[5:]) == "COMMIT\x00" && c.fault.seen.Load() && c.fault.lost.CompareAndSwap(false, true) {
			_ = c.Conn.Close()
			return 0, io.EOF
		}
		c.pending = frame
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func expirePendingProviderOriginal(t *testing.T, f *orgFixture, original identity.CommandResult) {
	t.Helper()
	if original.Outcome != identity.CommitOutcomeUnknown || original.Binding.CommandID == "" || original.Binding.RecordID == "" {
		t.Fatal("missing actual pending original binding")
	}
	id, err := base64.RawURLEncoding.Strict().DecodeString(string(original.Binding.CommandID))
	if err != nil {
		t.Fatal("invalid original command identity")
	}
	// Only expire this real, already-attached original lease. No claim, plan,
	// effect, fingerprint, generation or authority is manufactured or changed.
	tag, err := f.pool.Raw().Exec(f.ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 microsecond' WHERE command_id=$1 AND tenant_id=$2 AND purpose='identity.sso.provider.register-oidc' AND state='pending' AND command_plan IS NOT NULL AND preparation_ciphertext IS NOT NULL`, id, string(original.Binding.TenantID))
	if err != nil || tag.RowsAffected() != 1 {
		t.Fatal("actual attached pending lease unavailable", err)
	}
	var effects, providers int
	if err = f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM sso_providers.command_effects WHERE command_id=$1),(SELECT count(*) FROM sso_providers.providers WHERE provider_id=$2)`, string(original.Binding.CommandID), original.Binding.RecordID).Scan(&effects, &providers); err != nil || effects != 0 || providers != 0 {
		t.Fatal("lost precommit work was not rolled back", effects, providers, err)
	}
}

func providerLossService(t *testing.T, f *orgFixture, config ssopg.ProviderServiceConfig, target string) (*ssopg.ProviderService, *providerCommitFault) {
	t.Helper()
	fault := &providerCommitFault{target: target}
	pool, err := database.Connect(f.ctx, database.Config{DSN: f.dsn, MaxConns: 2, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database = f.database
		c.ConnConfig.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			return &providerLossConn{Conn: conn, fault: fault}, nil
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if pool.Close(ctx) != nil {
			t.Error("provider fault pool cleanup")
		}
	})
	service, err := ssopg.NewProviderService(pool, config, f.auth("org-test-basic", "owner"), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	return service, fault
}

func TestNativeProviderAmbiguousCommitRecoversOriginalOnly(t *testing.T) {
	for _, boundary := range []string{"domain", "mapping"} {
		t.Run(boundary, func(t *testing.T) {
			f, normal, config := newProviderFixture(t)
			target := "INSERT INTO sso_providers.providers"
			if boundary == "mapping" {
				target = "INSERT INTO identity.request_key_mappings"
			}
			service, fault := providerLossService(t, f, config, target)
			request := providerRequest(t, "https://ambiguous.example.com", "ambiguous-provider")
			out, err := service.ProviderRegisterOidc(f.ctx, request)
			if !fault.lost.Load() || err == nil || out.Completion.Outcome == identity.CommitOutcomeCommitted || out.Provider.ID != "" {
				t.Fatal("lost commit response disclosed success", boundary, fault.lost.Load(), out.Completion.Outcome, err)
			}
			retry, retryErr := normal.ProviderRegisterOidc(f.ctx, request)
			var count int
			if err = f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM sso_providers.providers`).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if boundary == "domain" {
				if retryErr != nil || retry.Completion.Outcome != identity.CommitOutcomeCommitted || retry.Provider.ID == "" || retry.Provider.Enabled || count != 1 {
					t.Fatal("ambiguous committed original not recovered", count, retry.Completion.Outcome, retryErr)
				}
				second, secondErr := normal.ProviderRegisterOidc(f.ctx, request)
				if secondErr != nil || second.Provider.ID != retry.Provider.ID {
					t.Fatal("recovery changed stable original provider", secondErr)
				}
			} else {
				var unknown identity.UnknownCommitError
				if !errors.As(retryErr, &unknown) || retry.Completion.Outcome != identity.CommitOutcomeUnknown || retry.Provider.ID != "" || count != 0 {
					t.Fatal("mapping without journal became fresh execution", count, retry.Completion.Outcome, retryErr)
				}
			}
		})
	}
}
