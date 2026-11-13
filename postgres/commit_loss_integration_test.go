//go:build integration

package postgres_test

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	organizationpg "github.com/faustbrian/go-organization/postgres"
	database "github.com/faustbrian/go-postgres"
)

// commitResponseLoss withholds only the second successful COMMIT response after
// arming: reservation commits first, then the domain/audit/outbox transaction.
// Seeing PostgreSQL's CommandComplete proves server commit before client loss.
// No background goroutine or substitute coordinator participates in the fault.
type commitResponseLoss struct {
	armed atomic.Bool
	count atomic.Int32
	lost  atomic.Bool
}

type lossyCommitConn struct {
	net.Conn
	fault   *commitResponseLoss
	pending []byte
}

func (c *lossyCommitConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(c.pending) == 0 {
		var header [5]byte
		if _, e := io.ReadFull(c.Conn, header[:]); e != nil {
			return 0, e
		}
		size := binary.BigEndian.Uint32(header[1:])
		if size < 4 || size > 16<<20 {
			return 0, errors.New("invalid fixture PostgreSQL message size")
		}
		frame := make([]byte, int(size)+1)
		copy(frame, header[:])
		if _, e := io.ReadFull(c.Conn, frame[5:]); e != nil {
			return 0, e
		}
		if header[0] == 'C' && string(frame[5:]) == "COMMIT\x00" && c.fault.armed.Load() && c.fault.count.Add(1) == 2 {
			c.fault.lost.Store(true)
			_ = c.Conn.Close()
			return 0, io.EOF
		}
		c.pending = frame
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (f *orgFixture) lostCommitService(t *testing.T) (*organizationpg.Service, *commitResponseLoss) {
	t.Helper()
	fault := new(commitResponseLoss)
	pool, e := database.Connect(f.ctx, database.Config{DSN: f.dsn, MaxConns: 2, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database = f.database
		c.ConnConfig.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, e := (&net.Dialer{}).DialContext(ctx, network, address)
			if e != nil {
				return nil, e
			}
			return &lossyCommitConn{Conn: conn, fault: fault}, nil
		}
		return nil
	}})
	if e != nil {
		t.Fatal("fault connection unavailable", e)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if e := pool.Close(ctx); e != nil {
			t.Error("fault pool cleanup failed")
		}
	})
	copy := *f
	copy.pool = pool
	copy.compose(t)
	return copy.service, fault
}
