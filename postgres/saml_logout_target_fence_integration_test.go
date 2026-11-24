//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestSAMLIDPLogoutProbeSnapshotsExactCustody(t *testing.T) {
	f := newSAMLLogoutTargetFixture(t)
	f.insert(t, f.anchor("session"), f.scope, f.subject, 1, nil)
	probe, err := f.custody.prepareIDPLogoutProbe("tenant", f.scope, f.request())
	if err != nil {
		t.Fatal(err)
	}
	matches, err := probe.lookup(f.ctx, f.pool, f.payload.Envelope, f.custody, f.now)
	if err != nil || len(matches) != 1 || matches[0].Anchor != f.anchor("session") || matches[0].RowDigest == ([32]byte{}) {
		t.Fatal("probe did not authenticate and snapshot exact custody", len(matches), err)
	}
}

func TestSAMLIDPLogoutProbeFingerprintCoversCustody(t *testing.T) {
	for _, test := range []struct{ name, mutation string }{
		{"user", `user_id='changed-user'`},
		{"family", `family_id='changed-family'`},
		{"purpose", `issuance_purpose='identity.sso.saml-idp-init'`},
		{"issued", `issued_at=issued_at-interval '1 second'`},
		{"expires", `expires_at=expires_at+interval '1 second'`},
		{"index", `session_index_digest=NULL`},
		{"envelope", `subject_envelope=subject_envelope || decode('01','hex')`},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newSAMLLogoutTargetFixture(t)
			f.insert(t, f.anchor("session"), f.scope, f.subject, 1, nil)
			if test.name == "purpose" {
				commandAnchor := f.anchor("new-command")
				command, err := base64.RawURLEncoding.DecodeString(commandAnchor.Command)
				if err != nil {
					t.Fatal(err)
				}
				for _, statement := range []string{
					`INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,'tenant','identity.sso.saml-idp-init',sha256($1),1,decode('01','hex'))`,
					`INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,'tenant','identity.sso.saml-idp-init')`,
				} {
					if _, err := f.pool.Raw().Exec(f.ctx, statement, command); err != nil {
						t.Fatal(err)
					}
				}
			}
			request := f.request()
			request.SessionIndex = ""
			probe, err := f.custody.prepareIDPLogoutProbe("tenant", f.scope, request)
			if err != nil {
				t.Fatal(err)
			}
			matches, err := probe.lookup(f.ctx, f.pool, f.payload.Envelope, f.custody, f.now)
			if err != nil || len(matches) != 1 {
				t.Fatal("snapshot custody", err)
			}
			mutation := test.mutation
			var args []any
			if test.name == "purpose" {
				mutation = `issuance_command_id=$1,issuance_purpose='identity.sso.saml-idp-init'`
				args = []any{mustSAMLLogoutTargetCommand(t, f.anchor("new-command").Command)}
			}
			if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE sso_providers.saml_logout_subjects SET `+mutation+` WHERE tenant_id='tenant' AND session_id='session'`, args...); err != nil {
				t.Fatal(err)
			}
			var session string
			var digest []byte
			if err := f.pool.Raw().QueryRow(f.ctx, probe.fenceSQL(), probe.bindings(f.now)...).Scan(&session, &digest); err != nil || session != "session" || bytes.Equal(digest, matches[0].RowDigest[:]) {
				t.Fatal("custody mutation escaped the transactional fingerprint", session, err)
			}
		})
	}
}

func mustSAMLLogoutTargetCommand(t *testing.T, command string) []byte {
	t.Helper()
	wire, err := base64.RawURLEncoding.DecodeString(command)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestSAMLIDPLogoutProbeFenceUsesUTCIndependentFingerprint(t *testing.T) {
	f := newSAMLLogoutTargetFixture(t)
	f.insert(t, f.anchor("session"), f.scope, f.subject, 1, nil)
	probe, err := f.custody.prepareIDPLogoutProbe("tenant", f.scope, f.request())
	if err != nil {
		t.Fatal(err)
	}
	matches, err := probe.lookup(f.ctx, f.pool, f.payload.Envelope, f.custody, f.now)
	if err != nil || len(matches) != 1 {
		t.Fatal(err)
	}
	tx, err := f.pool.Raw().Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	if _, err := tx.Exec(f.ctx, `SET LOCAL TIME ZONE 'Pacific/Honolulu'`); err != nil {
		t.Fatal(err)
	}
	var session string
	var digest []byte
	if err := tx.QueryRow(f.ctx, probe.fenceSQL(), probe.bindings(f.now)...).Scan(&session, &digest); err != nil || !bytes.Equal(digest, matches[0].RowDigest[:]) {
		t.Fatal("session timezone changed the exact custody fingerprint", err)
	}
	if err := probe.requireInWork(f.ctx, kernel.Work{}, matches); err == nil {
		t.Fatal("zero Work accepted custody")
	}
}

func TestSAMLIDPLogoutProbeFenceProjectsOnlyBoundedFingerprints(t *testing.T) {
	f := newSAMLLogoutTargetFixture(t)
	for n := range samlLogoutTargetLimit {
		f.insert(t, f.anchor(fmt.Sprintf("session-%03d", n)), f.scope, f.subject, uint32(1+n%2), nil)
	}
	probe, err := f.custody.prepareIDPLogoutProbe("tenant", f.scope, f.request())
	if err != nil {
		t.Fatal(err)
	}
	matches, err := probe.lookup(f.ctx, f.pool, f.payload.Envelope, f.custody, f.now)
	if err != nil || len(matches) != samlLogoutTargetLimit {
		t.Fatal("snapshot maximum target set", len(matches), err)
	}
	// Storage permits 64 KiB per envelope. Such rows must not overflow Work's
	// aggregate 1 MiB result budget merely to establish that custody changed.
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE sso_providers.saml_logout_subjects SET subject_envelope=convert_to(repeat('x',65536),'UTF8')`); err != nil {
		t.Fatal(err)
	}
	rows, err := f.pool.Raw().Query(f.ctx, probe.fenceSQL(), probe.bindings(f.now)...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	count, size := 0, 0
	for rows.Next() {
		var session string
		var digest []byte
		if err := rows.Scan(&session, &digest); err != nil {
			t.Fatal(err)
		}
		if len(digest) != 32 {
			t.Fatal("invalid fingerprint length", len(digest))
		}
		count++
		size += len(session) + len(digest)
	}
	if err := rows.Err(); err != nil || count != samlLogoutTargetLimit || size >= 1<<20 {
		t.Fatal("complete fence exceeded Work's aggregate result budget", count, size, err)
	}
}
