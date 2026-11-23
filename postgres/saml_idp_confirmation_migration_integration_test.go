//go:build integration

package postgres_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/jackc/pgx/v5/pgconn"
)

func installSAMLIDPStorage(t *testing.T, f *orgFixture, source migrations.Source) {
	t.Helper()
	history, err := source.Load(f.ctx)
	if err != nil || len(history) == 0 {
		t.Fatal("load SAML storage migration", err)
	}
	for _, step := range history {
		tx, err := f.pool.Raw().Begin(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(f.ctx, step.UpSQL()); err != nil {
			_ = tx.Rollback(f.ctx)
			t.Fatal("apply exact SAML storage migration", err)
		}
		if err := tx.Commit(f.ctx); err != nil {
			t.Fatal(err)
		}
	}
}

func samlIDPMigrationCommandBytes(t *testing.T, f *orgFixture, tenant identity.TenantID, purpose string) []byte {
	t.Helper()
	id := seedProviderGrantAttemptForTest(t, f, tenant, purpose)
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(string(id))
	if err != nil || len(decoded) != 16 {
		t.Fatal("invalid fixture command ID", err)
	}
	return decoded
}

func assertSAMLIDPStorageSQLState(t *testing.T, state string, err error) {
	t.Helper()
	var server *pgconn.PgError
	if !errors.As(err, &server) || server.Code != state {
		t.Fatal("wrong storage rejection", state, err)
	}
}

func TestNativeSAMLIDPConfirmationStorageRetainsOriginalPendingUntilExactCompletion(t *testing.T) {
	x := newNativeSAMLIDPAdmissionFixture(t)
	f, tenant, org, provider := x.enable.f, x.enable.proof.TenantID, x.profile.OrganizationID, x.profile.ProviderID
	installSAMLIDPStorage(t, f, ssopg.SAMLIDPConfirmationMigrationSource{Version: 391})
	const prepare = "identity.sso.saml-idp-prepare"
	const complete = "identity.sso.saml-idp-init"
	arrival := samlIDPMigrationCommandBytes(t, f, tenant, prepare)
	validCompletion := samlIDPMigrationCommandBytes(t, f, tenant, complete)
	spCommand := samlIDPMigrationCommandBytes(t, f, tenant, "identity.sso.saml-acs")
	issued := time.Now().UTC().Truncate(time.Microsecond)
	expires := issued.Add(2 * time.Minute)
	sealed := []byte("synthetic-encrypted-pending-confirmation")
	browser, form := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	const insert = `INSERT INTO sso_providers.saml_idp_confirmations
 (tenant_id,organization_id,provider_id,user_id,confirmation_id,binding_envelope,confirmation_key_version,browser_digest,form_digest,issued_at,expires_at)
 VALUES($1,$2,$3,'linked-user',$4,$5,$6,$7,$8,$9,$10)`
	for _, wrong := range []struct {
		id, form []byte
		expires  time.Time
		state    string
	}{
		{spCommand, form, expires, "23503"},
		{arrival, browser, expires, "23514"},
		{arrival, form, issued.Add(5 * time.Minute).Add(time.Microsecond), "23514"},
	} {
		_, err := f.pool.Raw().Exec(f.ctx, insert, tenant, org, provider, wrong.id, sealed, 1, browser, wrong.form, issued, wrong.expires)
		assertSAMLIDPStorageSQLState(t, wrong.state, err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, insert, tenant, org, provider, arrival, sealed, 1, browser, form, issued, expires); err != nil {
		t.Fatal("store independently verified arrival with both commitments", err)
	}
	const scope = ` WHERE tenant_id=$1 AND confirmation_id=$2`
	assertPending := func() {
		t.Helper()
		var ok bool
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT completed_at IS NULL AND completion_command_id IS NULL AND binding_envelope=$3
 AND browser_digest=$4 AND form_digest=$5 AND confirmation_key_version=1 AND expires_at=$6 FROM sso_providers.saml_idp_confirmations`+scope,
			tenant, arrival, sealed, browser, form, expires).Scan(&ok); err != nil || !ok {
			t.Fatal("pending row lost original custody, expiry or scope", err)
		}
	}
	assertPending()
	_, err := f.pool.Raw().Exec(f.ctx, `UPDATE sso_providers.saml_idp_confirmations SET expires_at=expires_at+interval '1 second'`+scope, tenant, arrival)
	assertSAMLIDPStorageSQLState(t, "23514", err)
	_, err = f.pool.Raw().Exec(f.ctx, `UPDATE sso_providers.saml_idp_confirmations SET completed_at=$3,completion_command_id=$4`+scope, tenant, arrival, issued, validCompletion)
	assertSAMLIDPStorageSQLState(t, "23514", err)
	const finish = `UPDATE sso_providers.saml_idp_confirmations SET completed_at=$3,completion_command_id=$4,
 binding_envelope=NULL,confirmation_key_version=NULL,browser_digest=NULL,form_digest=NULL` + scope
	_, err = f.pool.Raw().Exec(f.ctx, finish, tenant, arrival, expires, validCompletion)
	assertSAMLIDPStorageSQLState(t, "23514", err)
	_, err = f.pool.Raw().Exec(f.ctx, finish, tenant, arrival, issued, spCommand)
	assertSAMLIDPStorageSQLState(t, "23503", err)
	_, err = f.pool.Raw().Exec(f.ctx, `UPDATE sso_providers.saml_idp_confirmations SET completed_at=$3,completion_command_id=$4,
 user_id='substituted-user',binding_envelope=NULL,confirmation_key_version=NULL,browser_digest=NULL,form_digest=NULL`+scope,
		tenant, arrival, issued, validCompletion)
	assertSAMLIDPStorageSQLState(t, "23514", err)
	assertPending()
	tx, err := f.pool.Raw().Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.ctx)
	if _, err := tx.Exec(f.ctx, finish, tenant, arrival, issued, validCompletion); err != nil {
		t.Fatal("matching completion failed provisionally", err)
	}
	if err := tx.Rollback(f.ctx); err != nil {
		t.Fatal(err)
	}
	assertPending()
	if _, err := f.pool.Raw().Exec(f.ctx, finish, tenant, arrival, issued, validCompletion); err != nil {
		t.Fatal("matching completion failed", err)
	}
	var terminal bool
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT completion_command_id=$3 AND completed_at=$4 AND expires_at=$5 AND binding_envelope IS NULL
 AND confirmation_key_version IS NULL AND browser_digest IS NULL AND form_digest IS NULL FROM sso_providers.saml_idp_confirmations`+scope,
		tenant, arrival, validCompletion, issued, expires).Scan(&terminal); err != nil || !terminal {
		t.Fatal("terminal row lost provenance or retained confirmation secrets", err)
	}
	_, err = f.pool.Raw().Exec(f.ctx, `UPDATE sso_providers.saml_idp_confirmations SET completed_at=NULL,completion_command_id=NULL,
 binding_envelope=$3,confirmation_key_version=1,browser_digest=$4,form_digest=$5`+scope, tenant, arrival, sealed, browser, form)
	assertSAMLIDPStorageSQLState(t, "23514", err)
}

func TestNativeSAMLIDPReplayExpansionSharesSPUniqueness(t *testing.T) {
	x := newNativeSAMLIDPAdmissionFixture(t)
	f, tenant, org, provider := x.enable.f, x.enable.proof.TenantID, x.profile.OrganizationID, x.profile.ProviderID
	installSAMLIDPStorage(t, f, ssopg.SAMLReplayMigrationSource{Version: 390})
	const unsolicited = "identity.sso.saml-idp-init"
	const sp = "identity.sso.saml-acs"
	spCommand := samlIDPMigrationCommandBytes(t, f, tenant, sp)
	idpCommand := samlIDPMigrationCommandBytes(t, f, tenant, unsolicited)
	otherCommand := samlIDPMigrationCommandBytes(t, f, tenant, "identity.sso.saml-idp-prepare")
	issuer, fingerprint := bytes.Repeat([]byte{5}, 32), bytes.Repeat([]byte{6}, 32)
	member := func(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }
	const add = `INSERT INTO sso_providers.saml_replay_members
 (tenant_id,organization_id,provider_id,issuer_digest,member_digest,member_kind,callback_command_id,callback_purpose,execution_fingerprint,execution_generation,retain_until)
 VALUES($1,$2,$3,$4,$5,1,$6,$7,$8,1,clock_timestamp()+interval '10 minutes'),
       ($1,$2,$3,$4,$9,2,$6,$7,$8,1,clock_timestamp()+interval '10 minutes')`
	insert := func(first, second []byte, command []byte, purpose string) error {
		_, err := f.pool.Raw().Exec(f.ctx, add, tenant, org, provider, issuer, first, command, purpose, fingerprint, second)
		return err
	}
	if err := insert(member(1), member(2), spCommand, sp); err != nil {
		t.Fatal("populate original SP pair", err)
	}
	assertSAMLIDPStorageSQLState(t, "23514", insert(member(3), member(4), idpCommand, unsolicited))
	steps, err := (ssopg.SAMLIDPReplayMigrationSource{Version: 392, ValidationVersion: 393}).Load(f.ctx)
	if err != nil || len(steps) != 2 {
		t.Fatal("read two replay expansion steps", err)
	}
	installSAMLIDPStorage(t, f, migrationList{steps[0]})
	assertValidated := func(expected bool) {
		t.Helper()
		var actual bool
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT convalidated FROM pg_constraint
 WHERE conrelid='sso_providers.saml_replay_members'::regclass AND conname='saml_replay_members_callback_purpose_check'`).Scan(&actual); err != nil || actual != expected {
			t.Fatal("purpose check has wrong validation state", actual, err)
		}
	}
	assertValidated(false)
	assertSAMLIDPStorageSQLState(t, "23505", insert(member(2), member(4), idpCommand, unsolicited))
	assertSAMLIDPStorageSQLState(t, "23503", insert(member(3), member(4), otherCommand, unsolicited))
	assertSAMLIDPStorageSQLState(t, "23514", insert(member(3), member(4), otherCommand, "identity.sso.saml-idp-prepare"))
	if err := insert(member(3), member(4), idpCommand, unsolicited); err != nil {
		t.Fatal("shared schema rejected clean unsolicited pair after enforcing expansion", err)
	}
	installSAMLIDPStorage(t, f, migrationList{steps[1]})
	assertValidated(true)
	var total, spMembers, unsolicitedMembers int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*),count(*) FILTER(WHERE callback_purpose=$1),count(*) FILTER(WHERE callback_purpose=$2)
 FROM sso_providers.saml_replay_members`, sp, unsolicited).Scan(&total, &spMembers, &unsolicitedMembers); err != nil || total != 4 || spMembers != 2 || unsolicitedMembers != 2 {
		t.Fatal("expansion or validation changed either original pair", total, spMembers, unsolicitedMembers, err)
	}
}
