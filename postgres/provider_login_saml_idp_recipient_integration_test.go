//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestNativeSAMLIDPLinkedRecipientRequiresCurrentExistingLinkWithoutSPStart(t *testing.T) {
	x := newNativeSAMLIDPAdmissionFixture(t)
	f, tenant := x.enable.f, x.enable.proof.TenantID
	accounts, err := (kernel.AccountMigrationSource{Base: f.history, Version: 390}).Load(f.ctx)
	if err != nil || len(accounts) != len(f.history)+1 {
		t.Fatal("load native account history", err)
	}
	installSAMLIDPStorage(t, f, migrationList{accounts[len(accounts)-1]})
	installSAMLIDPStorage(t, f, mfapg.MigrationSource{Version: 391})
	provider, err := ssopg.SSOSAMLAccountProviderNamespace(x.profile.OrganizationID, x.profile.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	expected := nativeSAMLIDPEvidence(time.Now().UTC())
	exec := func(statement string, args ...any) {
		t.Helper()
		if _, err := f.pool.Raw().Exec(f.ctx, statement, args...); err != nil {
			t.Fatal("prepare existing linked identity", err)
		}
	}
	exec(`INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES($1,'owner','idp-credential',3,'sso',1,true)`, tenant)
	exec(`WITH a AS (SELECT $2::text AS provider,$3::text AS issuer,$4::text AS subject)
INSERT INTO identity.accounts(tenant_id,user_id,account_id,provider,issuer,subject,subject_key,version,social_link_version,linked)
SELECT $1,'owner','idp-linked-account',provider,issuer,subject,
sha256(convert_to(octet_length(provider)::text||':'||provider||octet_length(issuer)::text||':'||issuer||octet_length(subject)::text||':'||subject,'UTF8')),1,1,true FROM a`, tenant, provider, x.installed.EntityID, expected.ProviderSubject)
	exec(`INSERT INTO identity.account_credentials(tenant_id,user_id,credential_id,account_id) VALUES($1,'owner','idp-credential','idp-linked-account')`, tenant)
	seedNativeCallbackJourneyFactors(t, providerLoginStartFixture{enable: x.enable, config: ssopg.ProviderLoginConfig{TenantID: tenant}}, "owner")
	var originalCutoff time.Time
	service, err := ssopg.NewProviderSAMLIDPAdmissionService(x.router, ssopg.ProviderSAMLIDPAdmissionConfig{
		TenantID: tenant, Profiles: []ssopg.StaticSAMLIDPAdmissionProfile{{Provider: x.profile, MaximumAge: time.Minute}},
		Verify: func(ctx context.Context, input ssopg.SAMLIDPResponseVerificationInput) (ssopg.SAMLVerifiedResponse, error) {
			x.assertVerifierInput(t, ctx, input, time.Minute)
			evidence := nativeSAMLIDPEvidence(input.Now)
			originalCutoff = input.Now.Add(3 * time.Second).Truncate(time.Microsecond)
			evidence.ValidUntil = originalCutoff
			return evidence, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := service.VerifyLinkedRecipient(f.ctx, x.request()); !errors.Is(err, sso.ErrInvalidInput) {
		t.Fatal("unselected recipient lookup was admitted", got, err)
	}
	if _, err := service.WithLinkedRecipientPolicy(""); !errors.Is(err, sso.ErrInvalidInput) {
		t.Fatal("empty policy namespace admitted", err)
	}
	selected, err := service.WithLinkedRecipientPolicy("users")
	if err != nil {
		t.Fatal(err)
	}
	// The fixture installs shared SP schema. Remove its normal name for this
	// check so any accidental SP read fails rather than seeing an empty table.
	exec(`ALTER TABLE sso_providers.login_transactions RENAME TO fixture_unavailable_sp_logins`)
	got, err := selected.VerifyLinkedRecipient(f.ctx, x.request())
	if err != nil || got.LinkedUser() != "owner" {
		t.Fatal("signed unsolicited response did not locate the verified existing linked member", err)
	}
	if snapshot, err := got.Evidence(); err != nil || snapshot.ProviderSubject != expected.ProviderSubject || !snapshot.ValidUntil.Equal(originalCutoff) {
		t.Fatal("recipient lookup lost its original response/cutoff", err)
	}
	exec(`DELETE FROM identity_mfa.factor_authorities WHERE tenant_id=$1 AND user_id='owner'`, tenant)
	if got, err := selected.VerifyLinkedRecipient(f.ctx, x.request()); err == nil || got.LinkedUser() != "" {
		t.Fatal("missing factor state was treated as known-empty", err)
	}
	seedNativeCallbackJourneyFactors(t, providerLoginStartFixture{enable: x.enable, config: ssopg.ProviderLoginConfig{TenantID: tenant}}, "owner")
	exec(`DELETE FROM identity.account_credentials WHERE tenant_id=$1 AND credential_id='idp-credential'`, tenant)
	if got, err := selected.VerifyLinkedRecipient(f.ctx, x.request()); !errors.Is(err, sso.ErrForbidden) || got.LinkedUser() != "" {
		t.Fatal("missing linked credential inferred a recipient or JIT permission", err)
	}
	if got, err := service.VerifyLinkedRecipient(f.ctx, x.request()); !errors.Is(err, sso.ErrInvalidInput) || got.LinkedUser() != "" {
		t.Fatal("selecting policy mutated the original immutable service", err)
	}
}
