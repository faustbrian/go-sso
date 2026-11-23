//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestNativeSAMLIDPArrivalCommitsOnlyPendingCustodyAndGrant(t *testing.T) {
	x := newNativeSAMLIDPAdmissionFixture(t)
	seedSAMLIDPLinkedRecipient(t, x)
	f, tenant := x.enable.f, x.enable.proof.TenantID
	installSAMLIDPStorage(t, f, ssopg.SAMLIDPConfirmationMigrationSource{Version: 392})
	installSAMLIDPStorage(t, f, migrationList{migrationBundle(t, 393, "native_saml_idp_capability", capabilitypg.Migrations(), "")})
	admissionConfig := ssopg.ProviderSAMLIDPAdmissionConfig{
		TenantID: tenant, Profiles: []ssopg.StaticSAMLIDPAdmissionProfile{{Provider: x.profile, MaximumAge: time.Minute}},
		Verify: func(ctx context.Context, input ssopg.SAMLIDPResponseVerificationInput) (ssopg.SAMLVerifiedResponse, error) {
			x.assertVerifierInput(t, ctx, input, time.Minute)
			return nativeSAMLIDPEvidence(input.Now), nil
		},
	}
	admission, err := ssopg.NewProviderSAMLIDPAdmissionService(x.router, admissionConfig)
	if err != nil {
		t.Fatal(err)
	}
	admission, err = admission.WithLinkedRecipientPolicy("users")
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0xa4}, 32)
	signer, err := capability.NewHMACSHA256Signer("idp-arrival-fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := capability.NewHMACSHA256Verifier(key)
	if err != nil {
		t.Fatal(err)
	}
	const issuerName = "https://identity.example.test"
	keys, err := capability.NewKeySet([]capability.Key{{Issuer: issuerName, ID: "idp-arrival-fixture", Verifier: verifier}})
	if err != nil {
		t.Fatal(err)
	}
	arrivalConfig := ssopg.ProviderSAMLIDPArrivalConfig{
		ActorID: "native-saml-arrival", PolicyID: "saml-idp-policy", PolicyVersion: 1, GlobalAuthorityID: "organization-tests",
		Coordinator: kernel.CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: 30 * time.Second, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {0xc1}},
			QueryPolicy: &kernel.CommandQueryPolicy{Authorization: idpFixtureQueryPolicy{}, Clock: clock.System{}, PolicyVersion: 1}},
		Capability: capabilitypg.IssuerConfig{
			Crypto:   capability.ServiceConfig{Issuer: issuerName, Signer: signer, Resolver: keys, Clock: func() time.Time { return time.Now().UTC() }, Limits: capability.DefaultLimits()},
			Audience: "identity", CurrentReplayKeyVersion: 1, RetainedReplayKeys: map[uint32][32]byte{1: {0xc2}}, PreparationTimeout: time.Second,
		},
		KeyReference: x.enable.config.KeyReference, CurrentConfirmationKey: 1, ConfirmationKeys: map[uint32][32]byte{1: {0xc3}}, AuditRetentionPolicyVersion: 1,
	}
	service, err := ssopg.NewProviderSAMLIDPArrivalService(admission, arrivalConfig)
	if err != nil {
		t.Fatal("compose native arrival", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `ALTER TABLE sso_providers.login_transactions RENAME TO fixture_unavailable_sp_logins`); err != nil {
		t.Fatal(err)
	}
	var existingSessions int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM organization_sessions.sessions`).Scan(&existingSessions); err != nil {
		t.Fatal("read the original session count", err)
	}
	result, err := service.Prepare(f.ctx, x.request())
	if err != nil || result.Outcome != identity.CommitOutcomeCommitted || result.CommandID == "" {
		t.Fatal("verified unsolicited arrival did not commit", result.Outcome, err)
	}
	browser, form, expiry, ok := result.TakeConfirmation()
	if !ok || len(browser.Token()) != 43 || len(form.Token()) != 43 || browser.Token() == form.Token() || !time.Now().Before(expiry) {
		t.Fatal("committed arrival did not disclose one independent browser pair")
	}
	if _, _, _, ok := result.TakeConfirmation(); ok {
		t.Fatal("the same arrival result disclosed the browser pair twice")
	}
	confirmation := ssopg.SAMLIDPConfirmationRequest{TenantID: tenant, ProviderID: x.profile.ProviderID, PendingID: result.CommandID,
		Origin: x.profile.TrustedOrigin, Browser: browser, Form: form}
	if err := ssopg.CheckSAMLIDPConfirmationInputForTest(f.ctx, service, confirmation); err != nil {
		t.Fatal("the original same-origin browser pair could not open committed custody", err)
	}
	for _, tc := range []struct {
		name   string
		change func(*ssopg.SAMLIDPConfirmationRequest)
	}{
		{"other tenant", func(r *ssopg.SAMLIDPConfirmationRequest) { r.TenantID = "foreign" }},
		{"other provider", func(r *ssopg.SAMLIDPConfirmationRequest) { r.ProviderID = "foreign" }},
		{"other origin", func(r *ssopg.SAMLIDPConfirmationRequest) { r.Origin = "https://foreign.example.test" }},
		{"swapped values", func(r *ssopg.SAMLIDPConfirmationRequest) { r.Browser, r.Form = r.Form, r.Browser }},
	} {
		request := confirmation
		tc.change(&request)
		if err := ssopg.CheckSAMLIDPConfirmationInputForTest(f.ctx, service, request); !errors.Is(err, sso.ErrForbidden) {
			t.Fatal("altered confirmation input did not fail closed", tc.name, err)
		}
	}
	query := identity.RecoveryQuery{CommandID: result.CommandID, TenantID: tenant, UserID: "owner", ActorID: "native-saml-arrival",
		ActorKind: authorization.SubjectServiceAccount, OperationID: kernel.SSOSAMLIDPArrivalOperation().OperationID, RecordID: string(result.CommandID)}
	decision := authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{
		Tenant: authorization.TenantID(tenant), Subject: authorization.Subject{ID: authorization.SubjectID(query.ActorID), Kind: query.ActorKind},
		Action: authorization.Action(query.OperationID), Resource: authorization.Resource{Type: "identity.user", ID: "owner"}}}
	recovered, err := service.RecoverArrival(f.ctx, query, decision)
	if _, _, _, ok := recovered.TakeConfirmation(); err != nil || ok || recovered.CommandID != result.CommandID || recovered.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("authorized recovery must observe the original receipt without re-disclosing the pair", recovered.Outcome, err)
	}
	query.UserID = "another-user"
	if recovered, err := service.RecoverArrival(f.ctx, query, decision); err == nil || recovered.CommandID != "" {
		t.Fatal("foreign recovery observed the original arrival", err)
	}
	assertNativeIDPArrivalCounts(t, f, 1, existingSessions)
	var sealed, browserDigest, formDigest []byte
	var subject string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT user_id,binding_envelope,browser_digest,form_digest FROM sso_providers.saml_idp_confirmations WHERE tenant_id=$1`, tenant).
		Scan(&subject, &sealed, &browserDigest, &formDigest); err != nil || subject != "owner" || len(sealed) == 0 || len(browserDigest) != 32 || len(formDigest) != 32 ||
		bytes.Equal(browserDigest, formDigest) || bytes.Contains(sealed, []byte(browser.Token())) || bytes.Contains(sealed, []byte(form.Token())) {
		t.Fatal("pending row retained raw browser custody or selected another user", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `ALTER TABLE public.capability_identity_one_use ADD CONSTRAINT fixture_force_grant_rollback CHECK(false) NOT VALID`); err != nil {
		t.Fatal(err)
	}
	rejected, err := service.Prepare(f.ctx, x.request())
	if _, _, _, ok := rejected.TakeConfirmation(); err == nil || ok || rejected.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("failed grant issuance exposed pending credentials or reported commit", rejected.Outcome, err)
	}
	assertNativeIDPArrivalCounts(t, f, 1, existingSessions)

	if _, err := f.pool.Raw().Exec(f.ctx, `ALTER TABLE public.capability_identity_one_use DROP CONSTRAINT fixture_force_grant_rollback`); err != nil {
		t.Fatal(err)
	}
	// The existing fixture drops the successful PostgreSQL COMMIT response
	// only after observing the actual pending write on this isolated pool.
	lossyPool, fault := providerLossPool(t, f, "INSERT INTO sso_providers.saml_idp_confirmations")
	lossyFixture := *f
	lossyFixture.pool = lossyPool
	lossyEnable := x.enable
	lossyEnable.f = &lossyFixture
	lossyRouter, err := newProviderRouter(t, lossyEnable, 4).WithProtocolRegistry()
	if err != nil {
		t.Fatal(err)
	}
	lossyRouter, err = lossyRouter.WithSAMLRouteValidation(func(_ context.Context, bundle []byte, at time.Time) (time.Time, error) {
		if !bytes.Equal(bundle, bytes.Repeat([]byte("fixture-activation-SP-signing/"), 2)) || !at.Before(x.routeExpiry) {
			return time.Time{}, sso.ErrInvalidInput
		}
		return x.routeExpiry, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	lossyAdmission, err := ssopg.NewProviderSAMLIDPAdmissionService(lossyRouter, admissionConfig)
	if err != nil {
		t.Fatal(err)
	}
	lossyAdmission, err = lossyAdmission.WithLinkedRecipientPolicy("users")
	if err != nil {
		t.Fatal(err)
	}
	lossyService, err := ssopg.NewProviderSAMLIDPArrivalService(lossyAdmission, arrivalConfig)
	if err != nil {
		t.Fatal(err)
	}
	unconfirmed, err := lossyService.Prepare(f.ctx, x.request())
	var uncertain identity.UnknownCommitError
	if _, _, _, disclosed := unconfirmed.TakeConfirmation(); !fault.seen.Load() || !fault.lost.Load() || disclosed || unconfirmed.CommandID == "" ||
		unconfirmed.Outcome != identity.CommitOutcomeUnknown || !errors.As(err, &uncertain) || uncertain.CommandID != unconfirmed.CommandID {
		t.Fatal("lost acknowledgement did not return the original unknown receipt without browser values", unconfirmed.Outcome, err)
	}
	assertNativeIDPArrivalCounts(t, f, 2, existingSessions)
	query.UserID, query.CommandID, query.RecordID = "owner", unconfirmed.CommandID, string(unconfirmed.CommandID)
	ack, err := service.RecoverArrival(f.ctx, query, decision)
	if _, _, _, disclosed := ack.TakeConfirmation(); err != nil || disclosed || ack.CommandID != unconfirmed.CommandID || ack.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("lost acknowledgement did not recover exactly the committed receipt without browser values", ack.Outcome, err)
	}
	assertNativeIDPArrivalCounts(t, f, 2, existingSessions)

	for _, mode := range []string{"fenced absence", "conflicting grant"} {
		q, grant, err := ssopg.ReserveSAMLIDPArrivalWithoutApplyingForTest(f.ctx, service, x.request())
		if err != nil {
			t.Fatal("reserve without attempting either mutation", err)
		}
		live, err := service.RecoverArrival(f.ctx, q, decision)
		if live.Outcome != identity.CommitOutcomeInProgress || err != nil {
			t.Fatal("live reservation was not left in progress", live.Outcome, err)
		}
		if tag, err := f.pool.Raw().Exec(f.ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 millisecond'
 WHERE tenant_id=$1 AND purpose=$2 AND command_id=decode(translate($3,'-_','+/')||'==','base64')`, string(q.TenantID), q.OperationID, string(q.CommandID)); err != nil || tag.RowsAffected() != 1 {
			t.Fatal("age only the isolated fixture reservation", err)
		}
		if mode == "conflicting grant" {
			// Same original ID but not the sealed origin or replay commitment:
			// the exact-match probe misses, but absence is not proven.
			digest := [32]byte{0xd4}
			if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO public.capability_identity_one_use
 (tenant_id,purpose,replay_key_version,replay_digest,capability_id,proof_fingerprint,expires_at,max_uses)
 VALUES($1,$2,$3,$4,$5,$6,$7,1)`, string(q.TenantID), string(grant.Purpose), int64(grant.ReplayKeyVersion), digest[:], grant.CapabilityID, digest[:], grant.ExpiresAt); err != nil {
				t.Fatal("install contradictory fixture evidence", err)
			}
		}
		recovered, err := service.RecoverArrival(f.ctx, q, decision)
		if _, _, _, disclosed := recovered.TakeConfirmation(); disclosed {
			t.Fatal("recovery exposed browser values", mode)
		}
		var unknown identity.UnknownCommitError
		var journalState string
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT state FROM identity.commands
 WHERE tenant_id=$1 AND purpose=$2 AND command_id=decode(translate($3,'-_','+/')||'==','base64')`,
			string(q.TenantID), q.OperationID, string(q.CommandID)).Scan(&journalState); err != nil {
			t.Fatal("read recovery journal state", err)
		}
		if mode == "conflicting grant" {
			if recovered.Outcome != identity.CommitOutcomeUnknown || !errors.As(err, &unknown) || unknown.CommandID != q.CommandID || journalState != "pending" {
				t.Fatal("conflicting primary evidence did not remain unknown and pending", recovered.Outcome, journalState, err)
			}
		} else if recovered.Outcome != identity.CommitOutcomeNotCommitted || errors.As(err, &unknown) || journalState != "aborted" {
			t.Fatal("unanimous absence did not recover a definite non-commit", recovered.Outcome, journalState, err)
		}
	}
}

type idpFixtureQueryPolicy struct{}

func (idpFixtureQueryPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if ctx.Err() != nil {
		return authorization.Decision{}, ctx.Err()
	}
	return authorization.Decision{Outcome: authorization.Allow, Revision: c.PolicyRevision}, nil
}

func assertNativeIDPArrivalCounts(t *testing.T, f *orgFixture, want, existingSessions int) {
	t.Helper()
	var records, grants, sessions, confirmations int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT count(*) FROM sso_providers.saml_idp_confirmations),
 (SELECT count(*) FROM public.capability_identity_one_use WHERE purpose='identity.sso.saml-idp-init'),
 (SELECT count(*) FROM organization_sessions.sessions),
 (SELECT count(*) FROM identity.commands WHERE purpose='identity.sso.saml-idp-init')`).Scan(&records, &grants, &sessions, &confirmations); err != nil || records != want || grants != want || sessions != existingSessions || confirmations != 0 {
		t.Fatal("pending arrival and grant were not atomic or a session was issued", records, grants, sessions, confirmations, err)
	}
}
