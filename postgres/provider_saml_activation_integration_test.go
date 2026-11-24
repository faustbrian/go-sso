//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func newProviderSAMLActivationFixture(t *testing.T) providerEnableFixture {
	t.Helper()
	return newProviderSAMLActivationFixtureForTenant(t, "org-test-basic")
}

func newProviderSAMLActivationFixtureForTenant(t *testing.T, tenant identity.TenantID) providerEnableFixture {
	t.Helper()
	return newProviderSAMLActivationFixtureWithBundle(t, tenant, nil)
}

func newProviderSAMLActivationFixtureWithBundle(t *testing.T, tenant identity.TenantID, signingBundle []byte) providerEnableFixture {
	t.Helper()
	f, base, config := newProviderFixtureForTenant(t, tenant, false,
		organizationpg.DomainClaimMigrationSource{Version: 316},
		organizationpg.DomainEvidenceMigrationSource{Version: 317})
	installProviderSAMLActivationHistory(t, f)
	f.domains = organization.DomainConfig{Version: 1, MaximumClaims: 5, EvidenceMaximumAge: time.Hour}
	var err error
	f.domainEvidence, err = organizationpg.NewDomainEvidenceSource(enableProofObserver{}, [32]byte{0x43})
	if err != nil {
		t.Fatal(err)
	}
	f.compose(t)
	base, err = base.WithSAMLRegistration("https://sso.example.com", validateSAMLRegistrationFixture)
	if err != nil {
		t.Fatal("select SAML registration", err)
	}
	registration := providerSAMLRegistrationRequest(t, "01ARZ3NDEKTSV4RRFFQ69G5FAV")
	registered, err := base.ProviderRegisterSaml(f.ctx, registration)
	if err != nil || registered.Completion.Outcome != identity.CommitOutcomeCommitted || registered.Provider.Enabled || registered.Provider.Version != 1 || registered.Provider.Protocol != "saml" {
		t.Fatal("register exact disabled SAML predecessor", err)
	}
	bundle := bytes.Clone(signingBundle)
	if bundle == nil {
		bundle = bytes.Repeat([]byte("fixture-activation-SP-signing/"), 2)
	}
	t.Cleanup(func() { clear(bundle) })
	certificateExpiry := time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond)
	base, err = base.WithSAMLSigningCredentialValidator(func(ctx context.Context, actual []byte, at time.Time) (time.Time, error) {
		if _, bounded := ctx.Deadline(); !bounded || ctx.Err() != nil || !bytes.Equal(actual, bundle) || !at.Before(certificateExpiry) {
			return time.Time{}, sso.ErrInvalidInput
		}
		return certificateExpiry, nil
	})
	if err != nil {
		t.Fatal("select SAML signing custody", err)
	}
	base, err = base.ForOrganization(registration.OrganizationID)
	if err != nil {
		t.Fatal(err)
	}
	credential := nativeSAMLSigningCredentialRequestForTenant(t, f, config, tenant, registered.Provider.ID, 1, 1, bundle)
	installed, err := nativeCredentialService(t, base).ProviderCredentialsRotate(f.ctx, credential)
	if err != nil || installed.Completion.Outcome != identity.CommitOutcomeCommitted || installed.Version != 2 || !installed.Active {
		t.Fatal("install encrypted SP signer on the disabled predecessor", err)
	}
	assertSAMLSigningCredentialState(t, f, registered.Provider.ID, "2", 1)
	proof := enableTestProofForTenant(t, f, tenant, registration.OrganizationID, registration.Domains[0], "test-saml-activation-domain", 1)
	service, err := base.WithProviderEnableAuthorization(enablePolicy{})
	if err != nil {
		t.Fatal(err)
	}
	service, err = service.WithProviderDisableAuthorization(providerDisablePolicy{})
	if err != nil {
		t.Fatal(err)
	}
	service, err = service.WithOAuthRegistration()
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := service.ObserveSAMLProviderCredentialCheckpoint(f.ctx, registered.Provider.ID, 2)
	if err != nil || checkpoint.Protocol() != "saml" {
		t.Fatal("observe exact current encrypted SAML signer", err)
	}
	binding, err := checkpoint.Bindings()
	if err != nil || binding.ProviderID != registered.Provider.ID || binding.ProviderVersion != 2 || binding.Generation != 1 || binding.ExpiresAt.After(certificateExpiry) {
		t.Fatal("SAML checkpoint lost exact signer generation or certificate cutoff", err)
	}
	key, err := identity.NewIdempotencyKey([]byte("original-saml-provider-enable"))
	if err != nil {
		t.Fatal(err)
	}
	request := sso.ProviderEnableRequest{
		ProviderID: registered.Provider.ID, ExpectedVersion: 2, CredentialCheckpoint: checkpoint, IdempotencyKey: key,
		DomainProofCheckpoint: sso.DomainProofCheckpoint{Key: organization.DomainProofKey(proof), ProofVersion: proof.ProofVersion},
	}
	return providerEnableFixture{f: f, base: base, service: service, config: config, proof: proof, request: request}
}

func TestNativeSAMLProviderActivationAndDisableRecoverExactSuccessors(t *testing.T) {
	x := newProviderSAMLActivationFixture(t)
	f, service, request := x.f, x.service, x.request
	var originalEnvelope, originalContext []byte
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT envelope,credential_context FROM sso_providers.credentials WHERE provider_id=$1`, request.ProviderID).Scan(&originalEnvelope, &originalContext); err != nil {
		t.Fatal(err)
	}
	enabled, err := service.ProviderEnable(f.ctx, request)
	if err != nil || enabled.Completion.Outcome != identity.CommitOutcomeCommitted || enabled.Completion.Binding.OperationID != "identity.sso.provider.enable" ||
		enabled.Provider.ID != request.ProviderID || enabled.Provider.OrganizationID != string(x.proof.OrganizationID) || enabled.Provider.Protocol != "saml" ||
		!enabled.Provider.Enabled || enabled.Provider.Version != 3 || enabled.Provider.MappingVersion != 3 || !reflect.DeepEqual(enabled.Provider.VerifiedDomains, []string{x.proof.Domain}) {
		t.Fatal("enable exact SAML provider with acknowledged proof and signer", err)
	}
	if retry, err := service.ProviderEnable(f.ctx, request); err != nil || !reflect.DeepEqual(enabled, retry) {
		t.Fatal("original activation key did not recover the exact enabled successor", err)
	}
	assertSAMLActivationProvider(t, x, enabled.Provider)
	disposition, err := sso.NewActiveTransactionDisposition(sso.ProviderID(request.ProviderID), 3, sso.ActiveTransactionRevoke)
	if err != nil {
		t.Fatal(err)
	}
	disable := sso.ProviderDisableRequest{
		ProviderID: request.ProviderID, ExpectedVersion: 3, Reason: "Stop new SAML enterprise sign-ins",
		ActiveTransactionDisposition: disposition,
	}
	for _, sibling := range []struct {
		name string
		call func(context.Context, sso.ProviderDisableRequest) (sso.ProviderDisableResult, error)
	}{{"oidc", service.ProviderDisable}, {"oauth2", service.ProviderDisableOAuth2}} {
		t.Run("reject-"+sibling.name+"-disable", func(t *testing.T) {
			if out, err := sibling.call(f.ctx, disable); err == nil || out.Disabled || out.Completion.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("sibling protocol selector disabled SAML", err)
			}
		})
	}
	disabled, err := service.ProviderDisableSAML(f.ctx, disable)
	if err != nil || disabled.Completion.Outcome != identity.CommitOutcomeCommitted || !disabled.Disabled || disabled.Deleted || disabled.ActiveTransactionCount != 0 ||
		disabled.Completion.Binding.OperationID != "identity.sso.provider.disable" || disabled.Completion.Binding.RecordID != request.ProviderID ||
		disabled.Completion.Feature == nil || disabled.Completion.Feature.BeforeVersion != 3 || disabled.Completion.Feature.AfterVersion != 4 {
		t.Fatal("disable exact enabled SAML predecessor", err)
	}
	if retry, err := service.ProviderDisableSAML(f.ctx, disable); err != nil || !reflect.DeepEqual(disabled, retry) {
		t.Fatal("same SAML disable did not recover its original receipt", err)
	}
	want := enabled.Provider
	want.Enabled, want.Version, want.VerifiedDomains = false, 4, []string{}
	assertSAMLActivationProvider(t, x, want)
	if retry, err := service.ProviderEnable(f.ctx, request); err != nil || !reflect.DeepEqual(enabled, retry) {
		t.Fatal("original activation key did not recover history after disablement", err)
	}
	assertSAMLActivationProvider(t, x, want)
	changed := disable
	changed.Reason = "A different SAML lifecycle reason"
	if out, err := service.ProviderDisableSAML(f.ctx, changed); !errors.Is(err, sso.ErrConflict) || out.Disabled {
		t.Fatal("different SAML intent recovered the original disablement", err)
	}
	for _, sibling := range []func(context.Context, sso.ProviderDisableRequest) (sso.ProviderDisableResult, error){service.ProviderDisable, service.ProviderDisableOAuth2} {
		if out, err := sibling(f.ctx, disable); err == nil || out.Disabled || out.Completion.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("sibling protocol selector recovered the SAML disable receipt", err)
		}
	}
	var version, credentialVersion, mode, predecessor, disableCommand string
	var enabledState, proofLinked, credentialLinked bool
	var envelope, credentialContext []byte
	var active, enables, disables, enableEvents, disableEvents, dispositions int
	err = f.pool.Raw().QueryRow(f.ctx, `SELECT p.metadata_version::text,p.enabled,p.enablement_proof IS NOT NULL,p.enablement_credential_generation IS NOT NULL,
 c.provider_version::text,c.envelope,c.credential_context,d.mode,d.provider_version::text,d.command_id,d.active_transaction_count,
 (SELECT count(*) FROM audit.records WHERE action='identity.sso.provider.enable' AND outcome=1),
 (SELECT count(*) FROM audit.records WHERE action='identity.sso.provider.disable' AND outcome=1),
 (SELECT count(*) FROM outbox_messages WHERE topic='sso.provider_enabled.v1'),
 (SELECT count(*) FROM outbox_messages WHERE topic='enterprise_provider.disabled.v1'),
 (SELECT count(*) FROM sso_providers.provider_login_dispositions)
 FROM sso_providers.providers p JOIN sso_providers.credentials c USING(tenant_id,organization_id,provider_id)
 JOIN sso_providers.provider_login_dispositions d USING(tenant_id,organization_id,provider_id)
 WHERE p.provider_id=$1`, request.ProviderID).Scan(&version, &enabledState, &proofLinked, &credentialLinked,
		&credentialVersion, &envelope, &credentialContext, &mode, &predecessor, &disableCommand, &active,
		&enables, &disables, &enableEvents, &disableEvents, &dispositions)
	if err != nil || version != "4" || enabledState || proofLinked || credentialLinked || credentialVersion != "2" ||
		!bytes.Equal(envelope, originalEnvelope) || !bytes.Equal(credentialContext, originalContext) || mode != string(sso.ActiveTransactionRevoke) || predecessor != "3" ||
		disableCommand != string(disabled.Completion.Binding.CommandID) || active != 0 || enables != 1 || disables != 1 || enableEvents != 1 || disableEvents != 1 || dispositions != 1 {
		t.Fatal("native SAML disable or replay changed custody, admission state or exactly-once lifecycle effects", err)
	}
	proof, err := x.config.Organizations.GetDomainProof(f.ctx, organization.DomainProofKey(x.proof))
	if err != nil || proof != x.proof {
		t.Fatal("SAML disable changed organization-owned domain proof", err)
	}
}

func TestNativeSAMLProviderActivationRejectsSiblingCheckpointsAndUnselectedService(t *testing.T) {
	x := newProviderSAMLActivationFixture(t)
	for _, observe := range []func(context.Context, string, uint64) (sso.CredentialCheckpoint, error){
		x.service.ObserveProviderCredentialCheckpoint, x.service.ObserveOAuth2ProviderCredentialCheckpoint,
	} {
		if checkpoint, err := observe(x.f.ctx, x.request.ProviderID, 2); err == nil || checkpoint.Protocol() != "" {
			t.Fatal("sibling protocol observation authenticated the installed SAML signer", err)
		}
	}
	binding, err := x.request.CredentialCheckpoint.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	for _, constructor := range []func(sso.CredentialCheckpointBinding) (sso.CredentialCheckpoint, error){sso.NewCredentialCheckpoint, sso.NewOAuth2CredentialCheckpoint} {
		wrong := x.request
		wrong.CredentialCheckpoint, err = constructor(binding)
		if err != nil {
			t.Fatal(err)
		}
		if out, err := x.service.ProviderEnable(x.f.ctx, wrong); err == nil || out.Provider.Enabled || out.Completion.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("sibling protocol checkpoint activated SAML", err)
		}
	}
	unselected, err := ssopg.NewProviderService(x.f.pool, x.config, x.f.auth(string(x.proof.TenantID), "owner"), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	unselected, err = unselected.ForOrganization(string(x.proof.OrganizationID))
	if err != nil {
		t.Fatal(err)
	}
	unselected, err = unselected.WithProviderEnableAuthorization(enablePolicy{})
	if err != nil {
		t.Fatal(err)
	}
	unselected, err = unselected.WithProviderDisableAuthorization(providerDisablePolicy{})
	if err != nil {
		t.Fatal(err)
	}
	if checkpoint, err := unselected.ObserveSAMLProviderCredentialCheckpoint(x.f.ctx, x.request.ProviderID, 2); !errors.Is(err, sso.ErrForbidden) || checkpoint.Protocol() != "" {
		t.Fatal("unselected service observed SAML signing authority", err)
	}
	if out, err := unselected.ProviderEnable(x.f.ctx, x.request); !errors.Is(err, sso.ErrForbidden) || out.Provider.Enabled || out.Completion.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("unselected service activated the SAML provider", err)
	}
	withoutSigner, err := unselected.WithSAMLRegistration("https://sso.example.com", validateSAMLRegistrationFixture)
	if err != nil {
		t.Fatal(err)
	}
	if checkpoint, err := withoutSigner.ObserveSAMLProviderCredentialCheckpoint(x.f.ctx, x.request.ProviderID, 2); !errors.Is(err, sso.ErrForbidden) || checkpoint.Protocol() != "" {
		t.Fatal("registration without a signing validator observed SAML signing authority", err)
	}
	if out, err := withoutSigner.ProviderEnable(x.f.ctx, x.request); !errors.Is(err, sso.ErrForbidden) || out.Provider.Enabled || out.Completion.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("registration without a signing validator activated SAML", err)
	}
	withoutDisable, err := x.base.WithProviderEnableAuthorization(enablePolicy{})
	if err != nil {
		t.Fatal(err)
	}
	if out, err := withoutDisable.ProviderEnable(x.f.ctx, x.request); !errors.Is(err, sso.ErrForbidden) || out.Provider.Enabled || out.Completion.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("SAML activated without a configured native disable owner", err)
	}
	otherOrigin, err := x.service.WithSAMLRegistration("https://other-origin.example", validateSAMLRegistrationFixture)
	if err != nil {
		t.Fatal(err)
	}
	if checkpoint, err := otherOrigin.ObserveSAMLProviderCredentialCheckpoint(x.f.ctx, x.request.ProviderID, 2); !errors.Is(err, sso.ErrForbidden) || checkpoint.Protocol() != "" {
		t.Fatal("a changed deployment origin observed the old signer's readiness", err)
	}
	changed := x.request
	changed.IdempotencyKey, err = identity.NewIdempotencyKey([]byte("enable-SAML-from-wrong-origin"))
	if err != nil {
		t.Fatal(err)
	}
	if out, err := otherOrigin.ProviderEnable(x.f.ctx, changed); !errors.Is(err, sso.ErrForbidden) || out.Provider.Enabled || out.Completion.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("a changed deployment origin activated the old SAML provider", err)
	}
	assertSAMLSigningCredentialState(t, x.f, x.request.ProviderID, "2", 1)
}

func TestNativeSAMLProviderActivationRejectsWrongDomainAndSignerGeneration(t *testing.T) {
	x := newProviderSAMLActivationFixture(t)
	wrongDomain := enableTestProof(t, x.f, string(x.proof.OrganizationID), "other.example.com", "test-saml-wrong-domain", 3)
	for _, name := range []string{"wrong-domain", "wrong-signer-generation"} {
		t.Run(name, func(t *testing.T) {
			request := x.request
			var err error
			request.IdempotencyKey, err = identity.NewIdempotencyKey([]byte("saml-activation-" + name))
			if err != nil {
				t.Fatal(err)
			}
			if name == "wrong-domain" {
				request.DomainProofCheckpoint = sso.DomainProofCheckpoint{Key: organization.DomainProofKey(wrongDomain), ProofVersion: wrongDomain.ProofVersion}
			} else {
				binding, err := request.CredentialCheckpoint.Bindings()
				if err != nil {
					t.Fatal(err)
				}
				binding.Generation++
				request.CredentialCheckpoint, err = sso.NewSAMLCredentialCheckpoint(binding)
				if err != nil {
					t.Fatal(err)
				}
			}
			if out, err := x.service.ProviderEnable(x.f.ctx, request); !errors.Is(err, sso.ErrForbidden) || out.Provider.Enabled || out.Completion.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("noncurrent SAML proof or signing generation activated provider", err)
			}
			assertSAMLSigningCredentialState(t, x.f, x.request.ProviderID, "2", 1)
		})
	}
}

func TestNativeSAMLProviderActivationFencesSignerExpiryAfterWriting(t *testing.T) {
	x := newProviderSAMLActivationFixture(t)
	f := x.f
	if _, err := f.pool.Raw().Exec(f.ctx, `CREATE SEQUENCE sso_providers.saml_enable_write_steps;
 CREATE TABLE sso_providers.saml_enable_cutoff (expires_at timestamptz NOT NULL);
 CREATE FUNCTION sso_providers.wait_for_saml_enable_expiry() RETURNS trigger LANGUAGE plpgsql AS $$
 BEGIN
   PERFORM nextval('sso_providers.saml_enable_write_steps');
   PERFORM pg_sleep_until((SELECT expires_at + interval '1 millisecond' FROM sso_providers.saml_enable_cutoff));
   PERFORM nextval('sso_providers.saml_enable_write_steps');
   RETURN NEW;
 END $$;
 CREATE TRIGGER wait_for_saml_enable_expiry BEFORE UPDATE OF enabled ON sso_providers.providers
 FOR EACH ROW WHEN (NEW.enabled AND NOT OLD.enabled)
 EXECUTE FUNCTION sso_providers.wait_for_saml_enable_expiry()`); err != nil {
		t.Fatal("install isolated cutoff-crossing test seam", err)
	}
	var expiry time.Time
	calls := 0
	selected, err := x.service.WithSAMLSigningCredentialValidator(func(ctx context.Context, signer []byte, at time.Time) (time.Time, error) {
		calls++
		if ctx.Err() != nil || len(signer) == 0 || !at.Before(expiry) {
			return time.Time{}, sso.ErrForbidden
		}
		return expiry, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = f.pool.Raw().QueryRow(f.ctx, `INSERT INTO sso_providers.saml_enable_cutoff(expires_at)
 VALUES(clock_timestamp()+interval '1 second') RETURNING expires_at`).Scan(&expiry); err != nil {
		t.Fatal(err)
	}
	expiry = expiry.UTC()
	observed, err := selected.ObserveSAMLProviderCredentialCheckpoint(f.ctx, x.request.ProviderID, 2)
	actual, shapeErr := observed.Bindings()
	earlier, earlierErr := x.request.CredentialCheckpoint.Bindings()
	if err != nil || shapeErr != nil || actual.ExpiresAt != expiry || earlierErr != nil || !expiry.Before(earlier.ExpiresAt) {
		t.Fatal("new observation did not retain the exact signer cutoff", err, shapeErr, earlierErr)
	}
	// A still-current, longer caller checkpoint cannot extend the installed
	// signer's shorter authoritative certificate lifetime.
	out, err := selected.ProviderEnable(f.ctx, x.request)
	var steps int64
	var crossed bool
	if readErr := f.pool.Raw().QueryRow(f.ctx, `SELECT last_value,is_called
 FROM sso_providers.saml_enable_write_steps`).Scan(&steps, &crossed); readErr != nil {
		t.Fatal("inspect cutoff crossing", readErr)
	}
	if calls != 2 || !crossed || steps != 2 || !errors.Is(err, sso.ErrForbidden) || out.Provider.Enabled || out.Completion.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("the expiry-crossing UPDATE did not fail at final admission", calls, steps, crossed, err)
	}
	var proof, generation bool
	var receipts, audits, events int
	if err = f.pool.Raw().QueryRow(f.ctx, `SELECT enablement_proof IS NOT NULL,enablement_credential_generation IS NOT NULL,
 (SELECT count(*) FROM sso_providers.enable_receipts),
 (SELECT count(*) FROM audit.records WHERE action='identity.sso.provider.enable' AND outcome=1),
 (SELECT count(*) FROM outbox_messages WHERE topic='sso.provider_enabled.v1')
 FROM sso_providers.providers WHERE provider_id=$1`, x.request.ProviderID).Scan(&proof, &generation, &receipts, &audits, &events); err != nil ||
		proof || generation || receipts != 0 || audits != 0 || events != 0 {
		t.Fatal("expiry left activation authority or success effects", err)
	}
	assertSAMLSigningCredentialState(t, f, x.request.ProviderID, "2", 1)
}

func TestNativeSAMLProviderActivationRetryDisableWithoutUsableSigner(t *testing.T) {
	x := newProviderSAMLActivationFixture(t)
	f := x.f
	enabled, err := x.service.ProviderEnable(f.ctx, x.request)
	if err != nil || !enabled.Provider.Enabled {
		t.Fatal("activate the exact signer before it becomes unavailable", err)
	}
	signerCalls := 0
	service, err := x.service.WithSAMLSigningCredentialValidator(func(context.Context, []byte, time.Time) (time.Time, error) {
		signerCalls++
		return time.Time{}, sso.ErrUnavailable
	})
	if err != nil {
		t.Fatal(err)
	}
	disposition, err := sso.NewActiveTransactionDisposition(sso.ProviderID(enabled.Provider.ID), enabled.Provider.Version, sso.ActiveTransactionRevoke)
	if err != nil {
		t.Fatal(err)
	}
	request := sso.ProviderDisableRequest{ProviderID: enabled.Provider.ID, ExpectedVersion: enabled.Provider.Version,
		Reason: "Disable the provider with no usable signer", ActiveTransactionDisposition: disposition}
	if _, err = f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION sso_providers.reject_saml_disable_outbox() RETURNS trigger LANGUAGE plpgsql AS $$
 BEGIN RAISE EXCEPTION 'controlled SAML disable outbox rollback'; END $$;
 CREATE TRIGGER reject_saml_disable_outbox BEFORE INSERT ON outbox_messages FOR EACH ROW
 WHEN (NEW.topic='enterprise_provider.disabled.v1') EXECUTE FUNCTION sso_providers.reject_saml_disable_outbox()`); err != nil {
		t.Fatal("install controlled native required-effect failure", err)
	}
	failed, err := service.ProviderDisableSAML(f.ctx, request)
	if err == nil || failed.Disabled || failed.Completion.Binding.CommandID == "" {
		t.Fatal("required effect failure did not retain its original failure", err)
	}
	original, _ := service.ProviderDisableSAML(f.ctx, request)
	if original.Disabled || original.Completion.Outcome != identity.CommitOutcomeNotCommitted || original.Completion.Binding != failed.Completion.Binding {
		t.Fatal("exact original failure was not confirmed", original.Completion.Outcome)
	}
	assertSAMLActivationProvider(t, x, enabled.Provider)
	if _, err = f.pool.Raw().Exec(f.ctx, `DROP TRIGGER reject_saml_disable_outbox ON outbox_messages`); err != nil {
		t.Fatal(err)
	}
	anchor := original.Completion.Binding.CommandID
	retried, err := service.RetryProviderDisableSAML(f.ctx, request, anchor)
	if err != nil || !retried.Disabled || retried.Completion.Outcome != identity.CommitOutcomeCommitted ||
		retried.Completion.Binding.CommandID == anchor || retried.Completion.Binding.RecordID != request.ProviderID || signerCalls != 0 {
		t.Fatal("exact retry did not disable the provider independently of signer usability", signerCalls, err)
	}
	if repeat, err := service.RetryProviderDisableSAML(f.ctx, request, anchor); err != nil || !reflect.DeepEqual(repeat, retried) || signerCalls != 0 {
		t.Fatal("exact retry did not recover the one disabled successor", signerCalls, err)
	}
	want := enabled.Provider
	want.Enabled, want.Version = false, 4
	assertSAMLActivationProvider(t, x, want)
}

func assertSAMLActivationProvider(t *testing.T, x providerEnableFixture, want sso.Provider) {
	t.Helper()
	// Get/List are safe administrative metadata, not current proof lookups.
	want.VerifiedDomains = []string{}
	read, err := x.service.ProviderGet(x.f.ctx, sso.ProviderGetRequest{OrganizationID: string(x.proof.OrganizationID), ProviderID: sso.ProviderID(x.request.ProviderID)})
	if err != nil || !reflect.DeepEqual(read.Provider, want) {
		t.Fatal("administrative read lost exact SAML lifecycle successor", err)
	}
	listed, err := x.service.ProviderList(x.f.ctx, sso.ProviderListRequest{OrganizationID: string(x.proof.OrganizationID), Limit: 2})
	if err != nil || len(listed.Providers) != 1 || listed.NextCursor != "" || !reflect.DeepEqual(listed.Providers[0], want) {
		t.Fatal("administrative list lost exact SAML lifecycle successor", err)
	}
}

func installProviderSAMLActivationHistory(t *testing.T, f *orgFixture) {
	t.Helper()
	config, err := pgx.ParseConfig(f.dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.Database = f.database
	db := stdlib.OpenDB(*config)
	defer db.Close()
	backend, err := migrationpg.New(db)
	if err != nil {
		t.Fatal(err)
	}
	history := append(migrationList(nil), f.history...)
	for _, source := range []migrations.Source{
		ssopg.ProviderUpdateMigrationSource{Version: 321},
		ssopg.ProviderCredentialsMigrationSource{Version: 322},
		ssopg.ProviderProtocolMigrationSource{Version: 323, ValidationVersion: 324},
		ssopg.ProviderSAMLProtocolMigrationSource{Version: 325, ValidationVersion: 326},
		ssopg.ProviderEnableMigrationSource{Version: 327},
		ssopg.LoginTransactionMigrationSource{Version: 328},
	} {
		loaded, err := source.Load(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		history = append(history, loaded...)
	}
	runner, err := migrations.NewRunner(history, backend)
	if err != nil {
		t.Fatal(err)
	}
	for range len(history) - len(f.history) {
		if _, err := runner.Up(f.ctx); err != nil {
			t.Fatal("install ordered native SAML activation and disposition history", err)
		}
	}
}
