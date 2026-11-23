//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestNativeDisabledSAMLProviderSigningCredentialInstallationAndOriginalRetry(t *testing.T) {
	f, legacy, config := newProviderFixtureWithUpdates(t, false)
	installSAMLProviderCredentialHistory(t, f)
	registrationOnly, err := legacy.WithSAMLRegistration("https://sso.example.com", validateSAMLRegistrationFixture)
	if err != nil {
		t.Fatal("select SAML registration", err)
	}
	registration := providerSAMLRegistrationRequest(t, "01ARZ3NDEKTSV4RRFFQ69G5FAV")
	created, err := registrationOnly.ProviderRegisterSaml(f.ctx, registration)
	if err != nil || created.Completion.Outcome != identity.CommitOutcomeCommitted || created.Provider.ID == "" || created.Provider.Protocol != "saml" || created.Provider.Enabled || created.Provider.Version != 1 {
		t.Fatal("register disabled SAML provider before installing SP signing custody", err)
	}
	var originalMetadata []byte
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT configuration_envelope FROM sso_providers.providers WHERE provider_id=$1`, created.Provider.ID).Scan(&originalMetadata); err != nil {
		t.Fatal(err)
	}
	if selected, err := registrationOnly.WithSAMLSigningCredentialValidator(nil); !errors.Is(err, sso.ErrInvalidInput) || selected != nil {
		t.Fatal("selected SAML signing custody without a validator", err)
	}

	firstBundle := bytes.Repeat([]byte("fixture-SP-signing-generation-one/"), 2)
	secondBundle := bytes.Repeat([]byte("fixture-SP-signing-generation-two/"), 2)
	expiredBundle := bytes.Repeat([]byte("fixture-expired-SP-signing/"), 2)
	defer clear(firstBundle)
	defer clear(secondBundle)
	defer clear(expiredBundle)
	certificateExpiry := time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond)
	var observations []time.Time
	validate := sso.SAMLSigningCredentialValidator(func(ctx context.Context, bundle []byte, at time.Time) (time.Time, error) {
		if deadline, bounded := ctx.Deadline(); !bounded || !time.Now().Before(deadline) || deadline.After(time.Now().Add(config.MaximumDuration)) {
			t.Error("signing validator did not receive the operation's bounded context")
			return time.Time{}, sso.ErrInvalidInput
		}
		if err := ctx.Err(); err != nil {
			return time.Time{}, err
		}
		if at.IsZero() || at != at.UTC().Truncate(time.Microsecond) || at.After(config.Clock.Now()) {
			t.Error("signing validator did not receive a canonical observed instant")
			return time.Time{}, sso.ErrInvalidInput
		}
		observations = append(observations, at)
		switch {
		case bytes.Equal(bundle, firstBundle), bytes.Equal(bundle, secondBundle):
			return certificateExpiry, nil
		case bytes.Equal(bundle, expiredBundle):
			return at, nil
		default:
			return time.Time{}, sso.ErrInvalidInput
		}
	})
	selected, err := registrationOnly.WithSAMLSigningCredentialValidator(validate)
	if err != nil {
		t.Fatal("select locally validated SAML signing custody", err)
	}
	selected, err = selected.ForOrganization(registration.OrganizationID)
	if err != nil {
		t.Fatal(err)
	}
	service := nativeCredentialService(t, selected)
	registrationOnly, err = registrationOnly.ForOrganization(registration.OrganizationID)
	if err != nil {
		t.Fatal(err)
	}
	withoutSigning := nativeCredentialService(t, registrationOnly)
	first := nativeSAMLSigningCredentialRequest(t, f, config, created.Provider.ID, 1, 1, firstBundle)
	if out, err := withoutSigning.ProviderCredentialsRotate(f.ctx, first); err == nil || out.Active || out.Completion.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("SAML registration alone authorized signing-credential installation", err)
	}
	if len(observations) != 0 {
		t.Fatal("selecting signing custody mutated the registration-only service")
	}
	for _, rejected := range []struct {
		name    string
		request sso.ProviderCredentialsRotateRequest
	}{
		{"oidc-substitution", nativeCredentialRequest(t, f, config, created.Provider.ID, 1, 1)},
		{"malformed-signing-bundle", nativeSAMLSigningCredentialRequest(t, f, config, created.Provider.ID, 1, 1, []byte("malformed-signing-material"))},
		{"expired-validator-cutoff", nativeSAMLSigningCredentialRequest(t, f, config, created.Provider.ID, 1, 1, expiredBundle)},
	} {
		t.Run(rejected.name, func(t *testing.T) {
			out, err := service.ProviderCredentialsRotate(f.ctx, rejected.request)
			if err == nil || out.Active || out.Completion.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("invalid signing ingress acquired durable authority", err)
			}
			assertSAMLSigningCredentialState(t, f, created.Provider.ID, "1", 0)
		})
	}
	if len(observations) < 2 {
		t.Fatal("native SAML custody skipped the malformed or expired bundle validator")
	}
	observations = nil
	installed, err := service.ProviderCredentialsRotate(f.ctx, first)
	if err != nil || installed.Completion.Outcome != identity.CommitOutcomeCommitted || installed.Completion.Binding.OperationID != "identity.sso.provider.credentials-rotate" || installed.ProviderID != first.ProviderID || installed.Version != 2 || !installed.Active || installed.ReconciliationRequired {
		t.Fatal("SAML signing installation did not commit the disabled provider successor", installed.Completion.Outcome, err)
	}
	if len(observations) == 0 {
		t.Fatal("native signing installation bypassed the selected wire validator")
	}
	for _, at := range observations {
		if first.CredentialReference.ValidateAt(at) != nil || !at.Before(certificateExpiry) {
			t.Fatal("signing validation did not retain the original ingress and certificate lifetime")
		}
	}
	assertSAMLSigningCredentialState(t, f, created.Provider.ID, "2", 1)
	second := nativeSAMLSigningCredentialRequest(t, f, config, created.Provider.ID, 2, 2, secondBundle)
	replaced, err := service.ProviderCredentialsRotate(f.ctx, second)
	if err != nil || replaced.Completion.Outcome != identity.CommitOutcomeCommitted || replaced.Version != 3 || !replaced.Active || replaced.ReconciliationRequired {
		t.Fatal("replacement did not advance the disabled SAML provider", err)
	}
	validationCallsBeforeRetry := len(observations)
	if retry, err := service.ProviderCredentialsRotate(f.ctx, first); err != nil || !reflect.DeepEqual(retry, installed) {
		t.Fatal("original signing-install retry did not recover its historical result", err)
	}
	if len(observations) != validationCallsBeforeRetry {
		t.Fatal("historical signing-install retry revalidated or renewed signing custody")
	}
	assertSAMLSigningCredentialState(t, f, created.Provider.ID, "3", 2)

	var storedWire, storedContext, metadata []byte
	var protocol, generation, credentialVersion string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT p.protocol,p.configuration_envelope,c.generation::text,c.provider_version::text,c.envelope,c.credential_context
 FROM sso_providers.providers p JOIN sso_providers.credentials c USING(tenant_id,organization_id,provider_id)
 WHERE p.provider_id=$1`, created.Provider.ID).Scan(&protocol, &metadata, &generation, &credentialVersion, &storedWire, &storedContext); err != nil || protocol != "saml" || generation != "2" || credentialVersion != "3" || !bytes.Equal(metadata, originalMetadata) {
		t.Fatal("signing custody changed protocol, metadata or the exact successor generation", err)
	}
	wantWire, err := second.CredentialReference.EncryptedEnvelope().MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	wantContext, err := json.Marshal(second.CredentialReference.Context())
	if err != nil || !bytes.Equal(storedWire, wantWire) || !bytes.Equal(storedContext, wantContext) || bytes.Contains(storedWire, secondBundle) {
		t.Fatal("durable SAML signing row did not preserve exact encrypted custody and binding", err)
	}
	sealed, err := envelope.ParseEnvelope(storedWire)
	if err != nil {
		t.Fatal(err)
	}
	aad, err := second.CredentialReference.Context().EncryptionContext()
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := config.Envelope.Decrypt(f.ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	defer clear(plaintext)
	if err != nil || !bytes.Equal(plaintext, secondBundle) {
		t.Fatal("durable SAML generation did not authenticate under its original SP-signing binding", err)
	}
	wantProvider := created.Provider
	wantProvider.Version = 3
	read, err := selected.ProviderGet(f.ctx, sso.ProviderGetRequest{OrganizationID: registration.OrganizationID, ProviderID: sso.ProviderID(created.Provider.ID)})
	if err != nil || !reflect.DeepEqual(read.Provider, wantProvider) {
		t.Fatal("signing credential installation enabled or changed safe provider metadata", err)
	}
	listed, err := selected.ProviderList(f.ctx, sso.ProviderListRequest{OrganizationID: registration.OrganizationID, Limit: 2})
	if err != nil || len(listed.Providers) != 1 || listed.NextCursor != "" || !reflect.DeepEqual(listed.Providers[0], wantProvider) {
		t.Fatal("safe list lost the disabled SAML provider successor", err)
	}
	for _, safe := range []any{read, listed, installed, replaced} {
		projection, err := json.Marshal(safe)
		if err != nil {
			t.Fatal("serialize safe SAML credential result", err)
		}
		for _, sensitive := range [][]byte{firstBundle, secondBundle, storedWire, []byte(base64.StdEncoding.EncodeToString(secondBundle)), []byte(base64.StdEncoding.EncodeToString(storedWire))} {
			if bytes.Contains(projection, sensitive) {
				t.Fatal("safe SAML provider or rotation result exposed signing custody")
			}
		}
	}
}

func TestNativeSAMLSigningCertificateExpiryFencesFinalCommit(t *testing.T) {
	f, base, config := newProviderFixtureWithUpdates(t, false)
	installSAMLProviderCredentialHistory(t, f)
	base, err := base.WithSAMLRegistration("https://sso.example.com", validateSAMLRegistrationFixture)
	if err != nil {
		t.Fatal(err)
	}
	registration := providerSAMLRegistrationRequest(t, "01ARZ3NDEKTSV4RRFFQ69G5FAV")
	created, err := base.ProviderRegisterSaml(f.ctx, registration)
	if err != nil || created.Completion.Outcome != identity.CommitOutcomeCommitted || created.Provider.Enabled {
		t.Fatal("register disabled SAML provider for final certificate admission", err)
	}
	bundle := bytes.Repeat([]byte("fixture-short-lived-SP-signing/"), 2)
	defer clear(bundle)
	var certificateExpiry time.Time
	validationCalls := 0
	base, err = base.WithSAMLSigningCredentialValidator(func(ctx context.Context, actual []byte, at time.Time) (time.Time, error) {
		validationCalls++
		if _, bounded := ctx.Deadline(); !bounded || ctx.Err() != nil || !bytes.Equal(actual, bundle) || !at.Before(certificateExpiry) {
			return time.Time{}, sso.ErrInvalidInput
		}
		return certificateExpiry, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	base, err = base.ForOrganization(registration.OrganizationID)
	if err != nil {
		t.Fatal(err)
	}
	service := nativeCredentialService(t, base)
	request := nativeSAMLSigningCredentialRequest(t, f, config, created.Provider.ID, 1, 1, bundle)

	// The sequence survives rollback, proving that the protected UPDATE reached
	// and crossed the original cutoff instead of passing through an early denial.
	if _, err := f.pool.Raw().Exec(f.ctx, `CREATE SEQUENCE sso_providers.signing_expiry_write_steps;
 CREATE TABLE sso_providers.signing_expiry_fixture (expires_at timestamptz NOT NULL);
 CREATE FUNCTION sso_providers.wait_for_signing_expiry() RETURNS trigger LANGUAGE plpgsql AS $$
 BEGIN
   PERFORM nextval('sso_providers.signing_expiry_write_steps');
   PERFORM pg_sleep_until((SELECT expires_at+interval '1 millisecond' FROM sso_providers.signing_expiry_fixture));
   PERFORM nextval('sso_providers.signing_expiry_write_steps');
   RETURN NEW;
 END $$;
 CREATE TRIGGER wait_for_signing_expiry BEFORE UPDATE OF metadata_version ON sso_providers.providers
 FOR EACH ROW EXECUTE FUNCTION sso_providers.wait_for_signing_expiry()`); err != nil {
		t.Fatal("install isolated database cutoff seam", err)
	}
	if err := f.pool.Raw().QueryRow(f.ctx, `INSERT INTO sso_providers.signing_expiry_fixture(expires_at)
 VALUES(clock_timestamp()+interval '1 second') RETURNING expires_at`).Scan(&certificateExpiry); err != nil {
		t.Fatal(err)
	}
	certificateExpiry = certificateExpiry.UTC().Truncate(time.Microsecond)
	out, operationErr := service.ProviderCredentialsRotate(f.ctx, request)
	var after time.Time
	var writeSteps int64
	var reachedWrite bool
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT clock_timestamp(),last_value,is_called
 FROM sso_providers.signing_expiry_write_steps`).Scan(&after, &writeSteps, &reachedWrite); err != nil {
		t.Fatal("observe protected write across the original certificate cutoff", err)
	}
	if validationCalls != 1 || !reachedWrite || writeSteps != 2 || after.Before(certificateExpiry) {
		t.Fatal("certificate cutoff was not crossed inside the protected write", validationCalls, reachedWrite, writeSteps)
	}
	if !errors.Is(operationErr, sso.ErrForbidden) || out.Active || out.ProviderID != "" || out.Completion.Outcome == identity.CommitOutcomeCommitted || out.ReconciliationRequired {
		t.Fatal("certificate expiry at final admission did not reject the successor", out.Completion.Outcome, operationErr)
	}
	assertSAMLSigningCredentialState(t, f, created.Provider.ID, "1", 0)
}

func nativeSAMLSigningCredentialRequest(t *testing.T, f *orgFixture, config ssopg.ProviderServiceConfig, provider string, version, generation uint64, bundle []byte) sso.ProviderCredentialsRotateRequest {
	t.Helper()
	return nativeSAMLSigningCredentialRequestForTenant(t, f, config, "org-test-basic", provider, version, generation, bundle)
}

func nativeSAMLSigningCredentialRequestForTenant(t *testing.T, f *orgFixture, config ssopg.ProviderServiceConfig, tenant identity.TenantID, provider string, version, generation uint64, bundle []byte) sso.ProviderCredentialsRotateRequest {
	t.Helper()
	var at time.Time
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
		t.Fatal(err)
	}
	at = at.UTC().Truncate(time.Microsecond)
	binding := sso.CredentialReferenceContext{
		TenantID: string(tenant), OrganizationID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", ProviderID: provider,
		Protocol: "saml", Purpose: "sp-signing-key", Generation: generation, ProviderVersion: version,
		Audience: "identity.sso.provider.credentials-rotate", EnvelopeKeyID: config.KeyReference,
		IssuedAt: at, ExpiresAt: at.Add(time.Minute),
	}
	aad, err := binding.EncryptionContext()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := config.Envelope.Encrypt(f.ctx, envelope.EncryptRequest{Plaintext: bundle, KeyReference: config.KeyReference, Context: aad})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := sealed.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	reference, err := sso.NewEncryptedCredentialReference(f.ctx, config.Envelope, wire, binding)
	if err != nil {
		t.Fatal("authenticate SAML SP-signing ingress", err)
	}
	return sso.ProviderCredentialsRotateRequest{
		CommandID: commandID(t), ProviderID: provider, ExpectedVersion: version,
		CredentialReference: reference, OverlapPolicy: sso.NewNoCredentialOverlapPolicy(),
	}
}

func assertSAMLSigningCredentialState(t *testing.T, f *orgFixture, provider, wantVersion string, wantEffects int) {
	t.Helper()
	var version string
	var enabled bool
	var credentials, effects, audits, events int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT metadata_version::text,enabled,
 (SELECT count(*) FROM sso_providers.credentials),
 (SELECT count(*) FROM sso_providers.credential_effects),
 (SELECT count(*) FROM audit.records WHERE action='identity.sso.provider.credentials-rotate' AND outcome=1),
 (SELECT count(*) FROM outbox_messages WHERE topic='sso.provider_credentials_rotated.v1')
 FROM sso_providers.providers WHERE provider_id=$1`, provider).Scan(&version, &enabled, &credentials, &effects, &audits, &events); err != nil {
		t.Fatal("read SAML signing custody and effects", err)
	}
	wantCredentials := 0
	if wantEffects > 0 {
		wantCredentials = 1
	}
	if version != wantVersion || enabled || credentials != wantCredentials || effects != wantEffects || audits != wantEffects || events != wantEffects {
		t.Fatal("SAML signing installation, rejection or retry changed disabled/exactly-once state", version, enabled, credentials, effects, audits, events)
	}
}

func installSAMLProviderCredentialHistory(t *testing.T, f *orgFixture) {
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
			t.Fatal("install ordered SAML credential and protocol history", err)
		}
	}
}
