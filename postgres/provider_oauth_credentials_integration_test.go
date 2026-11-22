//go:build integration

package postgres_test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"testing"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestNativeDisabledOAuthProviderCredentialInstallationAndOriginalRetry(t *testing.T) {
	f, legacy, config := newProviderFixtureWithUpdates(t, false)
	installOAuthProviderCredentialHistory(t, f)
	selected, err := legacy.WithOAuthRegistration()
	if err != nil {
		t.Fatal("select migrated OAuth registry", err)
	}
	registration := providerOAuthRegistrationRequest(t, "01ARZ3NDEKTSV4RRFFQ69G5FAV")
	created, err := selected.ProviderRegisterOauth(f.ctx, registration)
	if err != nil || created.Completion.Outcome != identity.CommitOutcomeCommitted || created.Provider.ID == "" || created.Provider.Protocol != "oauth2" || created.Provider.Enabled || created.Provider.Version != 1 {
		t.Fatal("register real disabled OAuth provider", err)
	}
	selected, err = selected.ForOrganization(registration.OrganizationID)
	if err != nil {
		t.Fatal(err)
	}
	service := nativeCredentialService(t, selected)
	legacy, err = legacy.ForOrganization(registration.OrganizationID)
	if err != nil {
		t.Fatal(err)
	}
	legacyCredentials := nativeCredentialService(t, legacy)

	oidc := nativeCredentialRequest(t, f, config, created.Provider.ID, 1, 1)
	if out, err := service.ProviderCredentialsRotate(f.ctx, oidc); err == nil || out.Active || out.Completion.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("OIDC-bound ingress substituted for OAuth provider credentials", err)
	}
	binding := oidc.CredentialReference.Context()
	binding.Protocol = "oauth2"
	aad, err := binding.EncryptionContext()
	if err != nil {
		t.Fatal(err)
	}
	secret := make([]byte, 32)
	if _, err = rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	defer clear(secret)
	sealed, err := config.Envelope.Encrypt(f.ctx, envelope.EncryptRequest{Plaintext: secret, KeyReference: config.KeyReference, Context: aad})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := sealed.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	reference, err := sso.NewEncryptedCredentialReference(f.ctx, config.Envelope, wire, binding)
	if err != nil {
		t.Fatal("authenticate exact OAuth ingress binding", err)
	}
	request := sso.ProviderCredentialsRotateRequest{
		CommandID: commandID(t), ProviderID: created.Provider.ID, ExpectedVersion: 1,
		CredentialReference: reference, OverlapPolicy: sso.NewNoCredentialOverlapPolicy(),
	}
	if out, err := legacyCredentials.ProviderCredentialsRotate(f.ctx, request); err == nil || out.Active || out.Completion.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("legacy opt-out installed OAuth credentials", err)
	}
	var beforeVersion string
	var beforeCredentials, beforeEffects, beforeAudits, beforeEvents int
	if err = f.pool.Raw().QueryRow(f.ctx, `SELECT metadata_version::text,
 (SELECT count(*) FROM sso_providers.credentials),
 (SELECT count(*) FROM sso_providers.credential_effects),
 (SELECT count(*) FROM audit.records WHERE action='identity.sso.provider.credentials-rotate' AND outcome=1),
 (SELECT count(*) FROM outbox_messages WHERE topic='sso.provider_credentials_rotated.v1')
 FROM sso_providers.providers WHERE provider_id=$1`, request.ProviderID).Scan(&beforeVersion, &beforeCredentials, &beforeEffects, &beforeAudits, &beforeEvents); err != nil || beforeVersion != "1" || beforeCredentials != 0 || beforeEffects != 0 || beforeAudits != 0 || beforeEvents != 0 {
		t.Fatal("rejected protocol/profile ingress changed credential state", beforeVersion, beforeCredentials, beforeEffects, beforeAudits, beforeEvents, err)
	}
	first, err := service.ProviderCredentialsRotate(f.ctx, request)
	if err != nil || first.Completion.Outcome != identity.CommitOutcomeCommitted || first.ProviderID != request.ProviderID || first.Version != 2 || !first.Active || first.ReconciliationRequired {
		t.Fatal("OAuth credential installation did not commit the exact successor", first.Completion.Outcome, err)
	}
	retry, err := service.ProviderCredentialsRotate(f.ctx, request)
	if err != nil || !reflect.DeepEqual(retry, first) {
		t.Fatal("original OAuth credential retry changed its retained result", err)
	}
	var storedWire, storedContext []byte
	var protocol, version, generation, credentialVersion string
	var enabled bool
	var credentials, effects, audits, events int
	if err = f.pool.Raw().QueryRow(f.ctx, `SELECT p.protocol,p.metadata_version::text,p.enabled,
 c.generation::text,c.provider_version::text,c.envelope,c.credential_context,
 (SELECT count(*) FROM sso_providers.credentials),
 (SELECT count(*) FROM sso_providers.credential_effects),
 (SELECT count(*) FROM audit.records WHERE action='identity.sso.provider.credentials-rotate' AND outcome=1),
 (SELECT count(*) FROM outbox_messages WHERE topic='sso.provider_credentials_rotated.v1')
 FROM sso_providers.providers p JOIN sso_providers.credentials c USING(tenant_id,organization_id,provider_id)
 WHERE p.provider_id=$1`, request.ProviderID).Scan(&protocol, &version, &enabled, &generation, &credentialVersion, &storedWire, &storedContext, &credentials, &effects, &audits, &events); err != nil || protocol != "oauth2" || version != "2" || enabled || generation != "1" || credentialVersion != "2" || credentials != 1 || effects != 1 || audits != 1 || events != 1 {
		t.Fatal("OAuth installation/retry lost protocol, disabled state or exactly-once effects", protocol, version, generation, credentialVersion, credentials, effects, audits, events, err)
	}
	wantContext, err := json.Marshal(binding)
	if err != nil || !bytes.Equal(storedWire, wire) || !bytes.Equal(storedContext, wantContext) || bytes.Contains(storedWire, secret) {
		t.Fatal("persisted OAuth credential did not retain the exact encrypted generation and context", err)
	}
	persisted, err := envelope.ParseEnvelope(storedWire)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := config.Envelope.Decrypt(f.ctx, envelope.DecryptRequest{Envelope: persisted, Context: aad})
	defer clear(plaintext)
	if err != nil || !bytes.Equal(plaintext, secret) {
		t.Fatal("persisted generation did not authenticate under its exact OAuth binding", err)
	}
	wantProvider := created.Provider
	wantProvider.Version = 2
	read, err := selected.ProviderGet(f.ctx, sso.ProviderGetRequest{OrganizationID: registration.OrganizationID, ProviderID: sso.ProviderID(request.ProviderID)})
	if err != nil || !reflect.DeepEqual(read.Provider, wantProvider) {
		t.Fatal("credential installation changed safe disabled OAuth metadata", err)
	}
	listed, err := selected.ProviderList(f.ctx, sso.ProviderListRequest{OrganizationID: registration.OrganizationID, Limit: 2})
	if err != nil || len(listed.Providers) != 1 || listed.NextCursor != "" || !reflect.DeepEqual(listed.Providers[0], wantProvider) {
		t.Fatal("safe list did not preserve disabled OAuth successor", err)
	}
	for _, metadata := range []any{read, listed, first} {
		projection, err := json.Marshal(metadata)
		if err != nil {
			t.Fatal("serialize safe credential/provider result", err)
		}
		for _, sensitive := range [][]byte{secret, wire, []byte(base64.StdEncoding.EncodeToString(secret)), []byte(base64.StdEncoding.EncodeToString(wire))} {
			if bytes.Contains(projection, sensitive) {
				t.Fatal("safe credential/provider result exposed secret custody")
			}
		}
	}
}

func TestNativeOIDCEnableRejectsOAuth2CheckpointForSameCredential(t *testing.T) {
	x := newProviderEnableFixture(t)
	request := x.request
	binding, err := request.CredentialCheckpoint.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	request.CredentialCheckpoint, err = sso.NewOAuth2CredentialCheckpoint(binding)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := x.service.ProviderEnable(x.f.ctx, request); err == nil || out.Completion.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("OAuth checkpoint substituted for the exact OIDC credential", err)
	}
	if out, err := x.service.ProviderEnable(x.f.ctx, x.request); err != nil || out.Completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("denied protocol substitution displaced the original OIDC transition", err)
	}
}

func installOAuthProviderCredentialHistory(t *testing.T, f *orgFixture) {
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
		if _, err = runner.Up(f.ctx); err != nil {
			t.Fatal("install ordered credential and protocol migrations", err)
		}
	}
}
