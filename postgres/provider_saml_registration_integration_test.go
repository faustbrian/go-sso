//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"math/big"
	"reflect"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestNativeDisabledSAMLProviderRegistrationReadAndOriginalRetry(t *testing.T) {
	f, legacy, _ := newProviderFixture(t)
	oidcRequest := providerRequest(t, "https://existing-oidc.example.com", "oidc-before-saml-registration")
	oidc, err := legacy.ProviderRegisterOidc(f.ctx, oidcRequest)
	if err != nil || oidc.Completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("seed genuine OIDC provider before SAML expansion", err)
	}
	installProviderProtocolHistory(t, f)
	mixed, err := legacy.WithOAuthRegistration()
	if err != nil {
		t.Fatal("select upgraded OIDC and OAuth reader", err)
	}
	oauth, err := mixed.ProviderRegisterOauth(f.ctx, providerOAuthRegistrationRequest(t, oidcRequest.OrganizationID))
	if err != nil || oauth.Completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("seed genuine OAuth provider before SAML expansion", err)
	}
	installSAMLProviderRegistrationHistory(t, f)
	request := providerSAMLRegistrationRequest(t, oidcRequest.OrganizationID)
	if denied, err := mixed.ProviderRegisterSaml(f.ctx, request); !errors.Is(err, sso.ErrForbidden) || denied.Provider.ID != "" || denied.Completion.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("unselected SAML registration granted provider authority", err)
	}
	if selected, err := mixed.WithSAMLRegistration("https://sso.example.com", nil); !errors.Is(err, sso.ErrInvalidInput) || selected != nil {
		t.Fatal("SAML registration was enabled without an installed validation port", err)
	}
	service, err := mixed.WithSAMLRegistration("https://sso.example.com", validateSAMLRegistrationFixture)
	if err != nil {
		t.Fatal("select native SAML registration with trusted external origin", err)
	}
	if denied, err := mixed.ProviderRegisterSaml(f.ctx, request); !errors.Is(err, sso.ErrForbidden) || denied.Provider.ID != "" {
		t.Fatal("selecting SAML changed the original service", err)
	}

	invalid := request
	invalid.CommandID = commandID(t)
	invalid.IdempotencyKey, err = identity.NewIdempotencyKey([]byte("invalid-native-saml-certificate"))
	if err != nil {
		t.Fatal(err)
	}
	invalid.Configuration, err = sso.NewSAMLConfiguration(sso.SAMLConfigurationSpec{
		EntityID: "urn:example:invalid-idp", RedirectEndpoint: "https://idp.example.com/saml/redirect",
		SigningCertificates: [][]byte{[]byte("not-a-DER-certificate")},
	})
	if err != nil || invalid.Validate() != nil {
		t.Fatal("bounded root shape must leave actual certificate validation to native registration", err)
	}
	if denied, err := service.ProviderRegisterSaml(f.ctx, invalid); !errors.Is(err, sso.ErrInvalidInput) || denied.Provider.ID != "" || denied.Completion.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("native SAML registration accepted malformed certificate DER", err)
	}
	assertSAMLRegistrationEffects(t, f, 2, 2, 0, 2)

	got, err := service.ProviderRegisterSaml(f.ctx, request)
	if err != nil || got.Completion.Outcome != identity.CommitOutcomeCommitted || got.Completion.Binding.OperationID != "identity.sso.provider.register-saml" ||
		got.Provider.ID == "" || got.Provider.OrganizationID != request.OrganizationID || got.Provider.Protocol != "saml" ||
		got.Provider.Enabled || got.Provider.Version != 1 || got.Provider.MappingVersion != 3 ||
		len(got.Provider.VerifiedDomains) != 0 || got.VerificationRequirementCount != 1 {
		t.Fatal("SAML registration did not commit one disabled provider with pending domain verification", err)
	}
	if replay, err := service.ProviderRegisterSaml(f.ctx, request); err != nil || !reflect.DeepEqual(replay, got) {
		t.Fatal("original keyed retry did not recover the exact SAML registration", err)
	}
	spec, err := request.Configuration.Spec()
	if err != nil {
		t.Fatal(err)
	}
	changed := request
	changedSpec := spec
	changedSpec.RedirectEndpoint = "https://idp.example.com/changed-redirect"
	changed.Configuration, err = sso.NewSAMLConfiguration(changedSpec)
	if err != nil {
		t.Fatal(err)
	}
	if rejected, err := service.ProviderRegisterSaml(f.ctx, changed); !errors.Is(err, sso.ErrConflict) || rejected.Provider.ID != "" || rejected.Completion.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("changed configuration under the original key replaced SAML registration intent", err)
	}
	foreign := request
	foreign.CommandID = commandID(t)
	foreign.OrganizationID = "foreign-organization"
	foreign.IdempotencyKey, err = identity.NewIdempotencyKey([]byte("foreign-native-saml-registration"))
	if err != nil {
		t.Fatal(err)
	}
	if rejected, err := service.ProviderRegisterSaml(f.ctx, foreign); !errors.Is(err, sso.ErrForbidden) || rejected.Provider.ID != "" || rejected.Completion.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("SAML registration crossed organization authority", err)
	}
	if denied, err := service.ProviderGet(f.ctx, sso.ProviderGetRequest{OrganizationID: foreign.OrganizationID, ProviderID: sso.ProviderID(got.Provider.ID)}); !errors.Is(err, sso.ErrForbidden) || denied.Provider.ID != "" {
		t.Fatal("foreign organization read exposed SAML provider metadata", err)
	}

	for _, original := range []sso.Provider{oidc.Provider, oauth.Provider, got.Provider} {
		read, err := service.ProviderGet(f.ctx, sso.ProviderGetRequest{OrganizationID: original.OrganizationID, ProviderID: sso.ProviderID(original.ID)})
		if err != nil || !reflect.DeepEqual(read.Provider, original) {
			t.Fatal("upgraded safe read changed registered provider metadata", original.Protocol, err)
		}
	}
	page, err := service.ProviderList(f.ctx, sso.ProviderListRequest{OrganizationID: request.OrganizationID, Limit: 3})
	if err != nil || len(page.Providers) != 3 || page.NextCursor != "" {
		t.Fatal("safe provider listing lost an installed protocol", err)
	}
	listed := make(map[string]sso.Provider, len(page.Providers))
	for _, provider := range page.Providers {
		listed[provider.ID] = provider
	}
	for _, original := range []sso.Provider{oidc.Provider, oauth.Provider, got.Provider} {
		if !reflect.DeepEqual(listed[original.ID], original) {
			t.Fatal("safe listing reinterpreted provider protocol or metadata", original.Protocol)
		}
	}
	var protocol string
	var ciphertext []byte
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT protocol,configuration_envelope FROM sso_providers.providers WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`,
		"org-test-basic", request.OrganizationID, got.Provider.ID).Scan(&protocol, &ciphertext); err != nil || protocol != "saml" || len(ciphertext) == 0 ||
		bytes.Contains(ciphertext, []byte(spec.EntityID)) || bytes.Contains(ciphertext, []byte(spec.RedirectEndpoint)) || bytes.Contains(ciphertext, spec.SigningCertificates[0]) {
		t.Fatal("native SAML configuration was misclassified, absent or persisted in plaintext", err)
	}
	assertSAMLRegistrationEffects(t, f, 3, 3, 1, 3)
}

func TestNativeSAMLProviderRegistrationLostCommitRecoversOriginalOnly(t *testing.T) {
	f, normal, config := newProviderFixture(t)
	installProviderProtocolHistory(t, f)
	installSAMLProviderRegistrationHistory(t, f)
	const origin = "https://sso.example.com"
	var err error
	normal, err = normal.WithSAMLRegistration(origin, validateSAMLRegistrationFixture)
	if err != nil {
		t.Fatal(err)
	}
	lossy, fault := providerLossService(t, f, config, "INSERT INTO sso_providers.providers")
	lossy, err = lossy.WithSAMLRegistration(origin, validateSAMLRegistrationFixture)
	if err != nil {
		t.Fatal(err)
	}
	organizationID := providerRequest(t, "https://unused.example.com", "registration-organization").OrganizationID
	request := providerSAMLRegistrationRequest(t, organizationID)
	uncertain, err := lossy.ProviderRegisterSaml(f.ctx, request)
	var unknown identity.UnknownCommitError
	if !fault.lost.Load() || !errors.As(err, &unknown) || uncertain.Completion.Outcome != identity.CommitOutcomeUnknown || uncertain.Provider.ID != "" {
		t.Fatal("unacknowledged registration disclosed a provider or lost its original receipt", uncertain.Completion.Outcome, err)
	}
	assertSAMLRegistrationEffects(t, f, 1, 1, 1, 1)
	for range 2 {
		confirmed, err := normal.ProviderRegisterSaml(f.ctx, request)
		if err != nil || confirmed.Completion.Outcome != identity.CommitOutcomeCommitted || confirmed.Completion.Binding != uncertain.Completion.Binding || confirmed.Provider.ID != uncertain.Completion.Binding.RecordID || confirmed.Provider.Protocol != "saml" || confirmed.Provider.Enabled {
			t.Fatal("could not recover the original disabled SAML provider", confirmed.Completion.Outcome, err)
		}
	}
	assertSAMLRegistrationEffects(t, f, 1, 1, 1, 1)
}

// This checks the storage boundary's I/O-free selection without importing a
// protocol module into the persistence graph. The optional SAML module tests
// the full wire implementation of the same port independently.
func validateSAMLRegistrationFixture(ctx context.Context, _, _ string, signingCertificates [][]byte) error {
	if _, bounded := ctx.Deadline(); !bounded {
		return errors.New("registration validator was not given a deadline")
	}
	for _, der := range signingCertificates {
		if _, err := x509.ParseCertificate(der); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func providerSAMLRegistrationRequest(t *testing.T, organizationID string) sso.ProviderRegisterSamlRequest {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	configuration, err := sso.NewSAMLConfiguration(sso.SAMLConfigurationSpec{
		EntityID: "urn:example:enterprise-idp", RedirectEndpoint: "https://idp.example.com/saml/redirect?tenant=enterprise",
		SigningCertificates: [][]byte{der},
	})
	if err != nil {
		t.Fatal(err)
	}
	mapping, err := sso.NewAttributeMapping(sso.AttributeMappingSpec{Version: 3, SubjectClaim: "name_id"})
	if err != nil {
		t.Fatal(err)
	}
	idempotencyKey, err := identity.NewIdempotencyKey([]byte("original-native-saml-registration"))
	if err != nil {
		t.Fatal(err)
	}
	return sso.ProviderRegisterSamlRequest{
		CommandID: commandID(t), OrganizationID: organizationID, Configuration: configuration,
		Domains: []string{"example.com"}, Mapping: mapping, IdempotencyKey: idempotencyKey,
	}
}

func assertSAMLRegistrationEffects(t *testing.T, f *orgFixture, wantProviders, wantEffects, wantAudits, wantEvents int) {
	t.Helper()
	var providers, effects, audits, events int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT count(*) FROM sso_providers.providers),
 (SELECT count(*) FROM sso_providers.command_effects),
 (SELECT count(*) FROM audit.records WHERE action='identity.sso.provider.register-saml' AND outcome=1),
 (SELECT count(*) FROM outbox_messages WHERE topic='sso.provider_registered.v1')`).Scan(&providers, &effects, &audits, &events); err != nil {
		t.Fatal("read native SAML registration effects", err)
	}
	if providers != wantProviders || effects != wantEffects || audits != wantAudits || events != wantEvents {
		t.Fatal("SAML registration denial, retry or conflict changed durable effects", providers, effects, audits, events)
	}
}

func installSAMLProviderRegistrationHistory(t *testing.T, f *orgFixture) {
	t.Helper()
	previousUpdates, err := (ssopg.ProviderUpdateMigrationSource{Version: 321}).Load(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	previousProtocols, err := (ssopg.ProviderProtocolMigrationSource{Version: 322, ValidationVersion: 323}).Load(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	added, err := (ssopg.ProviderSAMLProtocolMigrationSource{Version: 324, ValidationVersion: 325}).Load(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	history := append(migrationList(nil), f.history...)
	history = append(history, previousUpdates...)
	history = append(history, previousProtocols...)
	history = append(history, added...)
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
	runner, err := migrations.NewRunner(history, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(f.ctx); err != nil {
		t.Fatal("expand populated provider registry for SAML registration", err)
	}
}
