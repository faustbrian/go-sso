//go:build integration

package postgres_test

import (
	"bytes"
	"errors"
	"net/url"
	"reflect"
	"testing"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestNativeProviderProtocolMigrationPreservesLegacyRegistry(t *testing.T) {
	f, legacy, _ := newProviderFixture(t)
	before := providerRequest(t, "https://before-protocol.example.com", "before-provider-protocol")
	registered, err := legacy.ProviderRegisterOidc(f.ctx, before)
	if err != nil || registered.Completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("populate provider registry before expansion", err)
	}
	fileNode := func() uint32 {
		t.Helper()
		var node uint32
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT pg_relation_filenode('sso_providers.providers')`).Scan(&node); err != nil || node == 0 {
			t.Fatal("read owned registry physical identity", err)
		}
		return node
	}
	originalFile := fileNode()
	installProviderProtocolHistory(t, f)
	if currentFile := fileNode(); originalFile != currentFile {
		t.Fatal("additive registry history rewrote existing provider storage")
	}
	var validated bool
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT convalidated FROM pg_constraint WHERE conrelid='sso_providers.providers'::regclass AND conname='sso_providers_protocol_check'`).Scan(&validated); err != nil || !validated {
		t.Fatal("separate protocol constraint validation was not applied", err)
	}
	after := providerRequest(t, "https://after-protocol.example.com", "after-provider-protocol")
	compatible, err := legacy.ProviderRegisterOidc(f.ctx, after)
	if err != nil || compatible.Completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("legacy insert stopped working after expansion", err)
	}
	current, err := legacy.WithOAuthRegistration()
	if err != nil {
		t.Fatal(err)
	}
	for _, original := range []sso.Provider{registered.Provider, compatible.Provider} {
		read, err := current.ProviderGet(f.ctx, sso.ProviderGetRequest{OrganizationID: original.OrganizationID, ProviderID: sso.ProviderID(original.ID)})
		if err != nil || !reflect.DeepEqual(read.Provider, original) {
			t.Fatal("expanded registry did not preserve old protocol metadata", err)
		}
	}
}

func TestNativeDisabledOAuthProviderRegistrationReadAndOriginalRetry(t *testing.T) {
	f, legacy, _ := newProviderFixture(t)
	oidc := providerRequest(t, "https://existing.example.com", "oidc-before-protocol-migration")
	originalOIDC, err := legacy.ProviderRegisterOidc(f.ctx, oidc)
	if err != nil || originalOIDC.Completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("seed genuine legacy OIDC provider", err)
	}
	oauth := providerOAuthRegistrationRequest(t, oidc.OrganizationID)
	if denied, err := legacy.ProviderRegisterOauth(f.ctx, oauth); err == nil || denied.Provider.ID != "" {
		t.Fatal("unselected OAuth profile registered a provider", err)
	}
	installProviderProtocolHistory(t, f)
	service, err := legacy.WithOAuthRegistration()
	if err != nil {
		t.Fatal("select OAuth registration profile", err)
	}
	if unchanged, err := service.ProviderGet(f.ctx, sso.ProviderGetRequest{OrganizationID: oidc.OrganizationID, ProviderID: sso.ProviderID(originalOIDC.Provider.ID)}); err != nil || !reflect.DeepEqual(unchanged.Provider, originalOIDC.Provider) {
		t.Fatal("migration reinterpreted prior OIDC metadata", err)
	}
	got, err := service.ProviderRegisterOauth(f.ctx, oauth)
	if err != nil || got.Completion.Outcome != identity.CommitOutcomeCommitted || got.Completion.Binding.OperationID != "identity.sso.provider.register-oauth" ||
		got.Provider.ID == "" || got.Provider.Protocol != "oauth2" || got.Provider.Enabled || got.Provider.Version != 1 ||
		got.Provider.MappingVersion != 2 || len(got.Provider.VerifiedDomains) != 0 || got.VerificationRequirementCount != 1 {
		t.Fatal("OAuth registration did not commit exactly one disabled, unverified provider", err)
	}
	if replay, err := service.ProviderRegisterOauth(f.ctx, oauth); err != nil || !reflect.DeepEqual(got, replay) {
		t.Fatal("exact retry failed to recover the original registration", err)
	}
	changed := oauth
	changed.IdentityEndpoint.Path = "/different-identity"
	if rejected, err := service.ProviderRegisterOauth(f.ctx, changed); !errors.Is(err, sso.ErrConflict) || rejected.Provider.ID != "" {
		t.Fatal("changed request under the original key replaced retained intent", err)
	}
	foreign := oauth
	foreign.OrganizationID = "foreign-organization"
	if rejected, err := service.ProviderRegisterOauth(f.ctx, foreign); !errors.Is(err, sso.ErrForbidden) || rejected.Provider.ID != "" {
		t.Fatal("foreign organization selected persisted OAuth provider metadata", err)
	}
	read, err := service.ProviderGet(f.ctx, sso.ProviderGetRequest{OrganizationID: oauth.OrganizationID, ProviderID: sso.ProviderID(got.Provider.ID)})
	if err != nil || !reflect.DeepEqual(read.Provider, got.Provider) {
		t.Fatal("safe current read did not preserve registered OAuth protocol", err)
	}
	page, err := service.ProviderList(f.ctx, sso.ProviderListRequest{OrganizationID: oauth.OrganizationID, Limit: 2})
	if err != nil || len(page.Providers) != 2 || page.NextCursor != "" {
		t.Fatal("common provider listing lost one native protocol", err)
	}
	protocols := make(map[string]string, 2)
	for _, p := range page.Providers {
		protocols[p.ID] = p.Protocol
	}
	if protocols[got.Provider.ID] != "oauth2" || protocols[originalOIDC.Provider.ID] != "oidc" {
		t.Fatal("provider listing misrepresented protocol")
	}
	bound, err := service.ForOrganization(oauth.OrganizationID)
	if err != nil {
		t.Fatal(err)
	}
	asOIDC := providerRequest(t, "https://provider.example.com/Enterprise", "cross-protocol-probe")
	update := providerUpdateRequest(t, asOIDC, got.Provider.ID, 1, "cross-protocol-update")
	update.Mapping, err = sso.NewAttributeMapping(sso.AttributeMappingSpec{Version: 3, SubjectClaim: "stable_id"})
	if err != nil {
		t.Fatal(err)
	}
	if out, err := bound.ProviderUpdate(f.ctx, update); err == nil || out.Provider.ID != "" || out.Completion.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("OIDC update accepted the registered OAuth provider", err)
	}
	still, err := service.ProviderGet(f.ctx, sso.ProviderGetRequest{OrganizationID: oauth.OrganizationID, ProviderID: sso.ProviderID(got.Provider.ID)})
	if err != nil || !reflect.DeepEqual(still.Provider, got.Provider) {
		t.Fatal("failed cross-protocol update changed native metadata", err)
	}
	var ciphertext []byte
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT configuration_envelope FROM sso_providers.providers WHERE organization_id=$1 AND provider_id=$2`,
		oauth.OrganizationID, got.Provider.ID).Scan(&ciphertext); err != nil || len(ciphertext) == 0 || bytes.Contains(ciphertext, []byte(oauth.IdentityEndpoint.String())) {
		t.Fatal("OAuth configuration was missing or stored in plaintext", err)
	}
	var providers, effects, audits, events int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT count(*) FROM sso_providers.providers),
 (SELECT count(*) FROM sso_providers.command_effects),
 (SELECT count(*) FROM audit.records WHERE action='identity.sso.provider.register-oauth' AND outcome=1),
 (SELECT count(*) FROM outbox_messages WHERE topic='sso.provider_registered.v1')`).Scan(&providers, &effects, &audits, &events); err != nil ||
		providers != 2 || effects != 2 || audits != 1 || events != 2 {
		t.Fatal("registration and retry did not preserve exactly one native effect, audit and event", err)
	}
}

func providerOAuthRegistrationRequest(t *testing.T, organization string) sso.ProviderRegisterOauthRequest {
	t.Helper()
	u := func(raw string) url.URL {
		t.Helper()
		parsed, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return *parsed
	}
	mapping, err := sso.NewAttributeMapping(sso.AttributeMappingSpec{Version: 2, SubjectClaim: "stable_id"})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := sso.NewIdentityProofPolicy(sso.IdentityProofPolicySpec{
		Version: 1, Issuer: "https://provider.example.com/Enterprise", SubjectKind: sso.OAuthSubjectString,
		EmailVerification: sso.OAuthEmailUnverified,
	})
	if err != nil {
		t.Fatal(err)
	}
	key, err := identity.NewIdempotencyKey([]byte("original-oauth-registration"))
	if err != nil {
		t.Fatal(err)
	}
	return sso.ProviderRegisterOauthRequest{
		CommandID: commandID(t), OrganizationID: organization, AuthorizationEndpoint: u("https://provider.example.com/authorize"),
		TokenEndpoint: u("https://provider.example.com/token"), IdentityEndpoint: u("https://provider.example.com/identity"),
		Mapping: mapping, IdentityProofPolicy: proof, IdempotencyKey: key, Domains: []string{"example.com"},
	}
}

func installProviderProtocolHistory(t *testing.T, f *orgFixture) {
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
	prior, err := (ssopg.ProviderUpdateMigrationSource{Version: 321}).Load(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	added, err := (ssopg.ProviderProtocolMigrationSource{Version: 322, ValidationVersion: 323}).Load(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	history := append(append(append(migrationList(nil), f.history...), prior...), added...)
	runner, err := migrations.NewRunner(history, backend)
	if err != nil {
		t.Fatal(err)
	}
	for range added {
		if _, err := runner.Up(f.ctx); err != nil {
			t.Fatal("expand protocol registry on a populated schema", err)
		}
	}
}
