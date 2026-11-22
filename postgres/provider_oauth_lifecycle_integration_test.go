//go:build integration

package postgres_test

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	organization "github.com/faustbrian/go-organization"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestNativeOAuth2ProviderActivationAndDisable(t *testing.T) {
	t.Run("original-and-replay", func(t *testing.T) { verifyNativeOAuth2ProviderActivationAndDisable(t, false) })
	t.Run("confirmed-failure-and-retry", func(t *testing.T) { verifyNativeOAuth2ProviderActivationAndDisable(t, true) })
}

func verifyNativeOAuth2ProviderActivationAndDisable(t *testing.T, failDisable bool) {
	t.Helper()
	x := newProviderEnableFixture(t)
	oidc := enableRouteFixture(t, x, false)
	installProviderOAuthLifecycleHistory(t, x.f)
	router, err := newProviderRouter(t, x, 4).WithProtocolRegistry()
	if err != nil {
		t.Fatal(err)
	}
	service, err := x.service.WithOAuthRegistration()
	if err != nil {
		t.Fatal(err)
	}
	registration := providerOAuthRegistrationRequest(t, string(x.proof.OrganizationID))
	registered, err := service.ProviderRegisterOauth(x.f.ctx, registration)
	if err != nil || registered.Provider.Enabled || registered.Provider.Version != 1 {
		t.Fatal("register disabled OAuth provider", err)
	}
	provider := registered.Provider.ID
	credential := nativeCredentialRequest(t, x.f, x.config, provider, 1, 1)
	binding := credential.CredentialReference.Context()
	binding.Protocol = "oauth2"
	aad, err := binding.EncryptionContext()
	if err != nil {
		t.Fatal(err)
	}
	secret := bytes.Repeat([]byte{0x37}, 32)
	defer clear(secret)
	sealed, err := x.config.Envelope.Encrypt(x.f.ctx, envelope.EncryptRequest{Plaintext: secret, KeyReference: binding.EnvelopeKeyID, Context: aad})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := sealed.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	credential.CredentialReference, err = sso.NewEncryptedCredentialReference(x.f.ctx, x.config.Envelope, wire, binding)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := nativeCredentialService(t, service).ProviderCredentialsRotate(x.f.ctx, credential); err != nil || result.Version != 2 {
		t.Fatal("install OAuth credential", err)
	}
	checkpoint, err := service.ObserveOAuth2ProviderCredentialCheckpoint(x.f.ctx, provider, 2)
	if err != nil || checkpoint.Protocol() != "oauth2" {
		t.Fatal("observe protocol-bound OAuth credential", err)
	}
	if _, err := service.ObserveProviderCredentialCheckpoint(x.f.ctx, provider, 2); err == nil {
		t.Fatal("OIDC observation authenticated the OAuth credential")
	}
	if _, err := service.ObserveOAuth2ProviderCredentialCheckpoint(x.f.ctx, x.request.ProviderID, 2); err == nil {
		t.Fatal("OAuth observation authenticated the sibling OIDC credential")
	}
	key, err := identity.NewIdempotencyKey([]byte("oauth-provider-enable"))
	if err != nil {
		t.Fatal(err)
	}
	enable := sso.ProviderEnableRequest{
		ProviderID: provider, ExpectedVersion: 2, CredentialCheckpoint: checkpoint, IdempotencyKey: key,
		DomainProofCheckpoint: sso.DomainProofCheckpoint{Key: organization.DomainProofKey(x.proof), ProofVersion: x.proof.ProofVersion},
	}
	if out, err := x.service.ProviderEnable(x.f.ctx, enable); !errors.Is(err, sso.ErrForbidden) || out.Provider.ID != "" {
		t.Fatal("legacy service enabled OAuth", err)
	}
	if out, err := service.ProviderEnable(x.f.ctx, enable); !errors.Is(err, sso.ErrForbidden) || out.Provider.ID != "" {
		t.Fatal("OAuth activated without a configured native disable policy", err)
	}
	service, err = service.WithProviderDisableAuthorization(providerDisablePolicy{})
	if err != nil {
		t.Fatal(err)
	}
	rejectedBinding, err := checkpoint.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	rejectedBinding.Generation++
	wrongGeneration, err := sso.NewOAuth2CredentialCheckpoint(rejectedBinding)
	if err != nil {
		t.Fatal(err)
	}
	mismatch, err := identity.NewIdempotencyKey([]byte("wrong-oauth-provider-generation"))
	if err != nil {
		t.Fatal(err)
	}
	wrong := enable
	wrong.CredentialCheckpoint, wrong.IdempotencyKey = wrongGeneration, mismatch
	if out, err := service.ProviderEnable(x.f.ctx, wrong); !errors.Is(err, sso.ErrForbidden) || out.Provider.ID != "" {
		t.Fatal("OAuth activated for a generation other than the installed one", err)
	}
	enabled, err := service.ProviderEnable(x.f.ctx, enable)
	if err != nil || enabled.Completion.Outcome != identity.CommitOutcomeCommitted || !enabled.Provider.Enabled || enabled.Provider.Version != 3 ||
		enabled.Provider.Protocol != "oauth2" || !reflect.DeepEqual(enabled.Provider.VerifiedDomains, []string{x.proof.Domain}) {
		t.Fatal("enable exact OAuth provider", err)
	}
	if retry, err := service.ProviderEnable(x.f.ctx, enable); err != nil || !reflect.DeepEqual(enabled, retry) {
		t.Fatal("OAuth enable retry did not recover original result", err)
	}
	assertRoute(t, x, router, x.proof.Domain, "", oidc, nil)
	assertRoute(t, x, router, x.proof.Domain, sso.ProviderID(provider), "", sso.ErrForbidden)
	disposition, err := sso.NewActiveTransactionDisposition(sso.ProviderID(provider), 3, sso.ActiveTransactionRevoke)
	if err != nil {
		t.Fatal(err)
	}
	disable := sso.ProviderDisableRequest{ProviderID: provider, ExpectedVersion: 3, Reason: "Close the native OAuth profile", ActiveTransactionDisposition: disposition}
	if out, err := service.ProviderDisable(x.f.ctx, disable); err == nil || out.Disabled {
		t.Fatal("OIDC disable accepted an OAuth predecessor", err)
	}
	disableCall := func() (sso.ProviderDisableResult, error) {
		return service.ProviderDisableOAuth2(x.f.ctx, disable)
	}
	if failDisable {
		if _, err := x.f.pool.Raw().Exec(x.f.ctx, `CREATE FUNCTION sso_providers.reject_oauth_disable_test() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'controlled OAuth disable rollback'; END $$;
 CREATE TRIGGER reject_oauth_disable_test BEFORE INSERT ON outbox_messages FOR EACH ROW WHEN (NEW.topic='enterprise_provider.disabled.v1') EXECUTE FUNCTION sso_providers.reject_oauth_disable_test()`); err != nil {
			t.Fatal(err)
		}
		failed, err := disableCall()
		if err == nil || failed.Disabled || failed.Completion.Outcome != identity.CommitOutcomeNotCommitted || failed.Completion.Binding.CommandID == "" {
			t.Fatal("controlled OAuth disable failure did not retain a confirmed original", failed.Completion.Outcome, err)
		}
		still, err := service.ProviderGet(x.f.ctx, sso.ProviderGetRequest{OrganizationID: registration.OrganizationID, ProviderID: sso.ProviderID(provider)})
		if err != nil || !still.Provider.Enabled || still.Provider.Version != 3 {
			t.Fatal("failed disable did not roll back provider state", err)
		}
		if _, err := x.f.pool.Raw().Exec(x.f.ctx, `DROP TRIGGER reject_oauth_disable_test ON outbox_messages`); err != nil {
			t.Fatal(err)
		}
		if out, err := service.RetryProviderDisable(x.f.ctx, disable, failed.Completion.Binding.CommandID); err == nil || out.Disabled {
			t.Fatal("OIDC retry accepted an OAuth failure anchor", err)
		}
		disableCall = func() (sso.ProviderDisableResult, error) {
			return service.RetryProviderDisableOAuth2(x.f.ctx, disable, failed.Completion.Binding.CommandID)
		}
	}
	disabled, err := disableCall()
	if err != nil || disabled.Completion.Outcome != identity.CommitOutcomeCommitted || !disabled.Disabled || disabled.ActiveTransactionCount != 0 {
		t.Fatal("disable exact OAuth provider", err)
	}
	if retry, err := disableCall(); err != nil || !reflect.DeepEqual(disabled, retry) {
		t.Fatal("OAuth disable retry did not recover original result", err)
	}
	current, err := service.ProviderGet(x.f.ctx, sso.ProviderGetRequest{OrganizationID: registration.OrganizationID, ProviderID: sso.ProviderID(provider)})
	if err != nil || current.Provider.Enabled || current.Provider.Protocol != "oauth2" || current.Provider.Version != 4 || len(current.Provider.VerifiedDomains) != 0 {
		t.Fatal("OAuth disable left authoritative provider enabled or reclassified", err)
	}
	var enableCount, disableCount, dispositions int
	err = x.f.pool.Raw().QueryRow(x.f.ctx, `SELECT
 (SELECT count(*) FROM audit.records WHERE action='identity.sso.provider.enable' AND outcome=1),
 (SELECT count(*) FROM audit.records WHERE action='identity.sso.provider.disable' AND outcome=1),
 (SELECT count(*) FROM sso_providers.provider_login_dispositions WHERE provider_id=$1)`, provider).Scan(&enableCount, &disableCount, &dispositions)
	if err != nil || enableCount != 2 || disableCount != 1 || dispositions != 1 {
		t.Fatal("OAuth lifecycle duplicated or omitted native effects", enableCount, disableCount, dispositions, err)
	}
}

func installProviderOAuthLifecycleHistory(t *testing.T, f *orgFixture) {
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
		ssopg.ProviderEnableMigrationSource{Version: 323},
		ssopg.ProviderProtocolMigrationSource{Version: 324, ValidationVersion: 325},
		ssopg.LoginTransactionMigrationSource{Version: 326},
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
	if _, err = runner.Up(f.ctx); err != nil {
		t.Fatal("install protocol registry and login disposition history", err)
	}
}
