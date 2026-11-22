//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

type credentialPolicyOwner struct {
	policy authorization.Service
	until  time.Time
	alter  func(*ssopg.ProviderCredentialsAuthorizationEvidence)
}

func (p credentialPolicyOwner) ObserveProviderCredentialsAuthorization(ctx context.Context, dc authorization.DecisionContext, _ uint64) (ssopg.ProviderCredentialsAuthorizationEvidence, error) {
	decision, err := p.policy.Decide(ctx, dc)
	if err != nil {
		return ssopg.ProviderCredentialsAuthorizationEvidence{}, err
	}
	evidence := ssopg.ProviderCredentialsAuthorizationEvidence{Context: dc.Clone(), Decision: decision, ActorAuthorizationVersion: 1, ValidUntil: p.until}
	if p.alter != nil {
		p.alter(&evidence)
	}
	return evidence, nil
}

func installProviderCredentials(t *testing.T, f *orgFixture) {
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
	updates, err := (ssopg.ProviderUpdateMigrationSource{Version: 321}).Load(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := (ssopg.ProviderCredentialsMigrationSource{Version: 322}).Load(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	history := append(append(append(migrationList{}, f.history...), updates...), credentials...)
	runner, err := migrations.NewRunner(history, backend)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err = runner.Up(f.ctx); err != nil {
			t.Fatal("additive credential schema", err)
		}
	}
}

func nativeCredentialService(t *testing.T, base *ssopg.ProviderService) *ssopg.ProviderCredentialsService {
	t.Helper()
	service, err := ssopg.NewProviderCredentialsService(base, ssopg.ProviderCredentialsConfig{Authorization: credentialPolicyOwner{policy: fixturePolicy{}, until: time.Now().UTC().Add(time.Hour)}, IngressKeyID: "provider-custody", MaximumReferenceLifetime: time.Minute})
	if err != nil {
		t.Fatal("native credential composition", err)
	}
	return service
}

func nativeCredentialRequest(t *testing.T, f *orgFixture, config ssopg.ProviderServiceConfig, provider string, version, generation uint64) sso.ProviderCredentialsRotateRequest {
	t.Helper()
	return nativeCredentialRequestForTenant(t, f, "org-test-basic", config, provider, version, generation)
}

func nativeCredentialRequestForTenant(t *testing.T, f *orgFixture, tenant identity.TenantID, config ssopg.ProviderServiceConfig, provider string, version, generation uint64) sso.ProviderCredentialsRotateRequest {
	t.Helper()
	var at time.Time
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
		t.Fatal(err)
	}
	at = at.UTC().Truncate(time.Microsecond)
	binding := sso.CredentialReferenceContext{TenantID: string(tenant), OrganizationID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", ProviderID: provider, Protocol: "oidc", Purpose: "client-secret", Generation: generation, ProviderVersion: version, Audience: "identity.sso.provider.credentials-rotate", EnvelopeKeyID: config.KeyReference, IssuedAt: at, ExpiresAt: at.Add(time.Minute)}
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
		t.Fatal(err)
	}
	return sso.ProviderCredentialsRotateRequest{CommandID: commandID(t), ProviderID: provider, ExpectedVersion: version, CredentialReference: reference, OverlapPolicy: sso.NewNoCredentialOverlapPolicy()}
}

func TestNativeProviderCredentialsInitializeReplaceAndRecoverOriginal(t *testing.T) {
	f, base, config := newProviderFixture(t)
	registration := providerRequest(t, "https://credentials.example.com", "credential-registration")
	created, err := base.ProviderRegisterOidc(f.ctx, registration)
	if err != nil {
		t.Fatal(err)
	}
	var legacy []byte
	if err = f.pool.Raw().QueryRow(f.ctx, `SELECT configuration_envelope FROM sso_providers.providers WHERE provider_id=$1`, created.Provider.ID).Scan(&legacy); err != nil {
		t.Fatal(err)
	}
	installProviderCredentials(t, f)
	base, err = base.ForOrganization(registration.OrganizationID)
	if err != nil {
		t.Fatal(err)
	}
	service := nativeCredentialService(t, base)
	first := nativeCredentialRequest(t, f, config, created.Provider.ID, 1, 1)
	out, err := service.ProviderCredentialsRotate(f.ctx, first)
	if err != nil || out.Completion.Outcome != identity.CommitOutcomeCommitted || out.Version != 2 || out.ProviderID != first.ProviderID || !out.Active || out.ReconciliationRequired {
		t.Fatal("initial disabled provider credential did not commit", out.Completion.Outcome, err)
	}
	second := nativeCredentialRequest(t, f, config, created.Provider.ID, 2, 2)
	replacement, err := service.ProviderCredentialsRotate(f.ctx, second)
	if err != nil || replacement.Version != 3 || !replacement.Active || replacement.ReconciliationRequired {
		t.Fatal("replacement did not establish the exact successor", err)
	}
	retry, err := service.ProviderCredentialsRotate(f.ctx, first)
	if err != nil || retry.Version != 2 || retry.Completion.Binding != out.Completion.Binding || retry.Completion.AuditEventID != out.Completion.AuditEventID {
		t.Fatal("original retry did not return its historical result", err)
	}
	changed := first
	changedBinding := first.CredentialReference.Context()
	changedAAD, _ := changedBinding.EncryptionContext()
	changedEnvelope, err := config.Envelope.Encrypt(f.ctx, envelope.EncryptRequest{Plaintext: bytes.Repeat([]byte{0x37}, 32), KeyReference: config.KeyReference, Context: changedAAD})
	if err != nil {
		t.Fatal(err)
	}
	changedWire, _ := changedEnvelope.MarshalBinary()
	changed.CredentialReference, err = sso.NewEncryptedCredentialReference(f.ctx, config.Envelope, changedWire, changedBinding)
	if err != nil {
		t.Fatal(err)
	}
	if changedResult, changedErr := service.ProviderCredentialsRotate(f.ctx, changed); !errors.Is(changedErr, sso.ErrConflict) || changedResult.Active {
		t.Fatal("changed original intent accepted", changedErr)
	}
	var currentWire, oldWire []byte
	var version, generation string
	var enabled bool
	var effects, audits, events, credentials int
	if err = f.pool.Raw().QueryRow(f.ctx, `SELECT p.metadata_version::text,p.enabled,p.configuration_envelope,c.envelope,c.generation::text,(SELECT count(*) FROM sso_providers.credential_effects),(SELECT count(*) FROM audit.records WHERE action='identity.sso.provider.credentials-rotate' AND outcome=1),(SELECT count(*) FROM outbox_messages WHERE topic='sso.provider_credentials_rotated.v1'),(SELECT count(*) FROM sso_providers.credentials) FROM sso_providers.providers p JOIN sso_providers.credentials c USING(tenant_id,organization_id,provider_id) WHERE p.provider_id=$1`, first.ProviderID).Scan(&version, &enabled, &oldWire, &currentWire, &generation, &effects, &audits, &events, &credentials); err != nil || version != "3" || generation != "2" || enabled || !bytes.Equal(legacy, oldWire) || effects != 2 || audits != 2 || events != 2 || credentials != 1 {
		t.Fatal("credential replacement changed legacy/enable state or repeated effects", version, generation, effects, audits, events, credentials, err)
	}
	want, _ := second.CredentialReference.EncryptedEnvelope().MarshalBinary()
	if !bytes.Equal(currentWire, want) {
		t.Fatal("retired credential remained the configured generation")
	}
	current, err := base.ProviderGet(f.ctx, sso.ProviderGetRequest{OrganizationID: registration.OrganizationID, ProviderID: sso.ProviderID(first.ProviderID)})
	if err != nil || current.Provider.Version != 3 || current.Provider.MappingVersion != 1 || current.Provider.Enabled || len(current.Provider.VerifiedDomains) != 0 {
		t.Fatal("safe reader projection changed semantics", err)
	}
	metadataUpdate := providerUpdateRequest(t, registration, first.ProviderID, 3, "after-credential-update")
	metadataUpdate.Mapping, err = sso.NewAttributeMapping(sso.AttributeMappingSpec{Version: 2, SubjectClaim: "sub", EmailClaim: "email"})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := base.ProviderUpdate(f.ctx, metadataUpdate)
	if err != nil || updated.Provider.Version != 4 || updated.Provider.MappingVersion != 2 {
		t.Fatal("credential successor broke metadata updates", err)
	}
}

func TestNativeProviderCredentialsRejectsWrongOwnersVersionsContextAndPolicy(t *testing.T) {
	f, base, config := newProviderFixture(t)
	created, err := base.ProviderRegisterOidc(f.ctx, providerRequest(t, "https://credentials-denial.example.com", "credentials-denial-registration"))
	if err != nil {
		t.Fatal(err)
	}
	installProviderCredentials(t, f)
	base, _ = base.ForOrganization(created.Provider.OrganizationID)
	service := nativeCredentialService(t, base)
	for _, name := range []string{"version", "generation", "provider", "tenant", "organization", "overlap", "command", "lifetime"} {
		t.Run(name, func(t *testing.T) {
			r := nativeCredentialRequest(t, f, config, created.Provider.ID, 1, 1)
			switch name {
			case "version":
				r.ExpectedVersion = 2
			case "generation":
				r = nativeCredentialRequest(t, f, config, created.Provider.ID, 1, 2)
			case "provider":
				r.ProviderID = "foreign"
			case "tenant", "organization", "lifetime":
				binding := r.CredentialReference.Context()
				if name == "tenant" {
					binding.TenantID = "org-test-other"
				}
				if name == "organization" {
					binding.OrganizationID = "foreign"
				}
				if name == "lifetime" {
					binding.ExpiresAt = binding.ExpiresAt.Add(time.Minute)
				}
				aad, _ := binding.EncryptionContext()
				sealed, sealingErr := config.Envelope.Encrypt(f.ctx, envelope.EncryptRequest{Plaintext: bytes.Repeat([]byte{0x53}, 32), KeyReference: config.KeyReference, Context: aad})
				if sealingErr != nil {
					t.Fatal(sealingErr)
				}
				wire, _ := sealed.MarshalBinary()
				r.CredentialReference, err = sso.NewEncryptedCredentialReference(f.ctx, config.Envelope, wire, binding)
				if err != nil {
					t.Fatal(err)
				}
			case "overlap":
				r.OverlapPolicy = sso.CredentialOverlapPolicy{}
			case "command":
				r.CommandID = "invalid"
			}
			out, err := service.ProviderCredentialsRotate(f.ctx, r)
			if err == nil || out.Active || out.Completion.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("wrong context committed credential", err)
			}
		})
	}
	for _, name := range []string{"epoch", "action", "deadline", "denied", "revision"} {
		t.Run(name, func(t *testing.T) {
			owner := credentialPolicyOwner{policy: fixturePolicy{}, until: time.Now().UTC().Add(time.Hour)}
			owner.alter = func(e *ssopg.ProviderCredentialsAuthorizationEvidence) {
				switch name {
				case "epoch":
					e.ActorAuthorizationVersion++
				case "action":
					e.Context.Request.Action = "org:sso-write"
				case "deadline":
					e.ValidUntil = e.Context.Request.Environment.Time
				case "denied":
					e.Decision.Outcome = authorization.Deny
				case "revision":
					e.Decision.Revision++
				}
			}
			denied, buildErr := ssopg.NewProviderCredentialsService(base, ssopg.ProviderCredentialsConfig{Authorization: owner, IngressKeyID: config.KeyReference, MaximumReferenceLifetime: time.Minute})
			if buildErr != nil {
				t.Fatal(buildErr)
			}
			if out, err := denied.ProviderCredentialsRotate(f.ctx, nativeCredentialRequest(t, f, config, created.Provider.ID, 1, 1)); !errors.Is(err, sso.ErrForbidden) || out.Active {
				t.Fatal("invalid native credentials policy accepted", err)
			}
		})
	}
	var count int
	if err = f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM sso_providers.credentials`).Scan(&count); err != nil || count != 0 {
		t.Fatal("denial retained credential", count, err)
	}
}

func TestNativeProviderCredentialsAndMetadataCompeteAtSameVersion(t *testing.T) {
	f, base, config := newProviderFixture(t)
	registration := providerRequest(t, "https://credentials-race.example.com", "credentials-race-registration")
	created, err := base.ProviderRegisterOidc(f.ctx, registration)
	if err != nil {
		t.Fatal(err)
	}
	installProviderCredentials(t, f)
	base, _ = base.ForOrganization(registration.OrganizationID)
	service := nativeCredentialService(t, base)
	r := nativeCredentialRequest(t, f, config, created.Provider.ID, 1, 1)
	update := providerUpdateRequest(t, registration, created.Provider.ID, 1, "credential-race-metadata")
	var wg sync.WaitGroup
	var credentialErr, metadataErr error
	wg.Add(2)
	go func() { defer wg.Done(); _, credentialErr = service.ProviderCredentialsRotate(f.ctx, r) }()
	go func() { defer wg.Done(); _, metadataErr = base.ProviderUpdate(f.ctx, update) }()
	wg.Wait()
	if (credentialErr == nil) == (metadataErr == nil) {
		t.Fatal("shared predecessor admitted zero or two successors", credentialErr, metadataErr)
	}
	var version string
	if err = f.pool.Raw().QueryRow(f.ctx, `SELECT metadata_version::text FROM sso_providers.providers WHERE provider_id=$1`, created.Provider.ID).Scan(&version); err != nil || version != "2" {
		t.Fatal("race advanced shared version incorrectly", version, err)
	}
}

func TestNativeProviderCredentialsAuditOutboxFailureRollsBackEntireSuccessor(t *testing.T) {
	for _, boundary := range []string{"audit", "outbox"} {
		t.Run(boundary, func(t *testing.T) {
			f, base, config := newProviderFixture(t)
			created, err := base.ProviderRegisterOidc(f.ctx, providerRequest(t, "https://credentials-rollback.example.com", "credentials-rollback-registration"))
			if err != nil {
				t.Fatal(err)
			}
			installProviderCredentials(t, f)
			base, _ = base.ForOrganization(created.Provider.OrganizationID)
			service := nativeCredentialService(t, base)
			sql := `CREATE FUNCTION sso_providers.reject_credentials() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'selected fixture rollback'; END $$; CREATE TRIGGER reject_credentials BEFORE INSERT ON audit.records FOR EACH ROW WHEN (NEW.action='identity.sso.provider.credentials-rotate' AND NEW.outcome=1) EXECUTE FUNCTION sso_providers.reject_credentials()`
			if boundary == "outbox" {
				sql = `CREATE FUNCTION sso_providers.reject_credentials() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'selected fixture rollback'; END $$; CREATE TRIGGER reject_credentials BEFORE INSERT ON outbox_messages FOR EACH ROW WHEN (NEW.topic='sso.provider_credentials_rotated.v1') EXECUTE FUNCTION sso_providers.reject_credentials()`
			}
			if _, err = f.pool.Raw().Exec(f.ctx, sql); err != nil {
				t.Fatal(err)
			}
			out, err := service.ProviderCredentialsRotate(f.ctx, nativeCredentialRequest(t, f, config, created.Provider.ID, 1, 1))
			if err == nil || out.Active || out.Completion.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("failed required effect reported success", err)
			}
			var version string
			var credentials, effects int
			if err = f.pool.Raw().QueryRow(f.ctx, `SELECT metadata_version::text,(SELECT count(*) FROM sso_providers.credentials),(SELECT count(*) FROM sso_providers.credential_effects) FROM sso_providers.providers WHERE provider_id=$1`, created.Provider.ID).Scan(&version, &credentials, &effects); err != nil || version != "1" || credentials != 0 || effects != 0 {
				t.Fatal("partial successor survived required-effect rollback", version, credentials, effects, err)
			}
		})
	}
}

func TestNativeProviderCredentialsLostCommitReturnsOnlyOriginalResult(t *testing.T) {
	f, base, config := newProviderFixture(t)
	created, err := base.ProviderRegisterOidc(f.ctx, providerRequest(t, "https://credentials-lost.example.com", "credentials-lost-registration"))
	if err != nil {
		t.Fatal(err)
	}
	installProviderCredentials(t, f)
	lossy, fault := providerLossService(t, f, config, "INSERT INTO sso_providers.credentials")
	lossy, _ = lossy.ForOrganization(created.Provider.OrganizationID)
	service := nativeCredentialService(t, lossy)
	r := nativeCredentialRequest(t, f, config, created.Provider.ID, 1, 1)
	out, err := service.ProviderCredentialsRotate(f.ctx, r)
	if !fault.lost.Load() || err == nil || out.Active || !out.ReconciliationRequired || out.Completion.Outcome != identity.CommitOutcomeUnknown {
		t.Fatal("lost actual commit disclosed successor", out.Completion.Outcome, err)
	}
	base, _ = base.ForOrganization(created.Provider.OrganizationID)
	recovered, err := nativeCredentialService(t, base).ProviderCredentialsRotate(f.ctx, r)
	if err != nil || !recovered.Active || recovered.Version != 2 || recovered.Completion.Binding != out.Completion.Binding {
		t.Fatal("native original outcome did not recover", err)
	}
	var credentials, effects, audits, events int
	if err = f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM sso_providers.credentials),(SELECT count(*) FROM sso_providers.credential_effects),(SELECT count(*) FROM audit.records WHERE action='identity.sso.provider.credentials-rotate' AND outcome=1),(SELECT count(*) FROM outbox_messages WHERE topic='sso.provider_credentials_rotated.v1')`).Scan(&credentials, &effects, &audits, &events); err != nil || credentials != 1 || effects != 1 || audits != 1 || events != 1 {
		t.Fatal("recovery repeated a durable effect", credentials, effects, audits, events, err)
	}
}

func TestNativeProviderCredentialsPrecommitOrKeyLossNeverReexecutes(t *testing.T) {
	for _, boundary := range []string{"precommit", "key-mapping"} {
		t.Run(boundary, func(t *testing.T) {
			f, base, config := newProviderFixture(t)
			created, err := base.ProviderRegisterOidc(f.ctx, providerRequest(t, "https://credentials-precommit.example.com", "credentials-precommit-registration"))
			if err != nil {
				t.Fatal(err)
			}
			installProviderCredentials(t, f)
			target := "INSERT INTO sso_providers.credentials"
			if boundary == "key-mapping" {
				target = "INSERT INTO identity.request_key_mappings"
			}
			lossy, fault := providerLossService(t, f, config, target)
			fault.beforeCommit.Store(boundary == "precommit")
			lossy, _ = lossy.ForOrganization(created.Provider.OrganizationID)
			request := nativeCredentialRequest(t, f, config, created.Provider.ID, 1, 1)
			out, operationErr := nativeCredentialService(t, lossy).ProviderCredentialsRotate(f.ctx, request)
			if !fault.lost.Load() || operationErr == nil || out.Active {
				t.Fatal("selected loss did not withhold result", operationErr)
			}
			if boundary == "key-mapping" && !out.ReconciliationRequired {
				t.Fatal("unknown native key custody omitted reconciliation")
			}
			if boundary == "precommit" {
				id, decodeErr := base64.RawURLEncoding.Strict().DecodeString(string(out.Completion.Binding.CommandID))
				if decodeErr != nil || out.Completion.Outcome != identity.CommitOutcomeUnknown {
					t.Fatal("missing native pending original", decodeErr)
				}
				tag, expireErr := f.pool.Raw().Exec(f.ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 microsecond' WHERE command_id=$1 AND tenant_id=$2 AND purpose='identity.sso.provider.credentials-rotate' AND state='pending' AND command_plan IS NOT NULL AND preparation_ciphertext IS NOT NULL`, id, "org-test-basic")
				if expireErr != nil || tag.RowsAffected() != 1 {
					t.Fatal("original pending lease unavailable", expireErr)
				}
			}
			base, _ = base.ForOrganization(created.Provider.OrganizationID)
			service := nativeCredentialService(t, base)
			for range 2 {
				recovered, recoveryErr := service.ProviderCredentialsRotate(f.ctx, request)
				if boundary == "precommit" {
					if !errors.Is(recoveryErr, sso.ErrUnavailable) || recovered.Completion.Outcome != identity.CommitOutcomeNotCommitted || recovered.Active {
						t.Fatal("rolled-back original reexecuted", recovered.Completion.Outcome, recoveryErr)
					}
				} else {
					var unknown identity.UnknownCommitError
					if !errors.As(recoveryErr, &unknown) || recovered.Completion.Outcome != identity.CommitOutcomeUnknown || !recovered.ReconciliationRequired || recovered.Active {
						t.Fatal("unattached original became fresh mutation", recovered.Completion.Outcome, recoveryErr)
					}
				}
			}
			var version string
			var credentials, effects, events int
			if err = f.pool.Raw().QueryRow(f.ctx, `SELECT metadata_version::text,(SELECT count(*) FROM sso_providers.credentials),(SELECT count(*) FROM sso_providers.credential_effects),(SELECT count(*) FROM outbox_messages WHERE topic='sso.provider_credentials_rotated.v1') FROM sso_providers.providers WHERE provider_id=$1`, created.Provider.ID).Scan(&version, &credentials, &effects, &events); err != nil || version != "1" || credentials != 0 || effects != 0 || events != 0 {
				t.Fatal("unknown recovery added effects", version, credentials, effects, events, err)
			}
		})
	}
}
