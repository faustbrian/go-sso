//go:build integration

package postgres_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
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

func TestNativeProviderUpdateRejectsCompleteOversizedSuccessorBeforeKeyCustody(t *testing.T) {
	f, service, _ := newProviderFixture(t)
	registration := providerRequest(t, "https://complete-size.example.com", "complete-size-registration")
	registration.Domains = make([]string, 128)
	for i := range registration.Domains {
		registration.Domains[i] = fmt.Sprintf("%03d.%s.%s.com", i, strings.Repeat("a", 60), strings.Repeat("b", 60))
	}
	created, err := service.ProviderRegisterOidc(f.ctx, registration)
	if err != nil {
		t.Fatal("valid populated provider source", err)
	}
	bound, err := service.ForOrganization(registration.OrganizationID)
	if err != nil {
		t.Fatal(err)
	}
	request := providerUpdateRequest(t, registration, created.Provider.ID, 1, "complete-size-update")
	endpoint := "https://endpoint.example.com/?" + strings.Repeat("&", 2000)
	metadata, err := sso.NewOIDCStaticMetadata(sso.OIDCStaticMetadataSpec{Issuer: registration.Issuer, AuthorizationEndpoint: endpoint, TokenEndpoint: endpoint, JWKSURI: endpoint})
	if err != nil {
		t.Fatal(err)
	}
	request.Configuration, err = sso.NewStaticOIDCProviderConfiguration(metadata)
	if err != nil {
		t.Fatal(err)
	}
	out, err := bound.ProviderUpdate(f.ctx, request)
	if !errors.Is(err, sso.ErrInvalidInput) || out.Provider.ID != "" || out.Completion.Binding.CommandID != "" {
		t.Fatal("complete oversized successor retained retry custody instead of early invalid input", out.Completion.Outcome, err)
	}
	var keys, commands, effects int
	var version string
	if err = f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM identity.request_key_mappings),(SELECT count(*) FROM identity.commands WHERE purpose='identity.sso.provider.update'),(SELECT count(*) FROM sso_providers.command_effects),metadata_version::text FROM sso_providers.providers WHERE provider_id=$1`, created.Provider.ID).Scan(&keys, &commands, &effects, &version); err != nil || keys != 1 || commands != 0 || effects != 1 || version != "1" {
		t.Fatal("invalid complete size reached durable key or provider state", keys, commands, effects, version, err)
	}
	corrected := providerUpdateRequest(t, registration, created.Provider.ID, 1, "complete-size-update")
	corrected.CommandID = request.CommandID
	updated, err := bound.ProviderUpdate(f.ctx, corrected)
	if err != nil || updated.Completion.Outcome != identity.CommitOutcomeCommitted || updated.Provider.Version != 2 {
		t.Fatal("smaller corrected input could not reuse exact rejected key", updated.Completion.Outcome, err)
	}
}

func TestNativeProviderUpdateAcceptsNearBoundCompleteSuccessor(t *testing.T) {
	f, service, _ := newProviderFixture(t)
	registration := providerRequest(t, "https://near-bound.example.com", "near-bound-registration")
	registration.Domains = make([]string, 128)
	for i := range registration.Domains {
		registration.Domains[i] = fmt.Sprintf("%03d.%s.%s.com", i, strings.Repeat("a", 60), strings.Repeat("b", 60))
	}
	created, err := service.ProviderRegisterOidc(f.ctx, registration)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := service.ForOrganization(registration.OrganizationID)
	if err != nil {
		t.Fatal(err)
	}
	request := providerUpdateRequest(t, registration, created.Provider.ID, 1, "near-bound-update")
	endpoint := "https://endpoint.example.com/?" + strings.Repeat("&", 1760)
	spec := sso.OIDCStaticMetadataSpec{Issuer: registration.Issuer, AuthorizationEndpoint: endpoint, TokenEndpoint: endpoint, JWKSURI: endpoint}
	metadata, err := sso.NewOIDCStaticMetadata(spec)
	if err != nil {
		t.Fatal(err)
	}
	request.Configuration, err = sso.NewStaticOIDCProviderConfiguration(metadata)
	if err != nil {
		t.Fatal(err)
	}
	mapping, _ := request.Mapping.Spec()
	complete, err := json.Marshal(struct {
		Metadata sso.OIDCStaticMetadataSpec
		Mapping  sso.AttributeMappingSpec
		Domains  []string
	}{spec, mapping, registration.Domains})
	if err != nil || len(complete) > 48<<10 || len(complete) < 47<<10 {
		t.Fatal("near-bound fixture is not within the existing complete configuration profile", len(complete), err)
	}
	t.Logf("complete configuration bytes=%d below existing49152-byte maximum", len(complete))
	out, err := bound.ProviderUpdate(f.ctx, request)
	if err != nil || out.Completion.Outcome != identity.CommitOutcomeCommitted || out.Provider.Version != 2 {
		t.Fatal("valid near-bound complete successor cannot round-trip preparation", out.Completion.Outcome, err)
	}
}

func installProviderUpdates(t *testing.T, f *orgFixture) {
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
	more, err := (ssopg.ProviderUpdateMigrationSource{Version: 321}).Load(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	history := append(append(migrationList{}, f.history...), more...)
	runner, err := migrations.NewRunner(history, backend)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err = runner.Up(f.ctx); err != nil {
			t.Fatal("additive provider schema", err)
		}
	}
}

func TestNativeProviderUpdateMigrationPreservesPopulatedV1AndEncryptedSuccessor(t *testing.T) {
	f, service, config := newProviderFixtureWithUpdates(t, false)
	registration := providerRequest(t, "https://migration-update.example.com", "migration-registration")
	created, err := service.ProviderRegisterOidc(f.ctx, registration)
	if err != nil {
		t.Fatal(err)
	}
	var legacy []byte
	if err = f.pool.Raw().QueryRow(f.ctx, `SELECT configuration_envelope FROM sso_providers.providers WHERE provider_id=$1`, created.Provider.ID).Scan(&legacy); err != nil {
		t.Fatal(err)
	}
	installProviderUpdates(t, f)
	bound, _ := service.ForOrganization(registration.OrganizationID)
	request := providerUpdateRequest(t, registration, created.Provider.ID, 1, "migration-update")
	updated, err := bound.ProviderUpdate(f.ctx, request)
	if err != nil || updated.Provider.Version != 2 {
		t.Fatal("populated migration lost successor", err)
	}
	var after, ciphertext []byte
	var version, mapping string
	var pending int
	if err = f.pool.Raw().QueryRow(f.ctx, `SELECT configuration_envelope,metadata_configuration_envelope,version::text,mapping_version::text,pending_domains FROM sso_providers.providers WHERE provider_id=$1`, created.Provider.ID).Scan(&after, &ciphertext, &version, &mapping, &pending); err != nil || !bytes.Equal(after, legacy) || version != "1" || mapping != "1" || pending != 1 {
		t.Fatal("legacy v1 projection or pending domains changed", err)
	}
	aad, err := envelope.NewContext(map[string]string{"owner": "sso/provider", "tenant": "org-test-basic", "organization": registration.OrganizationID, "provider": created.Provider.ID, "protocol": "oidc", "purpose": "static-configuration", "version": "2"})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := envelope.ParseEnvelope(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := config.Envelope.Decrypt(f.ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	defer clear(plain)
	if err != nil {
		t.Fatal("version-bound successor envelope unavailable", err)
	}
	var projection struct {
		Metadata sso.OIDCStaticMetadataSpec
		Mapping  sso.AttributeMappingSpec
		Domains  []string
	}
	if json.Unmarshal(plain, &projection) != nil || projection.Mapping.Version != 2 || projection.Mapping.EmailClaim != "email" || projection.Metadata.TokenEndpoint != registration.Issuer+"/new-token" || len(projection.Domains) != 1 || projection.Domains[0] != "example.com" {
		t.Fatal("encrypted metadata successor lost supplied or preserved values")
	}
	retry, err := service.ProviderRegisterOidc(f.ctx, registration)
	if err != nil || retry.Provider.Version != 1 || retry.Provider.MappingVersion != 1 || retry.Completion.Binding != created.Completion.Binding {
		t.Fatal("old original registration retry changed after schema/update", err)
	}
	fresh, err := service.ProviderRegisterOidc(f.ctx, providerRequest(t, "https://new-schema-register.example.com", "new-schema-registration"))
	if err != nil || fresh.Provider.Version != 1 || fresh.Provider.MappingVersion != 1 {
		t.Fatal("registration cannot write v1 on expanded schema", err)
	}
}

func TestNativeProviderUpdateLostCommitRecoversOriginalOnly(t *testing.T) {
	for _, boundary := range []string{"committed", "precommit", "key-mapping"} {
		t.Run(boundary, func(t *testing.T) {
			f, normal, config := newProviderFixture(t)
			registration := providerRequest(t, "https://lost-update.example.com", "lost-update-registration")
			created, err := normal.ProviderRegisterOidc(f.ctx, registration)
			if err != nil {
				t.Fatal(err)
			}
			target := "UPDATE sso_providers.providers SET metadata_version"
			if boundary == "key-mapping" {
				target = "INSERT INTO identity.request_key_mappings"
			}
			lossy, fault := providerLossService(t, f, config, target)
			lossy, _ = lossy.ForOrganization(registration.OrganizationID)
			normal, _ = normal.ForOrganization(registration.OrganizationID)
			fault.beforeCommit.Store(boundary == "precommit")
			request := providerUpdateRequest(t, registration, created.Provider.ID, 1, "lost-update-original")
			out, err := lossy.ProviderUpdate(f.ctx, request)
			if !fault.lost.Load() || err == nil || out.Provider.ID != "" {
				t.Fatal("lost update commit disclosed success", out.Completion.Outcome, err)
			}
			if boundary == "precommit" {
				id, decodeErr := base64.RawURLEncoding.Strict().DecodeString(string(out.Completion.Binding.CommandID))
				if decodeErr != nil || out.Completion.Outcome != identity.CommitOutcomeUnknown {
					t.Fatal("no original pending update", decodeErr)
				}
				tag, expireErr := f.pool.Raw().Exec(f.ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 microsecond' WHERE command_id=$1 AND tenant_id=$2 AND purpose='identity.sso.provider.update' AND state='pending' AND command_plan IS NOT NULL AND preparation_ciphertext IS NOT NULL`, id, "org-test-basic")
				if expireErr != nil || tag.RowsAffected() != 1 {
					t.Fatal("pending original update not attached", expireErr)
				}
			}
			retry, retryErr := normal.ProviderUpdate(f.ctx, request)
			if boundary == "committed" {
				if retryErr != nil || retry.Completion.Outcome != identity.CommitOutcomeCommitted || retry.Provider.Version != 2 || retry.Provider.ID != created.Provider.ID {
					t.Fatal("lost committed update not recovered", retry.Completion.Outcome, retryErr)
				}
			} else if boundary == "precommit" {
				if !errors.Is(retryErr, sso.ErrUnavailable) || retry.Completion.Outcome != identity.CommitOutcomeNotCommitted || retry.Provider.ID != "" {
					t.Fatal("precommit original was reexecuted", retry.Completion.Outcome, retryErr)
				}
			} else {
				var unknown identity.UnknownCommitError
				if !errors.As(retryErr, &unknown) || retry.Completion.Outcome != identity.CommitOutcomeUnknown || retry.Provider.ID != "" {
					t.Fatal("mapping without command became fresh update", retry.Completion.Outcome, retryErr)
				}
			}
			var version string
			var effects, audits, outbox int
			if err = f.pool.Raw().QueryRow(f.ctx, `SELECT metadata_version::text,(SELECT count(*) FROM sso_providers.command_effects),(SELECT count(*) FROM audit.records WHERE action='identity.sso.provider.update' AND outcome=1),(SELECT count(*) FROM outbox_messages WHERE topic='sso.provider_updated.v1') FROM sso_providers.providers WHERE provider_id=$1`, created.Provider.ID).Scan(&version, &effects, &audits, &outbox); err != nil {
				t.Fatal(err)
			}
			wantVersion, wantEffects, wantEvents := "1", 1, 0
			if boundary == "committed" {
				wantVersion, wantEffects, wantEvents = "2", 2, 1
			}
			if version != wantVersion || effects != wantEffects || audits != wantEvents || outbox != wantEvents {
				t.Fatal("recovery repeated or leaked atomic effects", version, effects, audits, outbox)
			}
		})
	}
}

func providerUpdateRequest(t *testing.T, registered sso.ProviderRegisterOidcRequest, provider string, version uint64, key string) sso.ProviderUpdateRequest {
	t.Helper()
	metadata, err := sso.NewOIDCStaticMetadata(sso.OIDCStaticMetadataSpec{Issuer: registered.Issuer, AuthorizationEndpoint: registered.Issuer + "/new-authorize", TokenEndpoint: registered.Issuer + "/new-token", JWKSURI: registered.Issuer + "/new-keys"})
	if err != nil {
		t.Fatal(err)
	}
	configuration, err := sso.NewStaticOIDCProviderConfiguration(metadata)
	if err != nil {
		t.Fatal(err)
	}
	mapping, err := sso.NewAttributeMapping(sso.AttributeMappingSpec{Version: version + 1, SubjectClaim: "sub", EmailClaim: "email", DisplayNameClaim: "name"})
	if err != nil {
		t.Fatal(err)
	}
	idempotency, err := identity.NewIdempotencyKey([]byte(key))
	if err != nil {
		t.Fatal(err)
	}
	return sso.ProviderUpdateRequest{CommandID: commandID(t), ProviderID: provider, ExpectedVersion: version, Configuration: configuration, Mapping: mapping, IdempotencyKey: idempotency}
}

func TestNativeProviderUpdateRejectsScopeAndProfileChanges(t *testing.T) {
	f, service, config := newProviderFixture(t)
	registration := providerRequest(t, "https://update-denials.example.com", "update-denials-registration")
	created, err := service.ProviderRegisterOidc(f.ctx, registration)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := service.ForOrganization(registration.OrganizationID)
	if err != nil {
		t.Fatal(err)
	}
	request := providerUpdateRequest(t, registration, created.Provider.ID, 1, "update-denials")
	if _, err = service.ProviderUpdate(f.ctx, request); !errors.Is(err, sso.ErrInvalidInput) {
		t.Fatal("unbound organization accepted", err)
	}
	for _, name := range []string{"missing", "stale", "issuer", "subject", "mapping-version", "zero-config", "zero-mapping", "zero-version", "bad-command"} {
		t.Run(name, func(t *testing.T) {
			r := providerUpdateRequest(t, registration, created.Provider.ID, 1, "update-denial-"+name)
			want := sso.ErrInvalidInput
			switch name {
			case "missing":
				r.ProviderID = "missing"
				want = sso.ErrForbidden
			case "stale":
				r.ExpectedVersion = 2
				want = sso.ErrConflict
			case "issuer":
				other := providerRequest(t, "https://different-issuer.example.com", "unused")
				r.Configuration, _ = sso.NewStaticOIDCProviderConfiguration(other.StaticMetadata)
			case "subject":
				r.Mapping, _ = sso.NewAttributeMapping(sso.AttributeMappingSpec{Version: 2, SubjectClaim: "other"})
			case "mapping-version":
				r.Mapping, _ = sso.NewAttributeMapping(sso.AttributeMappingSpec{Version: 3, SubjectClaim: "sub"})
			case "zero-config":
				r.Configuration = sso.TypedProviderConfiguration{}
			case "zero-mapping":
				r.Mapping = sso.AttributeMapping{}
			case "zero-version":
				r.ExpectedVersion = 0
			case "bad-command":
				r.CommandID = "invalid"
			}
			out, err := bound.ProviderUpdate(f.ctx, r)
			if !errors.Is(err, want) || out.Provider.ID != "" {
				t.Fatal("invalid update admitted", name, err)
			}
		})
	}
	config.Authorization = providerPolicy{revision: 2}
	denied, err := ssopg.NewProviderService(f.pool, config, f.auth("org-test-basic", "owner"), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	denied, _ = denied.ForOrganization(registration.OrganizationID)
	denied = withProviderUpdateOwner(t, denied)
	if _, err = denied.ProviderUpdate(f.ctx, request); !errors.Is(err, sso.ErrForbidden) {
		t.Fatal("write policy denied but update admitted", err)
	}
	config.Authorization = providerPolicy{unavailable: true}
	unavailable, err := ssopg.NewProviderService(f.pool, config, f.auth("org-test-basic", "owner"), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	unavailable, _ = unavailable.ForOrganization(registration.OrganizationID)
	unavailable = withProviderUpdateOwner(t, unavailable)
	if out, unavailableErr := unavailable.ProviderUpdate(f.ctx, request); !errors.Is(unavailableErr, sso.ErrUnavailable) || out.Provider.ID != "" {
		t.Fatal("unavailable authority became update success", unavailableErr)
	}
	var version, mapping string
	if err = f.pool.Raw().QueryRow(f.ctx, `SELECT metadata_version::text,COALESCE(metadata_mapping_version,mapping_version)::text FROM sso_providers.providers WHERE provider_id=$1`, created.Provider.ID).Scan(&version, &mapping); err != nil || version != "1" || mapping != "1" {
		t.Fatal("rejected updates mutated provider", err)
	}
}

func TestNativeProviderUpdateConcurrentVersionsHaveOneSuccessor(t *testing.T) {
	f, service, _ := newProviderFixture(t)
	registration := providerRequest(t, "https://update-race.example.com", "update-race-registration")
	created, err := service.ProviderRegisterOidc(f.ctx, registration)
	if err != nil {
		t.Fatal(err)
	}
	bound, _ := service.ForOrganization(registration.OrganizationID)
	requests := []sso.ProviderUpdateRequest{providerUpdateRequest(t, registration, created.Provider.ID, 1, "update-race-a"), providerUpdateRequest(t, registration, created.Provider.ID, 1, "update-race-b")}
	var group sync.WaitGroup
	errorsByCall := make([]error, 2)
	for i := range requests {
		group.Add(1)
		go func(i int) { defer group.Done(); _, errorsByCall[i] = bound.ProviderUpdate(f.ctx, requests[i]) }(i)
	}
	group.Wait()
	success := 0
	for _, err := range errorsByCall {
		if err == nil {
			success++
		} else if !errors.Is(err, sso.ErrConflict) {
			t.Fatal("unexpected concurrent update error", err)
		}
	}
	if success != 1 {
		t.Fatal("concurrent expected version did not serialize", success)
	}
	var version string
	var effects, audits, events int
	if err = f.pool.Raw().QueryRow(f.ctx, `SELECT metadata_version::text,(SELECT count(*) FROM sso_providers.command_effects),(SELECT count(*) FROM audit.records WHERE action='identity.sso.provider.update' AND outcome=1),(SELECT count(*) FROM outbox_messages WHERE topic='sso.provider_updated.v1') FROM sso_providers.providers WHERE provider_id=$1`, created.Provider.ID).Scan(&version, &effects, &audits, &events); err != nil || version != "2" || effects != 2 || audits != 1 || events != 1 {
		t.Fatal("compare-and-set refusal leaked metadata effects", version, effects, audits, events, err)
	}
}

func TestNativeProviderUpdateRequiresCurrentOrganizationAdministration(t *testing.T) {
	f, service, config := newProviderFixture(t)
	registration := providerRequest(t, "https://authority-update.example.com", "authority-registration")
	created, err := service.ProviderRegisterOidc(f.ctx, registration)
	if err != nil {
		t.Fatal(err)
	}
	request := providerUpdateRequest(t, registration, created.Provider.ID, 1, "authority-update")
	f.seedUser(t, "org-test-basic", "member")
	f.add(t, "org-test-basic", "member", organization.RoleMember, 1)
	for _, identityScope := range []struct{ tenant, user string }{{"org-test-other", "owner"}, {"org-test-basic", "member"}} {
		other, constructErr := ssopg.NewProviderService(f.pool, config, f.auth(identityScope.tenant, identityScope.user), "127.0.0.1")
		if constructErr != nil {
			t.Fatal(constructErr)
		}
		other, _ = other.ForOrganization(registration.OrganizationID)
		other = withProviderUpdateOwner(t, other)
		out, updateErr := other.ProviderUpdate(f.ctx, request)
		if !errors.Is(updateErr, sso.ErrForbidden) || out.Provider.ID != "" {
			t.Fatal("foreign tenant/member updated provider", updateErr)
		}
	}
	bound, _ := service.ForOrganization(registration.OrganizationID)
	if _, err = bound.ProviderUpdate(f.ctx, request); err != nil {
		t.Fatal(err)
	}
	if _, err = f.pool.Raw().Exec(f.ctx, `UPDATE organization.memberships SET state='removed' WHERE tenant_id='org-test-basic' AND user_id='owner'`); err != nil {
		t.Fatal(err)
	}
	if out, updateErr := bound.ProviderUpdate(f.ctx, request); !errors.Is(updateErr, sso.ErrForbidden) || out.Provider.ID != "" {
		t.Fatal("withdrawn administrator recovered update metadata", updateErr)
	}
}

func TestNativeProviderUpdateRequiredEffectsAndFinalAuthorityRollBack(t *testing.T) {
	for _, boundary := range []string{"audit", "outbox", "session", "user-status"} {
		t.Run(boundary, func(t *testing.T) {
			f, service, _ := newProviderFixture(t)
			registration := providerRequest(t, "https://atomic-update.example.com", "atomic-registration")
			created, err := service.ProviderRegisterOidc(f.ctx, registration)
			if err != nil {
				t.Fatal(err)
			}
			var sql string
			switch boundary {
			case "audit":
				sql = `CREATE FUNCTION sso_providers.reject_update() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'controlled update audit rollback'; END $$; CREATE TRIGGER reject_update BEFORE INSERT ON audit.records FOR EACH ROW WHEN (NEW.action='identity.sso.provider.update' AND NEW.outcome=1) EXECUTE FUNCTION sso_providers.reject_update()`
			case "outbox":
				sql = `CREATE FUNCTION sso_providers.reject_update() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'controlled update outbox rollback'; END $$; CREATE TRIGGER reject_update BEFORE INSERT ON public.identity_outbox_bindings FOR EACH ROW EXECUTE FUNCTION sso_providers.reject_update()`
			case "session":
				sql = `CREATE FUNCTION sso_providers.reject_update() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN UPDATE organization_sessions.sessions SET state='revoked' WHERE tenant_id=NEW.tenant_id AND user_id='owner'; RETURN NEW; END $$; CREATE TRIGGER reject_update AFTER UPDATE OF metadata_version ON sso_providers.providers FOR EACH ROW EXECUTE FUNCTION sso_providers.reject_update()`
			case "user-status":
				sql = `CREATE FUNCTION sso_providers.reject_update() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN UPDATE identity.users SET status='suspended',authority_version=authority_version+1,version=version+1 WHERE tenant_id=NEW.tenant_id AND user_id='owner'; RETURN NEW; END $$; CREATE TRIGGER reject_update AFTER UPDATE OF metadata_version ON sso_providers.providers FOR EACH ROW EXECUTE FUNCTION sso_providers.reject_update()`
			}
			if _, err = f.pool.Raw().Exec(f.ctx, sql); err != nil {
				t.Fatal(err)
			}
			bound, _ := service.ForOrganization(registration.OrganizationID)
			out, err := bound.ProviderUpdate(f.ctx, providerUpdateRequest(t, registration, created.Provider.ID, 1, "atomic-update"))
			if err == nil || out.Completion.Outcome == identity.CommitOutcomeCommitted || out.Provider.ID != "" {
				t.Fatal("required boundary failure committed metadata", boundary, err)
			}
			var version string
			var effects, audits, events int
			if err = f.pool.Raw().QueryRow(f.ctx, `SELECT metadata_version::text,(SELECT count(*) FROM sso_providers.command_effects),(SELECT count(*) FROM audit.records WHERE action='identity.sso.provider.update' AND outcome=1),(SELECT count(*) FROM outbox_messages WHERE topic='sso.provider_updated.v1') FROM sso_providers.providers WHERE provider_id=$1`, created.Provider.ID).Scan(&version, &effects, &audits, &events); err != nil || version != "1" || effects != 1 || audits != 0 || events != 0 {
				t.Fatal("failed metadata update leaked durable effects", version, effects, audits, events, err)
			}
		})
	}
}

func TestNativeProviderUpdatePersistsSuccessorAndPreservesOriginalRegistration(t *testing.T) {
	f, service, _ := newProviderFixture(t)
	registration := providerRequest(t, "https://update.example.com", "registration-before-update")
	created, err := service.ProviderRegisterOidc(f.ctx, registration)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := service.ForOrganization(registration.OrganizationID)
	if err != nil {
		t.Fatal(err)
	}
	request := providerUpdateRequest(t, registration, created.Provider.ID, 1, "update-original")
	updated, err := bound.ProviderUpdate(f.ctx, request)
	if err != nil || updated.Completion.Outcome != identity.CommitOutcomeCommitted || updated.Provider.ID != created.Provider.ID || updated.Provider.Version != 2 || updated.Provider.MappingVersion != 2 || updated.Provider.Enabled || len(updated.Provider.VerifiedDomains) != 0 {
		t.Fatal("disabled metadata successor did not commit", updated.Completion.Outcome, err)
	}
	read, err := service.ProviderGet(f.ctx, sso.ProviderGetRequest{OrganizationID: registration.OrganizationID, ProviderID: sso.ProviderID(created.Provider.ID)})
	if err != nil || read.Provider.Version != 2 || read.Provider.MappingVersion != 2 || read.Provider.Enabled {
		t.Fatal("native get lost successor", err)
	}
	retry, err := bound.ProviderUpdate(f.ctx, request)
	if err != nil || retry.Provider.Version != 2 || retry.Completion.Binding != updated.Completion.Binding {
		t.Fatal("retry did not recover original update", err)
	}
	second, err := bound.ProviderUpdate(f.ctx, providerUpdateRequest(t, registration, created.Provider.ID, 2, "update-next"))
	if err != nil || second.Provider.Version != 3 || second.Provider.MappingVersion != 3 {
		t.Fatal("second metadata successor failed", err)
	}
	retry, err = bound.ProviderUpdate(f.ctx, request)
	if err != nil || retry.Provider.Version != 2 || retry.Provider.MappingVersion != 2 || retry.Completion.Binding != updated.Completion.Binding {
		t.Fatal("later successor changed original update response", err)
	}
	old, err := service.ProviderRegisterOidc(f.ctx, registration)
	if err != nil || old.Provider.Version != 1 || old.Provider.MappingVersion != 1 || old.Completion.Binding != created.Completion.Binding {
		t.Fatal("original registration replay changed", err)
	}
	for _, name := range []string{"version", "provider", "command", "mapping", "configuration"} {
		t.Run("changed-key-"+name, func(t *testing.T) {
			changed := request
			switch name {
			case "version":
				changed.ExpectedVersion = 2
			case "provider":
				changed.ProviderID = "missing"
			case "command":
				changed.CommandID = commandID(t)
			case "mapping":
				changed.Mapping, _ = sso.NewAttributeMapping(sso.AttributeMappingSpec{Version: 2, SubjectClaim: "sub", DisplayNameClaim: "display"})
			case "configuration":
				metadata, _ := sso.NewOIDCStaticMetadata(sso.OIDCStaticMetadataSpec{Issuer: registration.Issuer, AuthorizationEndpoint: registration.Issuer + "/changed", TokenEndpoint: registration.Issuer + "/token", JWKSURI: registration.Issuer + "/keys"})
				changed.Configuration, _ = sso.NewStaticOIDCProviderConfiguration(metadata)
			}
			if out, changedErr := bound.ProviderUpdate(f.ctx, changed); !errors.Is(changedErr, sso.ErrConflict) || out.Provider.ID != "" {
				t.Fatal("same key changed input accepted", name, changedErr)
			}
		})
	}
	var effects, audits, events int
	if err = f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM sso_providers.command_effects),(SELECT count(*) FROM audit.records WHERE action='identity.sso.provider.update' AND outcome=1),(SELECT count(*) FROM outbox_messages WHERE topic='sso.provider_updated.v1')`).Scan(&effects, &audits, &events); err != nil || effects != 3 || audits != 2 || events != 2 {
		t.Fatal("original retries duplicated mutation effects", effects, audits, events, err)
	}
}
