//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func newProviderFixture(t *testing.T) (*orgFixture, *ssopg.ProviderService, ssopg.ProviderServiceConfig) {
	return newProviderFixtureWithUpdates(t, true)
}

func newProviderFixtureWithUpdates(t *testing.T, updates bool) (*orgFixture, *ssopg.ProviderService, ssopg.ProviderServiceConfig) {
	t.Helper()
	// Compose real optional kernel migrations without duplicating the already
	// installed kernel base or changing the accepted DNS fixture's history.
	history, err := (kernel.RequestKeyPreparationMigrationSource{Base: kernel.RequestKeyMigrationSource{Base: kernel.CounterPreparationMigrationSource{Base: kernel.AdmissionPreparationMigrationSource{Base: kernel.PreparationMigrationSource{Base: kernel.MigrationSource{}, Version: 310}, Version: 311}, Version: 312}, Version: 313}, Version: 314}).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var additions migrationList
	for _, migration := range history {
		if migration.Version() >= 310 {
			additions = append(additions, migration)
		}
	}
	f := newOrgFixtureWithIdentities(t, []identity.TenantID{"org-test-basic", "org-test-other"}, []identity.UserID{"owner"}, additions, organizationpg.CredentialAuthorityMigrationSource{Version: 315}, ssopg.ProviderMigrationSource{Version: 320})
	if updates {
		installProviderUpdates(t, f)
	}
	f.create(t, "org-test-basic")
	repository, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := keyring.New(map[string][]byte{"provider-custody": bytes.Repeat([]byte{0x94}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	crypto, err := envelope.NewService(keys)
	if err != nil {
		t.Fatal(err)
	}
	queryPolicy := kernel.CommandQueryPolicy{Authorization: fixturePolicy{}, Clock: clock.System{}, PolicyVersion: 1}
	requestKeys, err := kernel.NewRequestKeyConfig("sso-providers", [32]byte{0x95}, queryPolicy)
	if err != nil {
		t.Fatal(err)
	}
	config := ssopg.ProviderServiceConfig{
		Clock: clock.System{}, MaximumDuration: 4 * time.Second,
		Sessions: f.sessions, Session: sessionpg.Config{Schema: "organization_sessions", MaximumDuration: time.Second},
		Profile: f.profile, LookupKeys: map[uint32]session.DigestKey{1: f.key},
		Organizations: repository, Authorization: fixturePolicy{}, PolicyID: "sso-providers", PolicyVersion: 1,
		Counters: nativeRisk(t), RequestKeys: requestKeys,
		Coordinator: kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute,
			CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {0x96}},
			QueryPolicy: &queryPolicy, AdmissionPolicy: &queryPolicy},
		Envelope: crypto, KeyReference: "provider-custody",
	}
	service, err := ssopg.NewProviderService(f.pool, config, f.auth("org-test-basic", "owner"), "127.0.0.1")
	if err != nil {
		t.Fatal("actual provider composition", err)
	}
	return f, withProviderUpdateOwner(t, service), config
}

func providerRequest(t *testing.T, issuer, key string) sso.ProviderRegisterOidcRequest {
	t.Helper()
	metadata, err := sso.NewOIDCStaticMetadata(sso.OIDCStaticMetadataSpec{Issuer: issuer, AuthorizationEndpoint: issuer + "/authorize", TokenEndpoint: issuer + "/token", JWKSURI: issuer + "/keys"})
	if err != nil {
		t.Fatal(err)
	}
	mapping, err := sso.NewAttributeMapping(sso.AttributeMappingSpec{Version: 1, SubjectClaim: "sub"})
	if err != nil {
		t.Fatal(err)
	}
	idempotency, err := identity.NewIdempotencyKey([]byte(key))
	if err != nil {
		t.Fatal(err)
	}
	return sso.ProviderRegisterOidcRequest{CommandID: commandID(t), OrganizationID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Issuer: issuer, StaticMetadata: metadata, Domains: []string{"example.com"}, Mapping: mapping, IdempotencyKey: idempotency}
}

func TestNativeDisabledOIDCProviderRegistrationReadAndOriginalRetry(t *testing.T) {
	f, service, _ := newProviderFixture(t)
	metadata, err := sso.NewOIDCStaticMetadata(sso.OIDCStaticMetadataSpec{Issuer: "https://issuer.example.com/company", AuthorizationEndpoint: "https://issuer.example.com/authorize", TokenEndpoint: "https://issuer.example.com/token", JWKSURI: "https://issuer.example.com/keys"})
	if err != nil {
		t.Fatal(err)
	}
	mapping, err := sso.NewAttributeMapping(sso.AttributeMappingSpec{Version: 1, SubjectClaim: "sub"})
	if err != nil {
		t.Fatal(err)
	}
	key, err := identity.NewIdempotencyKey([]byte("original-sso-provider"))
	if err != nil {
		t.Fatal(err)
	}
	request := sso.ProviderRegisterOidcRequest{CommandID: commandID(t), OrganizationID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Issuer: "https://issuer.example.com/company", StaticMetadata: metadata, Domains: []string{"example.com"}, Mapping: mapping, IdempotencyKey: key}
	created, err := service.ProviderRegisterOidc(f.ctx, request)
	if err != nil || created.Completion.Outcome != identity.CommitOutcomeCommitted || created.Provider.ID == "" || created.Provider.Enabled || len(created.Provider.VerifiedDomains) != 0 || created.VerificationRequirementCount != 1 {
		t.Fatal("disabled registration did not commit without inventing domain proof", err)
	}
	current, err := service.ProviderGet(f.ctx, sso.ProviderGetRequest{OrganizationID: request.OrganizationID, ProviderID: sso.ProviderID(created.Provider.ID)})
	if err != nil || current.Provider.ID != created.Provider.ID || current.Provider.Enabled || current.Provider.Version != 1 {
		t.Fatal("persisted provider metadata unavailable", err)
	}
	listed, err := service.ProviderList(f.ctx, sso.ProviderListRequest{OrganizationID: request.OrganizationID, Limit: 10})
	if err != nil || len(listed.Providers) != 1 || listed.Providers[0].ID != created.Provider.ID || listed.NextCursor != "" {
		t.Fatal("scoped provider listing changed", err)
	}
	retry, err := service.ProviderRegisterOidc(f.ctx, request)
	if err != nil || retry.Completion.Outcome != identity.CommitOutcomeCommitted || retry.Provider.ID != created.Provider.ID || retry.Provider.Version != created.Provider.Version {
		t.Fatal("original registration retry created another provider", err)
	}
	changed := request
	changed.Domains = []string{"other.example.com"}
	conflict, err := service.ProviderRegisterOidc(f.ctx, changed)
	if !errors.Is(err, sso.ErrConflict) || conflict.Provider.ID != "" {
		t.Fatal("changed keyed intent was not rejected", err)
	}
	duplicate := providerRequest(t, request.Issuer, "duplicate-issuer")
	conflict, err = service.ProviderRegisterOidc(f.ctx, duplicate)
	if err == nil || conflict.Completion.Outcome == identity.CommitOutcomeCommitted || conflict.Provider.ID != "" {
		t.Fatal("owner issuer uniqueness was not enforced", err)
	}
	var providers, effects, audits, lifecycle int
	if err = f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM sso_providers.providers),(SELECT count(*) FROM sso_providers.command_effects),(SELECT count(*) FROM audit.records WHERE action='identity.sso.provider.register-oidc' AND outcome=1),(SELECT count(*) FROM outbox_messages WHERE topic='sso.provider_registered.v1')`).Scan(&providers, &effects, &audits, &lifecycle); err != nil || providers != 1 || effects != 1 || audits != 1 || lifecycle != 1 {
		t.Fatal("registration/retry effects not atomic and exactly once", providers, effects, audits, lifecycle, err)
	}
}

func TestNativeProviderRejectsUnsupportedInputsBeforeMutation(t *testing.T) {
	f, service, _ := newProviderFixture(t)
	original := providerRequest(t, "https://input.example.com", "invalid-input")
	for _, change := range []struct {
		name  string
		alter func(*sso.ProviderRegisterOidcRequest)
	}{
		{"issuer-mismatch", func(r *sso.ProviderRegisterOidcRequest) { r.Issuer = "https://foreign.example.com" }},
		{"discovery", func(r *sso.ProviderRegisterOidcRequest) {
			r.DiscoveryURL = url.URL{Scheme: "https", Host: "metadata.example.com"}
		}},
		{"duplicate-domain", func(r *sso.ProviderRegisterOidcRequest) { r.Domains = []string{"example.com", "example.com"} }},
		{"nil-domains", func(r *sso.ProviderRegisterOidcRequest) { r.Domains = nil }},
		{"empty-domains", func(r *sso.ProviderRegisterOidcRequest) { r.Domains = []string{} }},
		{"noncanonical-domain", func(r *sso.ProviderRegisterOidcRequest) { r.Domains = []string{"Example.com"} }},
		{"zero-mapping", func(r *sso.ProviderRegisterOidcRequest) { r.Mapping = sso.AttributeMapping{} }},
		{"malformed-command", func(r *sso.ProviderRegisterOidcRequest) { r.CommandID = "malformed" }},
	} {
		t.Run(change.name, func(t *testing.T) {
			request := original
			change.alter(&request)
			out, err := service.ProviderRegisterOidc(f.ctx, request)
			if !errors.Is(err, sso.ErrInvalidInput) || out.Provider.ID != "" {
				t.Fatal("invalid registration admitted", err)
			}
		})
	}
	for _, limit := range []uint32{0, 101, ^uint32(0)} {
		if _, err := service.ProviderList(f.ctx, sso.ProviderListRequest{OrganizationID: original.OrganizationID, Limit: limit}); !errors.Is(err, sso.ErrInvalidInput) {
			t.Fatal("unbounded provider list accepted", limit, err)
		}
	}
	var count int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM sso_providers.providers`).Scan(&count); err != nil || count != 0 {
		t.Fatal("invalid input mutated provider state", count, err)
	}
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM identity.request_key_mappings`).Scan(&count); err != nil || count != 0 {
		t.Fatal("invalid input reached original key preparation", count, err)
	}
}

func TestNativeProviderDomainCountContract(t *testing.T) {
	f, service, _ := newProviderFixture(t)
	request := providerRequest(t, "https://domain-bound.example.com", "domains-128")
	request.Domains = make([]string, 128)
	for i := range request.Domains {
		request.Domains[i] = fmt.Sprintf("domain-%03d.example.com", i)
	}
	created, err := service.ProviderRegisterOidc(f.ctx, request)
	if err != nil || created.Completion.Outcome != identity.CommitOutcomeCommitted || created.VerificationRequirementCount != 128 || created.Provider.Enabled || len(created.Provider.VerifiedDomains) != 0 {
		t.Fatal("128 canonical pending domains were not accepted", err)
	}
	tooMany := providerRequest(t, "https://domain-overflow.example.com", "domains-129")
	tooMany.Domains = append(append([]string(nil), request.Domains...), "overflow.example.com")
	out, err := service.ProviderRegisterOidc(f.ctx, tooMany)
	if !errors.Is(err, sso.ErrInvalidInput) || out.Provider.ID != "" {
		t.Fatal("129 domains reached registration", err)
	}
	var providers, mappings int
	if err = f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM sso_providers.providers),(SELECT count(*) FROM identity.request_key_mappings)`).Scan(&providers, &mappings); err != nil || providers != 1 || mappings != 1 {
		t.Fatal("rejected domain overflow reached original preparation", providers, mappings, err)
	}
}

func TestNativeProviderCurrentAuthorityAndTenantIsolation(t *testing.T) {
	f, service, config := newProviderFixture(t)
	request := providerRequest(t, "https://isolation.example.com", "provider-isolation")
	created, err := service.ProviderRegisterOidc(f.ctx, request)
	if err != nil || created.Provider.ID == "" {
		t.Fatal(err)
	}
	if out, err := service.ProviderGet(f.ctx, sso.ProviderGetRequest{OrganizationID: request.OrganizationID, ProviderID: "missing"}); !errors.Is(err, sso.ErrForbidden) || out.Provider.ID != "" {
		t.Fatal("missing provider denial changed", err)
	}
	other, err := ssopg.NewProviderService(f.pool, config, f.auth("org-test-other", "owner"), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := other.ProviderGet(f.ctx, sso.ProviderGetRequest{OrganizationID: request.OrganizationID, ProviderID: sso.ProviderID(created.Provider.ID)}); !errors.Is(err, sso.ErrForbidden) || out.Provider.ID != "" {
		t.Fatal("foreign provider denial or metadata boundary changed", err)
	}
	if out, err := other.ProviderList(f.ctx, sso.ProviderListRequest{OrganizationID: request.OrganizationID, Limit: 10}); !errors.Is(err, sso.ErrForbidden) || len(out.Providers) != 0 {
		t.Fatal("cross-tenant provider listing disclosed", err)
	}
	f.seedUser(t, "org-test-basic", "member")
	f.add(t, "org-test-basic", "member", organization.RoleMember, 1)
	member, err := ssopg.NewProviderService(f.pool, config, f.auth("org-test-basic", "member"), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := member.ProviderRegisterOidc(f.ctx, providerRequest(t, "https://member.example.com", "member-denied")); err == nil || out.Provider.ID != "" {
		t.Fatal("ordinary member registered enterprise provider", err)
	}
	if _, err = f.pool.Raw().Exec(f.ctx, `UPDATE organization.memberships SET state='removed' WHERE tenant_id='org-test-basic' AND user_id='owner'`); err != nil {
		t.Fatal(err)
	}
	if out, err := service.ProviderRegisterOidc(f.ctx, request); err == nil || out.Provider.ID != "" {
		t.Fatal("withdrawn member recovered provider metadata", err)
	}
	if out, err := service.ProviderGet(f.ctx, sso.ProviderGetRequest{OrganizationID: request.OrganizationID, ProviderID: sso.ProviderID(created.Provider.ID)}); err == nil || out.Provider.ID != "" {
		t.Fatal("withdrawn member read provider metadata", err)
	}
}

type providerPolicy struct {
	revision    authorization.Revision
	unavailable bool
}

func (p providerPolicy) Decide(ctx context.Context, _ authorization.DecisionContext) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	if p.unavailable {
		return authorization.Decision{}, errors.New("controlled policy failure")
	}
	return authorization.Decision{Outcome: authorization.Allow, Revision: p.revision}, nil
}

func TestNativeProviderRequiresCurrentPolicyRevision(t *testing.T) {
	for _, unavailable := range []bool{false, true} {
		name := "revision"
		if unavailable {
			name = "unavailable"
		}
		t.Run(name, func(t *testing.T) {
			f, _, config := newProviderFixture(t)
			config.Authorization = providerPolicy{revision: 2, unavailable: unavailable}
			service, err := ssopg.NewProviderService(f.pool, config, f.auth("org-test-basic", "owner"), "127.0.0.1")
			if err != nil {
				t.Fatal(err)
			}
			out, err := service.ProviderRegisterOidc(f.ctx, providerRequest(t, "https://policy.example.com", "policy-denied"))
			if err == nil || out.Provider.ID != "" {
				t.Fatal("unavailable or mismatched policy admitted provider", err)
			}
			var count int
			if err = f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM identity.request_key_mappings`).Scan(&count); err != nil || count != 0 {
				t.Fatal("denied policy reached request preparation", count, err)
			}
		})
	}
}

func TestNativeProviderRequiredEffectsAndFinalWithdrawalRollback(t *testing.T) {
	for _, boundary := range []string{"audit", "outbox", "withdraw-session", "withdraw-user-status"} {
		t.Run(boundary, func(t *testing.T) {
			f, service, _ := newProviderFixture(t)
			var sql string
			switch boundary {
			case "audit":
				sql = `CREATE FUNCTION sso_providers.reject_effect() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='identity.sso.provider.register-oidc' AND NEW.outcome=1 THEN RAISE EXCEPTION 'controlled provider audit rollback'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_effect BEFORE INSERT ON audit.records FOR EACH ROW EXECUTE FUNCTION sso_providers.reject_effect()`
			case "outbox":
				sql = `CREATE FUNCTION sso_providers.reject_effect() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'controlled provider outbox rollback'; END $$; CREATE TRIGGER reject_effect BEFORE INSERT ON public.identity_outbox_bindings FOR EACH ROW EXECUTE FUNCTION sso_providers.reject_effect()`
			case "withdraw-session":
				sql = `CREATE FUNCTION sso_providers.reject_effect() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN UPDATE organization_sessions.sessions SET state='revoked' WHERE tenant_id=NEW.tenant_id AND user_id='owner'; RETURN NEW; END $$; CREATE TRIGGER reject_effect AFTER INSERT ON sso_providers.providers FOR EACH ROW EXECUTE FUNCTION sso_providers.reject_effect()`
			case "withdraw-user-status":
				sql = `CREATE FUNCTION sso_providers.reject_effect() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN UPDATE identity.users SET status='suspended',authority_version=authority_version+1,version=version+1 WHERE tenant_id=NEW.tenant_id AND user_id='owner'; RETURN NEW; END $$; CREATE TRIGGER reject_effect AFTER INSERT ON sso_providers.providers FOR EACH ROW EXECUTE FUNCTION sso_providers.reject_effect()`
			}
			if _, err := f.pool.Raw().Exec(f.ctx, sql); err != nil {
				t.Fatal(err)
			}
			out, err := service.ProviderRegisterOidc(f.ctx, providerRequest(t, "https://rollback.example.com", "provider-rollback"))
			if err == nil || out.Completion.Outcome == identity.CommitOutcomeCommitted || out.Provider.ID != "" {
				t.Fatal("failed required/final boundary committed provider", boundary, err)
			}
			if boundary == "withdraw-user-status" && (out.Completion.Outcome != identity.CommitOutcomeNotCommitted || out.Completion.Binding.UserID != "owner") {
				t.Fatal("status withdrawal did not roll back an admitted original", out.Completion.Outcome, err)
			}
			var count, effects, successAudits, outbox int
			if err = f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM sso_providers.providers),(SELECT count(*) FROM sso_providers.command_effects),(SELECT count(*) FROM audit.records WHERE action='identity.sso.provider.register-oidc' AND outcome=1),(SELECT count(*) FROM outbox_messages WHERE topic='sso.provider_registered.v1')`).Scan(&count, &effects, &successAudits, &outbox); err != nil || count != 0 || effects != 0 || successAudits != 0 || outbox != 0 {
				t.Fatal("failed transition leaked provider success effects", count, effects, successAudits, outbox, err)
			}
			if boundary == "withdraw-user-status" {
				var status, version string
				if err = f.pool.Raw().QueryRow(f.ctx, `SELECT status,authority_version::text FROM identity.users WHERE tenant_id='org-test-basic' AND user_id='owner'`).Scan(&status, &version); err != nil || status != "active" || version != "1" {
					t.Fatal("status/epoch withdrawal was not transactionally rolled back", status, version, err)
				}
			}
		})
	}
}

func TestNativeProviderOriginalSessionExpiryAfterAdmissionRollsBack(t *testing.T) {
	f, service, _ := newProviderFixture(t)
	var payload []byte
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT record::text FROM organization_sessions.sessions WHERE tenant_id='org-test-basic' AND user_id='owner'`).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var record struct {
		Schema                   uint32
		SessionID, FamilyID      string
		TenantID                 identity.TenantID
		UserID                   identity.UserID
		Audience                 string
		Version, FamilyVersion   uint64
		Remember                 session.RememberPolicySpec
		Authority                session.AuthoritySnapshotSpec
		Lookup                   session.TokenDigest
		Authentication           session.AuthenticationMetadata
		IssuedAt, LastActivityAt time.Time
	}
	if json.Unmarshal(payload, &record) != nil {
		t.Fatal("native session fixture decode")
	}
	expires := time.Now().UTC().Truncate(time.Microsecond).Add(1500 * time.Millisecond)
	record.IssuedAt = expires.Add(-time.Hour)
	record.LastActivityAt = expires.Add(-30 * time.Minute)
	record.Authentication.Proof.IssuedAt = record.IssuedAt.Add(-time.Second)
	record.Authentication.Proof.ExpiresAt = record.IssuedAt.Add(time.Minute)
	payload, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.pool.Raw().Exec(f.ctx, `UPDATE organization_sessions.sessions SET record=$1::jsonb,expires_at=$2 WHERE tenant_id='org-test-basic' AND user_id='owner'`, payload, expires.Format("2006-01-02T15:04:05.000000000Z")); err != nil {
		t.Fatal(err)
	}
	if _, err = f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION sso_providers.wait_for_expiry() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(1.6); RETURN NEW; END $$; CREATE TRIGGER wait_for_expiry AFTER INSERT ON sso_providers.providers FOR EACH ROW EXECUTE FUNCTION sso_providers.wait_for_expiry()`); err != nil {
		t.Fatal(err)
	}
	out, err := service.ProviderRegisterOidc(f.ctx, providerRequest(t, "https://expiry.example.com", "provider-expiry"))
	if err == nil || out.Completion.Outcome == identity.CommitOutcomeCommitted || out.Provider.ID != "" {
		t.Fatal("session expiry during final effects retained provider", err)
	}
	var count int
	if err = f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM sso_providers.providers`).Scan(&count); err != nil || count != 0 {
		t.Fatal("expired original admission leaked provider", count, err)
	}
}

func TestNativeProviderConcurrentExactOriginal(t *testing.T) {
	f, service, _ := newProviderFixture(t)
	request := providerRequest(t, "https://concurrent.example.com", "concurrent-original")
	type outcome struct {
		out sso.ProviderRegisterOidcResult
		err error
	}
	start := make(chan struct{})
	results := make(chan outcome, 2)
	var workers sync.WaitGroup
	for range 2 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			out, err := service.ProviderRegisterOidc(f.ctx, request)
			results <- outcome{out, err}
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	var committed string
	for result := range results {
		if result.out.Completion.Outcome == identity.CommitOutcomeCommitted {
			if result.err != nil || result.out.Provider.ID == "" || committed != "" && committed != result.out.Provider.ID {
				t.Fatal("concurrent original changed identity", result.err)
			}
			committed = result.out.Provider.ID
		} else if result.err == nil || result.out.Provider.ID != "" {
			t.Fatal("concurrent uncommitted invocation disclosed provider", result.err)
		}
	}
	if committed == "" {
		t.Fatal("no original invocation committed")
	}
	retry, err := service.ProviderRegisterOidc(f.ctx, request)
	if err != nil || retry.Provider.ID != committed {
		t.Fatal("concurrent original retry diverged", err)
	}
	var providers, effects int
	if err = f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM sso_providers.providers),(SELECT count(*) FROM sso_providers.command_effects)`).Scan(&providers, &effects); err != nil || providers != 1 || effects != 1 {
		t.Fatal("concurrent registration duplicated effects", providers, effects, err)
	}
}
