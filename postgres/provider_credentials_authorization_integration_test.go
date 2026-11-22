//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-authorization/v3/acl"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestNativeProviderCredentialsRejectsFactoryKeysAndExpiredOrFutureIngress(t *testing.T) {
	f, base, config := newProviderFixture(t)
	created, err := base.ProviderRegisterOidc(f.ctx, providerRequest(t, "https://credentials-ingress.example.com", "credentials-ingress-registration"))
	if err != nil {
		t.Fatal(err)
	}
	installProviderCredentials(t, f)
	base, _ = base.ForOrganization(created.Provider.OrganizationID)
	service := nativeCredentialService(t, base)
	foreign := make([]byte, 32)
	if _, err = rand.Read(foreign); err != nil {
		t.Fatal(err)
	}
	defer clear(foreign)
	keys, err := keyring.New(map[string][]byte{config.KeyReference: foreign})
	if err != nil {
		t.Fatal(err)
	}
	foreignEnvelope, err := envelope.NewService(keys)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"untrusted-factory-key", "expired", "future"} {
		t.Run(name, func(t *testing.T) {
			request := nativeCredentialRequest(t, f, config, created.Provider.ID, 1, 1)
			binding := request.CredentialReference.Context()
			crypto := config.Envelope
			if name == "untrusted-factory-key" {
				crypto = foreignEnvelope
			}
			if name == "expired" {
				binding.IssuedAt = binding.IssuedAt.Add(-2 * time.Minute)
				binding.ExpiresAt = binding.ExpiresAt.Add(-2 * time.Minute)
			}
			if name == "future" {
				binding.IssuedAt = binding.IssuedAt.Add(time.Minute)
				binding.ExpiresAt = binding.ExpiresAt.Add(time.Minute)
			}
			aad, _ := binding.EncryptionContext()
			sealed, err := crypto.Encrypt(f.ctx, envelope.EncryptRequest{Plaintext: bytes.Repeat([]byte{0x51}, 32), KeyReference: config.KeyReference, Context: aad})
			if err != nil {
				t.Fatal(err)
			}
			wire, _ := sealed.MarshalBinary()
			request.CredentialReference, err = sso.NewEncryptedCredentialReference(f.ctx, crypto, wire, binding)
			if err != nil {
				t.Fatal("public factory setup", err)
			}
			out, err := service.ProviderCredentialsRotate(f.ctx, request)
			if !errors.Is(err, sso.ErrForbidden) || out.Active || out.Completion.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("caller factory or lifetime became native trust", err)
			}
		})
	}
	var credentials, effects int
	if err = f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM sso_providers.credentials),(SELECT count(*) FROM sso_providers.credential_effects)`).Scan(&credentials, &effects); err != nil || credentials != 0 || effects != 0 {
		t.Fatal("untrusted ingress retained credential state", credentials, effects, err)
	}
}

type credentialPolicyPanicAfterAdmission struct{ calls atomic.Uint32 }

func (p *credentialPolicyPanicAfterAdmission) ObserveProviderCredentialsAuthorization(ctx context.Context, dc authorization.DecisionContext, epoch uint64) (ssopg.ProviderCredentialsAuthorizationEvidence, error) {
	if p.calls.Add(1) > 1 {
		panic("fixture policy unavailable after commit")
	}
	return (credentialPolicyOwner{policy: fixturePolicy{}, until: time.Now().UTC().Add(time.Hour)}).ObserveProviderCredentialsAuthorization(ctx, dc, epoch)
}

func TestNativeProviderCredentialsPolicyPanicPreservesKnownCommit(t *testing.T) {
	f, base, config := newProviderFixture(t)
	created, err := base.ProviderRegisterOidc(f.ctx, providerRequest(t, "https://credentials-policy-panic.example.com", "credentials-policy-panic-registration"))
	if err != nil {
		t.Fatal(err)
	}
	installProviderCredentials(t, f)
	base, _ = base.ForOrganization(created.Provider.OrganizationID)
	service, err := ssopg.NewProviderCredentialsService(base, ssopg.ProviderCredentialsConfig{Authorization: new(credentialPolicyPanicAfterAdmission), IngressKeyID: config.KeyReference, MaximumReferenceLifetime: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	out, err := service.ProviderCredentialsRotate(f.ctx, nativeCredentialRequest(t, f, config, created.Provider.ID, 1, 1))
	if !errors.Is(err, sso.ErrUnavailable) || out.Completion.Outcome != identity.CommitOutcomeCommitted || out.Active || out.ProviderID != "" {
		t.Fatal("postcommit policy unavailability erased native commitment or disclosed custody", out.Completion.Outcome, err)
	}
	var count int
	if err = f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM sso_providers.credentials`).Scan(&count); err != nil || count != 1 {
		t.Fatal("known committed credential fixture missing", count, err)
	}
}

func TestNativeProviderCredentialsPolicyDeadlineFencesFinalCommit(t *testing.T) {
	f, base, config := newProviderFixture(t)
	created, err := base.ProviderRegisterOidc(f.ctx, providerRequest(t, "https://credentials-policy-expiry.example.com", "credentials-policy-expiry-registration"))
	if err != nil {
		t.Fatal(err)
	}
	installProviderCredentials(t, f)
	if _, err = f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION sso_providers.credentials_wait_for_policy() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.4); RETURN NEW; END $$; CREATE TRIGGER credentials_wait_for_policy BEFORE UPDATE OF metadata_version ON sso_providers.providers FOR EACH ROW EXECUTE FUNCTION sso_providers.credentials_wait_for_policy()`); err != nil {
		t.Fatal(err)
	}
	var before time.Time
	if err = f.pool.Raw().QueryRow(f.ctx, `SELECT clock_timestamp()`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	until := before.Add(250 * time.Millisecond)
	grants, err := acl.New([]acl.Entry{{ID: "credential-owner", Tenant: "org-test-basic", Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: "owner"}, Action: "org:sso-credentials", ResourceType: "organization", ResourceID: authorization.ResourceID(created.Provider.OrganizationID), Effect: authorization.Allow}})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := authorization.NewSnapshot(1, authorization.DenyOverrides, authorization.PolicyDefinition{ID: "credential-window", ActiveUntil: until, Evaluator: grants})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := authorization.NewEngine(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := authorization.NewDecisionService(engine)
	if err != nil {
		t.Fatal(err)
	}
	base, _ = base.ForOrganization(created.Provider.OrganizationID)
	service, err := ssopg.NewProviderCredentialsService(base, ssopg.ProviderCredentialsConfig{Authorization: credentialPolicyOwner{policy: policy, until: until}, IngressKeyID: config.KeyReference, MaximumReferenceLifetime: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	out, operationErr := service.ProviderCredentialsRotate(f.ctx, nativeCredentialRequest(t, f, config, created.Provider.ID, 1, 1))
	var after time.Time
	var version, epoch string
	var credentials, effects, audits, events int
	if err = f.pool.Raw().QueryRow(f.ctx, `SELECT clock_timestamp(),metadata_version::text,(SELECT version::text FROM authorization_subject_authorities WHERE tenant_id='org-test-basic' AND policy_namespace='users' AND subject_id='owner'),(SELECT count(*) FROM sso_providers.credentials),(SELECT count(*) FROM sso_providers.credential_effects),(SELECT count(*) FROM audit.records WHERE action='identity.sso.provider.credentials-rotate' AND outcome=1),(SELECT count(*) FROM outbox_messages WHERE topic='sso.provider_credentials_rotated.v1') FROM sso_providers.providers WHERE provider_id=$1`, created.Provider.ID).Scan(&after, &version, &epoch, &credentials, &effects, &audits, &events); err != nil {
		t.Fatal(err)
	}
	decision, err := engine.Decide(f.ctx, authorization.Request{Tenant: "org-test-basic", Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: "owner"}, Action: "org:sso-credentials", Resource: authorization.Resource{Type: "organization", ID: authorization.ResourceID(created.Provider.OrganizationID)}, Environment: authorization.Environment{Time: after}})
	if err != nil || decision.Outcome != authorization.Deny || after.Before(until) || epoch != "1" {
		t.Fatal("real policy expiry with unchanged epoch not exercised", err)
	}
	if operationErr == nil || out.Active || out.Completion.Outcome == identity.CommitOutcomeCommitted || version != "1" || credentials != 0 || effects != 0 || audits != 0 || events != 0 {
		t.Fatal("expired credentials policy committed partial or complete successor", out.Completion.Outcome, version, credentials, effects, audits, events, operationErr)
	}
}

func TestNativeProviderCredentialsRejectsValidButStaleOriginalAuthentication(t *testing.T) {
	f, base, config := newProviderFixture(t)
	created, err := base.ProviderRegisterOidc(f.ctx, providerRequest(t, "https://credentials-freshness.example.com", "credentials-freshness-registration"))
	if err != nil {
		t.Fatal(err)
	}
	installProviderCredentials(t, f)
	base, _ = base.ForOrganization(created.Provider.OrganizationID)
	request := nativeCredentialRequest(t, f, config, created.Provider.ID, 1, 1)
	var payload []byte
	if err = f.pool.Raw().QueryRow(f.ctx, `SELECT record FROM organization_sessions.sessions WHERE tenant_id='org-test-basic' AND session_id='session-owner'`).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(payload, &fields); err != nil {
		t.Fatal(err)
	}
	var authentication session.AuthenticationMetadata
	if err = json.Unmarshal(fields["Authentication"], &authentication); err != nil {
		t.Fatal(err)
	}
	issued := time.Now().UTC().Truncate(time.Microsecond).Add(-20 * time.Minute)
	authentication.Proof.IssuedAt = issued.Add(-time.Second)
	authentication.Proof.ExpiresAt = issued.Add(time.Minute)
	fields["Authentication"], _ = json.Marshal(authentication)
	fields["IssuedAt"], _ = json.Marshal(issued)
	payload, err = json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.pool.Raw().Exec(f.ctx, `UPDATE organization_sessions.sessions SET record=$1 WHERE tenant_id='org-test-basic' AND session_id='session-owner'`, payload); err != nil {
		t.Fatal(err)
	}
	if _, err = f.pool.Raw().Exec(f.ctx, `UPDATE organization_sessions.families SET issued_at=$1 WHERE tenant_id='org-test-basic' AND family_id='family-owner'`, issued.Format("2006-01-02T15:04:05.000000000Z")); err != nil {
		t.Fatal(err)
	}
	// Ordinary current authorization still succeeds: the fixture is an actual
	// active native session, not malformed/expired synthetic authentication.
	if _, err = base.ProviderGet(f.ctx, sso.ProviderGetRequest{OrganizationID: created.Provider.OrganizationID, ProviderID: sso.ProviderID(created.Provider.ID)}); err != nil {
		t.Fatal("stale but active native session fixture invalid", err)
	}
	out, err := nativeCredentialService(t, base).ProviderCredentialsRotate(f.ctx, request)
	if !errors.Is(err, sso.ErrForbidden) || out.Active || out.Completion.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("stale original authentication became fresh credentials authority", err)
	}
}
