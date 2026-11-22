//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-authorization/v3/acl"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

type boundedProviderUpdateAuthorization struct {
	policy authorization.Service
	until  time.Time
	epoch  uint64
	alter  func(*ssopg.ProviderUpdateAuthorizationEvidence)
}

func (o boundedProviderUpdateAuthorization) ObserveProviderUpdateAuthorization(ctx context.Context, dc authorization.DecisionContext, _ uint64) (ssopg.ProviderUpdateAuthorizationEvidence, error) {
	decision, err := o.policy.Decide(ctx, dc)
	if err != nil {
		return ssopg.ProviderUpdateAuthorizationEvidence{}, err
	}
	evidence := ssopg.ProviderUpdateAuthorizationEvidence{Context: dc.Clone(), Decision: decision, ActorAuthorizationVersion: o.epoch, ValidUntil: o.until}
	if o.alter != nil {
		o.alter(&evidence)
	}
	return evidence, nil
}

func providerUpdateOwner(t *testing.T, until time.Time) boundedProviderUpdateAuthorization {
	t.Helper()
	policy, err := authorization.NewDecisionService(newProviderUpdateEngine(t, until))
	if err != nil {
		t.Fatal(err)
	}
	return boundedProviderUpdateAuthorization{policy: policy, until: until, epoch: 1}
}

func withProviderUpdateOwner(t *testing.T, service *ssopg.ProviderService) *ssopg.ProviderService {
	t.Helper()
	// The fixture policy's actual activation boundary is configured once and
	// supplied by its owner, never inferred as a production authorization TTL.
	bound, err := service.WithProviderUpdateAuthorization(providerUpdateOwner(t, time.Now().UTC().Add(time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	return bound
}

func newProviderUpdateEngine(t *testing.T, until time.Time) *authorization.Engine {
	t.Helper()
	grants, err := acl.New([]acl.Entry{{ID: "provider-update-owner", Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: "owner"}, Action: "org:sso-write", ResourceType: "organization", ResourceID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Tenant: "org-test-basic", Effect: authorization.Allow}})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := authorization.NewSnapshot(1, authorization.DenyOverrides, authorization.PolicyDefinition{ID: "provider-update-window", ActiveUntil: until, Evaluator: grants})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := authorization.NewEngine(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func TestNativeProviderUpdatePolicyDeadlineExpiresBeforeFinalCheck(t *testing.T) {
	f, service, config := newProviderFixture(t)
	registration := providerRequest(t, "https://policy-deadline.example.com", "policy-deadline-registration")
	created, err := service.ProviderRegisterOidc(f.ctx, registration)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION sso_providers.wait_for_policy_deadline() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.4); RETURN NEW; END $$; CREATE TRIGGER wait_for_policy_deadline BEFORE UPDATE OF metadata_version ON sso_providers.providers FOR EACH ROW EXECUTE FUNCTION sso_providers.wait_for_policy_deadline()`); err != nil {
		t.Fatal(err)
	}
	var before time.Time
	if err = f.pool.Raw().QueryRow(f.ctx, `SELECT clock_timestamp()`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	until := before.Add(250 * time.Millisecond)
	engine := newProviderUpdateEngine(t, until)
	config.Authorization, err = authorization.NewDecisionService(engine)
	if err != nil {
		t.Fatal(err)
	}
	service, err = ssopg.NewProviderService(f.pool, config, f.auth("org-test-basic", "owner"), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	service, err = service.ForOrganization(registration.OrganizationID)
	if err != nil {
		t.Fatal(err)
	}
	service, err = service.WithProviderUpdateAuthorization(boundedProviderUpdateAuthorization{policy: config.Authorization, until: until, epoch: 1})
	if err != nil {
		t.Fatal(err)
	}
	request := providerUpdateRequest(t, registration, created.Provider.ID, 1, "policy-deadline-update")
	out, updateErr := service.ProviderUpdate(f.ctx, request)
	var after time.Time
	var version, epoch string
	var effects, audits, events int
	if err = f.pool.Raw().QueryRow(f.ctx, `SELECT clock_timestamp(),metadata_version::text,(SELECT version::text FROM authorization_subject_authorities WHERE tenant_id='org-test-basic' AND policy_namespace='users' AND subject_id='owner'),(SELECT count(*) FROM sso_providers.command_effects),(SELECT count(*) FROM audit.records WHERE action='identity.sso.provider.update' AND outcome=1),(SELECT count(*) FROM outbox_messages WHERE topic='sso.provider_updated.v1') FROM sso_providers.providers WHERE provider_id=$1`, created.Provider.ID).Scan(&after, &version, &epoch, &effects, &audits, &events); err != nil {
		t.Fatal(err)
	}
	decision, err := engine.Decide(f.ctx, authorization.Request{Tenant: "org-test-basic", Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: "owner"}, Action: "org:sso-write", Resource: authorization.Resource{Type: "organization", ID: authorization.ResourceID(registration.OrganizationID)}, Environment: authorization.Environment{Time: after}})
	if err != nil || decision.Outcome != authorization.Deny || after.Before(until) || epoch != "1" {
		t.Fatal("actual policy expiry/unchanged epoch was not reached", err)
	}
	if updateErr == nil || out.Completion.Outcome == identity.CommitOutcomeCommitted || out.Provider.ID != "" || version != "1" || effects != 1 || audits != 0 || events != 0 {
		t.Fatal("expired policy committed a denied successor", out.Completion.Outcome, version, effects, audits, events, updateErr)
	}
}

func TestNativeProviderUpdateRequiresExactUnexpiredOwnerEvidence(t *testing.T) {
	f, service, config := newProviderFixture(t)
	registration := providerRequest(t, "https://policy-evidence.example.com", "policy-evidence-registration")
	created, err := service.ProviderRegisterOidc(f.ctx, registration)
	if err != nil {
		t.Fatal(err)
	}
	unselected, err := ssopg.NewProviderService(f.pool, config, f.auth("org-test-basic", "owner"), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	unselected, err = unselected.ForOrganization(registration.OrganizationID)
	if err != nil {
		t.Fatal(err)
	}
	request := providerUpdateRequest(t, registration, created.Provider.ID, 1, "policy-evidence-update")
	if out, missingErr := unselected.ProviderUpdate(f.ctx, request); !errors.Is(missingErr, sso.ErrForbidden) || out.Provider.ID != "" {
		t.Fatal("missing policy owner admitted update", missingErr)
	}
	for _, name := range []string{"zero", "expired", "epoch", "revision", "tenant", "actor", "action", "resource", "evaluation-time", "denied"} {
		t.Run(name, func(t *testing.T) {
			owner := providerUpdateOwner(t, time.Now().UTC().Add(time.Hour))
			owner.alter = func(e *ssopg.ProviderUpdateAuthorizationEvidence) {
				switch name {
				case "zero":
					e.ValidUntil = time.Time{}
				case "expired":
					e.ValidUntil = e.Context.Request.Environment.Time
				case "epoch":
					e.ActorAuthorizationVersion++
				case "revision":
					e.Decision.Revision++
				case "tenant":
					e.Context.Request.Tenant = "foreign"
				case "actor":
					e.Context.Request.Subject.ID = "foreign"
				case "action":
					e.Context.Request.Action = "org:sso-read"
				case "resource":
					e.Context.Request.Resource.ID = "foreign"
				case "evaluation-time":
					e.Context.Request.Environment.Time = e.Context.Request.Environment.Time.Add(time.Microsecond)
				case "denied":
					e.Decision.Outcome = authorization.Deny
				}
			}
			selected, selectErr := unselected.WithProviderUpdateAuthorization(owner)
			if selectErr != nil {
				t.Fatal(selectErr)
			}
			out, updateErr := selected.ProviderUpdate(f.ctx, request)
			if !errors.Is(updateErr, sso.ErrForbidden) || out.Provider.ID != "" {
				t.Fatal("invalid owner evidence admitted update", name, updateErr)
			}
		})
	}
	var keys, commands int
	if err = f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM identity.request_key_mappings),(SELECT count(*) FROM identity.commands WHERE purpose='identity.sso.provider.update')`).Scan(&keys, &commands); err != nil || keys != 1 || commands != 0 {
		t.Fatal("rejected owner evidence retained retry state", keys, commands, err)
	}
	selected, err := unselected.WithProviderUpdateAuthorization(providerUpdateOwner(t, time.Now().UTC().Add(time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	first, err := selected.ProviderUpdate(f.ctx, request)
	if err != nil || first.Completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("valid owner evidence could not reuse rejected key", err)
	}
	retry, err := selected.ProviderUpdate(f.ctx, request)
	if err != nil || retry.Completion.Binding != first.Completion.Binding || retry.Provider.Version != 2 {
		t.Fatal("fresh evidence changed original committed retry", err)
	}
}
