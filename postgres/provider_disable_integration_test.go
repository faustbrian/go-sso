//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	database "github.com/faustbrian/go-postgres"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

type providerDisablePolicy struct {
	alter func(*ssopg.ProviderDisableAuthorizationEvidence)
}

func (p providerDisablePolicy) ObserveProviderDisableAuthorization(ctx context.Context, dc authorization.DecisionContext, epoch uint64) (ssopg.ProviderDisableAuthorizationEvidence, error) {
	decision, err := (fixturePolicy{}).Decide(ctx, dc)
	if err != nil {
		return ssopg.ProviderDisableAuthorizationEvidence{}, err
	}
	if dc.Request.Action != "org:sso-write" {
		decision.Outcome = authorization.Deny
	}
	evidence := ssopg.ProviderDisableAuthorizationEvidence{
		Context: dc.Clone(), Decision: decision, ActorAuthorizationVersion: epoch,
		ValidUntil: dc.Request.Environment.Time.Add(time.Minute),
	}
	if p.alter != nil {
		p.alter(&evidence)
	}
	return evidence, nil
}

func nativeProviderDisableRequest(t *testing.T, x providerLoginStartFixture, mode sso.ActiveTransactionDispositionMode) sso.ProviderDisableRequest {
	t.Helper()
	disposition, err := sso.NewActiveTransactionDisposition(sso.ProviderID(x.request.ProviderID), 3, mode)
	if err != nil {
		t.Fatal("select exact enabled predecessor disposition", err)
	}
	return sso.ProviderDisableRequest{
		ProviderID: x.request.ProviderID, ExpectedVersion: 3,
		Reason:                       "Remove this provider from new enterprise sign-ins",
		ActiveTransactionDisposition: disposition,
	}
}

func nativeProviderDisableService(t *testing.T, x providerLoginStartFixture, policy providerDisablePolicy) *ssopg.ProviderService {
	t.Helper()
	return nativeProviderDisableOnPool(t, x, x.enable.f.pool, policy)
}

func nativeProviderDisableOnPool(t *testing.T, x providerLoginStartFixture, pool *database.Pool, policy providerDisablePolicy) *ssopg.ProviderService {
	t.Helper()
	service, err := ssopg.NewProviderService(pool, x.enable.config,
		x.enable.f.auth(string(x.enable.proof.TenantID), "owner"), "127.0.0.1")
	if err != nil {
		t.Fatal("compose independent provider administration instance", err)
	}
	service, err = service.ForOrganization(string(x.enable.proof.OrganizationID))
	if err != nil {
		t.Fatal("bind original organization", err)
	}
	service, err = service.WithProviderDisableAuthorization(policy)
	if err != nil {
		t.Fatal("select explicit native disable authorization owner", err)
	}
	return service
}

func nativeProviderDisableStart(t *testing.T, x providerLoginStartFixture, index int) sso.SigninStartResult {
	t.Helper()
	request := x.request
	request.CommandID = commandID(t)
	var err error
	request.IdempotencyKey, err = identity.NewIdempotencyKey([]byte(fmt.Sprintf("disable-predecessor-start-%d", index)))
	if err != nil {
		t.Fatal(err)
	}
	started, err := x.service.SigninStart(x.enable.f.ctx, request, x.browser)
	if err != nil || started.Completion.Outcome != identity.CommitOutcomeCommitted ||
		started.TransactionID == "" || started.RedirectURI.Query().Get("state") == "" {
		t.Fatal("admit actual browser-bound native login before disablement", err)
	}
	return started
}

type providerDisableEffects struct {
	commands, mappings, effects, dispositions, audits, events int
}

func nativeProviderDisableEffects(t *testing.T, x providerLoginStartFixture) providerDisableEffects {
	t.Helper()
	var got providerDisableEffects
	err := x.enable.f.pool.Raw().QueryRow(x.enable.f.ctx, `SELECT
 (SELECT count(*) FROM identity.commands WHERE purpose='identity.sso.provider.disable'),
 (SELECT count(*) FROM identity.request_key_mappings WHERE route_id='identity.sso.provider.disable'),
 (SELECT count(*) FROM sso_providers.command_effects),
 (SELECT count(*) FROM sso_providers.provider_login_dispositions),
 (SELECT count(*) FROM audit.records WHERE action='identity.sso.provider.disable' AND outcome=1),
 (SELECT count(*) FROM outbox_messages WHERE topic='enterprise_provider.disabled.v1')`).Scan(
		&got.commands, &got.mappings, &got.effects, &got.dispositions, &got.audits, &got.events)
	if err != nil {
		t.Fatal("inspect native disable command and required effects", err)
	}
	return got
}

type providerDisableCredential struct {
	generation, version string
	envelope, binding   []byte
}

func nativeProviderDisableCredential(t *testing.T, x providerLoginStartFixture) providerDisableCredential {
	t.Helper()
	var got providerDisableCredential
	err := x.enable.f.pool.Raw().QueryRow(x.enable.f.ctx, `SELECT generation::text,provider_version::text,envelope,credential_context
 FROM sso_providers.credentials WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`,
		string(x.enable.proof.TenantID), string(x.enable.proof.OrganizationID), x.request.ProviderID).
		Scan(&got.generation, &got.version, &got.envelope, &got.binding)
	if err != nil {
		t.Fatal("inspect installed credential without revealing it", err)
	}
	return got
}

func assertProviderDisableState(t *testing.T, x providerLoginStartFixture, enabled bool, version string) {
	t.Helper()
	var actualEnabled, proofLinked, credentialLinked bool
	var actualVersion string
	err := x.enable.f.pool.Raw().QueryRow(x.enable.f.ctx, `SELECT enabled,metadata_version::text,
 enablement_proof IS NOT NULL,enablement_credential_generation IS NOT NULL
 FROM sso_providers.providers WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`,
		string(x.enable.proof.TenantID), string(x.enable.proof.OrganizationID), x.request.ProviderID).
		Scan(&actualEnabled, &actualVersion, &proofLinked, &credentialLinked)
	if err != nil || actualEnabled != enabled || actualVersion != version || proofLinked != enabled || credentialLinked != enabled {
		t.Fatal("provider activation/version linkage does not match the atomic transition", err)
	}
}

func TestNativeProviderDisableCommitsExactGenerationDispositionAndReplay(t *testing.T) {
	for _, mode := range []sso.ActiveTransactionDispositionMode{sso.ActiveTransactionDrain, sso.ActiveTransactionRevoke} {
		t.Run(string(mode), func(t *testing.T) {
			x := newProviderLoginStartFixture(t)
			f := x.enable.f
			service := nativeProviderDisableService(t, x, providerDisablePolicy{})
			request := nativeProviderDisableRequest(t, x, mode)
			first := nativeProviderDisableStart(t, x, 1)
			second := nativeProviderDisableStart(t, x, 2)
			expired := nativeProviderDisableStart(t, x, 3)
			terminal := nativeProviderDisableStart(t, x, 4)
			if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE sso_providers.login_transactions
 SET issued_at=clock_timestamp()-interval '20 minutes',expires_at=clock_timestamp()-interval '15 minutes'
 WHERE start_command_id=$1`, expired.TransactionID); err != nil {
				t.Fatal("age an actually admitted transaction beyond its original lifetime", err)
			}
			if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE sso_providers.login_transactions
 SET completed_at=clock_timestamp(),verifier_envelope=NULL WHERE start_command_id=$1`, terminal.TransactionID); err != nil {
				t.Fatal("make an actually admitted transaction terminal", err)
			}
			before := nativeProviderDisableEffects(t, x)
			credential := nativeProviderDisableCredential(t, x)
			out, err := service.ProviderDisable(f.ctx, request)
			if err != nil || !out.Disabled || out.Deleted || out.ActiveTransactionCount != 2 ||
				out.Completion.Outcome != identity.CommitOutcomeCommitted || out.Completion.Binding.RecordID != request.ProviderID ||
				out.Completion.Feature == nil || out.Completion.Feature.BeforeVersion != 3 || out.Completion.Feature.AfterVersion != 4 {
				t.Fatal("native disable did not report the committed predecessor's real live count", err)
			}
			assertProviderDisableState(t, x, false, "4")
			if !reflect.DeepEqual(nativeProviderDisableCredential(t, x), credential) {
				t.Fatal("provider disable changed or removed the installed encrypted credential")
			}
			proof, err := x.enable.config.Organizations.GetDomainProof(f.ctx, organization.DomainProofKey(x.enable.proof))
			if err != nil || proof != x.enable.proof {
				t.Fatal("provider disable revoked or changed organization-owned domain evidence", err)
			}
			var storedMode, predecessor, command string
			var count int32
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT mode,provider_version::text,command_id,active_transaction_count
 FROM sso_providers.provider_login_dispositions WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`,
				string(x.enable.proof.TenantID), string(x.enable.proof.OrganizationID), request.ProviderID).
				Scan(&storedMode, &predecessor, &command, &count); err != nil || storedMode != string(mode) || predecessor != "3" ||
				command != string(out.Completion.Binding.CommandID) || count != 2 {
				t.Fatal("durable disposition lost its exact scope, selected mode or original live count", err)
			}
			after := nativeProviderDisableEffects(t, x)
			if after.commands != before.commands+1 || after.mappings != before.mappings+1 || after.effects != before.effects+1 ||
				after.dispositions != before.dispositions+1 || after.audits != before.audits+1 || after.events != before.events+1 {
				t.Fatal("disable did not commit exactly one command, mapping, disposition, audit and lifecycle event")
			}
			loginBefore := nativeProviderLoginCounts(t, x)
			newRequest := x.request
			newRequest.CommandID = commandID(t)
			newRequest.IdempotencyKey, err = identity.NewIdempotencyKey([]byte("after-provider-disable"))
			if err != nil {
				t.Fatal(err)
			}
			denied, err := x.service.SigninStart(f.ctx, newRequest, x.browser)
			if !errors.Is(err, sso.ErrForbidden) || denied.RedirectURI != (url.URL{}) || denied.TransactionID != "" {
				t.Fatal("disabled predecessor admitted a fresh native sign-in", err)
			}
			loginAfter := nativeProviderLoginCounts(t, x)
			if loginAfter.transactions != loginBefore.transactions || loginAfter.capabilities != loginBefore.capabilities || loginAfter.events != loginBefore.events {
				t.Fatal("rejected post-disable start created login authority or lifecycle effects")
			}
			// Complete the remaining rows independently of any callback implementation:
			// retry must return the receipt's original count, not recount live rows.
			if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE sso_providers.login_transactions
 SET completed_at=clock_timestamp(),verifier_envelope=NULL WHERE start_command_id IN ($1,$2)`, first.TransactionID, second.TransactionID); err != nil {
				t.Fatal("advance retained transaction fixture after disable commit", err)
			}
			restarted := nativeProviderDisableService(t, x, providerDisablePolicy{})
			replayed, err := restarted.ProviderDisable(f.ctx, request)
			if err != nil || !reflect.DeepEqual(out, replayed) {
				t.Fatal("same-intent restart retry did not recover the exact original disable receipt", err)
			}
			changedReason := request
			changedReason.Reason = "A different lifecycle reason"
			changedMode := request
			otherMode := sso.ActiveTransactionDrain
			if mode == sso.ActiveTransactionDrain {
				otherMode = sso.ActiveTransactionRevoke
			}
			changedMode.ActiveTransactionDisposition, err = sso.NewActiveTransactionDisposition(sso.ProviderID(request.ProviderID), 3, otherMode)
			if err != nil {
				t.Fatal(err)
			}
			for _, changed := range []sso.ProviderDisableRequest{changedReason, changedMode} {
				result, err := restarted.ProviderDisable(f.ctx, changed)
				if !errors.Is(err, sso.ErrConflict) || result.Disabled || result.Deleted || result.ActiveTransactionCount != 0 {
					t.Fatal("changed lifecycle intent recovered the original terminal result", err)
				}
			}
			if nativeProviderDisableEffects(t, x) != after {
				t.Fatal("exact replay or conflicting intent repeated durable disable effects")
			}
		})
	}
}

func TestNativeProviderDisableRequiresCurrentOwnerBeforeAdmissionAndReplayDisclosure(t *testing.T) {
	x := newProviderLoginStartFixture(t)
	nativeProviderDisableStart(t, x, 1)
	request := nativeProviderDisableRequest(t, x, sso.ActiveTransactionDrain)
	before := nativeProviderDisableEffects(t, x)
	for _, name := range []string{"denied", "expired", "epoch", "context"} {
		t.Run(name, func(t *testing.T) {
			policy := providerDisablePolicy{alter: func(e *ssopg.ProviderDisableAuthorizationEvidence) {
				switch name {
				case "denied":
					e.Decision.Outcome = authorization.Deny
				case "expired":
					e.ValidUntil = e.Context.Request.Environment.Time
				case "epoch":
					e.ActorAuthorizationVersion++
				case "context":
					e.Context.Request.Resource.ID = "foreign-organization"
				}
			}}
			service := nativeProviderDisableService(t, x, policy)
			out, err := service.ProviderDisable(x.enable.f.ctx, request)
			if !errors.Is(err, sso.ErrForbidden) || out.Disabled || out.Deleted || out.ActiveTransactionCount != 0 {
				t.Fatal("invalid current owner evidence admitted or disclosed disablement", err)
			}
		})
	}
	assertProviderDisableState(t, x, true, "3")
	if nativeProviderDisableEffects(t, x) != before {
		t.Fatal("rejected disable authority retained a command or success effects")
	}
	service := nativeProviderDisableService(t, x, providerDisablePolicy{})
	out, err := service.ProviderDisable(x.enable.f.ctx, request)
	if err != nil || !out.Disabled || out.ActiveTransactionCount != 1 {
		t.Fatal("fresh current owner could not disable the original enabled provider", err)
	}
	after := nativeProviderDisableEffects(t, x)
	denied := nativeProviderDisableService(t, x, providerDisablePolicy{alter: func(e *ssopg.ProviderDisableAuthorizationEvidence) {
		e.Decision.Outcome = authorization.Deny
	}})
	replay, err := denied.ProviderDisable(x.enable.f.ctx, request)
	if !errors.Is(err, sso.ErrForbidden) || replay.Disabled || replay.Deleted || replay.ActiveTransactionCount != 0 {
		t.Fatal("historical committed receipt bypassed current disclosure authorization", err)
	}
	if nativeProviderDisableEffects(t, x) != after {
		t.Fatal("denied historical disclosure changed durable disable effects")
	}
}

func TestNativeProviderDisableRequiredEffectsRollbackWholeTransition(t *testing.T) {
	for _, boundary := range []string{"audit", "outbox"} {
		t.Run(boundary, func(t *testing.T) {
			x := newProviderLoginStartFixture(t)
			f := x.enable.f
			nativeProviderDisableStart(t, x, 1)
			service := nativeProviderDisableService(t, x, providerDisablePolicy{})
			request := nativeProviderDisableRequest(t, x, sso.ActiveTransactionRevoke)
			credential := nativeProviderDisableCredential(t, x)
			before := nativeProviderDisableEffects(t, x)
			sql := `CREATE SEQUENCE sso_providers.disable_required_effect_fault;
 CREATE FUNCTION sso_providers.reject_disable_effect() RETURNS trigger LANGUAGE plpgsql AS $$
 BEGIN PERFORM nextval('sso_providers.disable_required_effect_fault');
 RAISE EXCEPTION 'controlled native disable required-effect rollback'; END $$;
 CREATE TRIGGER reject_disable_effect BEFORE INSERT ON audit.records FOR EACH ROW
 WHEN (NEW.action='identity.sso.provider.disable' AND NEW.outcome=1)
 EXECUTE FUNCTION sso_providers.reject_disable_effect()`
			if boundary == "outbox" {
				sql = `CREATE SEQUENCE sso_providers.disable_required_effect_fault;
 CREATE FUNCTION sso_providers.reject_disable_effect() RETURNS trigger LANGUAGE plpgsql AS $$
 BEGIN PERFORM nextval('sso_providers.disable_required_effect_fault');
 RAISE EXCEPTION 'controlled native disable required-effect rollback'; END $$;
 CREATE TRIGGER reject_disable_effect BEFORE INSERT ON outbox_messages FOR EACH ROW
 WHEN (NEW.topic='enterprise_provider.disabled.v1') EXECUTE FUNCTION sso_providers.reject_disable_effect()`
			}
			if _, err := f.pool.Raw().Exec(f.ctx, sql); err != nil {
				t.Fatal("install required disable effect fault", err)
			}
			out, err := service.ProviderDisable(f.ctx, request)
			if err == nil || out.Disabled || out.Deleted || out.ActiveTransactionCount != 0 || out.Completion.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("required-effect failure disclosed a successful disable result", err)
			}
			var reached bool
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT is_called FROM sso_providers.disable_required_effect_fault`).Scan(&reached); err != nil || !reached {
				t.Fatal("native disable did not reach the required-effect fault", err)
			}
			assertProviderDisableState(t, x, true, "3")
			after := nativeProviderDisableEffects(t, x)
			if after.effects != before.effects || after.dispositions != before.dispositions || after.audits != before.audits || after.events != before.events ||
				!reflect.DeepEqual(nativeProviderDisableCredential(t, x), credential) {
				t.Fatal("required-effect rollback left a partial disable successor or damaged installed credentials")
			}
			var live int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM sso_providers.login_transactions
 WHERE provider_id=$1 AND provider_version=3 AND completed_at IS NULL AND expires_at>clock_timestamp()`, request.ProviderID).Scan(&live); err != nil || live != 1 {
				t.Fatal("rolled-back disable altered the genuine predecessor transaction", err)
			}
		})
	}
}

func TestNativeProviderDisableRecoversOriginalAfterLostCommit(t *testing.T) {
	x := newProviderLoginStartFixture(t)
	f := x.enable.f
	nativeProviderDisableStart(t, x, 1)
	request := nativeProviderDisableRequest(t, x, sso.ActiveTransactionRevoke)
	before := nativeProviderDisableEffects(t, x)
	pool, fault := providerLossPool(t, f, "INSERT INTO sso_providers.provider_login_dispositions")
	service := nativeProviderDisableOnPool(t, x, pool, providerDisablePolicy{})
	out, err := service.ProviderDisable(f.ctx, request)
	var unknown identity.UnknownCommitError
	if !fault.seen.Load() || !fault.lost.Load() || !errors.As(err, &unknown) || out.Completion.Outcome != identity.CommitOutcomeUnknown ||
		out.Disabled || out.Deleted || out.ActiveTransactionCount != 0 || unknown.CommandID == "" || out.Completion.Binding.CommandID != unknown.CommandID {
		t.Fatal("lost disable commit response did not preserve unknown original without disclosure", out.Completion.Outcome, err)
	}
	assertProviderDisableState(t, x, false, "4")
	committed := nativeProviderDisableEffects(t, x)
	if committed.commands != before.commands+1 || committed.mappings != before.mappings+1 || committed.effects != before.effects+1 ||
		committed.dispositions != before.dispositions+1 || committed.audits != before.audits+1 || committed.events != before.events+1 {
		t.Fatal("lost response did not leave exactly one disable transition")
	}
	restarted := nativeProviderDisableService(t, x, providerDisablePolicy{})
	recovered, err := restarted.ProviderDisable(f.ctx, request)
	if err != nil || !recovered.Disabled || recovered.Deleted || recovered.ActiveTransactionCount != 1 ||
		recovered.Completion.Outcome != identity.CommitOutcomeCommitted || recovered.Completion.Binding != out.Completion.Binding {
		t.Fatal("restart did not recover the exact native disable after lost commit response", recovered.Completion.Outcome, err)
	}
	if nativeProviderDisableEffects(t, x) != committed {
		t.Fatal("lost-response recovery repeated durable effects")
	}
}

func TestNativeProviderDisableRetainsCommitOnDisclosureDenial(t *testing.T) {
	x := newProviderLoginStartFixture(t)
	f := x.enable.f
	nativeProviderDisableStart(t, x, 1)
	request := nativeProviderDisableRequest(t, x, sso.ActiveTransactionDrain)
	observations := 0
	service := nativeProviderDisableService(t, x, providerDisablePolicy{alter: func(e *ssopg.ProviderDisableAuthorizationEvidence) {
		observations++
		if observations > 1 {
			e.Decision.Outcome = authorization.Deny
		}
	}})
	out, err := service.ProviderDisable(f.ctx, request)
	if !errors.Is(err, sso.ErrForbidden) || out.Completion.Outcome != identity.CommitOutcomeCommitted || out.Disabled || out.Deleted || out.ActiveTransactionCount != 0 {
		t.Fatal("post-commit loss of disclosure authority exposed the receipt or hid its known outcome", out.Completion.Outcome, err)
	}
	assertProviderDisableState(t, x, false, "4")
	committed := nativeProviderDisableEffects(t, x)
	recovered, err := nativeProviderDisableService(t, x, providerDisablePolicy{}).ProviderDisable(f.ctx, request)
	if err != nil || !recovered.Disabled || recovered.ActiveTransactionCount != 1 || recovered.Completion.Binding != out.Completion.Binding || nativeProviderDisableEffects(t, x) != committed {
		t.Fatal("fresh disclosure did not recover the committed original exactly once", err)
	}
}
