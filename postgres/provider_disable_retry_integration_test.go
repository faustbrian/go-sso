//go:build integration

package postgres_test

import (
	"errors"
	"reflect"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-sso"
)

func TestNativeProviderDisableRetryRequiresExactConfirmedFailedAnchor(t *testing.T) {
	for _, boundary := range []string{"audit", "outbox"} {
		t.Run(boundary, func(t *testing.T) {
			x := newProviderLoginStartFixture(t)
			f := x.enable.f
			nativeProviderDisableStart(t, x, 1)
			service := nativeProviderDisableService(t, x, providerDisablePolicy{})
			request := nativeProviderDisableRequest(t, x, sso.ActiveTransactionRevoke)
			before := nativeProviderDisableEffects(t, x)
			faultSQL := `CREATE SEQUENCE sso_providers.disable_retry_effect_fault;
 CREATE FUNCTION sso_providers.reject_disable_retry_effect() RETURNS trigger LANGUAGE plpgsql AS $$
 BEGIN PERFORM nextval('sso_providers.disable_retry_effect_fault');
 RAISE EXCEPTION 'controlled native disable retry rollback'; END $$;
 CREATE TRIGGER reject_disable_retry_effect BEFORE INSERT ON audit.records FOR EACH ROW
 WHEN (NEW.action='identity.sso.provider.disable' AND NEW.outcome=1)
 EXECUTE FUNCTION sso_providers.reject_disable_retry_effect()`
			removeFaultSQL := `DROP TRIGGER reject_disable_retry_effect ON audit.records`
			if boundary == "outbox" {
				faultSQL = `CREATE SEQUENCE sso_providers.disable_retry_effect_fault;
 CREATE FUNCTION sso_providers.reject_disable_retry_effect() RETURNS trigger LANGUAGE plpgsql AS $$
 BEGIN PERFORM nextval('sso_providers.disable_retry_effect_fault');
 RAISE EXCEPTION 'controlled native disable retry rollback'; END $$;
 CREATE TRIGGER reject_disable_retry_effect BEFORE INSERT ON outbox_messages FOR EACH ROW
 WHEN (NEW.topic='enterprise_provider.disabled.v1')
 EXECUTE FUNCTION sso_providers.reject_disable_retry_effect()`
				removeFaultSQL = `DROP TRIGGER reject_disable_retry_effect ON outbox_messages`
			}
			if _, err := f.pool.Raw().Exec(f.ctx, faultSQL); err != nil {
				t.Fatal("install genuine required-effect rollback", err)
			}
			failed, err := service.ProviderDisable(f.ctx, request)
			if err == nil || failed.Disabled || failed.Deleted || failed.ActiveTransactionCount != 0 ||
				failed.Completion.Outcome == identity.CommitOutcomeCommitted || failed.Completion.Binding.CommandID == "" {
				t.Fatal("required-effect rollback did not retain an undisclosed original command", err)
			}
			var reached bool
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT is_called FROM sso_providers.disable_retry_effect_fault`).Scan(&reached); err != nil || !reached {
				t.Fatal("native disable did not reach the required-effect rollback", err)
			}
			assertProviderDisableState(t, x, true, "3")
			restarted := nativeProviderDisableService(t, x, providerDisablePolicy{})
			original, _ := restarted.ProviderDisable(f.ctx, request)
			if original.Completion.Outcome != identity.CommitOutcomeNotCommitted || original.Completion.Binding != failed.Completion.Binding ||
				original.Disabled || original.Deleted || original.ActiveTransactionCount != 0 {
				t.Fatal("same original request did not recover the confirmed non-committed outcome")
			}
			failedAnchor := original.Completion.Binding.CommandID
			afterFailure := nativeProviderDisableEffects(t, x)
			if afterFailure.commands != before.commands+1 || afterFailure.mappings != before.mappings+1 ||
				afterFailure.effects != before.effects || afterFailure.dispositions != before.dispositions ||
				afterFailure.audits != before.audits || afterFailure.events != before.events {
				t.Fatal("confirmed rollback left success effects or more than one original command")
			}
			changedReason := request
			changedReason.Reason = "A different reason cannot fork a failed disable"
			changedMode := request
			changedMode.ActiveTransactionDisposition, err = sso.NewActiveTransactionDisposition(sso.ProviderID(request.ProviderID), 3, sso.ActiveTransactionDrain)
			if err != nil {
				t.Fatal(err)
			}
			for _, changed := range []sso.ProviderDisableRequest{changedReason, changedMode} {
				out, err := restarted.ProviderDisable(f.ctx, changed)
				if !errors.Is(err, sso.ErrConflict) || out.Disabled || out.Deleted || out.ActiveTransactionCount != 0 {
					t.Fatal("changed canonical intent forked the original failure", err)
				}
				out, err = restarted.RetryProviderDisable(f.ctx, changed, failedAnchor)
				if !errors.Is(err, sso.ErrConflict) || out.Disabled || out.Deleted || out.ActiveTransactionCount != 0 {
					t.Fatal("explicit retry did not bind the complete failed intent", err)
				}
			}
			if nativeProviderDisableEffects(t, x) != afterFailure {
				t.Fatal("changed intent retained a new retry command or effects")
			}
			if _, err := f.pool.Raw().Exec(f.ctx, removeFaultSQL); err != nil {
				t.Fatal("remove the disposable required-effect fault", err)
			}
			stillOriginal, _ := restarted.ProviderDisable(f.ctx, request)
			if !reflect.DeepEqual(stillOriginal, original) || nativeProviderDisableEffects(t, x) != afterFailure {
				t.Fatal("removing the fault silently replaced the failed original without explicit retry")
			}
			retried, err := restarted.RetryProviderDisable(f.ctx, request, failedAnchor)
			if err != nil || !retried.Disabled || retried.Deleted || retried.ActiveTransactionCount != 1 ||
				retried.Completion.Outcome != identity.CommitOutcomeCommitted || retried.Completion.Binding.CommandID == "" ||
				retried.Completion.Binding.CommandID == failedAnchor || retried.Completion.Binding.RecordID != request.ProviderID {
				t.Fatal("exact confirmed-failure retry did not commit one distinct fresh command", err)
			}
			assertProviderDisableState(t, x, false, "4")
			committed := nativeProviderDisableEffects(t, x)
			if committed.commands != afterFailure.commands+1 || committed.mappings != afterFailure.mappings+1 ||
				committed.effects != afterFailure.effects+1 || committed.dispositions != afterFailure.dispositions+1 ||
				committed.audits != afterFailure.audits+1 || committed.events != afterFailure.events+1 {
				t.Fatal("explicit retry did not produce exactly one fresh command and required-effect set")
			}
			replayService := nativeProviderDisableService(t, x, providerDisablePolicy{})
			replay, err := replayService.RetryProviderDisable(f.ctx, request, failedAnchor)
			if err != nil || !reflect.DeepEqual(retried, replay) || nativeProviderDisableEffects(t, x) != committed {
				t.Fatal("same failed anchor did not recover its exact stable retry receipt", err)
			}
			unchangedOriginal, _ := replayService.ProviderDisable(f.ctx, request)
			if !reflect.DeepEqual(unchangedOriginal, original) {
				t.Fatal("successful explicit retry rewrote the historical original failure")
			}
			denied, err := replayService.RetryProviderDisable(f.ctx, request, retried.Completion.Binding.CommandID)
			if err == nil || denied.Disabled || denied.Deleted || denied.ActiveTransactionCount != 0 ||
				nativeProviderDisableEffects(t, x) != committed {
				t.Fatal("a committed command became a fresh retry anchor", err)
			}
		})
	}
}

func TestNativeProviderDisableRetryCannotUsePendingAttempt(t *testing.T) {
	x := newProviderLoginStartFixture(t)
	f := x.enable.f
	nativeProviderDisableStart(t, x, 1)
	request := nativeProviderDisableRequest(t, x, sso.ActiveTransactionDrain)
	pool, fault := providerLossPool(t, f, "INSERT INTO sso_providers.provider_login_dispositions")
	fault.beforeCommit.Store(true)
	service := nativeProviderDisableOnPool(t, x, pool, providerDisablePolicy{})
	unknown, err := service.ProviderDisable(f.ctx, request)
	var unresolved identity.UnknownCommitError
	if !fault.lost.Load() || !errors.As(err, &unresolved) || unknown.Completion.Outcome != identity.CommitOutcomeUnknown || unresolved.CommandID == "" {
		t.Fatal("fixture did not withhold the final commit and leave the real original pending", unknown.Completion.Outcome, err)
	}
	assertProviderDisableState(t, x, true, "3")
	before := nativeProviderDisableEffects(t, x)
	retry := nativeProviderDisableService(t, x, providerDisablePolicy{})
	out, err := retry.RetryProviderDisable(f.ctx, request, unresolved.CommandID)
	if err == nil || out.Disabled || out.Deleted || out.ActiveTransactionCount != 0 || nativeProviderDisableEffects(t, x) != before {
		t.Fatal("a genuinely pending original acted as authorization for a fresh disable", err)
	}
}
