//go:build integration

package postgres_test

import (
	"encoding/base64"
	"errors"
	"net/url"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-sso"
	"github.com/faustbrian/go-sso/oidc"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestNativeProviderLogoutCompleteUsesOriginalStateWithoutRevokedCookie(t *testing.T) {
	x := newNativeProviderLogoutFixture(t, true)
	request, started := startNativeProviderLogoutCallback(t, x)
	before := nativeProviderLogoutStartCounts(t, x)

	got, err := x.service.Complete(x.journey.start.enable.f.ctx, request)
	if err != nil || got.Validate() != nil || got.Outcome() != oidc.OIDCLogoutRedirect {
		t.Fatal("provider return did not complete the original native logout without a cookie or CSRF credential", err)
	}
	redirect, present := got.RedirectURI()
	if !present || redirect.String() != nativeLogoutFinalRedirect {
		t.Fatal("provider return did not disclose only the original exact allowlisted final target")
	}
	completion, err := got.Completion()
	if err != nil || completion.Outcome != identity.CommitOutcomeCommitted ||
		completion.Binding.OperationID != "identity.sso.oidc-logout-complete" ||
		completion.Binding.UserID != x.session.UserID || completion.Binding.RecordID != x.session.SessionID ||
		completion.Binding.CommandID == started.Binding.CommandID {
		t.Fatal("provider return did not retain a distinct native completion receipt for the original session owner", err)
	}
	assertNativeProviderLogoutTerminal(t, x, started, completion, "provider_complete")
	assertNativeProviderLogoutCookieState(t, x, false)
	after := nativeProviderLogoutStartCounts(t, x)
	if after.states != before.states || after.revocations != before.revocations || after.commands != before.commands || x.journey.posts.Load() != 2 {
		t.Fatal("provider completion restarted logout, repeated revocation or contacted the provider")
	}
	assertNativeProviderLogoutReplayDenied(t, x, request)
}

func TestNativeProviderLogoutCompleteRateSourceReadsOnlyExactPendingCustody(t *testing.T) {
	x := newNativeProviderLogoutFixture(t, true)
	request, started := startNativeProviderLogoutCallback(t, x)
	ctx, tenant := x.journey.start.enable.f.ctx, x.session.TenantID
	before := nativeProviderLogoutCompleteCounts(t, x)
	want := ssopg.ProviderLogoutRateContext{ProviderID: sso.ProviderID(request.ProviderID),
		TransactionID: string(started.Binding.CommandID), Lifetime: x.loginConfig.StateLifetime}
	for range 2 {
		got, err := x.service.CompleteRateSource(ctx, tenant, request)
		if err != nil || got != want {
			t.Fatal("quota source missed the original provider, transaction or lifetime", err)
		}
	}
	wrong := request
	wrong.CallbackURI = "https://wrong.example.test/sso/oidc/" + request.ProviderID + "/logout/callback"
	if got, err := x.service.CompleteRateSource(ctx, tenant, wrong); !errors.Is(err, sso.ErrForbidden) || got != (ssopg.ProviderLogoutRateContext{}) {
		t.Fatal("quota source accepted another receiving origin", err)
	}
	if got, err := x.service.CompleteRateSource(ctx, "another-tenant", request); !errors.Is(err, sso.ErrForbidden) || got != (ssopg.ProviderLogoutRateContext{}) {
		t.Fatal("quota source accepted another tenant", err)
	}
	if after := nativeProviderLogoutCompleteCounts(t, x); after != before {
		t.Fatal("quota observation reserved or consumed pending callback state")
	}
	if result, err := x.service.Complete(ctx, request); err != nil || result.Outcome() != oidc.OIDCLogoutRedirect {
		t.Fatal("read-only quota observation prevented original completion", err)
	}
	if got, err := x.service.CompleteRateSource(ctx, tenant, request); !errors.Is(err, sso.ErrForbidden) || got != (ssopg.ProviderLogoutRateContext{}) {
		t.Fatal("quota source accepted terminal callback state", err)
	}
}

func TestNativeProviderLogoutCompleteRejectsUnboundReturnBeforeConsumingOriginalState(t *testing.T) {
	x := newNativeProviderLogoutFixture(t, true)
	original, started := startNativeProviderLogoutCallback(t, x)
	foreignState := oidc.NewRPLogoutState([32]byte{0x7a}).Encode()
	for _, name := range []string{"wrong-callback-uri", "wrong-provider", "inbound-issuer", "foreign-state"} {
		t.Run(name, func(t *testing.T) {
			request := original
			switch name {
			case "wrong-callback-uri":
				request.CallbackURI = "https://another-app.example.test" + "/sso/oidc/" + request.ProviderID + "/logout/callback"
			case "wrong-provider":
				request.ProviderID = "another-provider"
			case "inbound-issuer":
				request.RawQuery += "&iss=" + url.QueryEscape(nativeCallbackJourneyIssuer)
			case "foreign-state":
				request.RawQuery = url.Values{"state": {foreignState}}.Encode()
			}
			before := nativeProviderLogoutCompleteCounts(t, x)
			got, err := x.service.Complete(x.journey.start.enable.f.ctx, request)
			if _, disclosed := got.RedirectURI(); err == nil || disclosed || got.Outcome() != oidc.OIDCLogoutInvalid || got.Validate() == nil {
				t.Fatal("unbound provider return disclosed a redirect or claimed a terminal logout outcome")
			}
			if after := nativeProviderLogoutCompleteCounts(t, x); after != before {
				t.Fatal("unbound provider return consumed native logout state or created durable completion effects")
			}
			assertNativeProviderLogoutCookieState(t, x, false)
		})
	}
	got, err := x.service.Complete(x.journey.start.enable.f.ctx, original)
	if err != nil || got.Validate() != nil || got.Outcome() != oidc.OIDCLogoutRedirect {
		t.Fatal("rejected provider returns consumed or corrupted the original valid callback", err)
	}
	redirect, present := got.RedirectURI()
	if !present || redirect.String() != nativeLogoutFinalRedirect {
		t.Fatal("original callback lost its exact allowlisted final target after rejected returns")
	}
	completion, err := got.Completion()
	if err != nil {
		t.Fatal(err)
	}
	assertNativeProviderLogoutTerminal(t, x, started, completion, "provider_complete")
	if x.journey.posts.Load() != 2 {
		t.Fatal("provider return made a token or end-session request")
	}
}

func TestNativeProviderLogoutCompleteProviderErrorKeepsLocalRevocationWithoutRedirect(t *testing.T) {
	x := newNativeProviderLogoutFixture(t, true)
	request, started := startNativeProviderLogoutCallback(t, x)
	successReturn := request
	request.RawQuery += "&error=access_denied&error_description=provider+did+not+end+the+session"
	before := nativeProviderLogoutStartCounts(t, x)

	got, err := x.service.Complete(x.journey.start.enable.f.ctx, request)
	if err != nil || got.Validate() != nil || got.Outcome() != oidc.OIDCLogoutProviderError {
		t.Fatal("provider failure did not preserve the explicit terminal failure disposition", err)
	}
	if _, disclosed := got.RedirectURI(); disclosed {
		t.Fatal("provider failure disclosed a success redirect")
	}
	completion, err := got.Completion()
	if err != nil || completion.Outcome != identity.CommitOutcomeCommitted ||
		completion.Binding.OperationID != "identity.sso.oidc-logout-complete" ||
		completion.Binding.UserID != x.session.UserID || completion.Binding.RecordID != x.session.SessionID {
		t.Fatal("provider failure lost the original-session native completion receipt", err)
	}
	assertNativeProviderLogoutTerminal(t, x, started, completion, "provider_error")
	assertNativeProviderLogoutCookieState(t, x, false)
	after := nativeProviderLogoutStartCounts(t, x)
	if after.revocations != before.revocations || after.commands != before.commands || x.journey.posts.Load() != 2 {
		t.Fatal("provider failure retried local logout or contacted the provider")
	}
	assertNativeProviderLogoutReplayDenied(t, x, request)
	assertNativeProviderLogoutReplayDenied(t, x, successReturn)
	assertNativeProviderLogoutTerminal(t, x, started, completion, "provider_error")
}

func TestNativeProviderLogoutCompleteLateReturnConsumesStateAsTimeout(t *testing.T) {
	x := newNativeProviderLogoutFixture(t, true)
	request, started := startNativeProviderLogoutCallback(t, x)
	ctx := x.journey.start.enable.f.ctx
	if err := ssopg.ExpireNativeProviderLogoutFixture(ctx, x.service, request.RawQuery); err != nil {
		t.Fatal("age the authenticated fixture state against database time", err)
	}
	got, err := x.service.Complete(ctx, request)
	if err != nil || got.Validate() != nil || got.Outcome() != oidc.OIDCLogoutTimeout {
		t.Fatal("late valid return did not settle as timeout", err)
	}
	if _, present := got.RedirectURI(); present {
		t.Fatal("late return exposed the final target")
	}
	completion, err := got.Completion()
	if err != nil || completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("timeout missed its distinct committed operation", err)
	}
	assertNativeProviderLogoutTerminal(t, x, started, completion, "timeout")
	assertNativeProviderLogoutReplayDenied(t, x, request)
}

func TestNativeProviderLogoutCompleteLostCommitDoesNotDiscloseOrRepeat(t *testing.T) {
	x := newNativeProviderLogoutFixture(t, true)
	request, started := startNativeProviderLogoutCallback(t, x)
	ctx := x.journey.start.enable.f.ctx
	service, fault := nativeProviderLogoutWithCommitFault(t, x, "WITH locked AS MATERIALIZED")
	got, err := service.Complete(ctx, request)
	if err != nil || !fault.seen.Load() || !fault.lost.Load() || got.Validate() != nil || got.Outcome() != oidc.OIDCLogoutUnknownReconciliation {
		t.Fatal("lost real COMMIT acknowledgement did not preserve uncertainty", err)
	}
	if _, present := got.RedirectURI(); present {
		t.Fatal("an unacknowledged callback exposed the final target")
	}
	completion, err := got.Completion()
	if err != nil || completion.Outcome != identity.CommitOutcomeUnknown {
		t.Fatal("unknown provider result lost the native command identity", err)
	}
	assertNativeProviderLogoutTerminal(t, x, started, completion, "provider_complete")
	assertNativeProviderLogoutReplayDenied(t, x, request)
}

func TestNativeProviderLogoutCompleteConcurrentReturnDisclosesOnce(t *testing.T) {
	x := newNativeProviderLogoutFixture(t, true)
	request, started := startNativeProviderLogoutCallback(t, x)
	type attempt struct {
		out oidc.LogoutCompleteResult
		err error
	}
	begin := make(chan struct{})
	done := make(chan attempt, 2)
	for range 2 {
		go func() {
			<-begin
			out, err := x.service.Complete(x.journey.start.enable.f.ctx, request)
			done <- attempt{out, err}
		}()
	}
	close(begin)
	var acknowledged []identity.CommandResult
	for range 2 {
		a := <-done
		if _, disclosed := a.out.RedirectURI(); disclosed {
			receipt, err := a.out.Completion()
			if err != nil || a.err != nil || receipt.Outcome != identity.CommitOutcomeCommitted {
				t.Error("the only redirect must have a valid acknowledged commit", err)
			}
			acknowledged = append(acknowledged, receipt)
		} else if a.out.Outcome() != oidc.OIDCLogoutUnknownReconciliation && !errors.Is(a.err, sso.ErrForbidden) && !errors.Is(a.err, sso.ErrConflict) {
			t.Error("a racing callback neither reconciled nor failed closed", a.err)
		}
	}
	if len(acknowledged) != 1 {
		t.Fatal("concurrent provider returns did not expose exactly one final redirect")
	}
	assertNativeProviderLogoutTerminal(t, x, started, acknowledged[0], "provider_complete")
	assertNativeProviderLogoutReplayDenied(t, x, request)
}

func assertNativeProviderLogoutReplayDenied(t *testing.T, x nativeProviderLogoutFixture, request ssopg.ProviderLogoutCompleteRequest) {
	t.Helper()
	before := nativeProviderLogoutCompleteCounts(t, x)
	var firstForbidden bool
	for attempt := range 2 {
		got, err := x.service.Complete(x.journey.start.enable.f.ctx, request)
		if _, disclosed := got.RedirectURI(); disclosed || got.Validate() == nil || got.Outcome() != oidc.OIDCLogoutInvalid ||
			!errors.Is(err, sso.ErrForbidden) && !errors.Is(err, sso.ErrConflict) {
			t.Fatal("a consumed logout state did not return a stable denial without a second redirect", err)
		}
		forbidden := errors.Is(err, sso.ErrForbidden)
		if attempt > 0 && forbidden != firstForbidden {
			t.Fatal("repeated consumed provider state changed its denial category")
		}
		firstForbidden = forbidden
		if after := nativeProviderLogoutCompleteCounts(t, x); after != before {
			t.Fatal("replayed provider return repeated or changed durable native logout effects")
		}
	}
	assertNativeProviderLogoutCookieState(t, x, false)
}

type nativeProviderLogoutCompletionCounts struct {
	start             nativeProviderLogoutCounts
	terminalRows      int
	completionCommand int
}

func nativeProviderLogoutCompleteCounts(t *testing.T, x nativeProviderLogoutFixture) nativeProviderLogoutCompletionCounts {
	t.Helper()
	n := nativeProviderLogoutCompletionCounts{start: nativeProviderLogoutStartCounts(t, x)}
	err := x.journey.start.enable.f.pool.Raw().QueryRow(x.journey.start.enable.f.ctx, `SELECT
 (SELECT count(*) FROM sso_providers.logout_transactions WHERE completed_at IS NOT NULL OR completion_command_id IS NOT NULL OR completion_kind IS NOT NULL),
 (SELECT count(*) FROM identity.commands WHERE purpose='identity.sso.oidc-logout-complete')`).
		Scan(&n.terminalRows, &n.completionCommand)
	if err != nil {
		t.Fatal("observe native completion custody and exact-once effects", err)
	}
	return n
}

func startNativeProviderLogoutCallback(t *testing.T, x nativeProviderLogoutFixture) (ssopg.ProviderLogoutCompleteRequest, identity.CommandResult) {
	t.Helper()
	started, err := x.service.Start(x.journey.start.enable.f.ctx, x.request, x.browser)
	if err != nil || started.Validate() != nil || started.Outcome() != oidc.OIDCLogoutRedirect {
		t.Fatal("start the real native logout before simulating the provider return", err)
	}
	redirect, present := started.RedirectURI()
	state := redirect.Query().Get("state")
	if !present || len(state) != 43 {
		t.Fatal("original native logout did not disclose its canonical one-use provider state")
	}
	completion, err := started.Completion()
	if err != nil || completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("original logout did not acknowledge exact-session local revocation", err)
	}
	assertNativeProviderLogoutCookieState(t, x, false)
	return ssopg.ProviderLogoutCompleteRequest{
		ProviderID: x.request.ProviderID, CallbackURI: nativeProviderLogoutCallback(x.journey),
		RawQuery: url.Values{"state": {state}}.Encode(),
	}, completion
}

func assertNativeProviderLogoutTerminal(t *testing.T, x nativeProviderLogoutFixture, started, completed identity.CommandResult, kind string) {
	t.Helper()
	startCommand, err := base64.RawURLEncoding.DecodeString(string(started.Binding.CommandID))
	if err != nil {
		t.Fatal(err)
	}
	completionCommand, err := base64.RawURLEncoding.DecodeString(string(completed.Binding.CommandID))
	if err != nil {
		t.Fatal(err)
	}
	var terminal, commands, startAudits, revocations int
	err = x.journey.start.enable.f.pool.Raw().QueryRow(x.journey.start.enable.f.ctx, `SELECT
 (SELECT count(*) FROM sso_providers.logout_transactions WHERE tenant_id=$1 AND start_command_id=$2 AND completed_at IS NOT NULL AND completed_at>=issued_at AND completion_command_id=$3 AND completion_kind=$4),
 (SELECT count(*) FROM identity.commands WHERE tenant_id=$1 AND command_id=$3 AND purpose='identity.sso.oidc-logout-complete'),
 (SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.tenant_id=$1 AND r.action='identity.sso.logout_oidc'),
 (SELECT count(*) FROM organization_sessions.session_revocations WHERE tenant_id=$1 AND session_id=$5 AND purpose='identity.sso.oidc-logout')`,
		string(x.session.TenantID), startCommand, completionCommand, kind, x.session.SessionID).
		Scan(&terminal, &commands, &startAudits, &revocations)
	if err != nil || terminal != 1 || commands != 1 || startAudits != 1 || revocations != 1 {
		t.Fatal("provider return did not retain exactly one terminal command and state while preserving the original revocation and start audit", err)
	}
}
