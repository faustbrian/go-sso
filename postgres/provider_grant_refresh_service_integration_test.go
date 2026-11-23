//go:build integration

package postgres_test

import (
	"bytes"
	"errors"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestNativeEnterpriseOAuth2RefreshCommitsOneSuccessor(t *testing.T) {
	for _, tc := range []struct {
		name, mode, provider string
		lost                 bool
	}{
		{name: "rotated", mode: "restorable-vault-refresh", provider: "rotated"},
		{name: "competing-revoke", mode: nativeOAuth2RefreshRaceMode, provider: "rotated"},
		{name: "retained", mode: "restorable-vault-refresh-retained", provider: "retained"},
		{name: "scope-after-rotation", mode: nativeOAuth2NarrowRotatedMode, provider: "rotated"},
		{name: "scope-after-retention", mode: nativeOAuth2NarrowRetainedMode, provider: "retained"},
		{name: "refused", mode: "restorable-vault-refresh-refused", provider: "refused"},
		{name: "rejected", mode: "restorable-vault-refresh-rejected", provider: "rejected"},
		{name: "unknown", mode: "restorable-vault-refresh-unknown", provider: "unknown"},
		{name: "late-factor", mode: "restorable-vault-refresh-late-factor"},
		{name: "lost-commit", mode: "restorable-vault-refresh", provider: "rotated", lost: true},
	} {
		t.Run(tc.name, func(t *testing.T) { testNativeEnterpriseOAuth2Refresh(t, tc.mode, tc.provider, tc.lost) })
	}
}

func testNativeEnterpriseOAuth2Refresh(t *testing.T, mode, expected string, lostCommit bool) {
	t.Helper()
	x := newNativeOAuth2JourneyFixture(t, mode)
	f := x.start.enable.f
	erasure, err := (kernel.SSOEnterpriseGrantRefreshPreparationErasureMigrationSource{Base: f.history, Version: 355}).Load(f.ctx)
	if err != nil || len(erasure) != len(f.history)+1 {
		t.Fatal("load refresh erasure after the actual callback history", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, erasure[len(erasure)-1].UpSQL()); err != nil {
		t.Fatal("install refresh erasure", err)
	}
	for _, src := range []migrations.Source{
		ssopg.ProviderGrantFenceMigrationSource{Version: 356},
		ssopg.ProviderGrantRefreshMigrationSource{Version: 357, ValidationVersion: 358, ReceiptVersion: 359},
		ssopg.ProviderGrantRevocationReceiptMigrationSource{Version: 360},
	} {
		steps, err := src.Load(f.ctx)
		if err != nil || len(steps) == 0 {
			t.Fatal("load native refresh migration", err)
		}
		for _, step := range steps {
			if _, err := f.pool.Raw().Exec(f.ctx, step.UpSQL()); err != nil {
				t.Fatal("install native refresh migration", err)
			}
		}
	}
	login, err := x.completion.SigninCallbackOAuth2(f.ctx, x.request)
	if err != nil || login.Completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("issue original enterprise session and grant", err)
	}
	var originalDigest []byte
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT sha256(token_ciphertext) FROM sso_providers.provider_login_token_sets WHERE callback_command_id=$1`,
		string(login.Completion.Binding.CommandID)).Scan(&originalDigest); err != nil {
		t.Fatal(err)
	}
	spec, err := login.Issuance.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := login.Issuance.Token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	grantSpec := sso.TokenVersionSpec{TenantID: spec.TenantID, OrganizationID: x.start.profile.OrganizationID,
		ProviderID: x.start.profile.ProviderID, ProviderSubject: nativeOAuth2JourneySubject,
		CommandID: login.Completion.Binding.CommandID, CredentialGeneration: x.start.profile.CredentialGeneration,
		Version: 1, Purpose: sso.EnterpriseTokenPurpose}
	grant, err := sso.NewTokenVersion(grantSpec)
	if err != nil {
		t.Fatal(err)
	}
	request := func(keyName string) sso.RefreshEnterpriseToken {
		t.Helper()
		key, err := identity.NewIdempotencyKey([]byte(keyName))
		if err != nil {
			t.Fatal(err)
		}
		input, err := sso.NewRefreshEnterpriseToken(grant, key)
		if err != nil {
			t.Fatal(err)
		}
		return input
	}
	cfg := ssopg.ProviderGrantRefreshConfig{
		Session: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: spec.Audience, Clock: clock.System{},
			MaximumDuration: time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{x.lookup}},
		Providers: []ssopg.ProviderGrantRefreshProvider{{OrganizationID: x.start.profile.OrganizationID, ProviderID: x.start.profile.ProviderID}},
	}
	open := func() *ssopg.ProviderGrantRefreshService {
		t.Helper()
		svc, err := ssopg.NewProviderGrantRefreshService(x.completion, cfg)
		if err != nil {
			t.Fatal("compose native refresh with original session and provider authorities", err)
		}
		return svc
	}
	browser := ssopg.ProviderGrantRefreshBrowser{Origin: x.start.config.Origin, Session: authentication.NewBearerCredential(cookie), CSRF: login.CSRF}
	svc := open()
	bad := browser
	bad.CSRF, err = session.NewCSRFToken()
	if err != nil {
		t.Fatal(err)
	}
	original := request("native-enterprise-refresh")
	if got, err := svc.Refresh(f.ctx, original, bad); err == nil || got.Completion.Binding.CommandID != "" || x.refreshes.Load() != 0 {
		t.Fatal("wrong CSRF reached the provider or created a result", err)
	}
	var unknownID identity.CommandID
	if lostCommit {
		login, fault := nativeOAuth2CompletionWithCommitFault(t, x, "INSERT INTO sso_providers.provider_grant_refresh_receipts")
		faulted, err := ssopg.NewProviderGrantRefreshService(login, cfg)
		if err != nil {
			t.Fatal(err)
		}
		got, err := faulted.Refresh(f.ctx, original, browser)
		var unknown identity.UnknownCommitError
		if !fault.lost.Load() || !errors.As(err, &unknown) || unknown.CommandID == "" || got.Successor != (sso.TokenVersion{}) || x.refreshes.Load() != 1 {
			t.Fatal("lost database acknowledgement did not withhold the successor and identify the original command", err)
		}
		unknownID = unknown.CommandID
	}
	var got ssopg.ProviderGrantRefreshResult
	if mode == nativeOAuth2RefreshRaceMode {
		got, err = raceNativeEnterpriseRefreshAndRevoke(t, x, svc, cfg.Session, original, grant, browser)
	} else {
		got, err = svc.Refresh(f.ctx, original, browser)
	}
	if expected == "" {
		var unknown identity.UnknownCommitError
		if !errors.As(err, &unknown) || unknown.CommandID == "" || got.Successor != (sso.TokenVersion{}) || x.refreshes.Load() != 1 {
			t.Fatal("late factor change permitted local refresh settlement after provider contact", err)
		}
		var unchanged, receipt bool
		err = f.pool.Raw().QueryRow(f.ctx, `SELECT
 EXISTS (SELECT 1 FROM sso_providers.provider_login_token_sets WHERE token_version=1 AND sha256(token_ciphertext)=$1),
 EXISTS (SELECT 1 FROM sso_providers.provider_grant_refresh_receipts)`, originalDigest).Scan(&unchanged, &receipt)
		if err != nil || !unchanged || receipt {
			t.Fatal("late withdrawal did not preserve the predecessor without a receipt", err)
		}
		if _, err := open().Refresh(f.ctx, original, browser); err == nil || x.refreshes.Load() != 1 {
			t.Fatal("late withdrawal permitted repeat refresh", err)
		}
		return
	}
	if err != nil || got.Completion.Outcome != identity.CommitOutcomeCommitted || string(got.ProviderOutcome) != expected || x.refreshes.Load() != 1 ||
		(unknownID != "" && got.Completion.Binding.CommandID != unknownID) {
		var started, prepared, attached, fenced bool
		diagnostic := f.pool.Raw().QueryRow(f.ctx, `SELECT
 EXISTS(SELECT 1 FROM identity.commands WHERE purpose='identity.sso.provider-token.refresh' AND preparation_started_generation IS NOT NULL),
 EXISTS(SELECT 1 FROM identity.commands WHERE purpose='identity.sso.provider-token.refresh' AND preparation_ciphertext IS NOT NULL),
 EXISTS(SELECT 1 FROM identity.commands WHERE purpose='identity.sso.provider-token.refresh' AND command_plan IS NOT NULL),
 EXISTS(SELECT 1 FROM sso_providers.provider_grant_fences)`).Scan(&started, &prepared, &attached, &fenced)
		t.Fatalf("refresh did not commit: sends=%d started=%t prepared=%t attached=%t fenced=%t err=%v diagnostic=%v",
			x.refreshes.Load(), started, prepared, attached, fenced, err, diagnostic)
	}
	succeeded := expected == "rotated" || expected == "retained"
	wantVersion := "1"
	if succeeded {
		grantSpec.Version, wantVersion = 2, "2"
		if successor, err := got.Successor.Spec(); err != nil || successor != grantSpec {
			t.Fatal("successor changed the original grant identity or failed to advance once", err)
		}
	} else if got.Successor != (sso.TokenVersion{}) {
		t.Fatal("non-success remote disposition created a successor")
	}
	var version string
	var scopes []string
	var ciphertext []byte
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT token_version::text,granted_scopes,token_ciphertext FROM sso_providers.provider_login_token_sets WHERE tenant_id=$1 AND callback_command_id=$2`,
		string(spec.TenantID), string(grantSpec.CommandID)).Scan(&version, &scopes, &ciphertext); err != nil || version != wantVersion ||
		len(ciphertext) == 0 || bytes.Contains(ciphertext, []byte(nativeOAuth2RotatedRefresh)) {
		t.Fatal("vault did not retain the expected encrypted grant", err)
	}
	wantNarrow := expected == "rotated" || mode == nativeOAuth2NarrowRetainedMode
	if wantNarrow && (len(scopes) != 1 || scopes[0] != "read:identity") ||
		expected == "retained" && !wantNarrow && (len(scopes) != 2 || scopes[0] != "read:identity" || scopes[1] != "email") {
		t.Fatal("vault failed to persist the successor's narrowed or inherited scopes")
	}
	if !succeeded {
		var unchanged bool
		err = f.pool.Raw().QueryRow(f.ctx, `SELECT EXISTS (SELECT 1 FROM sso_providers.provider_login_token_sets WHERE token_version=1 AND sha256(token_ciphertext)=$1)`, originalDigest).Scan(&unchanged)
		if err != nil || !unchanged {
			t.Fatal("non-success provider result changed the original grant", err)
		}
	}
	var retained bool
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT EXISTS (SELECT 1 FROM identity.commands WHERE purpose='identity.sso.provider-token.refresh' AND preparation_ciphertext IS NOT NULL)`).Scan(&retained); err != nil || retained {
		t.Fatal("temporary successor custody survived the definitive result", err)
	}
	reopened := open()
	replay, err := reopened.Refresh(f.ctx, original, browser)
	if err != nil || replay.Completion.Binding != got.Completion.Binding || replay.Successor != got.Successor || replay.ProviderOutcome != got.ProviderOutcome || x.refreshes.Load() != 1 {
		t.Fatal("fresh service did not recover the exact original refresh result", err)
	}
	if _, err := reopened.Refresh(f.ctx, request("another-original-grant-command"), browser); err == nil || x.refreshes.Load() != 1 {
		t.Fatal("stale generation or a different key reached the provider again", err)
	}
	if !succeeded {
		return
	}
	latest, sends := got.Successor, int32(1)
	if mode == nativeOAuth2NarrowRotatedMode || mode == nativeOAuth2NarrowRetainedMode {
		latest = refreshNarrowedSuccessor(t, x, reopened, got.Successor, browser)
		sends++
	}
	revocations := nativeEnterpriseRefreshRevocation(t, x, cfg.Session)
	key, err := identity.NewIdempotencyKey([]byte("native-refresh-revoke-custody"))
	if err != nil {
		t.Fatal(err)
	}
	prior, err := sso.NewRevokeEnterpriseToken(grant, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := revocations.Revoke(f.ctx, prior, browser); err == nil || x.revokes.Load() != 0 {
		t.Fatal("revocation reached the provider through the stale generation", err)
	}
	key, err = identity.NewIdempotencyKey([]byte("native-refresh-revoke-successor"))
	if err != nil {
		t.Fatal(err)
	}
	successor, err := sso.NewRevokeEnterpriseToken(latest, key)
	if err != nil {
		t.Fatal(err)
	}
	removed, err := revocations.Revoke(f.ctx, successor, browser)
	if err != nil || !removed.LocalErased || x.revokes.Load() != 1 {
		t.Fatal("successor could not reopen with the exact provider refresh token and revoke", err)
	}
	replay, err = reopened.Refresh(f.ctx, original, browser)
	if err != nil || replay.Successor != got.Successor || x.refreshes.Load() != sends {
		t.Fatal("original refresh history depended on surviving token custody", err)
	}
}

func refreshNarrowedSuccessor(t *testing.T, x nativeOAuth2JourneyFixture, service *ssopg.ProviderGrantRefreshService,
	prior sso.TokenVersion, browser ssopg.ProviderGrantRefreshBrowser,
) sso.TokenVersion {
	t.Helper()
	key, err := identity.NewIdempotencyKey([]byte("native-enterprise-narrowed-successor"))
	if err != nil {
		t.Fatal(err)
	}
	request, err := sso.NewRefreshEnterpriseToken(prior, key)
	if err != nil {
		t.Fatal(err)
	}
	f := x.start.enable.f
	result, err := service.Refresh(f.ctx, request, browser)
	if err != nil || result.Completion.Outcome != identity.CommitOutcomeCommitted || result.ProviderOutcome != ssopg.ProviderGrantRefreshRotated || x.refreshes.Load() != 2 {
		t.Fatal("narrowed successor did not refresh at the exact provider scope", err)
	}
	spec, err := result.Successor.Spec()
	if err != nil || spec.Version != 3 {
		t.Fatal("narrowed successor did not advance to version three", err)
	}
	var scopes []string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT granted_scopes FROM sso_providers.provider_login_token_sets WHERE tenant_id=$1 AND callback_command_id=$2 AND token_version=3`,
		string(spec.TenantID), string(spec.CommandID)).Scan(&scopes); err != nil || len(scopes) != 1 || scopes[0] != "read:identity" {
		t.Fatal("omitted provider response scope widened the exact request", err)
	}
	return result.Successor
}

func nativeEnterpriseRefreshRevocation(t *testing.T, x nativeOAuth2JourneyFixture, cfg session.ServiceConfig) *ssopg.ProviderGrantRevocationService {
	t.Helper()
	svc, err := ssopg.NewProviderGrantRevocationService(x.completion, ssopg.ProviderGrantRevocationConfig{Session: cfg,
		Endpoints: []ssopg.ProviderGrantRevocationEndpoint{{OrganizationID: x.start.profile.OrganizationID,
			ProviderID: x.start.profile.ProviderID, URL: "https://provider.example.com/revoke"}}})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func raceNativeEnterpriseRefreshAndRevoke(t *testing.T, x nativeOAuth2JourneyFixture, refresh *ssopg.ProviderGrantRefreshService,
	cfg session.ServiceConfig, original sso.RefreshEnterpriseToken, grant sso.TokenVersion, browser ssopg.ProviderGrantRefreshBrowser,
) (ssopg.ProviderGrantRefreshResult, error) {
	t.Helper()
	ctx := x.start.enable.f.ctx
	revoke := nativeEnterpriseRefreshRevocation(t, x, cfg)
	key, err := identity.NewIdempotencyKey([]byte("native-refresh-competing-revoke"))
	if err != nil {
		t.Fatal(err)
	}
	request, err := sso.NewRevokeEnterpriseToken(grant, key)
	if err != nil {
		t.Fatal(err)
	}
	type response struct {
		out ssopg.ProviderGrantRefreshResult
		err error
	}
	done := make(chan response, 1)
	go func() {
		out, err := refresh.Refresh(ctx, original, browser)
		done <- response{out, err}
	}()
	select {
	case <-x.refreshEntered:
	case reply := <-done:
		t.Fatal("refresh did not reach the provider first", reply.err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	_, err = revoke.Revoke(ctx, request, browser)
	close(x.refreshRelease)
	reply := <-done
	var blocked identity.UnknownCommitError
	if !errors.As(err, &blocked) || blocked.CommandID == "" || x.revokes.Load() != 0 || x.refreshes.Load() != 1 {
		t.Fatal("competing original-generation revoke crossed the shared provider fence", err)
	}
	return reply.out, reply.err
}
