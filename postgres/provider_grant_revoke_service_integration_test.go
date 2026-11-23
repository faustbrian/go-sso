//go:build integration

package postgres_test

import (
	"errors"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestNativeEnterpriseOAuth2RevokeSettlesAndRecovers(t *testing.T) {
	for _, tc := range []struct {
		mode, outcome string
		erased        bool
		lateFactor    bool
		lostCommit    bool
	}{
		{mode: "restorable-vault-revoke-local-outcome", outcome: "acknowledged", erased: true},
		{mode: "restorable-vault-revoke-refused", outcome: "refused"},
		{mode: "restorable-vault-revoke-unknown", outcome: "unknown"},
		{mode: "restorable-vault-revoke-late-factor", outcome: "late-factor", lateFactor: true},
		{mode: "restorable-vault-revoke", outcome: "acknowledged", erased: true, lostCommit: true},
	} {
		name := tc.outcome
		if tc.lostCommit {
			name = "lost-commit"
		}
		t.Run(name, func(t *testing.T) {
			x := newNativeOAuth2JourneyFixture(t, tc.mode)
			f := x.start.enable.f
			for _, source := range []migrations.Source{
				ssopg.ProviderGrantFenceMigrationSource{Version: 355},
				ssopg.ProviderGrantRevocationReceiptMigrationSource{Version: 356},
			} {
				steps, err := source.Load(f.ctx)
				if err != nil || len(steps) != 1 {
					t.Fatal("load grant lifecycle migration", err)
				}
				if _, err := f.pool.Raw().Exec(f.ctx, steps[0].UpSQL()); err != nil {
					t.Fatal("install grant lifecycle migration", err)
				}
			}
			login, err := x.completion.SigninCallbackOAuth2(f.ctx, x.request)
			if err != nil || login.Completion.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("establish the real enterprise session and grant", err)
			}
			spec, err := login.Issuance.Session.Bindings()
			if err != nil {
				t.Fatal(err)
			}
			wire, err := login.Issuance.Token.Reveal()
			if err != nil {
				t.Fatal("disclose only the actual enterprise session", err)
			}
			grant, err := sso.NewTokenVersion(sso.TokenVersionSpec{
				TenantID: spec.TenantID, OrganizationID: x.start.profile.OrganizationID, ProviderID: x.start.profile.ProviderID,
				ProviderSubject: nativeOAuth2JourneySubject, CommandID: login.Completion.Binding.CommandID,
				CredentialGeneration: x.start.profile.CredentialGeneration, Version: 1, Purpose: sso.EnterpriseTokenPurpose,
			})
			if err != nil {
				t.Fatal(err)
			}
			request := func(name string) sso.RevokeEnterpriseToken {
				t.Helper()
				key, err := identity.NewIdempotencyKey([]byte(name))
				if err != nil {
					t.Fatal(err)
				}
				input, err := sso.NewRevokeEnterpriseToken(grant, key)
				if err != nil {
					t.Fatal(err)
				}
				return input
			}
			cfg := ssopg.ProviderGrantRevocationConfig{
				Session: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: spec.Audience, Clock: clock.System{},
					MaximumDuration: time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{x.lookup}},
				Endpoints: []ssopg.ProviderGrantRevocationEndpoint{{
					OrganizationID: x.start.profile.OrganizationID, ProviderID: x.start.profile.ProviderID, URL: "https://provider.example.com/revoke",
				}},
			}
			browser := ssopg.ProviderGrantRevocationBrowser{Origin: x.start.config.Origin,
				Session: authentication.NewBearerCredential(wire), CSRF: login.CSRF}
			newService := func() *ssopg.ProviderGrantRevocationService {
				t.Helper()
				svc, err := ssopg.NewProviderGrantRevocationService(x.completion, cfg)
				if err != nil {
					t.Fatal("compose selected grant revocation with existing authorities", err)
				}
				return svc
			}
			svc := newService()
			original := request("native-enterprise-revoke")
			bad := browser
			bad.CSRF, err = session.NewCSRFToken()
			if err != nil {
				t.Fatal(err)
			}
			if out, err := svc.Revoke(f.ctx, original, bad); err == nil || out.Completion.Binding.CommandID != "" || x.revokes.Load() != 0 {
				t.Fatal("wrong CSRF reached durable or provider revocation", err)
			}
			var lostID identity.CommandID
			if tc.lostCommit {
				faulted, fault := nativeProviderGrantRevocationWithCommitFault(t, x, cfg)
				lost, err := faulted.Revoke(f.ctx, original, browser)
				var unknown identity.UnknownCommitError
				if !fault.lost.Load() || !errors.As(err, &unknown) || unknown.CommandID == "" || lost.LocalErased || x.revokes.Load() != 1 {
					t.Fatal("lost settlement acknowledgment did not report the original command as unknown", err)
				}
				lostID = unknown.CommandID
			}
			got, err := svc.Revoke(f.ctx, original, browser)
			if tc.lateFactor {
				var unknown identity.UnknownCommitError
				if !errors.As(err, &unknown) || unknown.CommandID == "" || got.LocalErased || x.revokes.Load() != 1 {
					t.Fatal("late factor change did not withhold local settlement after provider contact", err)
				}
				var grant, fence, receipt bool
				err = f.pool.Raw().QueryRow(f.ctx, `SELECT EXISTS (SELECT 1 FROM sso_providers.provider_login_token_sets),
 EXISTS (SELECT 1 FROM sso_providers.provider_grant_fences),
 EXISTS (SELECT 1 FROM sso_providers.provider_grant_revocation_receipts)`).Scan(&grant, &fence, &receipt)
				if err != nil || !grant || !fence || receipt {
					t.Fatal("late factor change did not retain the exact grant and fence without a receipt", err)
				}
				if _, err := newService().Revoke(f.ctx, original, browser); err == nil || x.revokes.Load() != 1 {
					t.Fatal("a stale original session was allowed to send again after authority changed", err)
				}
				return
			}
			if err != nil || got.Completion.Outcome != identity.CommitOutcomeCommitted ||
				string(got.ProviderOutcome) != tc.outcome || got.LocalErased != tc.erased || x.revokes.Load() != 1 ||
				(lostID != "" && got.Completion.Binding.CommandID != lostID) {
				var started, prepared, fenced bool
				diagnostic := f.pool.Raw().QueryRow(f.ctx, `SELECT
 EXISTS(SELECT 1 FROM identity.commands WHERE purpose='identity.sso.provider-token.revoke' AND preparation_started_generation IS NOT NULL),
 EXISTS(SELECT 1 FROM identity.commands WHERE purpose='identity.sso.provider-token.revoke' AND preparation_ciphertext IS NOT NULL),
 EXISTS(SELECT 1 FROM sso_providers.provider_grant_fences)`).Scan(&started, &prepared, &fenced)
				t.Fatalf("revocation failed: provider=%s erased=%t sends=%d started=%t prepared=%t fenced=%t err=%v diagnostic=%v",
					got.ProviderOutcome, got.LocalErased, x.revokes.Load(), started, prepared, fenced, err, diagnostic)
			}
			var present bool
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM sso_providers.provider_login_token_sets WHERE tenant_id=$1 AND callback_command_id=$2)`,
				string(spec.TenantID), string(login.Completion.Binding.CommandID)).Scan(&present); err != nil || present == tc.erased {
				t.Fatal("provider outcome and durable local ciphertext erasure disagree", err)
			}
			reopened := newService()
			replayed, err := reopened.Revoke(f.ctx, request("native-enterprise-revoke"), browser)
			if err != nil || replayed.Completion.Binding != got.Completion.Binding ||
				replayed.ProviderOutcome != got.ProviderOutcome || replayed.LocalErased != got.LocalErased || x.revokes.Load() != 1 {
				t.Fatal("restart did not recover the exact prior result without another provider operation", err)
			}
			if _, err := reopened.Revoke(f.ctx, request("fresh-request-key"), browser); err == nil || x.revokes.Load() != 1 {
				t.Fatal("a new command against the same grant was allowed to resend", err)
			}
		})
	}
}

func nativeProviderGrantRevocationWithCommitFault(t *testing.T, x nativeOAuth2JourneyFixture, cfg ssopg.ProviderGrantRevocationConfig) (*ssopg.ProviderGrantRevocationService, *providerCommitFault) {
	t.Helper()
	login, fault := nativeOAuth2CompletionWithCommitFault(t, x, "INSERT INTO sso_providers.provider_grant_revocation_receipts")
	service, err := ssopg.NewProviderGrantRevocationService(login, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return service, fault
}

func nativeOAuth2CompletionWithCommitFault(t *testing.T, x nativeOAuth2JourneyFixture, statement string) (*ssopg.ProviderOAuth2LoginCompletionService, *providerCommitFault) {
	t.Helper()
	pool, fault := providerLossPool(t, x.start.enable.f, statement)
	f := *x.start.enable.f
	f.pool = pool
	enabled := x.start.enable
	enabled.f = &f
	router, err := newProviderRouter(t, enabled, 4).WithProtocolRegistry()
	if err != nil {
		t.Fatal(err)
	}
	start, err := ssopg.NewProviderLoginServiceWithOAuth2(router, x.start.config, []ssopg.StaticOAuth2LoginProfile{x.start.profile})
	if err != nil {
		t.Fatal(err)
	}
	login, err := ssopg.NewProviderOAuth2LoginCompletionService(start, x.completionConfig, []ssopg.StaticOAuth2CompletionProfile{x.transport})
	if err != nil {
		t.Fatal(err)
	}
	return login, fault
}
