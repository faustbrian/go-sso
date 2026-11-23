//go:build integration

package postgres_test

import (
	"errors"
	"testing"

	identity "github.com/faustbrian/go-identity"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestNativeProviderGrantRevocationFencesOneTLSAttempt(t *testing.T) {
	for _, tc := range []struct {
		mode string
		want string
	}{
		{"restorable-vault-revoke", "acknowledged"},
		{"restorable-vault-revoke-refused", "refused"},
		{"restorable-vault-revoke-unknown", "unknown"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			x := newNativeOAuth2JourneyFixture(t, tc.mode)
			f := x.start.enable.f
			got, err := x.completion.SigninCallbackOAuth2(f.ctx, x.request)
			if err != nil || got.Completion.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("persist a grant through the selected provider", err)
			}
			history, err := (ssopg.ProviderGrantFenceMigrationSource{Version: 355}).Load(f.ctx)
			if err != nil || len(history) != 1 {
				t.Fatal("load exact grant fence migration", err)
			}
			if _, err := f.pool.Raw().Exec(f.ctx, history[0].UpSQL()); err != nil {
				t.Fatal("install additive grant fence", err)
			}
			tenant, callback := got.Completion.Binding.TenantID, got.Completion.Binding.CommandID
			execute := func(attempt identity.CommandID) (string, error) {
				row := f.pool.Raw().QueryRow(f.ctx, committedNativeOAuth2VaultRowForTest, string(tenant), string(callback))
				return ssopg.RevokeProviderGrantFromRowForTest(f.ctx, x.start.service, x.transport, row, attempt, "https://provider.example.com/revoke")
			}
			if tc.want == "acknowledged" {
				unanchored, err := identity.NewCommandID()
				if err != nil {
					t.Fatal(err)
				}
				outcome, err := execute(unanchored)
				var unknown identity.UnknownCommitError
				if !errors.As(err, &unknown) || unknown.CommandID != unanchored || outcome != "" || x.revokes.Load() != 0 {
					t.Fatal("a storage error before acknowledgement authorized a provider attempt", outcome, err)
				}
			}
			run := func() (string, error) {
				return execute(seedProviderGrantAttemptForTest(t, f, tenant, "identity.sso.provider-token.revoke"))
			}
			if outcome, err := run(); err != nil || outcome != tc.want || x.revokes.Load() != 1 {
				t.Fatal("single original provider attempt lost its exact wire disposition", outcome, err)
			}
			if outcome, err := run(); !errors.Is(err, identity.ConflictError{}) || outcome != "" || x.revokes.Load() != 1 {
				t.Fatal("a fresh command resent a possibly submitted revocation", outcome, err)
			}
			if x.posts.Load() != 1 || x.identities.Load() != 1 {
				t.Fatal("revocation repeated the original browser exchange or identity query")
			}
		})
	}
}
