//go:build integration

package postgres_test

import (
	"errors"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestProviderLoginCallbackMaterialReadsCurrentAndImmediateNativeDrainWithoutWriting(t *testing.T) {
	for _, mode := range []sso.ActiveTransactionDispositionMode{sso.ActiveTransactionDrain, sso.ActiveTransactionRevoke} {
		t.Run(string(mode), func(t *testing.T) {
			x := newProviderLoginStartFixture(t)
			state, _ := startProviderLoginCallbackLookup(t, x)
			ctx := x.enable.f.ctx
			before := nativeProviderLoginCounts(t, x)
			current, err := ssopg.ReadProviderLoginCallbackMaterialForTest(ctx, x.service, state, x.browser)
			if err != nil || current.Issuer == "" || current.AuthorizationEndpoint == "" || current.TokenEndpoint == "" || current.JWKSURI == "" {
				t.Fatal("current original provider material was not available", err)
			}
			if nativeProviderLoginCounts(t, x) != before {
				t.Fatal("reading material reserved, consumed or wrote state")
			}
			out, err := nativeProviderDisableService(t, x, providerDisablePolicy{}).ProviderDisable(ctx, nativeProviderDisableRequest(t, x, mode))
			if err != nil || out.Completion.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("commit native predecessor disposition", err)
			}
			before = nativeProviderLoginCounts(t, x)
			disabled, err := ssopg.ReadProviderLoginCallbackMaterialForTest(ctx, x.service, state, x.browser)
			if mode == sso.ActiveTransactionDrain && (err != nil || disabled != current) {
				t.Fatal("native drain's successor envelope did not preserve exact original metadata", err)
			}
			if mode == sso.ActiveTransactionRevoke && !errors.Is(err, sso.ErrForbidden) {
				t.Fatal("revoked predecessor released callback material", err)
			}
			if nativeProviderLoginCounts(t, x) != before {
				t.Fatal("reading disposition-qualified material wrote state")
			}
		})
	}
}

func TestProviderLoginCallbackMaterialRejectsChangedInstalledAndPendingCustody(t *testing.T) {
	for _, tc := range []struct{ name, sql string }{
		{"mapping changed", `UPDATE sso_providers.providers SET metadata_mapping_version=2`},
		{"credential generation changed", `UPDATE sso_providers.credentials SET generation=2`},
		{"activation generation changed", `UPDATE sso_providers.providers SET enablement_credential_generation=2`},
		{"later enabled version", `UPDATE sso_providers.providers SET metadata_version=5`},
		{"issuer changed", `UPDATE sso_providers.providers SET issuer_digest=decode(repeat('01',32),'hex')`},
		{"credential context changed", `UPDATE sso_providers.credentials SET credential_context=convert_to('{}','UTF8')`},
		{"pending commitment changed", `UPDATE sso_providers.login_transactions SET pkce_commitment=decode(repeat('01',32),'hex')`},
		{"terminal original", `UPDATE sso_providers.login_transactions SET completed_at=clock_timestamp(),verifier_envelope=NULL`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := newProviderLoginStartFixture(t)
			state, _ := startProviderLoginCallbackLookup(t, x)
			ctx := x.enable.f.ctx
			if _, err := ssopg.ReadProviderLoginCallbackMaterialForTest(ctx, x.service, state, x.browser); err != nil {
				t.Fatal("baseline original material was denied", err)
			}
			if _, err := x.enable.f.pool.Raw().Exec(ctx, tc.sql); err != nil {
				t.Fatal("stage bounded isolated material substitution", err)
			}
			if _, err := ssopg.ReadProviderLoginCallbackMaterialForTest(ctx, x.service, state, x.browser); err == nil {
				t.Fatal("changed installed or pending original custody released material")
			}
		})
	}
}
