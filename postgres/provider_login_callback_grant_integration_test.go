//go:build integration

package postgres_test

import (
	"errors"
	"testing"

	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestProviderLoginCallbackGrantRequiresSignedOriginalBindingWithoutConsumption(t *testing.T) {
	x := newProviderLoginStartFixture(t)
	state, _ := startProviderLoginCallbackLookup(t, x)
	ctx := x.enable.f.ctx
	before := nativeProviderLoginCounts(t, x)
	if err := ssopg.VerifyProviderLoginCallbackGrantForTest(ctx, x.service, state, ""); err != nil {
		t.Fatalf("original capability did not authenticate from the genuine native start: %v", err)
	}
	for _, altered := range []string{"nonce", "fingerprint"} {
		t.Run(altered, func(t *testing.T) {
			if err := ssopg.VerifyProviderLoginCallbackGrantForTest(ctx, x.service, state, altered); !errors.Is(err, sso.ErrForbidden) {
				t.Fatalf("altered RP binding was not denied: %v", err)
			}
		})
	}
	if err := ssopg.VerifyProviderLoginCallbackGrantForTest(ctx, x.service, state, ""); err != nil || nativeProviderLoginCounts(t, x) != before {
		t.Fatalf("read-only preparation consumed or mutated the original callback capability: %v", err)
	}
}
