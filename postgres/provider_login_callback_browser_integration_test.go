//go:build integration

package postgres_test

import (
	"errors"
	"testing"

	"github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestProviderLoginCallbackBrowserRequiresOriginalCookieAndScope(t *testing.T) {
	x := newProviderLoginStartFixture(t)
	state, command := startProviderLoginCallbackLookup(t, x)
	ctx := x.enable.f.ctx
	before := nativeProviderLoginCounts(t, x)
	got, err := ssopg.AuthenticateProviderLoginCallbackBrowserForTest(ctx, x.service, state, x.browser)
	if err != nil || got.Binding != x.originalFlow || got.Binding.ID != x.browser.FlowID {
		t.Fatalf("callback did not authenticate the genuine original unconsumed flow: %v", err)
	}
	foreignFlow, err := identity.NewPreAuthTransactionID()
	if err != nil {
		t.Fatal(err)
	}
	cookie := []byte(x.browser.FlowCookie.Token())
	if cookie[len(cookie)/2] == 'A' {
		cookie[len(cookie)/2] = 'B'
	} else {
		cookie[len(cookie)/2] = 'A'
	}
	defer clear(cookie)
	for name, alter := range map[string]func(*ssopg.ProviderLoginBrowser){
		"wrong cookie": func(browser *ssopg.ProviderLoginBrowser) {
			browser.FlowCookie = authentication.NewBearerCredential(string(cookie))
		},
		"wrong flow":   func(browser *ssopg.ProviderLoginBrowser) { browser.FlowID = foreignFlow },
		"wrong origin": func(browser *ssopg.ProviderLoginBrowser) { browser.Origin = "https://other.example.test" },
		"empty device": func(browser *ssopg.ProviderLoginBrowser) { browser.Device = "" },
	} {
		t.Run(name, func(t *testing.T) {
			browser := x.browser
			alter(&browser)
			if _, err := ssopg.AuthenticateProviderLoginCallbackBrowserForTest(ctx, x.service, state, browser); !errors.Is(err, sso.ErrForbidden) {
				t.Fatalf("foreign callback browser was not denied uniformly: %v", err)
			}
		})
	}
	if nativeProviderLoginCounts(t, x) != before {
		t.Fatal("browser authentication consumed or changed native callback state")
	}
	if _, err := x.enable.f.pool.Raw().Exec(ctx, `UPDATE sso_providers.login_transactions SET completed_at=clock_timestamp(),verifier_envelope=NULL WHERE start_command_id=$1`, command); err != nil {
		t.Fatal("mark original lookup terminal in isolated fixture", err)
	}
	if _, err := ssopg.AuthenticateProviderLoginCallbackBrowserForTest(ctx, x.service, state, x.browser); !errors.Is(err, sso.ErrForbidden) {
		t.Fatalf("historical terminal lookup entered fresh browser admission: %v", err)
	}
}
