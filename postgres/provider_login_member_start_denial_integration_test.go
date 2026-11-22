//go:build integration

package postgres_test

import (
	"errors"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestNativeProviderMemberLinkJourneyDeniesWrongOriginAndCSRF(t *testing.T) {
	x := newNativeCallbackJourneyFixture(t, "explicit-member")
	before := nativeProviderLoginCounts(t, x.start)
	foreignCSRF, err := session.NewCSRFToken()
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*ssopg.ProviderLinkBrowser){
		"wrong-origin": func(browser *ssopg.ProviderLinkBrowser) { browser.Origin = "https://elsewhere.example.test" },
		"wrong-csrf":   func(browser *ssopg.ProviderLinkBrowser) { browser.CSRF = foreignCSRF },
	} {
		t.Run(name, func(t *testing.T) {
			browser, request := x.linkBrowser, x.start.request
			mutate(&browser)
			request.CommandID = commandID(t)
			key, err := identity.NewIdempotencyKey([]byte("native-link-start-denial-" + name))
			if err != nil {
				t.Fatal(err)
			}
			request.IdempotencyKey = key
			got, err := x.start.service.LinkStart(x.start.enable.f.ctx, request, browser)
			if !errors.Is(err, sso.ErrForbidden) || got.Completion.Outcome == identity.CommitOutcomeCommitted || got.RedirectURI.Host != "" ||
				nativeProviderLoginCounts(t, x.start) != before || x.posts.Load() != 0 {
				t.Fatal("invalid same-origin consent left provider redirect or durable effects", err)
			}
		})
	}
}
