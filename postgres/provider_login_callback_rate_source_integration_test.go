//go:build integration

package postgres_test

import (
	"context"
	"encoding/base64"
	"errors"
	"net/netip"
	"testing"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestProviderLoginCallbackRateSourceAuthenticatesOriginalWithoutEffects(t *testing.T) {
	x := newNativeCallbackJourneyFixture(t, "")
	ctx := x.start.enable.f.ctx
	state := x.started.RedirectURI.Query().Get("state")
	original, err := ssopg.LookupProviderLoginCallbackForTest(ctx, x.start.service, state)
	if err != nil {
		t.Fatal("read the genuine original callback identity", err)
	}
	before := nativeProviderLoginCounts(t, x.start)
	var commandsBefore int
	if err := x.start.enable.f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.commands`).Scan(&commandsBefore); err != nil {
		t.Fatal("inspect existing native command custody", err)
	}
	binaryCommand, err := base64.RawURLEncoding.DecodeString(original.CallbackCommandID)
	if err != nil {
		t.Fatal(err)
	}
	effects := nativeCallbackJourneyDenialEffects(t, x, original.CallbackCommandID, binaryCommand)
	request := x.request
	request.Browser.FlowID = ""
	got, err := x.completion.SigninCallbackRateSource(ctx, x.start.config.TenantID, request)
	want := ssopg.ProviderLoginCallbackRateContext{ProviderID: sso.ProviderID(x.start.request.ProviderID),
		FlowID: x.start.browser.FlowID, TransactionID: original.CallbackCommandID, Lifetime: original.ExpiresAt.Sub(original.IssuedAt)}
	if err != nil || got != want || got.TransactionID == x.started.TransactionID || got.Lifetime <= 0 {
		t.Fatal("provider GET without a flow selector did not recover the exact original callback rate context", err)
	}
	request.Browser.FlowID = x.start.browser.FlowID
	repeated, err := x.completion.SigninCallbackRateSource(ctx, x.start.config.TenantID, request)
	if err != nil || repeated != got {
		t.Fatal("explicit original flow changed callback identity or immutable quota lifetime", err)
	}
	if _, err := x.completion.SigninCallbackRateSource(ctx, "foreign-rate-tenant", request); !errors.Is(err, sso.ErrForbidden) {
		t.Fatal("trusted foreign tenant selected another tenant's original callback", err)
	}
	foreignFlow, err := identity.NewPreAuthTransactionID()
	if err != nil {
		t.Fatal(err)
	}
	for name, alter := range map[string]func(*ssopg.ProviderLoginCallbackRequest){
		"foreign flow": func(r *ssopg.ProviderLoginCallbackRequest) { r.Browser.FlowID = foreignFlow },
		"foreign cookie": func(r *ssopg.ProviderLoginCallbackRequest) {
			r.Browser.FlowCookie = authentication.NewBearerCredential("not-the-original-flow-cookie")
		},
		"foreign origin":  func(r *ssopg.ProviderLoginCallbackRequest) { r.Browser.Origin = "https://foreign.example.test" },
		"invalid network": func(r *ssopg.ProviderLoginCallbackRequest) { r.Browser.Network = netip.Addr{} },
		"empty device":    func(r *ssopg.ProviderLoginCallbackRequest) { r.Browser.Device = "" },
		"foreign redirect": func(r *ssopg.ProviderLoginCallbackRequest) {
			r.ReceivedRedirectURI = "https://foreign.example.test/callback"
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := request
			alter(&changed)
			out, err := x.completion.SigninCallbackRateSource(ctx, x.start.config.TenantID, changed)
			if !errors.Is(err, sso.ErrForbidden) || out != (ssopg.ProviderLoginCallbackRateContext{}) {
				t.Fatal("substituted callback browser or route disclosed rate correlation", err)
			}
		})
	}
	alteredState := "A" + state[1:]
	if state[0] == 'A' {
		alteredState = "B" + state[1:]
	}
	for name, selectedState := range map[string]string{
		"absent state":  base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		"altered state": alteredState,
	} {
		t.Run(name, func(t *testing.T) {
			input, err := identity.NewOAuthCallbackInput([]byte("native-enterprise-original-code"), selectedState, identity.OAuthCallbackLimits{MaxCodeBytes: 4096, StateBytes: 32})
			if err != nil {
				t.Fatal(err)
			}
			defer input.Destroy()
			changed := request
			changed.Input = input
			out, err := x.completion.SigninCallbackRateSource(ctx, x.start.config.TenantID, changed)
			if !errors.Is(err, sso.ErrForbidden) || out != (ssopg.ProviderLoginCallbackRateContext{}) {
				t.Fatal("unmatched opaque callback state disclosed original quota correlation", err)
			}
		})
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := x.completion.SigninCallbackRateSource(cancelled, x.start.config.TenantID, request); !errors.Is(err, context.Canceled) {
		t.Fatal("rate attribution ignored caller cancellation", err)
	}
	if x.posts.Load() != 0 || nativeProviderLoginCounts(t, x.start) != before ||
		nativeCallbackJourneyDenialEffects(t, x, original.CallbackCommandID, binaryCommand) != effects {
		t.Fatal("rate attribution exchanged, reserved, consumed, issued or persisted callback effects")
	}
	var commandsAfter int
	if err := x.start.enable.f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.commands`).Scan(&commandsAfter); err != nil || commandsAfter != commandsBefore {
		t.Fatal("rate attribution reserved a callback command", err)
	}
	after, err := ssopg.LookupProviderLoginCallbackForTest(ctx, x.start.service, state)
	if err != nil || after.CompletedAt != nil || !after.HasProof || !after.HasPlan ||
		after.StartCommandID != original.StartCommandID || after.CallbackCommandID != original.CallbackCommandID ||
		!after.IssuedAt.Equal(original.IssuedAt) || !after.ExpiresAt.Equal(original.ExpiresAt) {
		t.Fatal("rate attribution changed original pending custody or renewed original authority", err)
	}
}

func TestProviderLoginCallbackRateSourceRejectsExpiredTerminalAndCorruptOriginal(t *testing.T) {
	for _, mode := range []string{"expired", "terminal", "corrupt"} {
		t.Run(mode, func(t *testing.T) {
			x := newNativeCallbackJourneyFixture(t, "")
			ctx := x.start.enable.f.ctx
			state := x.started.RedirectURI.Query().Get("state")
			if mode == "corrupt" {
				_, err := x.start.enable.f.pool.Raw().Exec(ctx, `UPDATE sso_providers.login_transactions SET binding_envelope=decode('010203','hex') WHERE start_command_id=$1`, x.started.TransactionID)
				if err != nil {
					t.Fatal("stage corrupt original binding in the isolated fixture", err)
				}
			} else if err := ssopg.AgeProviderLoginCallbackForTest(ctx, x.start.service, state, mode == "terminal"); err != nil {
				t.Fatal("move genuine authenticated state to its refused lifecycle boundary", err)
			}
			before := nativeProviderLoginCounts(t, x.start)
			out, err := x.completion.SigninCallbackRateSource(ctx, x.start.config.TenantID, x.request)
			if !errors.Is(err, sso.ErrForbidden) || out != (ssopg.ProviderLoginCallbackRateContext{}) {
				t.Fatal("expired, terminal or corrupt original disclosed a fresh rate context", err)
			}
			if x.posts.Load() != 0 || nativeProviderLoginCounts(t, x.start) != before {
				t.Fatal("refused rate attribution exchanged or persisted callback effects")
			}
		})
	}
}

func TestProviderLoginCallbackRateSourceRejectsInvalidComposition(t *testing.T) {
	var absent *ssopg.ProviderLoginCompletionService
	for _, service := range []*ssopg.ProviderLoginCompletionService{absent, {}} {
		out, err := service.SigninCallbackRateSource(context.Background(), "rate-tenant", ssopg.ProviderLoginCallbackRequest{})
		if !errors.Is(err, sso.ErrInvalidInput) || out != (ssopg.ProviderLoginCallbackRateContext{}) {
			t.Fatal("unconfigured source did not reject attribution without effects", err)
		}
	}
}
