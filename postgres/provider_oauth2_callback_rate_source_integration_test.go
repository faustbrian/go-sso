//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestProviderOAuth2CallbackRateSourceAuthenticatesOriginalWithoutEffects(t *testing.T) {
	x := newNativeOAuth2JourneyFixture(t, "linked-member")
	ctx := x.start.enable.f.ctx
	values, err := url.ParseQuery(x.request.RawQuery)
	if err != nil {
		t.Fatal(err)
	}
	state := values.Get("state")
	original, err := ssopg.LookupProviderOAuth2LoginCallbackForTest(ctx, x.start.service, state)
	if err != nil {
		t.Fatal("read original native OAuth2 callback", err)
	}
	want := ssopg.ProviderLoginCallbackRateContext{ProviderID: x.start.profile.ProviderID,
		FlowID: x.start.browser.FlowID, TransactionID: original.CallbackCommandID, Lifetime: original.ExpiresAt.Sub(original.IssuedAt)}
	before := nativeOAuth2RateCustody(t, x)
	counts := nativeProviderLoginCounts(t, x.start.providerLoginStartFixture)
	effects := nativeOAuth2JourneySuccessEffects(t, x)
	request := x.request
	request.Browser.FlowID = ""
	got, err := x.completion.SigninCallbackRateSource(ctx, x.start.config.TenantID, request)
	if err != nil || got != want || got.TransactionID == x.startedID || got.Lifetime <= 0 {
		t.Fatal("provider GET did not identify the original callback command and lifetime", err)
	}
	request.Browser.FlowID = x.start.browser.FlowID
	repeated, err := x.completion.SigninCallbackRateSource(ctx, x.start.config.TenantID, request)
	if err != nil || repeated != got {
		t.Fatal("repeated original browser changed callback rate facts", err)
	}
	foreignFlow, err := identity.NewPreAuthTransactionID()
	if err != nil {
		t.Fatal(err)
	}
	for name, alter := range map[string]func(*ssopg.ProviderOAuth2LoginCallbackRequest){
		"foreign flow": func(r *ssopg.ProviderOAuth2LoginCallbackRequest) { r.Browser.FlowID = foreignFlow },
		"foreign cookie": func(r *ssopg.ProviderOAuth2LoginCallbackRequest) {
			r.Browser.FlowCookie = authentication.NewBearerCredential("not-the-original-flow-cookie")
		},
		"foreign origin":  func(r *ssopg.ProviderOAuth2LoginCallbackRequest) { r.Browser.Origin = "https://foreign.example.test" },
		"invalid network": func(r *ssopg.ProviderOAuth2LoginCallbackRequest) { r.Browser.Network = netip.Addr{} },
		"empty device":    func(r *ssopg.ProviderOAuth2LoginCallbackRequest) { r.Browser.Device = "" },
		"foreign redirect": func(r *ssopg.ProviderOAuth2LoginCallbackRequest) {
			r.ReceivedRedirectURI = "https://foreign.example.test/callback"
		},
		"missing state": func(r *ssopg.ProviderOAuth2LoginCallbackRequest) { r.RawQuery = "code=unused" },
		"foreign state": func(r *ssopg.ProviderOAuth2LoginCallbackRequest) {
			r.RawQuery = url.Values{"code": {nativeOAuth2JourneyCode}, "state": {strings.Repeat("A", 43)}}.Encode()
		},
		"duplicate state": func(r *ssopg.ProviderOAuth2LoginCallbackRequest) { r.RawQuery += "&state=" + state },
	} {
		t.Run(name, func(t *testing.T) {
			changed := request
			alter(&changed)
			out, err := x.completion.SigninCallbackRateSource(ctx, x.start.config.TenantID, changed)
			if !errors.Is(err, sso.ErrForbidden) || out != (ssopg.ProviderLoginCallbackRateContext{}) {
				t.Fatal("foreign callback custody disclosed quota correlation", err)
			}
		})
	}
	if out, err := x.completion.SigninCallbackRateSource(ctx, "foreign-rate-tenant", request); !errors.Is(err, sso.ErrForbidden) || out != (ssopg.ProviderLoginCallbackRateContext{}) {
		t.Fatal("foreign trusted tenant disclosed original callback correlation", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := x.completion.SigninCallbackRateSource(cancelled, x.start.config.TenantID, request); !errors.Is(err, context.Canceled) {
		t.Fatal("OAuth2 rate attribution ignored cancellation", err)
	}
	if nativeOAuth2RateCustody(t, x) != before || nativeProviderLoginCounts(t, x.start.providerLoginStartFixture) != counts ||
		nativeOAuth2JourneySuccessEffects(t, x) != effects || x.posts.Load() != 0 || x.identities.Load() != 0 {
		t.Fatal("rate attribution changed native state, commands, capability, flow, session or provider custody")
	}
	after, err := ssopg.LookupProviderOAuth2LoginCallbackForTest(ctx, x.start.service, state)
	if err != nil || after.CompletedAt != nil || !after.HasProof || !after.HasPlan ||
		after.StartCommandID != original.StartCommandID || after.CallbackCommandID != original.CallbackCommandID ||
		!after.IssuedAt.Equal(original.IssuedAt) || !after.ExpiresAt.Equal(original.ExpiresAt) {
		t.Fatal("rate attribution changed the authenticated pending callback", err)
	}
	completed, err := x.completion.SigninCallbackOAuth2(ctx, x.request)
	if err != nil || completed.Completion.Outcome != identity.CommitOutcomeCommitted ||
		completed.Issuance.Token == (session.Token{}) || x.posts.Load() != 1 || x.identities.Load() != 1 {
		t.Fatal("attribution did not leave the original callback executable", err)
	}
	if out, err := x.completion.SigninCallbackRateSource(ctx, x.start.config.TenantID, request); !errors.Is(err, sso.ErrForbidden) || out != (ssopg.ProviderLoginCallbackRateContext{}) {
		t.Fatal("terminal replay disclosed fresh rate correlation", err)
	}
	if x.posts.Load() != 1 || x.identities.Load() != 1 {
		t.Fatal("terminal rate attribution repeated provider I/O")
	}
}

func TestProviderOAuth2CallbackRateSourceAttributesIssuerRefusalWithoutSettling(t *testing.T) {
	x := newNativeOAuth2JourneyFixture(t, "linked-member")
	ctx := x.start.enable.f.ctx
	values, err := url.ParseQuery(x.request.RawQuery)
	if err != nil {
		t.Fatal(err)
	}
	original, err := ssopg.LookupProviderOAuth2LoginCallbackForTest(ctx, x.start.service, values.Get("state"))
	if err != nil {
		t.Fatal(err)
	}
	want := ssopg.ProviderLoginCallbackRateContext{ProviderID: x.start.profile.ProviderID, FlowID: x.start.browser.FlowID,
		TransactionID: original.CallbackCommandID, Lifetime: original.ExpiresAt.Sub(original.IssuedAt)}
	before := nativeOAuth2RateCustody(t, x)
	counts := nativeProviderLoginCounts(t, x.start.providerLoginStartFixture)
	for name, issuer := range map[string]string{"wrong issuer": "https://foreign.example.test", "missing issuer": "", "malformed issuer": "%zz", "duplicate issuer": "duplicate"} {
		t.Run(name, func(t *testing.T) {
			query := url.Values{"code": {nativeOAuth2JourneyCode}, "state": {values.Get("state")}}
			if issuer == "duplicate" {
				query["iss"] = []string{nativeOAuth2JourneyIssuer, nativeOAuth2JourneyIssuer}
			} else if issuer != "" {
				query.Set("iss", issuer)
			}
			request := x.request
			request.RawQuery = query.Encode()
			if issuer == "%zz" {
				request.RawQuery += "&iss=%zz"
			}
			got, err := x.completion.SigninCallbackRateSource(ctx, x.start.config.TenantID, request)
			if err != nil || got != want {
				t.Fatal("original state and browser could not attribute a definitive issuer refusal", err)
			}
		})
	}
	if nativeOAuth2RateCustody(t, x) != before || nativeProviderLoginCounts(t, x.start.providerLoginStartFixture) != counts || x.posts.Load() != 0 || x.identities.Load() != 0 {
		t.Fatal("issuer attribution settled, reserved or exchanged the original callback")
	}
	values.Set("iss", "https://foreign.example.test")
	request := x.request
	request.RawQuery = values.Encode()
	denied, err := x.completion.SigninCallbackOAuth2(ctx, request)
	assertNativeOAuth2JourneyNoDisclosure(t, denied)
	if !errors.Is(err, sso.ErrForbidden) || x.posts.Load() != 0 || x.identities.Load() != 0 {
		t.Fatal("native completion did not retain definitive issuer denial after attribution", err)
	}
	if out, err := x.completion.SigninCallbackRateSource(ctx, x.start.config.TenantID, x.request); !errors.Is(err, sso.ErrForbidden) || out != (ssopg.ProviderLoginCallbackRateContext{}) {
		t.Fatal("terminal issuer refusal accepted fresh rate attribution", err)
	}
}

type nativeOAuth2RateCustodySnapshot struct {
	commands, capabilityUses                               int
	capability, capabilityCommand, flow, binding, verifier string
}

func nativeOAuth2RateCustody(t *testing.T, x nativeOAuth2JourneyFixture) nativeOAuth2RateCustodySnapshot {
	t.Helper()
	var got nativeOAuth2RateCustodySnapshot
	err := x.start.enable.f.pool.Raw().QueryRow(x.start.enable.f.ctx, `SELECT
(SELECT count(*) FROM identity.commands),c.uses,c.state,COALESCE(c.command_id,''),p.state,
encode(sha256(l.binding_envelope),'hex'),encode(sha256(l.verifier_envelope),'hex')
FROM sso_providers.login_transactions l
JOIN organization_sessions.preauth_transactions p ON p.tenant_id=l.tenant_id AND p.flow_id=$2
JOIN public.capability_identity_one_use c ON c.tenant_id=l.tenant_id AND c.origin_command_id=l.start_command_id AND c.purpose='identity.sso.oauth-callback'
WHERE l.start_command_id=$1`, x.startedID, string(x.start.browser.FlowID)).Scan(
		&got.commands, &got.capabilityUses, &got.capability, &got.capabilityCommand, &got.flow, &got.binding, &got.verifier)
	if err != nil {
		t.Fatal("inspect pending native callback custody without revealing secrets", err)
	}
	return got
}

func TestProviderOAuth2CallbackRateSourceRejectsInvalidComposition(t *testing.T) {
	var absent *ssopg.ProviderOAuth2LoginCompletionService
	for _, service := range []*ssopg.ProviderOAuth2LoginCompletionService{absent, {}} {
		out, err := service.SigninCallbackRateSource(context.Background(), "rate-tenant", ssopg.ProviderOAuth2LoginCallbackRequest{})
		if !errors.Is(err, sso.ErrInvalidInput) || out != (ssopg.ProviderLoginCallbackRateContext{}) {
			t.Fatal("unconfigured OAuth2 source accepted attribution", err)
		}
	}
}
