//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestProviderLoginSharedCallbackRateSourceSelectsOnlyStoredMode(t *testing.T) {
	for _, mode := range []string{"anonymous", "explicit-member"} {
		t.Run(mode, func(t *testing.T) {
			x := newNativeCallbackJourneyFixture(t, mode)
			ctx := x.start.enable.f.ctx
			request := x.request
			request.Browser.FlowID = ""
			member := x.linkBrowser.Session
			if mode == "anonymous" {
				member = x.start.enable.f.auth(string(x.start.config.TenantID), "owner").Bearer
			}
			original, err := ssopg.LookupProviderLoginCallbackForTest(ctx, x.start.service, x.started.RedirectURI.Query().Get("state"))
			if err != nil {
				t.Fatal("read the original authenticated transaction", err)
			}
			before := sharedCallbackSourceEffects(t, x)
			want := ssopg.ProviderSharedCallbackRateContext{ProviderLoginCallbackRateContext: ssopg.ProviderLoginCallbackRateContext{
				ProviderID: sso.ProviderID(x.start.request.ProviderID), TransactionID: original.CallbackCommandID,
				Lifetime: original.ExpiresAt.Sub(original.IssuedAt)}, MemberLink: mode == "explicit-member"}
			if !want.MemberLink {
				want.FlowID = x.start.browser.FlowID
			}
			for _, suppliedFlow := range []identity.PreAuthTransactionID{"", x.start.browser.FlowID} {
				request.Browser.FlowID = suppliedFlow
				got, err := x.completion.SharedCallbackRateSource(ctx, x.start.config.TenantID, request, member)
				if err != nil || got != want || got.TransactionID == x.started.TransactionID || got.Lifetime <= 0 {
					t.Fatal("both cookies must retain the stored mode and exact immutable callback correlation", err)
				}
			}
			if want.MemberLink {
				out, err := x.completion.SigninCallbackRateSource(ctx, x.start.config.TenantID, request)
				if !errors.Is(err, sso.ErrForbidden) || out != (ssopg.ProviderLoginCallbackRateContext{}) {
					t.Fatal("the existing anonymous API must continue to reject stored member mode", err)
				}
				for _, cookie := range []authentication.BearerCredential{{}, authentication.NewBearerCredential("foreign-member-cookie"), x.start.enable.f.auth(string(x.start.config.TenantID), "owner").Bearer} {
					out, err := x.completion.SharedCallbackRateSource(ctx, x.start.config.TenantID, request, cookie)
					assertSharedCallbackSourceDenied(t, out, err)
				}
			} else {
				request.Browser.FlowCookie = authentication.NewBearerCredential("foreign-flow-cookie")
				out, err := x.completion.SharedCallbackRateSource(ctx, x.start.config.TenantID, request, member)
				assertSharedCallbackSourceDenied(t, out, err)
			}
			if x.posts.Load() != 0 || sharedCallbackSourceEffects(t, x) != before {
				t.Fatal("callback attribution reserved, exchanged, consumed or wrote durable effects")
			}
		})
	}
}

func TestProviderLoginSharedCallbackRateSourceRejectsForeignBrowserAndProfile(t *testing.T) {
	x := newNativeCallbackJourneyFixture(t, "explicit-member")
	ctx := x.start.enable.f.ctx
	before := sharedCallbackSourceEffects(t, x)
	for name, alter := range map[string]func(*ssopg.ProviderLoginCallbackRequest){
		"origin":  func(r *ssopg.ProviderLoginCallbackRequest) { r.Browser.Origin = "https://foreign.example.test" },
		"network": func(r *ssopg.ProviderLoginCallbackRequest) { r.Browser.Network = netip.Addr{} },
		"device":  func(r *ssopg.ProviderLoginCallbackRequest) { r.Browser.Device = "" },
		"redirect": func(r *ssopg.ProviderLoginCallbackRequest) {
			r.ReceivedRedirectURI = "https://foreign.example.test/callback"
		},
	} {
		t.Run(name, func(t *testing.T) {
			request := x.request
			alter(&request)
			out, err := x.completion.SharedCallbackRateSource(ctx, x.start.config.TenantID, request, x.linkBrowser.Session)
			assertSharedCallbackSourceDenied(t, out, err)
		})
	}
	out, err := x.completion.SharedCallbackRateSource(ctx, "foreign-tenant", x.request, x.linkBrowser.Session)
	assertSharedCallbackSourceDenied(t, out, err)
	for name, alter := range map[string]func(*ssopg.ProviderLoginConfig){
		"policy": func(c *ssopg.ProviderLoginConfig) { c.PolicyID = "foreign-policy" },
		"client": func(c *ssopg.ProviderLoginConfig) { c.Profiles[0].ClientID = "foreign-client" },
		"configured redirect": func(c *ssopg.ProviderLoginConfig) {
			c.Profiles[0].ProtocolRedirectURI = "https://foreign.example.test/callback"
		},
		"provider version":      func(c *ssopg.ProviderLoginConfig) { c.Profiles[0].ProviderVersion++ },
		"credential generation": func(c *ssopg.ProviderLoginConfig) { c.Profiles[0].CredentialGeneration++ },
		"mapping":               func(c *ssopg.ProviderLoginConfig) { c.Profiles[0].MappingVersion++ },
	} {
		t.Run(name, func(t *testing.T) {
			config := x.start.config
			config.Profiles = slices.Clone(config.Profiles)
			alter(&config)
			service := sharedCallbackSourceCompletion(t, x, config, x.start.enable.f.profile)
			out, err := service.SharedCallbackRateSource(ctx, config.TenantID, x.request, x.linkBrowser.Session)
			assertSharedCallbackSourceDenied(t, out, err)
		})
	}
	profile := x.start.enable.f.profile
	profile.Audience = "foreign-password-profile"
	foreign := sharedCallbackSourceCompletion(t, x, x.start.config, profile)
	out, err = foreign.SharedCallbackRateSource(ctx, x.start.config.TenantID, x.request, x.linkBrowser.Session)
	assertSharedCallbackSourceDenied(t, out, err)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	out, err = x.completion.SharedCallbackRateSource(cancelled, x.start.config.TenantID, x.request, x.linkBrowser.Session)
	if !errors.Is(err, context.Canceled) || out != (ssopg.ProviderSharedCallbackRateContext{}) {
		t.Fatal("cancelled attribution disclosed correlation or ignored cancellation", err)
	}
	if x.posts.Load() != 0 || sharedCallbackSourceEffects(t, x) != before {
		t.Fatal("refused attribution changed original custody or durable effects")
	}
}

func TestProviderLoginSharedCallbackRateSourceRejectsStaleAndTerminalCustody(t *testing.T) {
	for _, mode := range []string{"anonymous", "explicit-member"} {
		for _, refusal := range []string{"expired", "terminal", "corrupt", "unknown", "revoked-session"} {
			if mode == "anonymous" && refusal == "revoked-session" {
				continue
			}
			t.Run(mode+"/"+refusal, func(t *testing.T) {
				x := newNativeCallbackJourneyFixture(t, mode)
				ctx := x.start.enable.f.ctx
				request := x.request
				state := x.started.RedirectURI.Query().Get("state")
				switch refusal {
				case "terminal":
					if mode == "explicit-member" {
						completed, err := x.completion.LinkCallback(ctx, nativeMemberJourneyCallback(x))
						if err != nil || completed.Completion.Outcome != identity.CommitOutcomeCommitted {
							t.Fatal("complete genuine member callback before testing terminal attribution", err)
						}
					} else if err := ssopg.AgeProviderLoginCallbackForTest(ctx, x.start.service, state, true); err != nil {
						t.Fatal("age genuine terminal callback custody", err)
					}
				case "revoked-session":
					nativeCallbackJourneyExec(t, x.start, `UPDATE organization_sessions.sessions SET state='revoked' WHERE tenant_id=$1 AND user_id=$2`, string(x.start.config.TenantID), string(nativeLinkMember))
				case "corrupt":
					nativeCallbackJourneyExec(t, x.start, `UPDATE sso_providers.login_transactions SET binding_envelope=decode('010203','hex') WHERE start_command_id=$1`, x.started.TransactionID)
				case "unknown":
					changed := "A" + state[1:]
					if state[0] == 'A' {
						changed = "B" + state[1:]
					}
					input, err := identity.NewOAuthCallbackInput([]byte("native-enterprise-original-code"), changed, identity.OAuthCallbackLimits{MaxCodeBytes: 4096, StateBytes: 32})
					if err != nil {
						t.Fatal(err)
					}
					defer input.Destroy()
					request.Input = input
				default:
					if err := ssopg.AgeProviderLoginCallbackForTest(ctx, x.start.service, state, false); err != nil {
						t.Fatal("age genuine callback custody", err)
					}
				}
				before := sharedCallbackSourceEffects(t, x)
				posts := x.posts.Load()
				out, err := x.completion.SharedCallbackRateSource(ctx, x.start.config.TenantID, request, x.linkBrowser.Session)
				assertSharedCallbackSourceDenied(t, out, err)
				if x.posts.Load() != posts || sharedCallbackSourceEffects(t, x) != before {
					t.Fatal("stale or terminal attribution changed custody or durable effects")
				}
			})
		}
	}
}

func assertSharedCallbackSourceDenied(t *testing.T, out ssopg.ProviderSharedCallbackRateContext, err error) {
	t.Helper()
	if !errors.Is(err, sso.ErrForbidden) || out != (ssopg.ProviderSharedCallbackRateContext{}) {
		t.Fatal("unmatched original custody disclosed callback correlation or selected another mode", err)
	}
}

func sharedCallbackSourceCompletion(t *testing.T, x nativeCallbackJourneyFixture, config ssopg.ProviderLoginConfig, profile sessionpg.IdentifierAdmissionConfig) *ssopg.ProviderLoginCompletionService {
	t.Helper()
	f := x.start.enable.f
	start, err := ssopg.NewProviderLoginServiceWithLink(newProviderRouter(t, x.start.enable, 4), config, ssopg.ProviderLinkConfig{
		ConfigurationID: "native-member-link-v1", Sessions: *f.sessions, Profile: profile,
		LookupKeys: []session.DigestKey{f.key}, CSRFKeys: []session.CSRFKey{x.csrf},
	})
	if err != nil {
		t.Fatal("compose selected native link profile", err)
	}
	service, err := ssopg.NewProviderLoginCompletionService(start, x.completionConfig)
	if err != nil {
		t.Fatal("compose selected native completion profile", err)
	}
	return service
}

type sharedCallbackSourceEffectSnapshot struct {
	providerLoginCounts
	commands, sessions, deposits int
	binding, verifier            string
}

func sharedCallbackSourceEffects(t *testing.T, x nativeCallbackJourneyFixture) sharedCallbackSourceEffectSnapshot {
	t.Helper()
	out := sharedCallbackSourceEffectSnapshot{providerLoginCounts: nativeProviderLoginCounts(t, x.start)}
	err := x.start.enable.f.pool.Raw().QueryRow(x.start.enable.f.ctx, `SELECT
 (SELECT count(*) FROM identity.commands),
 (SELECT count(*) FROM organization_sessions.sessions),
 (SELECT count(*) FROM sso_providers.provider_login_token_sets),
 md5(binding_envelope),COALESCE(md5(verifier_envelope),'')
 FROM sso_providers.login_transactions WHERE start_command_id=$1`, x.started.TransactionID).
		Scan(&out.commands, &out.sessions, &out.deposits, &out.binding, &out.verifier)
	if err != nil {
		t.Fatal("inspect callback custody and durable effects", err)
	}
	return out
}
