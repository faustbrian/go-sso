//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestProviderSAMLCallbackRateSourceAuthenticatesOriginalWithoutEffects(t *testing.T) {
	x := newNativeSAMLCallbackFixture(t)
	f := x.start.start.enable.f
	original, err := ssopg.LookupProviderSAMLLoginCallbackForTest(f.ctx, x.start.start.service, x.request.RelayState)
	if err != nil {
		t.Fatal("read original SAML callback correlation", err)
	}
	want := ssopg.ProviderLoginCallbackRateContext{ProviderID: x.request.ProviderID, FlowID: x.request.Browser.FlowID,
		TransactionID: original.CallbackCommandID, Lifetime: original.ExpiresAt.Sub(original.IssuedAt)}
	before := nativeSAMLRateCustody(t, x)
	request := x.request
	request.Browser.FlowID = ""
	for name, response := range map[string]string{"absent response": "", "unparsed response": "not XML or base64"} {
		t.Run(name, func(t *testing.T) {
			request.SAMLResponse = response
			got, err := x.completion.SigninCallbackRateSource(f.ctx, x.start.start.config.TenantID, request)
			if err != nil || got != want || got.TransactionID == x.started.TransactionID || got.Lifetime <= 0 {
				t.Fatal("POST without a flow selector did not recover only the original callback and initial lifetime", err)
			}
			request.Browser.FlowID = x.request.Browser.FlowID
			repeated, err := x.completion.SigninCallbackRateSource(f.ctx, x.start.start.config.TenantID, request)
			if err != nil || repeated != got {
				t.Fatal("original explicit flow changed authenticated callback quota facts", err)
			}
			request.Browser.FlowID = ""
		})
	}
	foreignFlow, err := identity.NewPreAuthTransactionID()
	if err != nil {
		t.Fatal(err)
	}
	for name, alter := range map[string]func(*ssopg.SAMLSigninCallbackRequest){
		"foreign flow": func(r *ssopg.SAMLSigninCallbackRequest) { r.Browser.FlowID = foreignFlow },
		"foreign cookie": func(r *ssopg.SAMLSigninCallbackRequest) {
			r.Browser.FlowCookie = authentication.NewBearerCredential("not-the-original-frontchannel-cookie")
		},
		"foreign origin":  func(r *ssopg.SAMLSigninCallbackRequest) { r.Browser.Origin = "https://foreign.example.test" },
		"invalid network": func(r *ssopg.SAMLSigninCallbackRequest) { r.Browser.Network = netip.Addr{} },
		"empty device":    func(r *ssopg.SAMLSigninCallbackRequest) { r.Browser.Device = "" },
		"wrong ACS":       func(r *ssopg.SAMLSigninCallbackRequest) { r.ReceivedAssertionConsumerURL += "/other" },
		"IdP initiated route": func(r *ssopg.SAMLSigninCallbackRequest) {
			r.ReceivedAssertionConsumerURL = strings.TrimSuffix(r.ReceivedAssertionConsumerURL, "/acs") + "/idp-init"
		},
		"wrong provider":       func(r *ssopg.SAMLSigninCallbackRequest) { r.ProviderID = "foreign-provider" },
		"missing RelayState":   func(r *ssopg.SAMLSigninCallbackRequest) { r.RelayState = "" },
		"unmatched RelayState": func(r *ssopg.SAMLSigninCallbackRequest) { r.RelayState = strings.Repeat("A", 43) },
		"oversize RelayState":  func(r *ssopg.SAMLSigninCallbackRequest) { r.RelayState = strings.Repeat("A", 81) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := request
			alter(&changed)
			out, err := x.completion.SigninCallbackRateSource(f.ctx, x.start.start.config.TenantID, changed)
			if !errors.Is(err, sso.ErrForbidden) || out != (ssopg.ProviderLoginCallbackRateContext{}) {
				t.Fatal("unmatched callback custody disclosed quota correlation", err)
			}
		})
	}
	if out, err := x.completion.SigninCallbackRateSource(f.ctx, "foreign-rate-tenant", request); !errors.Is(err, sso.ErrForbidden) || out != (ssopg.ProviderLoginCallbackRateContext{}) {
		t.Fatal("foreign trusted tenant disclosed original callback correlation", err)
	}
	cancelled, cancel := context.WithCancel(f.ctx)
	cancel()
	if out, err := x.completion.SigninCallbackRateSource(cancelled, x.start.start.config.TenantID, request); !errors.Is(err, context.Canceled) || out != (ssopg.ProviderLoginCallbackRateContext{}) {
		t.Fatal("cancelled attribution disclosed correlation or ignored cancellation", err)
	}
	if x.calls != 0 || nativeSAMLRateCustody(t, x) != before {
		t.Fatal("rate attribution verified a response or changed native commands, browser, capability, replay or session custody")
	}
	completed, err := x.completion.SigninCallback(f.ctx, x.request)
	if err != nil || completed.Completion.Outcome != identity.CommitOutcomeCommitted || completed.Issuance.Token == (session.Token{}) || x.calls != 1 {
		t.Fatal("read-only attribution did not leave the original callback executable", err)
	}
	after := nativeSAMLRateCustody(t, x)
	if out, err := x.completion.SigninCallbackRateSource(f.ctx, x.start.start.config.TenantID, request); !errors.Is(err, sso.ErrForbidden) || out != (ssopg.ProviderLoginCallbackRateContext{}) {
		t.Fatal("terminal callback disclosed fresh quota correlation", err)
	}
	if x.calls != 1 || nativeSAMLRateCustody(t, x) != after {
		t.Fatal("terminal attribution repeated verification or a native write")
	}
}

func TestProviderSAMLCallbackRateSourceRequiresInstalledProfileAndProtectedOriginalRead(t *testing.T) {
	x := newNativeSAMLCallbackFixture(t)
	f := x.start.start.enable.f
	before := nativeSAMLRateCustody(t, x)
	for _, mode := range []string{"provider version", "credential generation", "mapping version", "organization", "original read denied"} {
		t.Run(mode, func(t *testing.T) {
			profiles := append([]ssopg.StaticSAMLLoginProfile(nil), x.start.profiles...)
			config := x.start.start.config
			switch mode {
			case "provider version":
				profiles[0].ProviderVersion++
			case "credential generation":
				profiles[0].CredentialGeneration++
			case "mapping version":
				profiles[0].MappingVersion++
			case "organization":
				profiles[0].OrganizationID = "foreign-organization"
			case "original read denied":
				query := *config.Coordinator.QueryPolicy
				query.Authorization = denySAMLRateOriginalRead{tenant: config.TenantID}
				config.Coordinator.QueryPolicy = &query
			}
			start, err := ssopg.NewProviderLoginServiceWithSAML(x.start.router, config, profiles, x.start.sign)
			if err != nil {
				t.Fatal("compose mismatched SAML profile or protected original reader", err)
			}
			completion, err := ssopg.NewProviderSAMLLoginCompletionService(start, ssopg.ProviderSAMLLoginCompletionConfig{
				Audience: "native-saml-app", PolicyNamespace: "users", CSRFKey: x.csrf,
				Issuer: session.IssuerConfig{Clock: clock.System{}, MaximumDuration: 3 * time.Second, LookupKey: x.lookup, TokenSize: 32,
					Cookie: nativeSAMLRateSessionCookie(t)},
				Verify: func(context.Context, ssopg.SAMLResponseVerificationInput) (ssopg.SAMLVerifiedResponse, error) {
					t.Error("rate attribution entered SAML response verification")
					return ssopg.SAMLVerifiedResponse{}, sso.ErrForbidden
				},
			})
			if err != nil {
				t.Fatal("compose SAML completion for rate attribution", err)
			}
			out, err := completion.SigninCallbackRateSource(f.ctx, config.TenantID, x.request)
			if !errors.Is(err, sso.ErrForbidden) || out != (ssopg.ProviderLoginCallbackRateContext{}) {
				t.Fatal("profile substitution or denied original read disclosed quota correlation", err)
			}
		})
	}
	if x.calls != 0 || nativeSAMLRateCustody(t, x) != before {
		t.Fatal("denied attribution verified or changed original custody")
	}
}

type denySAMLRateOriginalRead struct{ tenant identity.TenantID }

func (p denySAMLRateOriginalRead) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if c.Request.Action == "identity.sso.saml-start" && c.Request.Resource.Type == "identity.anonymous-flow" {
		return authorization.Decision{Outcome: authorization.Deny, Revision: c.PolicyRevision}, nil
	}
	return (nativeSAMLCallbackPolicy{tenant: p.tenant}).Decide(ctx, c)
}

func nativeSAMLRateSessionCookie(t *testing.T) session.CookiePolicy {
	t.Helper()
	cookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_session", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	return cookie
}

func TestProviderSAMLCallbackRateSourceRejectsExpiredAndCorruptOriginal(t *testing.T) {
	for _, mode := range []string{"expired", "corrupt", "terminal"} {
		t.Run(mode, func(t *testing.T) {
			x := newNativeSAMLCallbackFixture(t)
			f := x.start.start.enable.f
			if mode == "terminal" {
				if err := ssopg.RecordProviderSAMLCallbackTerminalForTest(f.ctx, x.start.start.service, x.request.RelayState); err != nil {
					t.Fatal("retain terminal SAML original without verification", err)
				}
			} else {
				query := `UPDATE sso_providers.login_transactions SET binding_envelope=decode('010203','hex') WHERE start_command_id=$1`
				if mode == "expired" {
					query = `UPDATE sso_providers.login_transactions SET issued_at=issued_at-interval '11 minutes',expires_at=expires_at-interval '11 minutes' WHERE start_command_id=$1`
				}
				if _, err := f.pool.Raw().Exec(f.ctx, query, x.started.TransactionID); err != nil {
					t.Fatal("stage refused SAML custody in isolated fixture", err)
				}
			}
			before := nativeSAMLRateCustody(t, x)
			out, err := x.completion.SigninCallbackRateSource(f.ctx, x.start.start.config.TenantID, x.request)
			if !errors.Is(err, sso.ErrForbidden) || out != (ssopg.ProviderLoginCallbackRateContext{}) {
				t.Fatal("expired, terminal or corrupt original disclosed quota correlation", err)
			}
			if x.calls != 0 || nativeSAMLRateCustody(t, x) != before {
				t.Fatal("refused attribution verified or persisted native effects")
			}
		})
	}
}

type nativeSAMLRateCustodySnapshot struct {
	commands                int
	login, flow, capability string
	effects                 [6]int
}

func nativeSAMLRateCustody(t *testing.T, x *nativeSAMLCallbackFixture) nativeSAMLRateCustodySnapshot {
	t.Helper()
	f := x.start.start.enable.f
	var got nativeSAMLRateCustodySnapshot
	err := f.pool.Raw().QueryRow(f.ctx, `SELECT
(SELECT count(*) FROM identity.commands),
encode(sha256(convert_to(to_jsonb(l)::text,'UTF8')),'hex'),
encode(sha256(convert_to(to_jsonb(p)::text,'UTF8')),'hex'),
encode(sha256(convert_to(to_jsonb(c)::text,'UTF8')),'hex')
FROM sso_providers.login_transactions l
JOIN organization_sessions.preauth_transactions p ON p.tenant_id=l.tenant_id AND p.flow_id=$2
JOIN public.capability_identity_one_use c ON c.tenant_id=l.tenant_id AND c.origin_command_id=l.start_command_id AND c.purpose='identity.sso.saml-acs'
WHERE l.start_command_id=$1`, x.started.TransactionID, string(x.request.Browser.FlowID)).Scan(&got.commands, &got.login, &got.flow, &got.capability)
	if err != nil {
		t.Fatal("inspect exact native custody without disclosing encrypted or browser material", err)
	}
	got.effects = nativeSAMLCallbackSuccessCounts(t, x)
	return got
}

func TestProviderSAMLCallbackRateSourceRejectsInvalidComposition(t *testing.T) {
	var absent *ssopg.ProviderSAMLLoginCompletionService
	for _, service := range []*ssopg.ProviderSAMLLoginCompletionService{absent, {}} {
		out, err := service.SigninCallbackRateSource(context.Background(), "rate-tenant", ssopg.SAMLSigninCallbackRequest{})
		if !errors.Is(err, sso.ErrInvalidInput) || out != (ssopg.ProviderLoginCallbackRateContext{}) {
			t.Fatal("unconfigured SAML source accepted attribution", err)
		}
	}
}
