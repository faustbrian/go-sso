//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/session"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestNativeOAuth2AdapterStartUsesCommittedOriginalCustodyWithoutFallback(t *testing.T) {
	for _, mode := range []string{"selected adapter", "factory failure", "durable start failure"} {
		t.Run(mode, func(t *testing.T) {
			x := newProviderOAuthLoginStartFixture(t)
			config, profiles := nativeOAuth2AdapterStartConfiguration(t, x)
			var factoryCalls, startCalls, completeCalls int
			var selected ssopg.OAuth2ProtocolAdapterConfig
			factoryFailure := errors.New("controlled OAuth2 Start factory failure")
			factory := func(config ssopg.OAuth2ProtocolAdapterConfig) (sso.ProtocolAdapter, error) {
				factoryCalls++
				selected = config
				if config.UseSecrets != nil || config.AcceptTokens != nil {
					t.Fatal("credential-free Start configuration exposed secret or token handoff hooks")
				}
				generation, err := config.Transaction.ValidateAt(config.Clock.Now())
				if err != nil || generation != x.profile.CredentialGeneration || config.CredentialGeneration != generation ||
					config.Transaction.TenantID != x.config.TenantID || config.Transaction.OrganizationID != x.profile.OrganizationID ||
					config.Transaction.ProviderID != string(x.profile.ProviderID) || config.Transaction.Protocol != "oauth2" ||
					config.Transaction.ProviderVersion != x.profile.ProviderVersion || config.Transaction.MappingVersion != x.profile.MappingVersion ||
					config.Transaction.Callback.String() != x.profile.ProtocolRedirectURI || config.Transaction.ID == string(config.Transaction.CommandID) ||
					len(config.Authorization.State) != 43 || len(config.Authorization.PKCEChallenge) != 43 {
					t.Fatal("Start factory lost the original provider, callback, command or S256 binding", err)
				}
				var durable bool
				err = x.enable.f.pool.Raw().QueryRow(x.enable.f.ctx, `SELECT
l.completed_at IS NULL AND l.binding_envelope IS NOT NULL AND l.verifier_envelope IS NOT NULL
AND l.expires_at=$5 AND c.expires_at=l.expires_at AND c.state='issued' AND c.uses=0 AND c.command_id IS NULL
FROM sso_providers.login_transactions l
JOIN public.capability_identity_one_use c
 ON c.tenant_id=l.tenant_id AND c.origin_command_id=l.start_command_id AND c.purpose='identity.sso.oauth-callback'
WHERE l.tenant_id=$1 AND l.start_command_id=$2 AND l.callback_command_id=$3
AND l.organization_id=$4 AND l.protocol='oauth2'`, string(x.config.TenantID), config.Transaction.ID,
					string(config.Transaction.CommandID), string(x.profile.OrganizationID), config.Transaction.ExpiresAt).Scan(&durable)
				if err != nil || !durable {
					t.Fatal("selected Start factory ran before original native custody and callback capability were durable", err)
				}
				if mode == "factory failure" {
					return nil, factoryFailure
				}
				return nativeOAuth2StartOnlyAdapter{
					start: func(ctx context.Context, command sso.ProtocolStartCommand) (sso.ProtocolStartResult, error) {
						startCalls++
						generation, err := command.ValidateAt(config.Clock.Now())
						if ctx.Err() != nil || err != nil || generation != x.profile.CredentialGeneration || command.Transaction != config.Transaction {
							t.Fatal("selected adapter Start received a different original command", err)
						}
						redirect, err := url.Parse(config.Profile.Profile.AuthorizationEndpoint)
						if err != nil {
							t.Fatal(err)
						}
						redirect.RawQuery = url.Values{
							"client_id": {config.Profile.Profile.ClientID}, "redirect_uri": {config.Transaction.Callback.String()},
							"response_type": {"code"}, "response_mode": {"query"}, "scope": {strings.Join(config.Profile.Profile.Scopes, " ")},
							"state": {config.Authorization.State}, "code_challenge": {config.Authorization.PKCEChallenge}, "code_challenge_method": {"S256"},
						}.Encode()
						return sso.ProtocolStartResult{Redirect: *redirect, ExpiresAt: config.CapabilityExpiresAt}, nil
					},
					complete: func(context.Context, sso.ProtocolCallback) (sso.ProtocolAssertion, error) {
						completeCalls++
						return sso.ProtocolAssertion{}, sso.ErrForbidden
					},
				}, nil
			}
			start, completion, err := ssopg.NewProviderOAuth2LoginServicesWithAdapter(x.service, config, profiles, factory)
			if err != nil || start == nil || start == x.service || completion == nil || factoryCalls != 0 {
				t.Fatal("opt-in composition did not clone the native start without invoking a protocol factory", err)
			}
			if mode == "durable start failure" {
				_, err := x.enable.f.pool.Raw().Exec(x.enable.f.ctx, `CREATE FUNCTION sso_providers.reject_adapter_start_effect() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 RAISE EXCEPTION 'controlled OAuth2 adapter start rollback';
END $$;
CREATE TRIGGER reject_adapter_start_effect BEFORE INSERT ON public.outbox_messages FOR EACH ROW
 WHEN (NEW.topic='oauth.rp_transaction.created.v1')
 EXECUTE FUNCTION sso_providers.reject_adapter_start_effect()`)
				if err != nil {
					t.Fatal("install native transactional start failure", err)
				}
			}
			before := nativeProviderLoginCounts(t, x.providerLoginStartFixture)
			started, err := start.SigninStartOAuth2(x.enable.f.ctx, x.request, x.browser)
			if mode == "durable start failure" {
				after := nativeProviderLoginCounts(t, x.providerLoginStartFixture)
				if err == nil || started.RedirectURI != (url.URL{}) || started.TransactionID != "" || factoryCalls != 0 || startCalls != 0 || completeCalls != 0 ||
					after.transactions != before.transactions || after.capabilities != before.capabilities || after.events != before.events {
					t.Fatal("uncommitted native start reached the selected adapter or disclosed a redirect", err)
				}
				return
			}
			after := nativeProviderLoginCounts(t, x.providerLoginStartFixture)
			if factoryCalls != 1 || completeCalls != 0 || after.transactions != before.transactions+1 || after.capabilities != before.capabilities+1 || after.events != before.events+1 {
				t.Fatal("selected Start did not preserve exactly one original native transaction and capability")
			}
			if mode == "factory failure" {
				if err == nil || started.RedirectURI != (url.URL{}) || started.TransactionID != "" || startCalls != 0 {
					t.Fatal("failed selected factory fell back to native redirect construction", err)
				}
			} else if err != nil || startCalls != 1 || started.Completion.Outcome != identity.CommitOutcomeCommitted ||
				started.TransactionID != selected.Transaction.ID || started.Completion.Binding.CommandID != identity.CommandID(selected.Transaction.ID) ||
				started.RedirectURI.Query().Get("state") != selected.Authorization.State || started.RedirectURI.Query().Get("code_challenge") != selected.Authorization.PKCEChallenge ||
				started.RedirectURI.Query().Get("code_challenge_method") != "S256" || started.RedirectURI.Query().Get("redirect_uri") != x.profile.ProtocolRedirectURI {
				t.Fatal("selected adapter changed the original redirect, callback or canonical command", err)
			}
			custody := nativeProviderLoginCustody(t, x.providerLoginStartFixture, identity.CommandID(selected.Transaction.ID))
			original, err := x.service.SigninStartOAuth2(x.enable.f.ctx, x.request, x.browser)
			if err != nil || original.TransactionID != selected.Transaction.ID || factoryCalls != 1 || startCalls > 1 ||
				original.RedirectURI.Query().Get("state") != selected.Authorization.State || original.RedirectURI.Query().Get("code_challenge") != selected.Authorization.PKCEChallenge ||
				!reflect.DeepEqual(nativeProviderLoginCustody(t, x.providerLoginStartFixture, identity.CommandID(selected.Transaction.ID)), custody) ||
				nativeProviderLoginCounts(t, x.providerLoginStartFixture) != after {
				t.Fatal("opt-in Start changed the original service or replaced retained browser custody", err)
			}
			if mode == "selected adapter" && original.RedirectURI != started.RedirectURI {
				t.Fatal("selected adapter did not preserve the original exact native redirect")
			}
		})
	}
}

type nativeOAuth2StartOnlyAdapter struct {
	start    func(context.Context, sso.ProtocolStartCommand) (sso.ProtocolStartResult, error)
	complete func(context.Context, sso.ProtocolCallback) (sso.ProtocolAssertion, error)
}

func (a nativeOAuth2StartOnlyAdapter) Start(ctx context.Context, command sso.ProtocolStartCommand) (sso.ProtocolStartResult, error) {
	return a.start(ctx, command)
}

func (a nativeOAuth2StartOnlyAdapter) Complete(ctx context.Context, callback sso.ProtocolCallback) (sso.ProtocolAssertion, error) {
	return a.complete(ctx, callback)
}

func nativeOAuth2AdapterStartConfiguration(t *testing.T, x providerOAuthLoginStartFixture) (ssopg.ProviderLoginCompletionConfig, []ssopg.StaticOAuth2CompletionProfile) {
	t.Helper()
	namespace, err := ssopg.SSOOAuth2AccountProviderNamespace(x.profile.OrganizationID, x.profile.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	lookup, err := session.NewDigestKey(1, bytes.Repeat([]byte{0xe1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := session.NewCSRFKey(1, bytes.Repeat([]byte{0xe2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_session", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	config := ssopg.ProviderLoginCompletionConfig{
		Audience: "native-enterprise-oauth2-app", PolicyNamespace: "users", CSRFKey: csrf,
		Issuer: session.IssuerConfig{Clock: clock.System{}, MaximumDuration: 3 * time.Second, LookupKey: lookup, TokenSize: 32, Cookie: cookie},
	}
	profiles := []ssopg.StaticOAuth2CompletionProfile{{OrganizationID: x.profile.OrganizationID, ProviderID: x.profile.ProviderID,
		Profile: oauth.OAuth2UserInfoProfile{Profile: oauth.ProviderProfile{
			ID: strings.ReplaceAll(namespace, ".", "-"), Version: x.profile.ProviderVersion, Issuer: nativeOAuth2JourneyIssuer, ClientID: x.profile.ClientID,
			AuthorizationEndpoint: "https://provider.example.com/authorize", TokenEndpoint: "https://provider.example.com/token", RedirectURI: x.profile.ProtocolRedirectURI,
			ClientAuthentication: oauth.ClientSecretPost, Scopes: x.profile.Scopes, ResponseMode: "query", PKCEMethod: "S256", StateBytes: 32,
			Timeout: time.Second, ClockSkew: time.Minute, MaxResponseBytes: 64 << 10, MaxTokenBytes: 16 << 10, MaxCodeBytes: 4096,
		}, Details: oauth.OAuth2UserInfoDetails{UserInfoEndpoint: "https://provider.example.com/identity", SubjectClaim: "stable_id", SubjectEncoding: oauth.OAuth2StringSubject, ProofLifetime: 20 * time.Second}},
	}}
	return config, profiles
}
