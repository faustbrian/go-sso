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

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/session"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestNativeOIDCAdapterStartUsesCommittedOriginalCustodyWithoutFallback(t *testing.T) {
	for _, mode := range []string{"selected adapter", "factory failure", "durable start failure"} {
		t.Run(mode, func(t *testing.T) {
			x := newProviderLoginStartFixture(t)
			profile := x.config.Profiles[0]
			completion := nativeOIDCAdapterStartCompletion(t, x)
			wantProfile, err := completion.SigninProtocolProfile(profile.OrganizationID, profile.ProviderID)
			if err != nil {
				t.Fatal(err)
			}
			var factoryCalls, startCalls, completeCalls int
			var selected ssopg.OIDCStartAdapterConfig
			factoryFailure := errors.New("controlled OIDC Start factory failure")
			factory := func(config ssopg.OIDCStartAdapterConfig) (sso.ProtocolAdapter, error) {
				factoryCalls++
				selected = config
				generation, err := config.Transaction.ValidateAt(config.Clock.Now())
				mapping, mappingErr := config.Mapping.Spec()
				if err != nil || mappingErr != nil || generation != profile.CredentialGeneration || config.CredentialGeneration != generation ||
					config.Transaction.TenantID != x.config.TenantID || config.Transaction.OrganizationID != profile.OrganizationID ||
					config.Transaction.ProviderID != string(profile.ProviderID) || config.Transaction.Protocol != "oidc" ||
					config.Transaction.ProviderVersion != profile.ProviderVersion || config.Transaction.MappingVersion != profile.MappingVersion ||
					config.Transaction.Callback.String() != profile.ProtocolRedirectURI || config.Transaction.ID == string(config.Transaction.CommandID) ||
					!reflect.DeepEqual(config.Profile, wantProfile) || !config.Profile.NonceRequired || mapping.Version != profile.MappingVersion || mapping.SubjectClaim != "sub" ||
					len(config.Authorization.State) != 43 || len(config.Authorization.Nonce) != 43 || len(config.Authorization.PKCEChallenge) != 43 ||
					!config.CapabilityExpiresAt.Equal(config.Transaction.ExpiresAt) {
					t.Fatal("Start factory lost the original OIDC profile, mapping, nonce or command binding", err, mappingErr)
				}
				var durable bool
				err = x.enable.f.pool.Raw().QueryRow(x.enable.f.ctx, `SELECT
l.completed_at IS NULL AND l.binding_envelope IS NOT NULL AND l.verifier_envelope IS NOT NULL
AND l.expires_at=$5 AND c.expires_at=l.expires_at AND c.state='issued' AND c.uses=0 AND c.command_id IS NULL
FROM sso_providers.login_transactions l
JOIN public.capability_identity_one_use c
 ON c.tenant_id=l.tenant_id AND c.origin_command_id=l.start_command_id AND c.purpose='identity.sso.oidc-callback'
WHERE l.tenant_id=$1 AND l.start_command_id=$2 AND l.callback_command_id=$3
AND l.organization_id=$4`, string(x.config.TenantID), config.Transaction.ID,
					string(config.Transaction.CommandID), string(profile.OrganizationID), config.Transaction.ExpiresAt).Scan(&durable)
				if err != nil || !durable {
					t.Fatal("selected OIDC Start factory ran before original native custody and callback capability were durable", err)
				}
				if mode == "factory failure" {
					return nil, factoryFailure
				}
				return nativeOIDCStartOnlyAdapter{
					start: func(ctx context.Context, command sso.ProtocolStartCommand) (sso.ProtocolStartResult, error) {
						startCalls++
						generation, err := command.ValidateAt(config.Clock.Now())
						if ctx.Err() != nil || err != nil || generation != profile.CredentialGeneration || command.Transaction != config.Transaction {
							t.Fatal("selected OIDC adapter Start received a different original command", err)
						}
						redirect, err := url.Parse(config.Profile.AuthorizationEndpoint)
						if err != nil {
							t.Fatal(err)
						}
						redirect.RawQuery = url.Values{
							"client_id": {config.Profile.ClientID}, "redirect_uri": {config.Transaction.Callback.String()},
							"response_type": {"code"}, "response_mode": {"query"}, "scope": {strings.Join(config.Profile.Scopes, " ")},
							"state": {config.Authorization.State}, "nonce": {config.Authorization.Nonce},
							"code_challenge": {config.Authorization.PKCEChallenge}, "code_challenge_method": {"S256"},
						}.Encode()
						return sso.ProtocolStartResult{Redirect: *redirect, ExpiresAt: config.CapabilityExpiresAt}, nil
					},
					complete: func(context.Context, sso.ProtocolCallback) (sso.ProtocolAssertion, error) {
						completeCalls++
						return sso.ProtocolAssertion{}, sso.ErrForbidden
					},
				}, nil
			}
			start, selectedCompletion, err := completion.WithOIDCStartAdapter(factory)
			if err != nil || start == nil || start == x.service || selectedCompletion == nil || selectedCompletion == completion || factoryCalls != 0 {
				t.Fatal("opt-in composition did not clone the native OIDC pair without invoking a protocol factory", err)
			}
			if mode == "durable start failure" {
				_, err := x.enable.f.pool.Raw().Exec(x.enable.f.ctx, `CREATE FUNCTION sso_providers.reject_oidc_adapter_start_effect() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 RAISE EXCEPTION 'controlled OIDC adapter start rollback';
END $$;
CREATE TRIGGER reject_oidc_adapter_start_effect BEFORE INSERT ON public.outbox_messages FOR EACH ROW
 WHEN (NEW.topic='oauth.rp_transaction.created.v1')
 EXECUTE FUNCTION sso_providers.reject_oidc_adapter_start_effect()`)
				if err != nil {
					t.Fatal("install native transactional OIDC start failure", err)
				}
			}
			before := nativeProviderLoginCounts(t, x)
			started, err := start.SigninStart(x.enable.f.ctx, x.request, x.browser)
			if mode == "durable start failure" {
				after := nativeProviderLoginCounts(t, x)
				if err == nil || started.RedirectURI != (url.URL{}) || started.TransactionID != "" || factoryCalls != 0 || startCalls != 0 || completeCalls != 0 ||
					after.transactions != before.transactions || after.capabilities != before.capabilities || after.events != before.events {
					t.Fatal("uncommitted native OIDC start reached the selected adapter or disclosed a redirect", err)
				}
				return
			}
			after := nativeProviderLoginCounts(t, x)
			if factoryCalls != 1 || completeCalls != 0 || after.transactions != before.transactions+1 || after.capabilities != before.capabilities+1 || after.events != before.events+1 {
				t.Fatal("selected OIDC Start did not preserve exactly one original native transaction and capability")
			}
			if mode == "factory failure" {
				if err == nil || started.RedirectURI != (url.URL{}) || started.TransactionID != "" || startCalls != 0 {
					t.Fatal("failed selected OIDC factory fell back to native redirect construction", err)
				}
			} else if err != nil || startCalls != 1 || started.Completion.Outcome != identity.CommitOutcomeCommitted ||
				started.TransactionID != selected.Transaction.ID || started.Completion.Binding.CommandID != identity.CommandID(selected.Transaction.ID) ||
				started.RedirectURI.Query().Get("state") != selected.Authorization.State || started.RedirectURI.Query().Get("nonce") != selected.Authorization.Nonce ||
				started.RedirectURI.Query().Get("code_challenge") != selected.Authorization.PKCEChallenge || started.RedirectURI.Query().Get("code_challenge_method") != "S256" ||
				started.RedirectURI.Query().Get("redirect_uri") != profile.ProtocolRedirectURI {
				t.Fatal("selected OIDC adapter changed the original redirect, nonce, callback or canonical command", err)
			}
			custody := nativeProviderLoginCustody(t, x, identity.CommandID(selected.Transaction.ID))
			original, err := x.service.SigninStart(x.enable.f.ctx, x.request, x.browser)
			if err != nil || original.TransactionID != selected.Transaction.ID || factoryCalls != 1 || startCalls > 1 ||
				original.RedirectURI.Query().Get("state") != selected.Authorization.State || original.RedirectURI.Query().Get("nonce") != selected.Authorization.Nonce ||
				original.RedirectURI.Query().Get("code_challenge") != selected.Authorization.PKCEChallenge ||
				!reflect.DeepEqual(nativeProviderLoginCustody(t, x, identity.CommandID(selected.Transaction.ID)), custody) || nativeProviderLoginCounts(t, x) != after {
				t.Fatal("opt-in OIDC Start changed the original service or replaced retained browser custody", err)
			}
			if mode == "selected adapter" && original.RedirectURI != started.RedirectURI {
				t.Fatal("selected OIDC adapter did not preserve the original exact native redirect")
			}
		})
	}
}

type nativeOIDCStartOnlyAdapter struct {
	start    func(context.Context, sso.ProtocolStartCommand) (sso.ProtocolStartResult, error)
	complete func(context.Context, sso.ProtocolCallback) (sso.ProtocolAssertion, error)
}

func (a nativeOIDCStartOnlyAdapter) Start(ctx context.Context, command sso.ProtocolStartCommand) (sso.ProtocolStartResult, error) {
	return a.start(ctx, command)
}

func (a nativeOIDCStartOnlyAdapter) Complete(ctx context.Context, callback sso.ProtocolCallback) (sso.ProtocolAssertion, error) {
	return a.complete(ctx, callback)
}

func nativeOIDCAdapterStartCompletion(t *testing.T, x providerLoginStartFixture) *ssopg.ProviderLoginCompletionService {
	t.Helper()
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
	profile := x.config.Profiles[0]
	completion, err := ssopg.NewProviderLoginCompletionService(x.service, ssopg.ProviderLoginCompletionConfig{
		Audience: "native-enterprise-app", PolicyNamespace: "users", CSRFKey: csrf,
		Issuer: session.IssuerConfig{MaximumDuration: 3 * time.Second, LookupKey: lookup, TokenSize: 32, Cookie: cookie},
		Profiles: []ssopg.StaticOIDCCompletionProfile{{OrganizationID: profile.OrganizationID, ProviderID: profile.ProviderID,
			Metadata: sso.OIDCStaticMetadataSpec{Issuer: "https://enable.example.com", AuthorizationEndpoint: "https://enable.example.com/authorize",
				TokenEndpoint: "https://enable.example.com/token", JWKSURI: "https://enable.example.com/keys"},
			ClientAuthentication: oauth.ClientSecretBasic, Algorithms: []string{"ES256"}, Keys: &coreoidc.StaticKeySet{},
		}},
	})
	if err != nil {
		t.Fatal("compose native completion for configured OIDC Start selection", err)
	}
	return completion
}
