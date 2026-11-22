//go:build integration

package postgres_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestNativeOAuth2ProtocolAdapterRequiresOriginalReservationWithoutFallback(t *testing.T) {
	var x nativeOAuth2JourneyFixture
	var factoryCalls, secretBorrows int
	var reserved bool
	factoryFailure := errors.New("trusted adapter construction failed")
	factory := func(config ssopg.OAuth2ProtocolAdapterConfig) (sso.ProtocolAdapter, error) {
		factoryCalls++
		ctx := x.start.enable.f.ctx
		command, err := base64.RawURLEncoding.DecodeString(string(config.Transaction.CommandID))
		if err != nil {
			t.Fatal("adapter received a malformed original callback command", err)
		}
		err = x.start.enable.f.pool.Raw().QueryRow(ctx, `SELECT
l.completed_at IS NULL AND l.verifier_envelope IS NOT NULL
AND j.state='pending' AND j.preparation_started_generation=j.generation
AND j.preparation_ciphertext IS NULL AND j.result IS NULL
AND c.state='reserved' AND c.uses=0 AND c.generation=j.generation
FROM sso_providers.login_transactions l
JOIN identity.commands j ON j.tenant_id=l.tenant_id AND j.command_id=$3 AND j.purpose='identity.sso.oauth-callback'
JOIN public.capability_identity_one_use c ON c.tenant_id=l.tenant_id AND c.command_id=l.callback_command_id AND c.purpose=j.purpose
WHERE l.tenant_id=$1 AND l.start_command_id=$2 AND l.callback_command_id=$4 AND l.protocol='oauth2'`, string(x.start.config.TenantID), x.startedID, command, string(config.Transaction.CommandID)).Scan(&reserved)
		if err != nil || !reserved {
			t.Fatal("trusted adapter was constructed before the original callback reservation was durable", err)
		}
		if config.Transaction.ID != x.startedID || config.Transaction.TenantID != x.start.config.TenantID ||
			config.Transaction.OrganizationID != x.start.profile.OrganizationID || config.Transaction.ProviderID != string(x.start.profile.ProviderID) ||
			config.Transaction.Protocol != "oauth2" || config.CredentialGeneration != x.start.profile.CredentialGeneration ||
			config.Authorization.State == "" || config.Authorization.PKCEChallenge == "" {
			t.Fatal("trusted adapter lost the exact original provider/browser binding")
		}
		err = config.UseSecrets(ctx, func(clientSecret, verifier []byte) error {
			secretBorrows++
			return nil
		})
		if !errors.Is(err, sso.ErrForbidden) || secretBorrows != 0 {
			t.Fatal("adapter construction opened client-secret or original-verifier custody", err)
		}
		return nil, factoryFailure
	}
	x = newNativeOAuth2JourneyFixtureWithAdapter(t, "linked-member", factory)
	if factoryCalls != 0 {
		t.Fatal("service composition invoked a callback-specific adapter factory")
	}
	before := nativeOAuth2JourneySuccessEffects(t, x)
	for _, mode := range []string{"malformed-state", "foreign-browser", "malformed-browser", "malformed-callback-and-foreign-browser"} {
		t.Run(mode, func(t *testing.T) {
			request := x.request
			switch mode {
			case "malformed-state":
				request.RawQuery = "code=untrusted&state=%ZZ"
			case "foreign-browser", "malformed-callback-and-foreign-browser":
				request.Browser.FlowCookie = authentication.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xee}, 32)))
				if mode == "malformed-callback-and-foreign-browser" {
					request.RawQuery += "&iss=%ZZ"
				}
			case "malformed-browser":
				request.Browser.FlowCookie = authentication.BearerCredential{}
			}
			got, err := x.completion.SigninCallbackOAuth2(x.start.enable.f.ctx, request)
			assertNativeOAuth2JourneyNoDisclosure(t, got)
			if err == nil || got.Completion.Outcome == identity.CommitOutcomeCommitted || factoryCalls != 0 || secretBorrows != 0 ||
				x.posts.Load() != 0 || x.identities.Load() != 0 || nativeOAuth2JourneySuccessEffects(t, x) != before {
				t.Fatal("foreign or malformed callback reached the adapter, provider, or native issuance", err)
			}
		})
	}
	got, err := x.completion.SigninCallbackOAuth2(x.start.enable.f.ctx, x.request)
	assertNativeOAuth2JourneyNoDisclosure(t, got)
	if err == nil || got.Completion.Outcome == identity.CommitOutcomeCommitted || factoryCalls != 1 || !reserved || secretBorrows != 0 ||
		x.posts.Load() != 0 || x.identities.Load() != 0 || nativeOAuth2JourneySuccessEffects(t, x) != before {
		t.Fatal("trusted adapter factory failure fell back to provider exchange or native issuance", err)
	}
	replayed, _ := x.completion.SigninCallbackOAuth2(x.start.enable.f.ctx, x.request)
	assertNativeOAuth2JourneyNoDisclosure(t, replayed)
	if factoryCalls != 1 || x.posts.Load() != 0 || nativeOAuth2JourneySuccessEffects(t, x) != before {
		t.Fatal("reentering the started generation attempted the adapter or provider again")
	}
	var issuances int
	err = x.start.enable.f.pool.Raw().QueryRow(x.start.enable.f.ctx, `SELECT count(*) FROM organization_sessions.session_issuances WHERE tenant_id=$1 AND purpose='identity.sso.oauth-callback'`, string(x.start.config.TenantID)).Scan(&issuances)
	if err != nil || issuances != 0 {
		t.Fatal("trusted adapter factory failure persisted an OAuth2 issuance", err)
	}
}
