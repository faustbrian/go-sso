//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"reflect"
	"testing"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestNativeOIDCParsedCallbackAdapterRequiresOriginalReservationWithoutFallback(t *testing.T) {
	for _, mode := range []string{"factory failure", "callback failure", "empty assertion", "unbacked assertion"} {
		t.Run(mode, func(t *testing.T) {
			x := newNativeCallbackJourneyFixture(t, "linked-member")
			ctx := x.start.enable.f.ctx
			profile := x.start.config.Profiles[0]
			protocol, err := x.completion.SigninProtocolProfile(profile.OrganizationID, profile.ProviderID)
			if err != nil {
				t.Fatal("read the original trusted OIDC parser profile", err)
			}
			rawQuery := url.Values{"code": {"native-enterprise-original-code"},
				"state": {x.started.RedirectURI.Query().Get("state")}, "iss": {protocol.Issuer}}.Encode()
			parse := func(profile oauth.ProviderProfile) oauth.QueryCallback {
				t.Helper()
				parsed, err := oauth.ParseQueryCallback(ctx, rawQuery, profile)
				if err != nil {
					t.Fatal("parse a bounded success under the selected OIDC profile", err)
				}
				t.Cleanup(parsed.Destroy)
				return parsed
			}
			var callback string
			if err := x.start.enable.f.pool.Raw().QueryRow(ctx,
				`SELECT callback_command_id FROM sso_providers.login_transactions WHERE tenant_id=$1 AND start_command_id=$2`,
				string(x.start.config.TenantID), x.started.TransactionID).Scan(&callback); err != nil {
				t.Fatal("read the original callback command", err)
			}
			command, err := base64.RawURLEncoding.DecodeString(callback)
			if err != nil {
				t.Fatal("decode the original native callback command", err)
			}
			before := nativeCallbackJourneyDenialEffects(t, x, callback, command)
			var factoryCalls, completeCalls, secretBorrows int
			var reserved bool
			adapterFailure := errors.New("controlled selected OIDC callback failure")
			factory := func(config ssopg.OIDCCallbackAdapterConfig) (ssopg.OIDCParsedCallbackAdapter, error) {
				factoryCalls++
				err := x.start.enable.f.pool.Raw().QueryRow(ctx, `SELECT
l.completed_at IS NULL AND l.binding_envelope IS NOT NULL AND l.verifier_envelope IS NOT NULL
AND j.state='pending' AND j.preparation_started_generation=j.generation
AND j.preparation_ciphertext IS NULL AND j.result IS NULL
AND c.state='reserved' AND c.uses=0 AND c.generation=j.generation
AND c.origin_command_id=l.start_command_id AND c.expires_at=l.expires_at
FROM sso_providers.login_transactions l
JOIN identity.commands j ON j.tenant_id=l.tenant_id AND j.command_id=$3 AND j.purpose='identity.sso.oidc-callback'
JOIN public.capability_identity_one_use c ON c.tenant_id=l.tenant_id AND c.command_id=l.callback_command_id AND c.purpose=j.purpose
WHERE l.tenant_id=$1 AND l.start_command_id=$2 AND l.callback_command_id=$4 AND l.protocol='oidc'`,
					string(x.start.config.TenantID), x.started.TransactionID, command, callback).Scan(&reserved)
				if err != nil || !reserved {
					t.Fatal("selected OIDC factory preceded the exact durable original callback reservation", err)
				}
				mapping, mappingErr := config.Mapping.Spec()
				authorization := x.started.RedirectURI.Query()
				if mappingErr != nil || config.Transaction.ID != x.started.TransactionID || string(config.Transaction.CommandID) != callback ||
					config.Transaction.TenantID != x.start.config.TenantID || config.Transaction.OrganizationID != profile.OrganizationID ||
					config.Transaction.ProviderID != string(profile.ProviderID) || config.Transaction.Protocol != "oidc" ||
					config.Transaction.ProviderVersion != profile.ProviderVersion || config.Transaction.MappingVersion != profile.MappingVersion ||
					config.Transaction.Callback.String() != x.request.ReceivedRedirectURI || config.CredentialGeneration != profile.CredentialGeneration ||
					!reflect.DeepEqual(config.Profile, protocol) || mapping.Version != profile.MappingVersion || mapping.SubjectClaim != "sub" ||
					config.Authorization.State != authorization.Get("state") || config.Authorization.Nonce != authorization.Get("nonce") ||
					config.Authorization.PKCEChallenge != authorization.Get("code_challenge") ||
					!config.CapabilityExpiresAt.Equal(config.Transaction.ExpiresAt) || config.ObservedAt.IsZero() ||
					!config.ObservedAt.Before(config.ValidUntil) || config.Clock == nil || config.HTTPClient == nil || config.KeySet == nil {
					t.Fatal("selected OIDC factory lost original provider, nonce, PKCE, mapping or observation bounds", mappingErr)
				}
				err = config.UseSecrets(ctx, func(_, _ []byte) error { secretBorrows++; return nil })
				if !errors.Is(err, sso.ErrForbidden) || secretBorrows != 0 {
					t.Fatal("constructor-time OIDC borrower opened secret custody", err)
				}
				if _, err := config.AcceptTokens(ctx, ssopg.OIDCCallbackEvidence{}, oauth.TokenSet{}); !errors.Is(err, sso.ErrForbidden) {
					t.Fatal("constructor-time OIDC token acceptance opened output custody", err)
				}
				if mode == "factory failure" {
					return nil, adapterFailure
				}
				return nativeOIDCParsedCallbackOnlyAdapter{complete: func(call context.Context, transaction sso.LoginTransaction, parsed oauth.QueryCallback) (sso.ProtocolAssertion, error) {
					completeCalls++
					if call.Err() != nil || transaction != config.Transaction || !reflect.DeepEqual(parsed.Profile(), protocol) {
						t.Fatal("selected callback received a different original transaction or parsed profile")
					}
					if mode == "callback failure" {
						err := config.UseSecrets(call, func(clientSecret, verifier []byte) error {
							secretBorrows++
							challenge := sha256.Sum256(verifier)
							if len(clientSecret) == 0 || base64.RawURLEncoding.EncodeToString(challenge[:]) != config.Authorization.PKCEChallenge {
								t.Fatal("callback borrower did not receive the original client secret and S256 verifier")
							}
							return nil
						})
						if err != nil {
							t.Fatal("reserved callback could not borrow original custody once", err)
						}
						return sso.ProtocolAssertion{}, adapterFailure
					}
					if mode == "unbacked assertion" {
						assertion := sso.ProtocolAssertion{ProviderID: profile.ProviderID, OrganizationID: profile.OrganizationID,
							ProviderSubject: nativeCallbackJourneySubject, ProviderProfileVersion: profile.ProviderVersion, MappingVersion: profile.MappingVersion}
						if err := assertion.Validate(); err != nil {
							t.Fatal("unbacked assertion fixture must otherwise match the linked original identity", err)
						}
						return assertion, nil
					}
					return sso.ProtocolAssertion{}, nil
				}}, nil
			}
			selected, err := x.completion.WithOIDCCallbackAdapter(factory)
			if err != nil || selected == nil || selected == x.completion || factoryCalls != 0 {
				t.Fatal("OIDC callback composition did not clone without invoking the selected factory", err)
			}
			for _, invalid := range []string{"foreign browser", "empty browser", "wrong redirect", "wrong parsed profile"} {
				t.Run(invalid, func(t *testing.T) {
					browser, redirect, parsedProfile := x.request.Browser, x.request.ReceivedRedirectURI, protocol
					switch invalid {
					case "foreign browser":
						browser.FlowCookie = authentication.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xee}, 32)))
					case "empty browser":
						browser.FlowCookie = authentication.BearerCredential{}
					case "wrong redirect":
						redirect = "https://app.example.com/not-the-original-callback"
					case "wrong parsed profile":
						parsedProfile.Version++
					}
					got, err := selected.SigninParsedCallback(ctx, browser, redirect, parse(parsedProfile))
					assertNativeCallbackRefusalWithholdsIssuance(t, got)
					if err == nil || got.Completion.Outcome == identity.CommitOutcomeCommitted || factoryCalls != 0 || completeCalls != 0 ||
						secretBorrows != 0 || x.posts.Load() != 0 || nativeCallbackJourneyDenialEffects(t, x, callback, command) != before {
						t.Fatal("unbound parsed OIDC input reached the selected factory, provider or native success", err)
					}
				})
			}
			got, err := selected.SigninParsedCallback(ctx, x.request.Browser, x.request.ReceivedRedirectURI, parse(protocol))
			assertNativeCallbackRefusalWithholdsIssuance(t, got)
			wantCompletes, wantBorrows := 1, 0
			if mode == "factory failure" {
				wantCompletes = 0
			}
			if mode == "callback failure" {
				wantBorrows = 1
			}
			if err == nil || got.Completion.Outcome == identity.CommitOutcomeCommitted || factoryCalls != 1 || completeCalls != wantCompletes ||
				secretBorrows != wantBorrows || !reserved || x.posts.Load() != 0 || nativeCallbackJourneyDenialEffects(t, x, callback, command) != before {
				t.Fatal("failed or unsupported selected OIDC result fell back to native provider exchange or issuance", err)
			}
			custody := readNativeCallbackRefusalCustody(t, x, callback, command)
			if !custody.started || custody.output || custody.outputGeneration {
				t.Fatal("selected callback failure lost its one-shot preparation fence or retained unsupported output")
			}
			for _, retry := range []string{"selected parsed entry", "original native entry"} {
				t.Run(retry, func(t *testing.T) {
					var replayed ssopg.ProviderLoginCallbackResult
					if retry == "selected parsed entry" {
						replayed, _ = selected.SigninParsedCallback(ctx, x.request.Browser, x.request.ReceivedRedirectURI, parse(protocol))
					} else {
						replayed, _ = x.completion.SigninCallback(ctx, x.request)
					}
					assertNativeCallbackRefusalWithholdsIssuance(t, replayed)
					if replayed.Completion.Outcome == identity.CommitOutcomeCommitted || factoryCalls != 1 || completeCalls != wantCompletes ||
						secretBorrows != wantBorrows || x.posts.Load() != 0 || nativeCallbackJourneyDenialEffects(t, x, callback, command) != before {
						t.Fatal("reentry of the exact failed reserved generation exchanged or issued through another path")
					}
					after := readNativeCallbackRefusalCustody(t, x, callback, command)
					assertNativeCallbackRefusalOriginalBinding(t, custody, after)
					if !after.started || after.output || after.outputGeneration {
						t.Fatal("callback reentry removed the one-shot preparation fence or retained output")
					}
				})
			}
		})
	}
}

type nativeOIDCParsedCallbackOnlyAdapter struct {
	complete func(context.Context, sso.LoginTransaction, oauth.QueryCallback) (sso.ProtocolAssertion, error)
}

func (a nativeOIDCParsedCallbackOnlyAdapter) CompleteParsed(ctx context.Context, transaction sso.LoginTransaction, parsed oauth.QueryCallback) (sso.ProtocolAssertion, error) {
	return a.complete(ctx, transaction, parsed)
}
