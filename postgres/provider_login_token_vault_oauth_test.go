package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
)

// Obtain real nonce-free OAuth custody from its protocol owner, using the same
// encrypted native payload fixture as the published OIDC vault tests.
func providerLoginOAuth2VaultFixture(t *testing.T, reported, refresh bool) (*ProviderLoginService, providerLoginCallbackLookup, identity.Command, oauth.TokenSet) {
	t.Helper()
	payload, input, now, _ := providerLoginPayloadFixture(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/token":
			response := map[string]any{"access_token": "synthetic-oauth-access", "token_type": "Bearer", "expires_in": 3600}
			if refresh {
				response["refresh_token"] = "synthetic-oauth-refresh"
			}
			if reported {
				response["scope"] = "read_user"
			}
			if err := json.NewEncoder(w).Encode(response); err != nil {
				t.Error("fixture response failed")
			}
		case "/userinfo":
			if r.Header.Get("Authorization") != "Bearer synthetic-oauth-access" {
				t.Error("UserInfo did not receive original access custody")
			}
			_, _ = fmt.Fprint(w, `{"id":"stable-subject"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	input.Protocol, input.Issuer = providerProtocolOAuth2, server.URL
	input.Command.SchemaID = kernel.SSOOAuth2SigninStartOperation().SchemaID
	profile := StaticOAuth2LoginProfile{ProviderID: sso.ProviderID(input.ProviderID), OrganizationID: organization.ID(input.OrganizationID), Domain: "enterprise.example", ClientID: input.ClientID, ProtocolRedirectURI: input.RedirectURI, ProviderVersion: input.ProviderVersion, CredentialGeneration: input.CredentialGeneration, MappingVersion: input.MappingVersion, Scopes: []string{"read_user", "email"}}
	provider, err := oauth.NewSharedOAuth2UserInfoProvider(oauth.OAuth2UserInfoConfig{ID: input.ProviderID, Version: input.ProviderVersion, Issuer: input.Issuer, AuthorizationEndpoint: server.URL + "/authorize", TokenEndpoint: server.URL + "/token", UserInfoEndpoint: server.URL + "/userinfo", RedirectURI: input.RedirectURI, ClientID: input.ClientID, ClientSecret: []byte("synthetic-client-secret"), ClientAuthentication: oauth.ClientSecretPost, Scopes: profile.Scopes, SubjectClaim: "id", SubjectEncoding: oauth.OAuth2StringSubject, Clock: providerLoginVaultClock{now.Add(time.Second + 123456789)}, HTTPClient: server.Client(), Timeout: time.Second}, nil)
	if err != nil {
		t.Fatal("construct shared OAuth token fixture", err)
	}
	t.Cleanup(provider.Close)
	state := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
	query := (url.Values{"code": {"synthetic-enterprise-code"}, "state": {state}, "iss": {input.Issuer}}).Encode()
	callbackInput, err := oauth.ParseSharedOAuth2QueryCallback(t.Context(), query, input.RedirectURI, provider.Profile())
	if err != nil {
		t.Fatal("create original OAuth callback custody", err)
	}
	defer callbackInput.Destroy()
	pkce, err := oauth.NewPKCEVerifier(bytes.Repeat([]byte{'v'}, 43))
	if err != nil {
		t.Fatal("create original OAuth PKCE verifier", err)
	}
	defer pkce.Destroy()
	exchanged, err := provider.Exchange(t.Context(), callbackInput, pkce, oauth.AuthorizationParameters{State: state, PKCEChallenge: pkce.Challenge()})
	if err != nil {
		t.Fatal("exchange original OAuth token custody", err)
	}
	t.Cleanup(exchanged.Tokens.Destroy)
	callback, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	found := providerLoginCallbackLookup{Row: input.rowIdentity(), ObservedAt: *now, BindingWireDigest: [32]byte{10}, Binding: providerLoginStoredBinding{Metadata: providerLoginBindingMetadata{Schema: 1, Input: input, CallbackCommand: callback, StateKey: 1, PKCEKey: 1, StateDigest: [32]byte{8}, PKCECommitment: [32]byte{9}}}}
	account := kernel.ProviderAccountAdmission{Account: identity.Account{ID: "existing-account", TenantID: input.Command.TenantID, UserID: "selected-user", Provider: "sso-organization-provider", Issuer: input.Issuer, Subject: "stable-subject", Version: 5}, SocialLinkVersion: 7, Credential: kernel.CredentialAdmission{Credential: identity.CredentialRef{ID: "provider-reference", TenantID: input.Command.TenantID, UserID: "selected-user", Kind: identity.CredentialProvider, Owner: "sso", Version: 11}, UserAuthorityVersion: 13, IdentifierAuthorityVersion: 17, CredentialAuthorityVersion: 19}}
	fields, err := kernel.SSOOAuth2SigninAccountFields(account)
	if err != nil {
		t.Fatal("bind original OAuth provider account", err)
	}
	command, err := identity.NewFeaturePreAuthCommand(identity.FeatureCommandSpec{Operation: kernel.SSOOAuth2SigninOperation(), Binding: providerLoginTokenCallback(input, callback), Fields: fields}, auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32))))
	if err != nil {
		t.Fatal("create original OAuth callback command", err)
	}
	service := &ProviderLoginService{config: ProviderLoginConfig{TenantID: input.Command.TenantID}, payload: payload, oauthProfiles: map[providerLoginProfileKey]StaticOAuth2LoginProfile{{organization: profile.OrganizationID, provider: profile.ProviderID}: profile}}
	return service, found, command, exchanged.Tokens
}

func TestProviderLoginOAuth2TokenVaultRetainsNonceFreeAccessRefreshCustody(t *testing.T) {
	for _, reported := range []bool{false, true} {
		for _, refresh := range []bool{false, true} {
			t.Run(fmt.Sprintf("reported=%t/refresh=%t", reported, refresh), func(t *testing.T) {
				service, found, command, tokens := providerLoginOAuth2VaultFixture(t, reported, refresh)
				alias := tokens
				if err := tokens.Use(t.Context(), func(_ context.Context, b oauth.TokenBytes) error {
					if len(b.IDToken) != 0 {
						t.Fatal("OAuth fixture acquired OIDC token evidence")
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				requested, granted := tokens.RequestedScopes(), tokens.GrantedScopes()
				prepared, err := service.prepareProviderLoginTokens(t.Context(), found, command, 3, tokens)
				if err != nil || service.validateProviderLoginTokens(t.Context(), prepared) != nil {
					t.Fatal("original OAuth token custody was rejected", err)
				}
				if alias.Use(t.Context(), func(context.Context, oauth.TokenBytes) error { return nil }) == nil {
					t.Fatal("OAuth token alias survived custody transfer")
				}
				if prepared.Input.Protocol != providerProtocolOAuth2 || prepared.Callback.OperationID != "identity.sso.oauth-callback" || !slices.Equal(prepared.RequestedScopes, requested) || !slices.Equal(prepared.GrantedScopes, granted) || prepared.ScopeReported != reported {
					t.Fatal("OAuth custody lost its exact original protocol or scopes")
				}
				aad, err := providerLoginTokenAAD(prepared)
				if err != nil {
					t.Fatal(err)
				}
				if aad.Values()["profile"] != "native-static-oauth2-token-v1" {
					t.Fatal("OAuth token custody did not select its distinct AAD domain")
				}
				plain, err := service.payload.open(t.Context(), aad, prepared.Ciphertext, 65536, providerLoginTokenMaximumFrame)
				defer clear(plain)
				if err != nil || !bytes.Contains(plain, []byte("synthetic-oauth-access")) || bytes.Contains(plain, []byte("synthetic-oauth-refresh")) != refresh {
					t.Fatal("OAuth vault changed original bounded token material", err)
				}
				changed := prepared
				changed.Input.Protocol = ""
				oidcAAD, err := providerLoginTokenAAD(changed)
				if err != nil || bytes.Equal(aad.AdditionalData(), oidcAAD.AdditionalData()) {
					t.Fatal("OAuth token AAD aliases published OIDC custody", err)
				}
				foreign, err := service.payload.open(t.Context(), oidcAAD, prepared.Ciphertext, 65536, providerLoginTokenMaximumFrame)
				clear(foreign)
				if err == nil {
					t.Fatal("OAuth ciphertext opened in OIDC token domain")
				}
			})
		}
	}
}

func TestProviderLoginTokenVaultPreservesPublishedOIDCAADBytes(t *testing.T) {
	service, found, command, tokens := providerLoginVaultFixture(t, false)
	prepared, err := service.prepareProviderLoginTokens(t.Context(), found, command, 3, tokens)
	if err != nil {
		t.Fatal(err)
	}
	// Freeze the published v1 JSON field order and shape independently of the
	// current preparation type, which now also carries a version discriminator.
	legacyMetadata := struct {
		Input              providerLoginPayloadInput
		Callback           identity.CommandBinding
		CallbackGeneration uint64
		BindingDigest      [32]byte
		BindingWireDigest  [32]byte
		StateKey           uint32
		StateDigest        [32]byte
		Account            identity.Account
		SocialLinkVersion  uint64
		RequestedScopes    []string
		GrantedScopes      []string
		ScopeReported      bool
		ReceivedAt         time.Time
		AccessExpiresAt    time.Time
		Version            uint64
		Ciphertext         []byte
	}{prepared.Input, prepared.Callback, prepared.CallbackGeneration, prepared.BindingDigest, prepared.BindingWireDigest,
		prepared.StateKey, prepared.StateDigest, prepared.Account, prepared.SocialLinkVersion, prepared.RequestedScopes,
		prepared.GrantedScopes, prepared.ScopeReported, prepared.ReceivedAt, prepared.AccessExpiresAt, prepared.Version, nil}
	plain, err := json.Marshal(legacyMetadata)
	defer clear(plain)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(plain)
	legacy, err := envelope.NewContext(map[string]string{
		"owner": "sso", "profile": "native-static-oidc-token-v1", "purpose": "enterprise-provider-tokens",
		"tenant": string(prepared.Input.Command.TenantID), "organization": prepared.Input.OrganizationID,
		"provider": prepared.Input.ProviderID, "subject": prepared.Account.Subject, "version": strconv.FormatUint(prepared.Version, 10),
		"callback": string(prepared.Callback.CommandID), "callback_generation": strconv.FormatUint(prepared.CallbackGeneration, 10),
		"metadata": base64.RawURLEncoding.EncodeToString(digest[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	current, err := providerLoginTokenAAD(prepared)
	if err != nil || !bytes.Equal(legacy.AdditionalData(), current.AdditionalData()) {
		t.Fatal("OAuth expansion changed published OIDC AAD bytes", err)
	}
	foreign, err := service.payload.open(t.Context(), legacy, prepared.Ciphertext, 65536, providerLoginTokenMaximumFrame)
	defer clear(foreign)
	if err != nil {
		t.Fatal("published OIDC token ciphertext became unreadable", err)
	}
}

func TestProviderLoginOAuth2TokenVaultRejectsProfileAndProtocolSubstitution(t *testing.T) {
	for _, mode := range []string{"OIDC profile only", "scope drift", "openid profile", "OIDC command", "OIDC row", "unknown protocol"} {
		t.Run(mode, func(t *testing.T) {
			service, found, command, tokens := providerLoginOAuth2VaultFixture(t, true, true)
			alias := tokens
			for key, profile := range service.oauthProfiles {
				switch mode {
				case "OIDC profile only":
					service.profiles = map[providerLoginProfileKey]StaticOIDCLoginProfile{key: StaticOIDCLoginProfile(profile)}
					delete(service.oauthProfiles, key)
				case "scope drift":
					profile.Scopes = []string{"read_user"}
					service.oauthProfiles[key] = profile
				case "openid profile":
					profile.Scopes = []string{"openid", "read_user", "email"}
					service.oauthProfiles[key] = profile
				}
			}
			switch mode {
			case "OIDC command":
				_, _, command, _ = providerLoginVaultFixture(t, false)
			case "OIDC row":
				found.Row.Protocol = ""
			case "unknown protocol":
				found.Binding.Metadata.Input.Protocol = "unknown"
			}
			if _, err := service.prepareProviderLoginTokens(t.Context(), found, command, 3, tokens); err == nil {
				t.Fatal("substituted profile or protocol reached token custody")
			}
			if alias.Use(t.Context(), func(context.Context, oauth.TokenBytes) error { return nil }) == nil {
				t.Fatal("rejected OAuth token aliases survived")
			}
		})
	}
}

func TestProviderLoginOAuth2TokenVaultRejectsAuthenticatedMetadataChanges(t *testing.T) {
	service, found, command, tokens := providerLoginOAuth2VaultFixture(t, true, true)
	prepared, err := service.prepareProviderLoginTokens(t.Context(), found, command, 3, tokens)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*providerLoginPreparedTokens){
		"tenant":       func(p *providerLoginPreparedTokens) { p.Input.Command.TenantID = "foreign" },
		"issuer":       func(p *providerLoginPreparedTokens) { p.Input.Issuer = "https://foreign.example" },
		"provider":     func(p *providerLoginPreparedTokens) { p.Input.ProviderID = "foreign" },
		"account":      func(p *providerLoginPreparedTokens) { p.Account.ID = "other-account" },
		"generation":   func(p *providerLoginPreparedTokens) { p.CallbackGeneration++ },
		"wire digest":  func(p *providerLoginPreparedTokens) { p.BindingWireDigest[0] ^= 1 },
		"scope widen":  func(p *providerLoginPreparedTokens) { p.GrantedScopes = []string{"read_user", "admin"} },
		"scope omit":   func(p *providerLoginPreparedTokens) { p.ScopeReported = false },
		"received":     func(p *providerLoginPreparedTokens) { p.ReceivedAt = p.ReceivedAt.Add(time.Second) },
		"expiry":       func(p *providerLoginPreparedTokens) { p.AccessExpiresAt = p.AccessExpiresAt.Add(time.Second) },
		"OIDC purpose": func(p *providerLoginPreparedTokens) { p.Callback.OperationID = providerOIDCCallback },
	} {
		t.Run(name, func(t *testing.T) {
			changed := prepared
			change(&changed)
			if service.validateProviderLoginTokens(t.Context(), changed) == nil {
				t.Fatal("substituted OAuth token metadata authenticated")
			}
		})
	}
	service.payload.Envelope = nil
	if err := service.validateProviderLoginTokenMetadata(prepared); err != nil {
		t.Fatal("OAuth metadata validation required envelope I/O", err)
	}
	if service.persistProviderLoginTokens(t.Context(), kernel.Work{}, nil, command, prepared, [32]byte{11}) == nil {
		t.Fatal("OAuth deposit accepted unowned Work")
	}
}
