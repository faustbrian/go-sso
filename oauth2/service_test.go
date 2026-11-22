package oauth2_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/session"
	"github.com/faustbrian/go-sso"
	"github.com/faustbrian/go-sso/oauth2"
)

type protocolClock struct{ at time.Time }

func (c protocolClock) Now() time.Time { return c.at }

type countedBody struct {
	io.Reader
	closes int
}

func (b *countedBody) Close() error { b.closes++; return nil }

func authorization(tx sso.LoginTransaction) sso.ProtocolStartCommand {
	return sso.ProtocolStartCommand{Transaction: tx, Provider: sso.Provider{
		ID: tx.ProviderID, OrganizationID: string(tx.OrganizationID), Protocol: tx.Protocol,
		Version: tx.ProviderVersion, MappingVersion: tx.MappingVersion, Enabled: true,
	}}
}

type adapterFixture struct {
	config                               oauth2.Config
	posts, identities, borrows, handoffs atomic.Int32
	borrowed                             oauth.TokenSet
	evidence                             oauth2.CallbackEvidence
}

func newAdapterFixture(t *testing.T) *adapterFixture {
	t.Helper()
	return newAdapterFixtureForEncoding(t, oauth.OAuth2StringSubject)
}

func newAdapterFixtureForEncoding(t *testing.T, encoding oauth.OAuth2SubjectEncoding) *adapterFixture {
	t.Helper()
	f := new(adapterFixture)
	now := time.Date(2026, 11, 22, 22, 10, 0, 0, time.UTC)
	verifier := strings.Repeat("A", 43)
	state := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	challenge := sha256.Sum256([]byte(verifier))
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch req.URL.Path {
		case "/token":
			f.posts.Add(1)
			if req.Method != http.MethodPost || req.ParseForm() != nil || req.Form.Get("code") != "example-code" || req.Form.Get("code_verifier") != verifier || req.Form.Get("client_secret") != "test-client-only" || req.Form.Get("redirect_uri") != "https://identity.example.com/oauth/callback" {
				t.Error("token request did not use the exact retained code, verifier and installation")
			}
			_, _ = io.WriteString(w, `{"access_token":"test-access-only","refresh_token":"test-refresh-only","token_type":"Bearer","expires_in":60}`)
		case "/identity":
			f.identities.Add(1)
			if req.Method != http.MethodGet || req.Header.Get("Authorization") != "Bearer test-access-only" {
				t.Error("identity endpoint did not receive the exchanged bearer")
			}
			if encoding == oauth.OAuth2PositiveIntegerSubject {
				_, _ = io.WriteString(w, `{"stable_id":9007199254740993,"mail":"person@example.com","mail_verified":false}`)
			} else {
				_, _ = io.WriteString(w, `{"stable_id":"subject-9","mail":"person@example.com","mail_verified":true,"nickname":null}`)
			}
		default:
			t.Error("unconfigured endpoint reached")
			http.NotFound(w, req)
		}
	}))
	t.Cleanup(server.Close)
	redirect := url.URL{Scheme: "https", Host: "identity.example.com", Path: "/oauth/callback"}
	details := oauth.OAuth2UserInfoDetails{UserInfoEndpoint: server.URL + "/identity", SubjectClaim: "stable_id", SubjectEncoding: encoding, ProofLifetime: 10 * time.Second}
	provider, err := oauth.NewSharedOAuth2UserInfoProvider(oauth.OAuth2UserInfoConfig{
		ID: "configured-provider", Version: 9, Issuer: server.URL, AuthorizationEndpoint: server.URL + "/authorize", TokenEndpoint: server.URL + "/token", ClientID: "configured-client",
		UserInfoEndpoint: details.UserInfoEndpoint, RedirectURI: redirect.String(), ClientSecret: []byte("test-client-only"), ClientAuthentication: oauth.ClientSecretPost,
		Scopes: []string{"identity", "email"}, SubjectClaim: details.SubjectClaim, SubjectEncoding: details.SubjectEncoding, ProofLifetime: details.ProofLifetime, HTTPClient: server.Client(), Clock: protocolClock{now},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	profile := oauth.OAuth2UserInfoProfile{Profile: provider.Profile(), Details: details}
	provider.Close()
	remember, err := session.NewRememberPolicy(session.RememberPolicySpec{Choice: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := sso.NewLoginTransaction(sso.LoginTransaction{
		TenantID: "tenant", ID: "AQEBAQEBAQEBAQEBAQEBAQ", ProviderID: "provider", OrganizationID: "org", Protocol: "oauth2", Callback: redirect,
		ExpiresAt: now.Add(time.Minute), ProviderVersion: 9, MappingVersion: 4, RememberPolicy: remember, CommandID: "AgICAgICAgICAgICAgICAg",
	}, 3)
	if err != nil {
		t.Fatal(err)
	}
	subjectKind := sso.OAuthSubjectString
	if encoding == oauth.OAuth2PositiveIntegerSubject {
		subjectKind = sso.OAuthSubjectPositiveInteger
	}
	proof, err := sso.NewIdentityProofPolicy(sso.IdentityProofPolicySpec{Version: 2, Issuer: server.URL, SubjectKind: subjectKind, EmailVerification: sso.OAuthEmailBooleanClaim})
	if err != nil {
		t.Fatal(err)
	}
	mapping, err := sso.NewAttributeMapping(sso.AttributeMappingSpec{Version: 4, SubjectClaim: "stable_id", EmailClaim: "mail", DisplayNameClaim: "nickname", VerifiedEmailClaim: "mail_verified"})
	if err != nil {
		t.Fatal(err)
	}
	f.config = oauth2.Config{
		Transaction: tx, CredentialGeneration: 3, Profile: profile, IdentityProof: proof, Mapping: mapping,
		Authorization:       oauth.AuthorizationParameters{State: state, PKCEChallenge: base64.RawURLEncoding.EncodeToString(challenge[:])},
		CapabilityExpiresAt: now.Add(40 * time.Second), Clock: protocolClock{now}, HTTPClient: server.Client(),
		Callback: &oauth2.CallbackCustody{
			ObservedAt: now.Add(-time.Second), ValidUntil: now.Add(12 * time.Second),
			UseSecrets: func(_ context.Context, use func(clientSecret, verifier []byte) error) error {
				f.borrows.Add(1)
				return use([]byte("test-client-only"), []byte(verifier))
			},
			AcceptTokens: func(ctx context.Context, evidence oauth2.CallbackEvidence, tokens oauth.TokenSet) (sso.TokenVersion, error) {
				f.handoffs.Add(1)
				f.borrowed, f.evidence = tokens, evidence
				return sso.TokenVersion{}, tokens.Use(ctx, func(_ context.Context, material oauth.TokenBytes) error {
					if string(material.AccessToken) != "test-access-only" || string(material.RefreshToken) != "test-refresh-only" || len(material.IDToken) != 0 {
						t.Error("SSO did not receive the original OAuth token material")
					}
					return nil
				})
			},
		},
	}
	return f
}

func (f *adapterFixture) body(issuer string) *countedBody {
	values := url.Values{"state": {f.config.Authorization.State}, "code": {"example-code"}, "iss": {issuer}}
	return &countedBody{Reader: strings.NewReader(values.Encode())}
}

func TestAdapterStartAndCompleteUseOriginalSSOAuthority(t *testing.T) {
	f := newAdapterFixture(t)
	svc, err := oauth2.New(f.config)
	if err != nil {
		t.Fatal(err)
	}
	var adapter sso.ProtocolAdapter = svc
	start, err := adapter.Start(t.Context(), authorization(f.config.Transaction))
	if err != nil {
		t.Fatal(err)
	}
	query := start.Redirect.Query()
	if query.Get("state") != f.config.Authorization.State || query.Get("code_challenge") != f.config.Authorization.PKCEChallenge || query.Get("code_challenge_method") != "S256" || query.Has("nonce") || !start.ExpiresAt.Equal(f.config.CapabilityExpiresAt) || f.borrows.Load() != 0 || f.posts.Load() != 0 {
		t.Fatal("start did not preserve original browser redirect and expiry without borrowing credentials")
	}
	body := f.body(f.config.Profile.Profile.Issuer)
	assertion, err := adapter.Complete(t.Context(), sso.ProtocolCallback{Transaction: f.config.Transaction, Payload: body, MaximumBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	if body.closes != 1 || assertion.ProviderSubject != "subject-9" || assertion.ProviderID != "provider" || assertion.OrganizationID != "org" || assertion.MappingVersion != 4 || assertion.ProviderProfileVersion != 9 || f.handoffs.Load() != 1 || f.posts.Load() != 1 || f.identities.Load() != 1 {
		t.Fatal("complete did not supply exact verified SSO evidence and one token handoff")
	}
	if !f.evidence.ExpiresAt.Equal(f.config.Clock.Now().Add(10*time.Second)) || f.evidence.Transaction != f.config.Transaction {
		t.Fatal("handoff renewed or lost original authority")
	}
	attributes := map[string]sso.VerifiedAttributeSpec{}
	for _, a := range assertion.Attributes {
		spec, err := a.Spec()
		if err != nil {
			t.Fatal(err)
		}
		attributes[spec.Name] = spec
	}
	if mail := attributes["mail"]; !mail.Verified || !mail.Authoritative || mail.Provenance.Source != sso.AttributeSourceOAuthIdentityEndpoint || attributes["nickname"].Presence != sso.AttributeNull {
		t.Fatal("explicit proof or null presence was lost")
	}
	if err := f.borrowed.Use(t.Context(), func(context.Context, oauth.TokenBytes) error {
		t.Error("handoff retained live token bytes")
		return nil
	}); err == nil {
		t.Fatal("token borrow survived its handoff")
	}
	repeat := f.body(f.config.Profile.Profile.Issuer)
	if _, err := adapter.Complete(t.Context(), sso.ProtocolCallback{Transaction: f.config.Transaction, Payload: repeat, MaximumBytes: 4096}); !errors.Is(err, sso.ErrConflict) || repeat.closes != 1 || f.posts.Load() != 1 {
		t.Fatal("reusing one admitted adapter resubmitted the code or leaked its payload", err)
	}
}

func TestAdapterRejectsWrongIssuerAndBoundedInputBeforeOpeningSecrets(t *testing.T) {
	for _, tc := range []struct {
		name    string
		issuer  func(string) string
		maximum uint64
	}{
		{"foreign issuer", func(string) string { return "https://wrong.example.com" }, 4096},
		{"truncated", func(issuer string) string { return issuer }, 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAdapterFixture(t)
			svc, err := oauth2.New(f.config)
			if err != nil {
				t.Fatal(err)
			}
			body := f.body(tc.issuer(f.config.Profile.Profile.Issuer))
			if result, err := svc.Complete(t.Context(), sso.ProtocolCallback{Transaction: f.config.Transaction, Payload: body, MaximumBytes: tc.maximum}); err == nil || result.ProviderSubject != "" || f.posts.Load() != 0 || f.borrows.Load() != 0 || f.handoffs.Load() != 0 || body.closes != 1 {
				t.Fatal("invalid callback reached protected work or remained open", err)
			}
		})
	}
}

func TestAdapterDenialMustMatchOriginalState(t *testing.T) {
	for _, same := range []bool{true, false} {
		f := newAdapterFixture(t)
		svc, err := oauth2.New(f.config)
		if err != nil {
			t.Fatal(err)
		}
		state := f.config.Authorization.State
		if !same {
			state = "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		}
		values := url.Values{"state": {state}, "error": {"access_denied"}, "iss": {f.config.Profile.Profile.Issuer}}
		body := &countedBody{Reader: strings.NewReader(values.Encode())}
		_, err = svc.Complete(t.Context(), sso.ProtocolCallback{Transaction: f.config.Transaction, Payload: body, MaximumBytes: 4096})
		if errors.Is(err, oauth2.ErrProviderDenied) != same || err == nil || f.posts.Load() != 0 || f.borrows.Load() != 0 || body.closes != 1 {
			t.Fatalf("same state %t: denial lost its original custody: %v", same, err)
		}
	}
}

func TestAdapterHandoffFailureRequiresReconciliationWithoutExposingSecrets(t *testing.T) {
	f := newAdapterFixture(t)
	f.config.Callback.AcceptTokens = func(_ context.Context, _ oauth2.CallbackEvidence, tokens oauth.TokenSet) (sso.TokenVersion, error) {
		f.borrowed = tokens
		return sso.TokenVersion{}, errors.New("private vault reason")
	}
	svc, err := oauth2.New(f.config)
	if err != nil {
		t.Fatal(err)
	}
	complete := func() (sso.ProtocolAssertion, error) {
		return svc.Complete(t.Context(), sso.ProtocolCallback{Transaction: f.config.Transaction, Payload: f.body(f.config.Profile.Profile.Issuer), MaximumBytes: 4096})
	}
	if result, err := complete(); result.ProviderSubject != "" || !errors.Is(err, oauth2.ErrExchangeUnsettled) || strings.Contains(err.Error(), "private vault reason") || f.posts.Load() != 1 {
		t.Fatal("failed token handoff disclosed a result or failed to preserve uncertainty", err)
	}
	if err := f.borrowed.Use(t.Context(), func(context.Context, oauth.TokenBytes) error { return nil }); err == nil {
		t.Fatal("failed handoff retained live tokens")
	}
	if _, err := complete(); !errors.Is(err, sso.ErrConflict) || f.posts.Load() != 1 {
		t.Fatal("uncertain completion permitted a second provider request", err)
	}
}

func TestAdapterPanickingCustodyOwnerDoesNotExposePostExchangeOutcome(t *testing.T) {
	for _, tc := range []string{"secret borrower", "token handoff"} {
		t.Run(tc, func(t *testing.T) {
			f := newAdapterFixture(t)
			if tc == "secret borrower" {
				borrow := f.config.Callback.UseSecrets
				f.config.Callback.UseSecrets = func(ctx context.Context, use func([]byte, []byte) error) error {
					if err := borrow(ctx, use); err != nil {
						return err
					}
					panic("private custody reason")
				}
			} else {
				f.config.Callback.AcceptTokens = func(_ context.Context, _ oauth2.CallbackEvidence, tokens oauth.TokenSet) (sso.TokenVersion, error) {
					f.borrowed = tokens
					panic("private custody reason")
				}
			}
			svc, err := oauth2.New(f.config)
			if err != nil {
				t.Fatal(err)
			}
			body := f.body(f.config.Profile.Profile.Issuer)
			result, err := svc.Complete(t.Context(), sso.ProtocolCallback{Transaction: f.config.Transaction, Payload: body, MaximumBytes: 4096})
			if result.ProviderSubject != "" || !errors.Is(err, oauth2.ErrExchangeUnsettled) || strings.Contains(err.Error(), "private custody reason") || f.posts.Load() != 1 || body.closes != 1 {
				t.Fatal("post-exchange panic lost or disclosed original custody", err)
			}
			if err := f.borrowed.Use(t.Context(), func(context.Context, oauth.TokenBytes) error { return nil }); err == nil {
				t.Fatal("panicking handoff retained live tokens")
			}
		})
	}
}

func TestAdapterRejectsRenewedObservationAndForeignGeneration(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*oauth2.Config)
	}{
		{"extended observation", func(cfg *oauth2.Config) {
			cfg.Callback.ValidUntil = cfg.Callback.ObservedAt.Add(20*time.Second + time.Nanosecond)
		}},
		{"generation change", func(cfg *oauth2.Config) { cfg.CredentialGeneration++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAdapterFixture(t)
			tc.change(&f.config)
			if adapter, err := oauth2.New(f.config); adapter != nil || !errors.Is(err, sso.ErrInvalidInput) || f.posts.Load() != 0 || f.borrows.Load() != 0 {
				t.Fatal("changed owner scope accepted", err)
			}
		})
	}
}

func TestAdapterConcurrentCompletionSubmitsExactlyOneProviderRequest(t *testing.T) {
	f := newAdapterFixture(t)
	svc, err := oauth2.New(f.config)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 2)
	for range 2 {
		go func() {
			body := f.body(f.config.Profile.Profile.Issuer)
			_, err := svc.Complete(t.Context(), sso.ProtocolCallback{Transaction: f.config.Transaction, Payload: body, MaximumBytes: 4096})
			done <- err
		}()
	}
	var successes, conflicts int
	for range 2 {
		switch err := <-done; {
		case err == nil:
			successes++
		case errors.Is(err, sso.ErrConflict):
			conflicts++
		default:
			t.Error("unexpected completion", err)
		}
	}
	if successes != 1 || conflicts != 1 || f.posts.Load() != 1 || f.handoffs.Load() != 1 {
		t.Fatal("concurrent completion did not use exactly one provider request and handoff")
	}
}

func TestAdapterPreservesExactIntegerSubjectAndUnverifiedClaims(t *testing.T) {
	f := newAdapterFixtureForEncoding(t, oauth.OAuth2PositiveIntegerSubject)
	svc, err := oauth2.New(f.config)
	if err != nil {
		t.Fatal(err)
	}
	assertion, err := svc.Complete(t.Context(), sso.ProtocolCallback{
		Transaction: f.config.Transaction, Payload: f.body(f.config.Profile.Profile.Issuer), MaximumBytes: 4096,
	})
	if err != nil || assertion.ProviderSubject != "9007199254740993" {
		t.Fatal("integer subject changed or failed", err)
	}
	attributes := make(map[string]sso.VerifiedAttributeSpec)
	for _, a := range assertion.Attributes {
		spec, err := a.Spec()
		if err != nil {
			t.Fatal(err)
		}
		attributes[spec.Name] = spec
	}
	if mail := attributes["mail"]; mail.Verified || mail.Authoritative || mail.Presence != sso.AttributeValue || attributes["nickname"].Presence != sso.AttributeAbsent {
		t.Fatal("unverified mail or absent attribute was promoted or discarded")
	}
}
