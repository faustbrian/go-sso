package oidc_test

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-sso"
	"github.com/faustbrian/go-sso/oidc"
)

func TestCompleteParsedUsesOriginalCustodyAndSignedPolicyClaims(t *testing.T) {
	claims := signinClaims()
	claims["member_active"] = true
	f := newSigninFixture(t, claims)
	names := []string{"member_active"}
	f.config.AdditionalClaims = names
	service, err := oidc.New(f.config)
	if err != nil {
		t.Fatal(err)
	}
	names[0] = "different_claim"
	parsed := parsedSigninCallback(t, f.config.Profile, signinState)
	defer parsed.Destroy()
	assertion, err := service.CompleteParsed(t.Context(), f.config.Transaction, parsed)
	if err != nil {
		t.Fatal(err)
	}
	if assertion.ProviderSubject != "signed-subject-9" || len(assertion.Attributes) != 3 || f.requests.Load() != 1 || f.hooks.Load() != 1 {
		t.Fatal("policy-only claims must not widen the mapped assertion or repeat the exchange")
	}
	id := f.evidence.Identity
	if id.ProviderID() != f.config.Profile.ID || id.Subject() != assertion.ProviderSubject ||
		!id.IDTokenIssuedAt().Equal(f.evidence.IDTokenIssuedAt) || !id.IDTokenExpiresAt().Equal(f.evidence.IDTokenExpiresAt) {
		t.Fatal("verified wire identity and original signed times were not retained")
	}
	signed := (oauth.ExchangeResult{Identity: id}).VerifiedOIDCClaims()
	if len(signed) != 4 || signed[3].Name() != "member_active" {
		t.Fatal("the exact trusted policy selection did not survive construction")
	}
	if active, ok := signed[3].BoolValue(); !ok || !active {
		t.Fatal("signed policy evidence lost its exact Boolean observation")
	}
	input, ok := parsed.Input()
	if !ok || input.Use(t.Context(), func(context.Context, []byte, []byte) error { return nil }) != nil {
		t.Fatal("adapter destroyed transport-owned custody")
	}
	body := f.body(signinState, f.config.Profile.Issuer)
	_, err = service.Complete(t.Context(), sso.ProtocolCallback{Transaction: f.config.Transaction, Payload: body, MaximumBytes: 4096})
	if !errors.Is(err, sso.ErrConflict) || f.requests.Load() != 1 || body.closes != 1 {
		t.Fatal("the raw and parsed APIs do not share the same exchange-attempt owner")
	}
}

func TestCompleteParsedRejectsMismatchedAuthorityBeforeSecrets(t *testing.T) {
	for _, scenario := range []string{"profile", "state", "destroyed", "cancellation"} {
		t.Run(scenario, func(t *testing.T) {
			f := newSigninFixture(t, signinClaims())
			service, err := oidc.New(f.config)
			if err != nil {
				t.Fatal(err)
			}
			profile, state := f.config.Profile, signinState
			if scenario == "profile" {
				profile.Version++
			}
			if scenario == "state" {
				state = signinNonce
			}
			parsed := parsedSigninCallback(t, profile, state)
			defer parsed.Destroy()
			if scenario == "destroyed" {
				parsed.Destroy()
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if scenario == "cancellation" {
				cancel()
			}
			got, err := service.CompleteParsed(ctx, f.config.Transaction, parsed)
			if err == nil || got.ProviderSubject != "" || f.borrows.Load() != 0 || f.requests.Load() != 0 || f.hooks.Load() != 0 {
				t.Fatal("invalid parsed custody reached the secret or exchange boundary")
			}
		})
	}
}

func parsedSigninCallback(t *testing.T, profile oauth.ProviderProfile, state string) oauth.QueryCallback {
	t.Helper()
	query := url.Values{"state": {state}, "iss": {profile.Issuer}, "code": {" original +/=: code "}}
	parsed, err := oauth.ParseQueryCallback(t.Context(), query.Encode(), profile)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
