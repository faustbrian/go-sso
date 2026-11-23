package oidc_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/faustbrian/go-sso"
	"github.com/faustbrian/go-sso/oidc"
)

func logoutWireProfile() oidc.RPLogoutProfileConfig {
	return oidc.RPLogoutProfileConfig{
		Issuer: "https://issuer.example/tenant", ClientID: "client:/registered",
		EndSessionEndpoint: "https://issuer.example/end-session",
		CallbackURI:        "https://rp.example/sso/oidc/provider/logout/callback",
	}
}

func TestRPLogoutWireRedirectUsesOnlyRegisteredTargetAndOriginalState(t *testing.T) {
	c := logoutWireProfile()
	profile, err := oidc.NewRPLogoutProfile(c)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := profile.Spec(); err != nil || got != c {
		t.Fatal("profile did not retain the exact installed logout facts", err)
	}
	state := oidc.NewRPLogoutState([32]byte{0: 1, 31: 1})
	out, err := profile.Redirect(t.Context(), state)
	const wire = "https://issuer.example/end-session?client_id=client%3A%2Fregistered&post_logout_redirect_uri=https%3A%2F%2Frp.example%2Fsso%2Foidc%2Fprovider%2Flogout%2Fcallback&state=AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE"
	if err != nil || out.String() != wire {
		t.Fatal("redirect changed the registered destination or original state")
	}
	if _, err := profile.Redirect(t.Context(), oidc.RPLogoutState{}); !errors.Is(err, sso.ErrInvalidInput) {
		t.Fatal("uninitialized state was accepted")
	}
	for _, tc := range []struct {
		name   string
		change func(*oidc.RPLogoutProfileConfig)
	}{
		{"issuer query", func(c *oidc.RPLogoutProfileConfig) { c.Issuer += "?tenant=other" }},
		{"endpoint query", func(c *oidc.RPLogoutProfileConfig) { c.EndSessionEndpoint += "?state=foreign" }},
		{"insecure endpoint", func(c *oidc.RPLogoutProfileConfig) { c.EndSessionEndpoint = "http://issuer.example/end-session" }},
		{"callback userinfo", func(c *oidc.RPLogoutProfileConfig) { c.CallbackURI = "https://user@rp.example/logout" }},
		{"callback fragment", func(c *oidc.RPLogoutProfileConfig) { c.CallbackURI += "#state" }},
		{"callback empty query flag", func(c *oidc.RPLogoutProfileConfig) { c.CallbackURI += "?" }},
		{"decoded callback control", func(c *oidc.RPLogoutProfileConfig) { c.CallbackURI += "%00" }},
		{"decoded callback backslash", func(c *oidc.RPLogoutProfileConfig) { c.CallbackURI += "%5Cwww" }},
		{"callback dot segment", func(c *oidc.RPLogoutProfileConfig) { c.CallbackURI += "/../other" }},
		{"oversize encoded redirect", func(c *oidc.RPLogoutProfileConfig) { c.ClientID = strings.Repeat(":", 1024) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			invalid := c
			tc.change(&invalid)
			if _, err := oidc.NewRPLogoutProfile(invalid); !errors.Is(err, sso.ErrInvalidInput) {
				t.Fatal("unsupported installed profile was admitted")
			}
		})
	}
}

func TestRPLogoutCallbackMatchesOriginalRouteAndState(t *testing.T) {
	config := logoutWireProfile()
	profile, err := oidc.NewRPLogoutProfile(config)
	if err != nil {
		t.Fatal(err)
	}
	state := oidc.NewRPLogoutState([32]byte{1})
	query := "state=" + state.Encode()
	for _, tc := range []struct {
		raw  string
		want oidc.OIDCLogoutOutcome
	}{
		{query, oidc.OIDCLogoutProviderComplete},
		{query + "&error=denied&error_description=do+not+disclose", oidc.OIDCLogoutProviderError},
	} {
		callback, err := oidc.ParseRPLogoutCallback(tc.raw)
		if err != nil || callback.State() != state {
			t.Fatal("callback lost the original state")
		}
		out, err := callback.OutcomeFor(t.Context(), profile, state, config.CallbackURI)
		if err != nil || out != tc.want {
			t.Fatal("matching return was not classified")
		}
		if _, err := callback.OutcomeFor(t.Context(), profile, state, config.CallbackURI+"?untrusted=1"); !errors.Is(err, sso.ErrForbidden) {
			t.Fatal("callback route substitution did not deny")
		}
		if _, err := callback.OutcomeFor(t.Context(), profile, oidc.NewRPLogoutState([32]byte{2}), config.CallbackURI); !errors.Is(err, sso.ErrForbidden) {
			t.Fatal("foreign state did not deny")
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := callback.OutcomeFor(ctx, profile, state, config.CallbackURI); !errors.Is(err, context.Canceled) {
			t.Fatal("canceled callback did not stop", err)
		}
		for _, value := range []any{callback, state} {
			if _, err := json.Marshal(value); !errors.Is(err, sso.ErrSensitiveSerialization) || strings.Contains(fmt.Sprintf("%#v", value), state.Encode()) {
				t.Fatal("callback or state exposed sensitive custody")
			}
		}
		if strings.Contains(fmt.Sprintf("%+v", callback), "do not disclose") {
			t.Fatal("arbitrary provider error text survived validation")
		}
	}
}

func TestRPLogoutCallbackRejectsNoncanonicalAndAmbiguousInput(t *testing.T) {
	state := oidc.NewRPLogoutState([32]byte{1}).Encode()
	query := "state=" + state
	for _, raw := range []string{
		"", "state=", "state=short", "state=" + strings.Repeat("A", 43),
		query + "=", query + "&st%61te=" + state, query + "&issuer=https%3A%2F%2Fother.example",
		query + "&error=", query + "&error=denied&error=other", query + "&error_description=unexpected",
		query + "&error=deny&error_description=%00", query + "&error=deny&error_description=%FF",
		query + "&error=deny&error_description=x#fragment", query + "&error=deny&error_description=" + strings.Repeat("x", 1025),
		query + "&error=" + url.QueryEscape(strings.Repeat("a", 129)), strings.Repeat("x", 4097),
	} {
		if callback, err := oidc.ParseRPLogoutCallback(raw); !errors.Is(err, sso.ErrInvalidInput) || callback.State().Encode() != "" {
			t.Fatal("malformed callback produced usable state")
		}
	}
}

func FuzzRPLogoutCallbackState(f *testing.F) {
	state := oidc.NewRPLogoutState([32]byte{1}).Encode()
	for _, seed := range []string{"state=" + state, "state=" + state + "&error=access_denied", "state=short", "state=%FF", ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		callback, err := oidc.ParseRPLogoutCallback(raw)
		if err != nil {
			if callback.State().Encode() != "" {
				t.Fatal("an invalid response retained usable state")
			}
			return
		}
		encoded := callback.State().Encode()
		reparsed, err := oidc.ParseRPLogoutCallback("state=" + encoded)
		if len(raw) > 4096 || len(encoded) != 43 || err != nil || reparsed.State() != callback.State() {
			t.Fatal("an accepted response did not yield bounded canonical state")
		}
	})
}
