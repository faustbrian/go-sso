package sso_test

import (
	"bytes"
	"context"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	"github.com/faustbrian/go-sso"
)

func signinStartRequest(t testing.TB) sso.SigninStartRequest {
	t.Helper()
	command, err := identity.ParseCommandID("AQEBAQEBAQEBAQEBAQEBAQ")
	if err != nil {
		t.Fatal(err)
	}
	key, err := identity.NewIdempotencyKey([]byte("signin-sensitive-key"))
	if err != nil {
		t.Fatal(err)
	}
	remember, err := session.NewRememberPolicy(session.RememberPolicySpec{
		Choice: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute,
		RefreshAfter: 5 * time.Minute, FreshFor: 15 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	intent, err := sso.NewLoginIntent(remember)
	if err != nil {
		t.Fatal(err)
	}
	return sso.SigninStartRequest{
		CommandID: command, ProviderID: "signin-sensitive-provider", Domain: "signin.example.com",
		SuccessCallback: url.URL{Scheme: "https", Host: "client.example.com", Path: "/sensitive-success", RawQuery: "next=exact%2Fpath"},
		ErrorCallback:   url.URL{Scheme: "https", Host: "client.example.com", Path: "/sensitive-error"},
		LoginIntent:     intent, IdempotencyKey: key,
	}
}

func TestLoginIntentPreservesResolvedRememberPolicy(t *testing.T) {
	for _, choice := range []session.RememberChoice{session.BrowserSession, session.PersistentSession} {
		policy, err := session.NewRememberPolicy(session.RememberPolicySpec{
			Choice: choice, AbsoluteTTL: 24 * time.Hour, IdleTTL: time.Hour,
			RefreshAfter: 5*time.Minute + time.Nanosecond, FreshFor: 15 * time.Minute,
		})
		if err != nil {
			t.Fatal(err)
		}
		intent, err := sso.NewLoginIntent(policy)
		if err != nil {
			t.Fatal(err)
		}
		got, err := intent.RememberPolicy()
		if err != nil || got != policy {
			t.Fatal("intent changed the exact resolved remember policy", err)
		}
		got = session.RememberPolicy{}
		again, err := intent.RememberPolicy()
		if err != nil || again != policy || got == again {
			t.Fatal("returned copy changed immutable intent", err)
		}
	}
	intent, err := sso.NewLoginIntent(session.RememberPolicy{})
	if !errors.Is(err, sso.ErrInvalidInput) || intent != (sso.LoginIntent{}) {
		t.Fatal("zero remember policy produced a valid intent", err)
	}
	if policy, err := (sso.LoginIntent{}).RememberPolicy(); !errors.Is(err, sso.ErrInvalidInput) || policy != (session.RememberPolicy{}) {
		t.Fatal("zero intent manufactured remember policy", err)
	}
}

func TestSigninStartRequestPreservesExactInputs(t *testing.T) {
	for _, selector := range []string{"provider", "domain", "both"} {
		t.Run(selector, func(t *testing.T) {
			request := signinStartRequest(t)
			if selector == "provider" {
				request.Domain = ""
			}
			if selector == "domain" {
				request.ProviderID = ""
			}
			original := request
			if err := request.Validate(); err != nil {
				t.Fatal("valid core request rejected", err)
			}
			if request != original {
				t.Fatal("validation changed original command, selector, callback, intent or key")
			}
		})
	}
	request := signinStartRequest(t)
	request.ProviderID = strings.Repeat("p", 128)
	request.Domain = strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	request.SuccessCallback = url.URL{Scheme: "https", Host: "client.example.com", Path: "/" + strings.Repeat("p", 2048-len("https://client.example.com/"))}
	if err := request.Validate(); err != nil {
		t.Fatal("valid exact field byte bounds rejected", err)
	}
}

func TestSigninStartRequestRejectsInvalidShape(t *testing.T) {
	cases := map[string]func(*sso.SigninStartRequest){
		"missing command":      func(r *sso.SigninStartRequest) { r.CommandID = "" },
		"malformed command":    func(r *sso.SigninStartRequest) { r.CommandID = "not-a-command" },
		"noncanonical command": func(r *sso.SigninStartRequest) { r.CommandID = "AQEBAQEBAQEBAQEBAQEBAR" },
		"missing selectors":    func(r *sso.SigninStartRequest) { r.ProviderID, r.Domain = "", "" },
		"oversized provider":   func(r *sso.SigninStartRequest) { r.ProviderID = strings.Repeat("p", 129) },
		"padded provider":      func(r *sso.SigninStartRequest) { r.ProviderID = " provider" },
		"non ASCII provider":   func(r *sso.SigninStartRequest) { r.ProviderID = "pröv" },
		"uppercase domain":     func(r *sso.SigninStartRequest) { r.Domain = "Signin.example.com" },
		"padded domain":        func(r *sso.SigninStartRequest) { r.Domain = " signin.example.com" },
		"trailing dot domain":  func(r *sso.SigninStartRequest) { r.Domain = "signin.example.com." },
		"email selector":       func(r *sso.SigninStartRequest) { r.Domain = "user@signin.example.com" },
		"oversized domain":     func(r *sso.SigninStartRequest) { r.Domain = strings.Repeat("a", 254) },
		"zero intent":          func(r *sso.SigninStartRequest) { r.LoginIntent = sso.LoginIntent{} },
		"zero key":             func(r *sso.SigninStartRequest) { r.IdempotencyKey = identity.IdempotencyKey{} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			request := signinStartRequest(t)
			mutate(&request)
			if err := request.Validate(); err != sso.ErrInvalidInput {
				t.Fatal("invalid request did not return the exact redacted error category")
			}
		})
	}
}

func TestSigninStartCallbacksRequireExactHTTPSShape(t *testing.T) {
	invalid := map[string]url.URL{
		"zero":                {},
		"HTTP":                {Scheme: "http", Host: "client.example.com", Path: "/callback"},
		"relative":            {Path: "/callback"},
		"opaque":              {Scheme: "https", Opaque: "client.example.com/callback"},
		"missing host":        {Scheme: "https", Path: "/callback"},
		"credentials":         {Scheme: "https", Host: "client.example.com", User: url.UserPassword("sensitive-user", "sensitive-password")},
		"fragment":            {Scheme: "https", Host: "client.example.com", Fragment: "sensitive-fragment"},
		"hidden raw fragment": {Scheme: "https", Host: "client.example.com", RawFragment: "discarded"},
		"hidden raw path":     {Scheme: "https", Host: "client.example.com", Path: "/callback", RawPath: "/other"},
		"omitted host":        {Scheme: "https", Host: "client.example.com", OmitHost: true},
		"host space":          {Scheme: "https", Host: "client.example.com "},
		"invalid port":        {Scheme: "https", Host: "client.example.com:invalid"},
		"oversized":           {Scheme: "https", Host: "client.example.com", Path: "/" + strings.Repeat("p", 2049-len("https://client.example.com/"))},
	}
	for name, callback := range invalid {
		for _, field := range []string{"success", "error"} {
			t.Run(name+"/"+field, func(t *testing.T) {
				request := signinStartRequest(t)
				if field == "success" {
					request.SuccessCallback = callback
				} else {
					request.ErrorCallback = callback
				}
				if err := request.Validate(); err != sso.ErrInvalidInput {
					t.Fatal("invalid callback shape admitted or disclosed input")
				}
			})
		}
	}
	for _, raw := range []string{"https://client.example.com/callback?next=one%2Ftwo", "https://client.example.com:8443/callback", "https://client.example.com/exact%2Fpath?"} {
		callback, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		request := signinStartRequest(t)
		request.SuccessCallback, request.ErrorCallback = *callback, *callback
		if err := request.Validate(); err != nil || request.SuccessCallback.String() != raw || request.ErrorCallback.String() != raw {
			t.Fatal("valid exact callback changed or rejected", err)
		}
	}
}

func TestSigninStartValuesRedactImplicitDisclosure(t *testing.T) {
	request := signinStartRequest(t)
	result := sso.SigninStartResult{
		RedirectURI: request.SuccessCallback, TransactionID: "sensitive-transaction", ProviderID: request.ProviderID, Protocol: "oidc",
	}
	for _, value := range []any{request, request.LoginIntent, result, sso.SigninStartRequest{}, sso.LoginIntent{}, sso.SigninStartResult{}} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
			if got := fmt.Sprintf(format, value); !strings.Contains(got, "redacted") || strings.Contains(got, "sensitive") || strings.Contains(got, "client.example.com") || strings.Contains(got, "AQEBAQ") {
				t.Fatal("implicit formatting disclosed signin value")
			}
		}
		if _, err := json.Marshal(value); !errors.Is(err, sso.ErrSensitiveSerialization) {
			t.Fatal("JSON serialization did not fail closed", err)
		}
		marshaler, ok := value.(encoding.TextMarshaler)
		if !ok {
			t.Fatal("missing text serialization denial")
		}
		if data, err := marshaler.MarshalText(); !errors.Is(err, sso.ErrSensitiveSerialization) || len(data) != 0 {
			t.Fatal("text serialization did not fail closed", err)
		}
		var output bytes.Buffer
		slog.New(slog.NewJSONHandler(&output, nil)).Log(context.Background(), slog.LevelInfo, "signin", "value", value)
		if got := output.String(); !strings.Contains(got, "redacted") || strings.Contains(got, "sensitive") || strings.Contains(got, "client.example.com") || strings.Contains(got, "AQEBAQ") {
			t.Fatal("structured logging disclosed signin value")
		}
	}
}

func FuzzSigninStartCallbackShape(f *testing.F) {
	for _, raw := range []string{
		"https://client.example.com/callback",
		"https://client.example.com/exact%2Fpath?next=one%2Ftwo",
		"https://client.example.com:8443/callback?",
		"https://client.example.com/" + strings.Repeat("p", 2048-len("https://client.example.com/")),
		"https://client.example.com/" + strings.Repeat("p", 2049-len("https://client.example.com/")),
		"http://client.example.com/callback",
		"https://user:password@client.example.com/callback",
		"https://client.example.com/callback#fragment",
		"https:client.example.com/callback",
		"https:///callback",
		"https://client.example.com:invalid/callback",
		"https://client.example.com/%invalid",
		"/callback",
		"",
	} {
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 4096 {
			return
		}
		callback, err := url.Parse(raw)
		if err != nil {
			return
		}
		request := signinStartRequest(t)
		request.SuccessCallback, request.ErrorCallback = *callback, *callback
		original := request
		err = request.Validate()
		again := request.Validate()
		if err != again || request != original {
			t.Fatal("callback validation changed original inputs or was unstable")
		}
		if err != nil {
			if err != sso.ErrInvalidInput {
				t.Fatal("invalid callback returned a non-redacted error category")
			}
			return
		}
		if callback.Scheme != "https" || callback.Hostname() == "" || callback.User != nil || callback.Opaque != "" || callback.OmitHost || callback.Fragment != "" || callback.RawFragment != "" {
			t.Fatal("accepted callback violated HTTPS or forbidden-state invariants")
		}
		wire := callback.String()
		if len(wire) == 0 || len(wire) > 2048 {
			t.Fatal("accepted callback violated serialized byte bounds")
		}
		reconstructed, err := url.Parse(wire)
		if err != nil || *reconstructed != *callback {
			t.Fatal("accepted callback did not round-trip exactly")
		}
	})
}
