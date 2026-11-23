package oidc_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-sso"
	"github.com/faustbrian/go-sso/oidc"
)

func TestRPLogoutTLSBrowserRoundTrip(t *testing.T) {
	const providerFailureText = "provider-failure-detail-must-not-leak"
	for _, test := range []struct {
		name          string
		providerError bool
		tamper        string
		want          oidc.OIDCLogoutOutcome
	}{
		{name: "registered callback", want: oidc.OIDCLogoutProviderComplete},
		{name: "provider error", providerError: true, want: oidc.OIDCLogoutProviderError},
		{name: "different state", tamper: "state", want: oidc.OIDCLogoutInvalid},
		{name: "different callback route", tamper: "route", want: oidc.OIDCLogoutInvalid},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			entropy := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9}
			state := oidc.NewRPLogoutState(entropy)
			wireState := base64.RawURLEncoding.EncodeToString(entropy[:])
			if state.Encode() != wireState || len(wireState) != 43 {
				t.Fatal("state did not preserve the canonical unpadded encoding")
			}

			var profile oidc.RPLogoutProfile
			var callbackOrigin string
			profileReady := make(chan struct{})
			var providerRequests, callbackRequests atomic.Int32
			type callbackResult struct {
				state   oidc.RPLogoutState
				outcome oidc.OIDCLogoutOutcome
				err     error
				display string
			}
			results := make(chan callbackResult, 1)
			callbackServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				<-profileReady
				callbackRequests.Add(1)
				if request.Method != http.MethodGet || request.TLS == nil {
					t.Error("browser callback was not an HTTPS GET")
				}
				callback, err := oidc.ParseRPLogoutCallback(request.URL.RawQuery)
				result := callbackResult{err: err}
				if err == nil {
					result.state = callback.State()
					receivedURI := callbackOrigin + request.URL.EscapedPath()
					result.outcome, result.err = callback.OutcomeFor(request.Context(), profile, state, receivedURI)
					result.display = fmt.Sprintf("%v %+v %#v %v", callback, callback, callback, result.err)
				}
				select {
				case results <- result:
				default:
					t.Error("browser made an unexpected additional callback")
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			defer callbackServer.Close()
			callbackOrigin = callbackServer.URL
			callbackURI := callbackOrigin + "/signed-out"

			providerServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				providerRequests.Add(1)
				if request.Method != http.MethodGet || request.TLS == nil || request.URL.Path != "/end-session" {
					t.Error("provider received an unexpected request instead of the HTTPS logout redirect")
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				query, err := url.ParseQuery(request.URL.RawQuery)
				wantQuery := url.Values{
					"client_id":                {"registered-client"},
					"post_logout_redirect_uri": {callbackURI},
					"state":                    {wireState},
				}
				if err != nil || !reflect.DeepEqual(query, wantQuery) {
					t.Error("logout request changed the registered callback, state, client ID, or sent extra parameters")
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				redirect, err := url.Parse(query.Get("post_logout_redirect_uri"))
				if err != nil {
					t.Error("provider could not parse the registered callback")
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				response := url.Values{"state": {query.Get("state")}}
				if test.providerError {
					response.Set("error", "access_denied")
					response.Set("error_description", providerFailureText)
				}
				if test.tamper == "state" {
					response.Set("state", oidc.NewRPLogoutState([32]byte{99}).Encode())
				}
				if test.tamper == "route" {
					redirect.Path = "/different-route"
				}
				redirect.RawQuery = response.Encode()
				http.Redirect(w, request, redirect.String(), http.StatusFound)
			}))
			defer providerServer.Close()

			var err error
			profile, err = oidc.NewRPLogoutProfile(oidc.RPLogoutProfileConfig{
				Issuer:             providerServer.URL + "/issuer",
				ClientID:           "registered-client",
				EndSessionEndpoint: providerServer.URL + "/end-session",
				CallbackURI:        callbackURI,
			})
			if err != nil {
				t.Fatal("explicitly registered logout profile was rejected", err)
			}
			redirect, err := profile.Redirect(ctx, state)
			if err != nil {
				t.Fatal("logout redirect could not be constructed", err)
			}
			if providerRequests.Load() != 0 || callbackRequests.Load() != 0 {
				t.Fatal("constructing the profile or redirect performed network I/O")
			}
			close(profileReady)

			roots := x509.NewCertPool()
			roots.AddCert(providerServer.Certificate())
			roots.AddCert(callbackServer.Certificate())
			transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
			defer transport.CloseIdleConnections()
			browser := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, redirect.String(), nil)
			if err != nil {
				t.Fatal("browser request could not be constructed", err)
			}
			response, err := browser.Do(request)
			if err != nil {
				t.Fatal("browser could not complete the HTTPS redirect round-trip", err)
			}
			if err := response.Body.Close(); err != nil {
				t.Fatal("browser response could not be closed", err)
			}
			if response.StatusCode != http.StatusNoContent {
				t.Fatal("browser did not reach the callback")
			}
			if providerRequests.Load() != 1 || callbackRequests.Load() != 1 {
				t.Fatal("logout adapter or browser made additional network requests")
			}
			var result callbackResult
			select {
			case result = <-results:
			default:
				t.Fatal("browser response did not produce a callback observation")
			}
			if test.tamper != "" {
				if !errors.Is(result.err, sso.ErrForbidden) || result.outcome != oidc.OIDCLogoutInvalid {
					t.Fatal("a callback with a different state or route acquired provider completion authority", result.err)
				}
				return
			}
			if result.err != nil || result.outcome != test.want || result.state != state {
				t.Fatal("registered correlated callback did not preserve state and provider outcome", result.err)
			}
			if strings.Contains(result.display, providerFailureText) {
				t.Fatal("provider failure detail escaped through callback formatting or errors")
			}
		})
	}
}
