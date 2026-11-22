package oidc_test

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-sso"
	"github.com/faustbrian/go-sso/oidc"
)

func TestUnconfiguredAdapterRejectsAndClosesCallback(t *testing.T) {
	if service, err := oidc.New(oidc.Config{}); service != nil || !errors.Is(err, sso.ErrInvalidInput) {
		t.Fatal("an unconfigured adapter must not be constructed")
	}
	var service oidc.Service
	var adapter sso.ProtocolAdapter = &service
	payload := &closedQuery{Reader: strings.NewReader("unused")}
	if _, err := adapter.Complete(context.Background(), sso.ProtocolCallback{Payload: payload, MaximumBytes: 32}); !errors.Is(err, sso.ErrInvalidInput) {
		t.Fatalf("zero adapter completed a callback: %v", err)
	}
	if payload.closes != 1 || payload.Len() != len("unused") {
		t.Fatal("an unconfigured callback must be closed without being read")
	}
}

type closedQuery struct {
	*strings.Reader
	closes int
}

func (r *closedQuery) Close() error { r.closes++; return nil }

func TestSigninAdapterRejectsWrongRetainedPKCEBeforeExchange(t *testing.T) {
	f := newSigninFixture(t, signinClaims())
	f.config.Callback.UseSecrets = func(_ context.Context, use func([]byte, []byte) error) error {
		f.borrows.Add(1)
		return use([]byte("installed-client-secret"), []byte(strings.Repeat("A", 43)))
	}
	svc, err := oidc.New(f.config)
	if err != nil {
		t.Fatal(err)
	}
	body := f.body(signinState, "https://issuer.example")
	_, err = svc.Complete(t.Context(), sso.ProtocolCallback{Transaction: f.config.Transaction, Payload: body, MaximumBytes: 4096})
	if !errors.Is(err, sso.ErrForbidden) || body.closes != 1 || f.borrows.Load() != 1 || f.requests.Load() != 0 || f.hooks.Load() != 0 {
		t.Fatal("a different retained verifier must deny before provider I/O")
	}
}

func TestSigninAdapterSettlesProviderDenialWithoutOpeningCredentials(t *testing.T) {
	f := newSigninFixture(t, signinClaims())
	svc, err := oidc.New(f.config)
	if err != nil {
		t.Fatal(err)
	}
	query := url.Values{"state": {signinState}, "iss": {"https://issuer.example"}, "error": {"access_denied"}}
	payload := &closedQuery{Reader: strings.NewReader(query.Encode())}
	_, err = svc.Complete(t.Context(), sso.ProtocolCallback{Transaction: f.config.Transaction, Payload: payload, MaximumBytes: 4096})
	if !errors.Is(err, oidc.ErrProviderDenied) || payload.closes != 1 || f.borrows.Load() != 0 || f.requests.Load() != 0 || f.hooks.Load() != 0 {
		t.Fatal("an authenticated provider denial must not open credentials")
	}
}

func TestSigninAdapterNeverRestartsAnUnsettledTokenHandoff(t *testing.T) {
	for _, withinBorrower := range []bool{false, true} {
		name := "token sink panics"
		if withinBorrower {
			name = "secret borrower panics after exchange"
		}
		t.Run(name, func(t *testing.T) {
			f := newSigninFixture(t, signinClaims())
			if withinBorrower {
				original := f.config.Callback.UseSecrets
				f.config.Callback.UseSecrets = func(ctx context.Context, use func([]byte, []byte) error) error {
					if err := original(ctx, use); err != nil {
						return err
					}
					panic("unpublished borrower detail")
				}
			} else {
				f.config.Callback.AcceptTokens = func(_ context.Context, _ oidc.CallbackEvidence, tokens oauth.TokenSet) (sso.TokenVersion, error) {
					f.hooks.Add(1)
					f.tokens = tokens
					panic("unpublished sink detail")
				}
			}
			svc, err := oidc.New(f.config)
			if err != nil {
				t.Fatal(err)
			}
			tx := f.config.Transaction
			body := f.body(signinState, "https://issuer.example")
			assertion, err := svc.Complete(t.Context(), sso.ProtocolCallback{Transaction: tx, Payload: body, MaximumBytes: 4096})
			if !errors.Is(err, oidc.ErrExchangeUnsettled) || assertion.ProviderSubject != "" || body.closes != 1 || f.requests.Load() != 1 {
				t.Fatal("a panicking custodian after the exchange must leave no usable result")
			}
			if !withinBorrower {
				if f.hooks.Load() != 1 || f.tokens.Use(t.Context(), func(context.Context, oauth.TokenBytes) error { return nil }) == nil {
					t.Fatal("a failed token sink must not retain custody")
				}
			}
			body = f.body(signinState, "https://issuer.example")
			if _, err := svc.Complete(t.Context(), sso.ProtocolCallback{Transaction: tx, Payload: body, MaximumBytes: 4096}); !errors.Is(err, sso.ErrConflict) ||
				body.closes != 1 || f.requests.Load() != 1 {
				t.Fatal("reconciliation must not allow a second exchange")
			}
		})
	}
}

func TestSigninAdapterRejectsExpiredAndTruncatedCallbackWithoutExchange(t *testing.T) {
	for _, expire := range []bool{false, true} {
		name := "caller byte limit"
		if expire {
			name = "at original deadline"
		}
		t.Run(name, func(t *testing.T) {
			f := newSigninFixture(t, signinClaims())
			clock := &controlledAdapterClock{at: signinNow}
			f.config.Clock = clock
			svc, err := oidc.New(f.config)
			if err != nil {
				t.Fatal(err)
			}
			payload := &closedQuery{Reader: strings.NewReader("callback body")}
			limit, unread, want := uint64(4), payload.Len()-4, sso.ErrInvalidInput
			if expire {
				clock.at = f.config.Callback.ValidUntil
				limit, unread, want = 4096, payload.Len(), sso.ErrForbidden
			}
			_, err = svc.Complete(t.Context(), sso.ProtocolCallback{Transaction: f.config.Transaction, Payload: payload, MaximumBytes: limit})
			if !errors.Is(err, want) || payload.closes != 1 || payload.Len() != unread || f.borrows.Load() != 0 || f.requests.Load() != 0 {
				t.Fatal("callback read beyond its original authority")
			}
		})
	}
}

type controlledAdapterClock struct{ at time.Time }

func (c *controlledAdapterClock) Now() time.Time { return c.at }
