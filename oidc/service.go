package oidc

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"sync/atomic"
	"time"

	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-sso"
)

var (
	// ErrProviderDenied reports a definitive denial for the exact original
	// callback. No provider-selected error text or redirect is exposed.
	ErrProviderDenied = errors.New("sso oidc: provider denied the callback")
	// ErrExchangeUnsettled requires reconciliation of the original command;
	// its authorization code must not be submitted again.
	ErrExchangeUnsettled = errors.New("sso oidc: exchange requires reconciliation")
)

// CallbackEvidence carries verified signed-token evidence and the original
// cutoff to the coordinator. ExpiresAt caps delivery at the earlier of the
// signed exp and the reservation's validity. The signed iat is not an
// authentication time. AuthenticatedAt is set only for validated auth_time.
type CallbackEvidence struct {
	Transaction                       sso.LoginTransaction
	Assertion                         sso.ProtocolAssertion
	ExpiresAt                         time.Time
	IDTokenIssuedAt, IDTokenExpiresAt time.Time
	AuthenticatedAt                   time.Time
	HasAuthenticationTime             bool
}

// CallbackCustody is supplied by the coordinator only after acknowledgement
// of the original one-use reservation. Hooks are synchronous, must honor
// cancellation, and must not retain the borrowed material.
type CallbackCustody struct {
	ObservedAt, ValidUntil time.Time
	// UseSecrets validates current admission and borrows the exact installed
	// client secret and decrypted PKCE verifier once for this generation.
	// The coordinator owns the original bytes; the adapter clears its copies.
	UseSecrets func(context.Context, func(clientSecret, verifier []byte) error) error
	// AcceptTokens borrows tokens only until it returns and owns encrypted
	// staging and final application. It returns zero until a durable token
	// version exists. A returned error requires original-command reconciliation.
	AcceptTokens func(context.Context, CallbackEvidence, oauth.TokenSet) (sso.TokenVersion, error)
}

// Config binds one exact coordinator-owned transaction and activated
// credential generation to an explicitly selected static OIDC profile.
// Clock is required. KeySet is a trusted signing-key source and is required
// only for Complete; Callback nil selects credential-free Start. The
// coordinator authenticates and reserves state and selects the provider.
// Profile.ID is the selected wire owner's logical ID, which may differ
// from the durable, case-sensitive SSO provider identifier.
type Config struct {
	Transaction          sso.LoginTransaction
	CredentialGeneration uint64
	Profile              oauth.ProviderProfile
	Mapping              sso.AttributeMapping
	Authorization        oauth.AuthorizationParameters
	CapabilityExpiresAt  time.Time
	Clock                oauth.Clock
	HTTPClient           *http.Client
	KeySet               oauth.SigningKeySet
	Callback             *CallbackCustody
}

// Service implements the selected command-scoped OIDC protocol. It neither
// stores tokens nor applies directory or session policy. Value copies share
// an in-process guard; durable one-use and retry authority stay with SSO.
type Service struct {
	cfg     Config
	mapping sso.AttributeMappingSpec
	claims  []string
	attempt *atomic.Bool
}

var _ sso.ProtocolAdapter = (*Service)(nil)

// New validates the original transaction and static configuration without
// borrowing keys or secrets or doing I/O. The configured clock and key source
// must be concurrency-safe. Do not mutate HTTP client settings while in use.
func New(cfg Config) (*Service, error) {
	if cfg.Clock == nil {
		return nil, sso.ErrInvalidInput
	}
	now := cfg.Clock.Now()
	tx, profile := cfg.Transaction, cfg.Profile
	generation, err := tx.ValidateAt(now)
	mapping, mappingErr := cfg.Mapping.Spec()
	if err != nil || mappingErr != nil || generation != cfg.CredentialGeneration || tx.Protocol != "oidc" ||
		profile.Version != tx.ProviderVersion || profile.RedirectURI != tx.Callback.String() ||
		mapping.Version != tx.MappingVersion || !now.Before(cfg.CapabilityExpiresAt) || cfg.CapabilityExpiresAt.After(tx.ExpiresAt) {
		return nil, sso.ErrInvalidInput
	}
	names, err := selectedClaims(mapping)
	if err != nil {
		return nil, err
	}
	if _, err := oauth.OIDCAuthorization(context.Background(), profile, cfg.Authorization); err != nil {
		return nil, err
	}
	cfg.Profile.Scopes = slices.Clone(profile.Scopes)
	cfg.Profile.Algorithms = slices.Clone(profile.Algorithms)
	var attempt *atomic.Bool
	if cfg.Callback != nil {
		c := *cfg.Callback
		if cfg.KeySet == nil || c.UseSecrets == nil || c.AcceptTokens == nil || c.ObservedAt.IsZero() ||
			now.Before(c.ObservedAt) || !now.Before(c.ValidUntil) || c.ValidUntil.After(c.ObservedAt.Add(20*time.Second)) ||
			c.ValidUntil.After(cfg.CapabilityExpiresAt) {
			return nil, sso.ErrInvalidInput
		}
		cfg.Callback = &c
		attempt = new(atomic.Bool)
	}
	return &Service{cfg: cfg, mapping: mapping, claims: names, attempt: attempt}, nil
}

// Start renders the exact original state, nonce, S256 challenge and callback.
// It does not authenticate, reserve or renew state, read credentials or do I/O.
func (s *Service) Start(ctx context.Context, command sso.ProtocolStartCommand) (sso.ProtocolStartResult, error) {
	if ctx == nil || s == nil || s.cfg.Clock == nil || command.Transaction != s.cfg.Transaction {
		return sso.ProtocolStartResult{}, sso.ErrInvalidInput
	}
	now := s.cfg.Clock.Now()
	if _, err := command.ValidateAt(now); err != nil || !now.Before(s.cfg.CapabilityExpiresAt) {
		return sso.ProtocolStartResult{}, sso.ErrForbidden
	}
	request, err := oauth.OIDCAuthorization(ctx, s.cfg.Profile, s.cfg.Authorization)
	if err != nil {
		return sso.ProtocolStartResult{}, err
	}
	redirect, err := url.Parse(request.URL())
	if err != nil {
		return sso.ProtocolStartResult{}, sso.ErrInvalidInput
	}
	result := sso.ProtocolStartResult{Redirect: *redirect, ExpiresAt: s.cfg.CapabilityExpiresAt}
	if err := result.ValidateFor(command.Transaction, s.cfg.Clock.Now(), s.cfg.CapabilityExpiresAt); err != nil {
		return sso.ProtocolStartResult{}, err
	}
	return result, nil
}

// Complete owns and closes the bounded buffered query payload. Call it only
// for the acknowledged original reservation; it performs at most one
// exchange and never returns token bytes or grants local session authority.
func (s *Service) Complete(ctx context.Context, callback sso.ProtocolCallback) (sso.ProtocolAssertion, error) {
	if callback.Payload == nil {
		return sso.ProtocolAssertion{}, sso.ErrInvalidInput
	}
	defer callback.Payload.Close()
	if ctx == nil || s == nil || s.attempt == nil || callback.Transaction != s.cfg.Transaction {
		return sso.ProtocolAssertion{}, sso.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return sso.ProtocolAssertion{}, err
	}
	now := s.cfg.Clock.Now()
	if !s.admittedAt(now) {
		return sso.ProtocolAssertion{}, sso.ErrForbidden
	}
	if !s.attempt.CompareAndSwap(false, true) {
		return sso.ProtocolAssertion{}, sso.ErrConflict
	}
	work, cancel := context.WithTimeout(ctx, s.cfg.Callback.ValidUntil.Sub(now))
	defer cancel()
	parsed, err := s.readCallback(work, callback)
	if err != nil {
		return sso.ProtocolAssertion{}, err
	}
	defer parsed.Destroy()
	if parsed.Denied() {
		return sso.ProtocolAssertion{}, ErrProviderDenied
	}
	result, err := s.exchange(work, parsed)
	defer result.Tokens.Destroy()
	if err != nil {
		return sso.ProtocolAssertion{}, err
	}
	return s.handoff(work, result)
}

func (s *Service) admittedAt(now time.Time) bool {
	return !now.IsZero() && !now.Before(s.cfg.Callback.ObservedAt) && now.Before(s.cfg.Callback.ValidUntil)
}

func (s *Service) readCallback(ctx context.Context, callback sso.ProtocolCallback) (oauth.QueryCallback, error) {
	// At the full caller budget there may be unread bytes; reject without
	// reading an extra byte or authenticating a truncated prefix.
	max := min(callback.MaximumBytes, uint64(3*s.cfg.Profile.MaxCodeBytes+16*1024+1))
	if max == 0 {
		return oauth.QueryCallback{}, sso.ErrInvalidInput
	}
	raw, err := io.ReadAll(io.LimitReader(callback.Payload, int64(max)))
	defer clear(raw)
	if ctx.Err() != nil {
		return oauth.QueryCallback{}, ctx.Err()
	}
	if err != nil || uint64(len(raw)) == max {
		return oauth.QueryCallback{}, sso.ErrInvalidInput
	}
	parsed, err := oauth.ParseQueryCallback(ctx, string(raw), s.cfg.Profile)
	if err != nil {
		return oauth.QueryCallback{}, err
	}
	check := func(_ context.Context, state []byte) error {
		if subtle.ConstantTimeCompare(state, []byte(s.cfg.Authorization.State)) != 1 {
			return sso.ErrForbidden
		}
		return nil
	}
	if parsed.Denied() {
		err = parsed.UseDeniedState(ctx, check)
	} else if input, ok := parsed.Input(); ok {
		err = input.Use(ctx, func(ctx context.Context, _ []byte, state []byte) error { return check(ctx, state) })
	} else {
		err = sso.ErrInvalidInput
	}
	if err != nil {
		parsed.Destroy()
		return oauth.QueryCallback{}, err
	}
	return parsed, nil
}

func (s *Service) exchange(ctx context.Context, parsed oauth.QueryCallback) (result oauth.ExchangeResult, err error) {
	called, repeated, started := false, false, false
	returned := false
	defer func() {
		if returned {
			return
		}
		// A borrower can unwind after use returns but before the caller
		// receives the tokens. Preserve cleanup and avoid arbitrary panic data.
		result.Tokens.Destroy()
		result = oauth.ExchangeResult{}
		if recover() != nil {
			err = sso.ErrUnavailable
			if started {
				err = ErrExchangeUnsettled
			}
		}
	}()
	input, ok := parsed.Input()
	if !ok {
		returned = true
		return oauth.ExchangeResult{}, sso.ErrInvalidInput
	}
	var exchangeErr error
	borrowErr := s.cfg.Callback.UseSecrets(ctx, func(secret, verifier []byte) (err error) {
		if called {
			repeated = true
			return sso.ErrConflict
		}
		called = true
		defer func() { exchangeErr = err }()
		if ctx.Err() != nil || !s.admittedAt(s.cfg.Clock.Now()) {
			return sso.ErrForbidden
		}
		proof, err := oauth.NewPKCEVerifier(verifier)
		if err != nil {
			return err
		}
		defer proof.Destroy()
		if subtle.ConstantTimeCompare([]byte(proof.Challenge()), []byte(s.cfg.Authorization.PKCEChallenge)) != 1 {
			return sso.ErrForbidden
		}
		provider, err := s.provider(secret)
		if err != nil {
			return err
		}
		defer provider.Close()
		if ctx.Err() != nil || !s.admittedAt(s.cfg.Clock.Now()) {
			return sso.ErrForbidden
		}
		started = true
		result, err = provider.Exchange(ctx, input, proof, s.cfg.Authorization.Nonce)
		return err
	})
	returned = true
	if exchangeErr != nil {
		return result, exchangeErr
	}
	if started && (borrowErr != nil || repeated) {
		return result, ErrExchangeUnsettled
	}
	if !started {
		return result, sso.ErrUnavailable
	}
	return result, nil
}

func (s *Service) provider(secret []byte) (*oauth.OIDCProvider, error) {
	p := s.cfg.Profile
	cfg := oauth.OIDCConfig{
		ID: p.ID, Version: p.Version, Issuer: p.Issuer, AuthorizationEndpoint: p.AuthorizationEndpoint,
		TokenEndpoint: p.TokenEndpoint, RedirectURI: p.RedirectURI, ClientID: p.ClientID, ClientSecret: secret,
		ClientAuthentication: p.ClientAuthentication, Scopes: p.Scopes, Algorithms: p.Algorithms,
		Clock: s.cfg.Clock, KeySet: s.cfg.KeySet, HTTPClient: s.cfg.HTTPClient, Timeout: p.Timeout,
		ClockSkew: p.ClockSkew, MaxResponseBytes: p.MaxResponseBytes, MaxTokenBytes: p.MaxTokenBytes, MaxCodeBytes: p.MaxCodeBytes,
	}
	if len(s.claims) == 0 {
		return oauth.NewOIDCProvider(cfg)
	}
	return oauth.NewOIDCProviderWithClaims(cfg, oauth.OIDCClaimProjectionConfig{Names: s.claims})
}

func (s *Service) handoff(ctx context.Context, result oauth.ExchangeResult) (sso.ProtocolAssertion, error) {
	at := s.cfg.Clock.Now()
	id := result.Identity
	expires := s.cfg.Callback.ValidUntil
	if id.IDTokenExpiresAt().Before(expires) {
		expires = id.IDTokenExpiresAt()
	}
	if ctx.Err() != nil || !s.admittedAt(at) || !at.Before(expires) {
		return sso.ProtocolAssertion{}, ErrExchangeUnsettled
	}
	assertion, err := s.projectAssertion(result)
	if err != nil {
		return sso.ProtocolAssertion{}, ErrExchangeUnsettled
	}
	authenticatedAt, hasAuthenticationTime := id.AuthenticationTime()
	evidence := CallbackEvidence{
		Transaction: s.cfg.Transaction, Assertion: assertion, ExpiresAt: expires,
		IDTokenIssuedAt: id.IDTokenIssuedAt(), IDTokenExpiresAt: id.IDTokenExpiresAt(),
		AuthenticatedAt: authenticatedAt, HasAuthenticationTime: hasAuthenticationTime,
	}
	evidence.Assertion.Attributes = slices.Clone(assertion.Attributes)
	delivery, cancel := context.WithTimeout(ctx, expires.Sub(at))
	defer cancel()
	reference, err := acceptTokens(delivery, s.cfg.Callback.AcceptTokens, evidence, result.Tokens)
	now := s.cfg.Clock.Now()
	if err != nil || delivery.Err() != nil || !s.admittedAt(now) || !now.Before(expires) {
		return sso.ProtocolAssertion{}, ErrExchangeUnsettled
	}
	if reference != (sso.TokenVersion{}) {
		spec, err := reference.Spec()
		tx := s.cfg.Transaction
		if err != nil || spec.TenantID != tx.TenantID || spec.CommandID != tx.CommandID || spec.CredentialGeneration != s.cfg.CredentialGeneration {
			return sso.ProtocolAssertion{}, ErrExchangeUnsettled
		}
		assertion.TokenReference = reference
		if err := assertion.Validate(); err != nil {
			return sso.ProtocolAssertion{}, ErrExchangeUnsettled
		}
	}
	return assertion, nil
}

func acceptTokens(ctx context.Context, accept func(context.Context, CallbackEvidence, oauth.TokenSet) (sso.TokenVersion, error), evidence CallbackEvidence, tokens oauth.TokenSet) (reference sso.TokenVersion, err error) {
	defer func() {
		if recover() != nil {
			reference, err = sso.TokenVersion{}, ErrExchangeUnsettled
		}
	}()
	return accept(ctx, evidence, tokens)
}

func (Config) Format(w fmt.State, _ rune)   { _, _ = io.WriteString(w, "sso/oidc.Config(redacted)") }
func (Config) LogValue() slog.Value         { return slog.StringValue("sso/oidc.Config(redacted)") }
func (Config) MarshalJSON() ([]byte, error) { return nil, sso.ErrSensitiveSerialization }
func (Config) MarshalText() ([]byte, error) { return nil, sso.ErrSensitiveSerialization }

func (Service) Format(w fmt.State, _ rune)   { _, _ = io.WriteString(w, "sso/oidc.Service(redacted)") }
func (Service) LogValue() slog.Value         { return slog.StringValue("sso/oidc.Service(redacted)") }
func (Service) MarshalJSON() ([]byte, error) { return nil, sso.ErrSensitiveSerialization }
func (Service) MarshalText() ([]byte, error) { return nil, sso.ErrSensitiveSerialization }
