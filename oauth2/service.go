// Package oauth2 implements the shared-redirect enterprise OAuth 2.0 profile
// with a separate authenticated identity resource. SSO retains reservation,
// token storage, membership, and session ownership.
package oauth2

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"sync/atomic"
	"time"

	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-sso"
)

var (
	// ErrProviderDenied reports a definitive provider denial for the exact
	// original callback. It does not disclose the remote response or code.
	ErrProviderDenied = errors.New("sso oauth2: provider denied the callback")
	// ErrExchangeUnsettled means the exchange completed but the coordinator
	// could not accept its evidence. Reconcile the original command; never
	// resubmit its authorization code.
	ErrExchangeUnsettled = errors.New("sso oauth2: exchange requires reconciliation")
)

// CallbackEvidence is the exact scoped, short-lived result made available to
// SSO before session or vault policy. ExpiresAt is the earlier identity proof
// or original authenticated observation cutoff. It is not a session TTL.
type CallbackEvidence struct {
	Transaction sso.LoginTransaction
	Assertion   sso.ProtocolAssertion
	ExpiresAt   time.Time
}

// CallbackCustody is constructed by the SSO coordinator only after it has
// reserved the original one-use callback. A new Service cannot reserve a new
// attempt. Both collaborators must be synchronous and honor cancellation.
type CallbackCustody struct {
	ObservedAt, ValidUntil time.Time
	// UseSecrets borrows the exact installed client secret and retained PKCE
	// verifier for this generation. Invoke use once before returning. The
	// caller owns decrypting/clearing its bytes and rechecking current admission.
	UseSecrets func(ctx context.Context, use func(clientSecret, verifier []byte) error) error
	// AcceptTokens borrows tokens only for this invocation; the adapter
	// destroys them on return. The coordinator owns encrypted staging and
	// its existing atomic application of storage and session policy. Return
	// zero when no durable token reference is available yet, never fabricate one.
	AcceptTokens func(context.Context, CallbackEvidence, oauth.TokenSet) (sso.TokenVersion, error)
}

// Config binds one SSO-owned transaction to its exact configured provider,
// installed generation, original state and capability lifetime. Use the same
// transaction value (or its unchanged copy) for operations on the resulting
// Service. Callback is nil for start-only composition. It does not opt in HTTP
// routes, activate a provider, authenticate state or allow unreserved exchange.
type Config struct {
	Transaction          sso.LoginTransaction
	CredentialGeneration uint64
	Profile              oauth.OAuth2UserInfoProfile
	IdentityProof        sso.IdentityProofPolicy
	Mapping              sso.AttributeMapping
	Authorization        oauth.AuthorizationParameters
	CapabilityExpiresAt  time.Time
	Clock                oauth.Clock
	HTTPClient           *http.Client
	Callback             *CallbackCustody
}

// Service implements one command-scoped SSO protocol adapter. It never owns a
// registry, stores decrypted secrets, retries an exchange or renews a deadline.
// Copies, including by value, share the same local single-invocation guard.
// The guard is not durable replay protection; that remains the caller's job.
type Service struct {
	config  Config
	mapping sso.AttributeMappingSpec
	proof   sso.IdentityProofPolicySpec
	claims  []string
	attempt *atomic.Bool
}

var _ sso.ProtocolAdapter = (*Service)(nil)

// New binds the exact profile and validates original deadlines without I/O or
// secret access. HTTPClient and Clock are borrowed; do not mutate shared client
// configuration while in use. The wire provider clones the HTTP transport.
func New(cfg Config) (*Service, error) {
	if cfg.Clock == nil {
		return nil, sso.ErrInvalidInput
	}
	now := cfg.Clock.Now()
	generation, err := cfg.Transaction.ValidateAt(now)
	if err != nil || generation != cfg.CredentialGeneration || cfg.Transaction.Protocol != "oauth2" ||
		!now.Before(cfg.CapabilityExpiresAt) || cfg.CapabilityExpiresAt.After(cfg.Transaction.ExpiresAt) {
		return nil, sso.ErrInvalidInput
	}
	base, details := cfg.Profile.Profile, cfg.Profile.Details
	proof, proofErr := cfg.IdentityProof.Spec()
	mapping, mappingErr := cfg.Mapping.Spec()
	if proofErr != nil || mappingErr != nil || base.Version != cfg.Transaction.ProviderVersion || base.RedirectURI != cfg.Transaction.Callback.String() ||
		base.Issuer != proof.Issuer || mapping.Version != cfg.Transaction.MappingVersion || mapping.SubjectClaim != details.SubjectClaim {
		return nil, sso.ErrInvalidInput
	}
	if err := validateIdentitySelection(mapping, proof, details.SubjectEncoding); err != nil {
		return nil, err
	}
	if _, err := oauth.SharedOAuth2Authorization(context.Background(), cfg.Profile, cfg.Authorization); err != nil {
		return nil, err
	}
	cfg.Profile.Profile.Scopes = slices.Clone(base.Scopes)
	var attempt *atomic.Bool
	if cfg.Callback != nil {
		callback := *cfg.Callback
		if callback.UseSecrets == nil || callback.AcceptTokens == nil || callback.ObservedAt.IsZero() || now.Before(callback.ObservedAt) ||
			!now.Before(callback.ValidUntil) || callback.ValidUntil.After(callback.ObservedAt.Add(20*time.Second)) || callback.ValidUntil.After(cfg.CapabilityExpiresAt) {
			return nil, sso.ErrInvalidInput
		}
		cfg.Callback = &callback
		attempt = new(atomic.Bool)
	}
	return &Service{config: cfg, mapping: mapping, proof: proof, claims: selectedClaims(mapping), attempt: attempt}, nil
}

func validateIdentitySelection(mapping sso.AttributeMappingSpec, proof sso.IdentityProofPolicySpec, encoding oauth.OAuth2SubjectEncoding) error {
	matchingSubject := proof.SubjectKind == sso.OAuthSubjectString && encoding == oauth.OAuth2StringSubject ||
		proof.SubjectKind == sso.OAuthSubjectPositiveInteger && encoding == oauth.OAuth2PositiveIntegerSubject
	if !matchingSubject {
		return sso.ErrInvalidInput
	}
	if encoding == oauth.OAuth2PositiveIntegerSubject && (mapping.SubjectClaim == mapping.EmailClaim || mapping.SubjectClaim == mapping.DisplayNameClaim) {
		return sso.ErrInvalidInput
	}
	if proof.EmailVerification == sso.OAuthEmailUnverified && mapping.VerifiedEmailClaim != "" {
		return sso.ErrInvalidInput
	}
	if proof.EmailVerification == sso.OAuthEmailBooleanClaim {
		verify := mapping.VerifiedEmailClaim
		if mapping.EmailClaim == "" || mapping.EmailClaim == mapping.DisplayNameClaim || verify == "" ||
			verify == mapping.SubjectClaim || verify == mapping.EmailClaim || verify == mapping.DisplayNameClaim {
			return sso.ErrInvalidInput
		}
	}
	return nil
}

// Start renders the original code/query/S256 request. No credential borrower
// is invoked, no HTTP occurs, and no state or expiry is minted here.
func (s *Service) Start(ctx context.Context, command sso.ProtocolStartCommand) (sso.ProtocolStartResult, error) {
	if ctx == nil || s == nil || s.config.Clock == nil || command.Transaction != s.config.Transaction {
		return sso.ProtocolStartResult{}, sso.ErrInvalidInput
	}
	now := s.config.Clock.Now()
	if _, err := command.ValidateAt(now); err != nil || !now.Before(s.config.CapabilityExpiresAt) {
		return sso.ProtocolStartResult{}, sso.ErrForbidden
	}
	request, err := oauth.SharedOAuth2Authorization(ctx, s.config.Profile, s.config.Authorization)
	if err != nil {
		return sso.ProtocolStartResult{}, err
	}
	redirect, err := url.Parse(request.URL())
	if err != nil {
		return sso.ProtocolStartResult{}, sso.ErrInvalidInput
	}
	result := sso.ProtocolStartResult{Redirect: *redirect, ExpiresAt: s.config.CapabilityExpiresAt}
	if err := result.ValidateFor(command.Transaction, s.config.Clock.Now(), s.config.CapabilityExpiresAt); err != nil {
		return sso.ProtocolStartResult{}, err
	}
	return result, nil
}

// Complete consumes one bounded raw query for the caller's already reserved
// transaction, then hands verified identity and short-lived tokens to SSO.
// Payload is the already bounded, buffered request query, not a network stream.
// It is owned by this call and closed exactly once, including on denial.
func (s *Service) Complete(ctx context.Context, callback sso.ProtocolCallback) (sso.ProtocolAssertion, error) {
	if callback.Payload == nil {
		return sso.ProtocolAssertion{}, sso.ErrInvalidInput
	}
	defer callback.Payload.Close()
	if ctx == nil || s == nil || s.attempt == nil || callback.Transaction != s.config.Transaction {
		return sso.ProtocolAssertion{}, sso.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return sso.ProtocolAssertion{}, err
	}
	now := s.config.Clock.Now()
	if !s.admittedAt(now) {
		return sso.ProtocolAssertion{}, sso.ErrForbidden
	}
	if !s.attempt.CompareAndSwap(false, true) {
		return sso.ProtocolAssertion{}, sso.ErrConflict
	}
	work, cancel := context.WithTimeout(ctx, s.config.Callback.ValidUntil.Sub(now))
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
	at := s.config.Clock.Now()
	expires := earlier(s.config.Callback.ValidUntil, result.Identity.EvidenceExpiresAt())
	if !s.admittedAt(at) || !at.Before(expires) || work.Err() != nil {
		return sso.ProtocolAssertion{}, ErrExchangeUnsettled
	}
	if result.Identity.ProviderID() != s.config.Profile.Profile.ID {
		return sso.ProtocolAssertion{}, ErrExchangeUnsettled
	}
	assertion, err := projectAssertion(result, s.config.Transaction, s.mapping, s.proof)
	if err != nil {
		return sso.ProtocolAssertion{}, ErrExchangeUnsettled
	}
	delivery, cancelDelivery := context.WithTimeout(work, expires.Sub(at))
	defer cancelDelivery()
	return s.handoff(delivery, assertion, expires, result.Tokens)
}

func (s *Service) admittedAt(now time.Time) bool {
	return !now.IsZero() && !now.Before(s.config.Callback.ObservedAt) && now.Before(s.config.Callback.ValidUntil)
}

func (s *Service) readCallback(ctx context.Context, callback sso.ProtocolCallback) (oauth.QueryCallback, error) {
	// Match the wire parser's current upper bound. Do not consume an extra
	// sentinel byte beyond the caller's budget: at the exact budget a reader
	// can have more data, so reject rather than accepting a truncated prefix.
	max := min(callback.MaximumBytes, uint64(3*s.config.Profile.Profile.MaxCodeBytes+16*1024+1))
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
	parsed, err := oauth.ParseSharedOAuth2QueryCallback(ctx, string(raw), s.config.Transaction.Callback.String(), s.config.Profile.Profile)
	if err != nil {
		return oauth.QueryCallback{}, err
	}
	if err := s.checkState(ctx, parsed); err != nil {
		parsed.Destroy()
		return oauth.QueryCallback{}, err
	}
	return parsed, nil
}

func (s *Service) checkState(ctx context.Context, parsed oauth.QueryCallback) error {
	check := func(_ context.Context, state []byte) error {
		if subtle.ConstantTimeCompare(state, []byte(s.config.Authorization.State)) != 1 {
			return sso.ErrForbidden
		}
		return nil
	}
	if parsed.Denied() {
		return parsed.UseDeniedState(ctx, check)
	}
	input, ok := parsed.Input()
	if !ok {
		return sso.ErrInvalidInput
	}
	return input.Use(ctx, func(ctx context.Context, _ []byte, state []byte) error { return check(ctx, state) })
}

func (s *Service) exchange(ctx context.Context, parsed oauth.QueryCallback) (result oauth.ExchangeResult, err error) {
	called, repeated, exchanged := false, false, false
	borrowReturned, exchangeStarted := false, false
	defer func() {
		if borrowReturned {
			return
		}
		// A borrower can still unwind after use returns. Keep custody here
		// until the caller can install its own destruction guard.
		result.Tokens.Destroy()
		result = oauth.ExchangeResult{}
		if recover() != nil {
			err = sso.ErrUnavailable
			if exchangeStarted {
				err = ErrExchangeUnsettled
			}
		}
	}()
	var exchangeErr error
	borrowErr := s.config.Callback.UseSecrets(ctx, func(secret, verifier []byte) (err error) {
		if called {
			repeated = true
			return sso.ErrConflict
		}
		called = true
		defer func() { exchangeErr = err }()
		if ctx.Err() != nil || !s.admittedAt(s.config.Clock.Now()) {
			return sso.ErrForbidden
		}
		proof, err := oauth.NewPKCEVerifier(verifier)
		if err != nil {
			return err
		}
		defer proof.Destroy()
		provider, err := s.provider(secret)
		if err != nil {
			return err
		}
		defer provider.Close()
		if ctx.Err() != nil || !s.admittedAt(s.config.Clock.Now()) {
			return sso.ErrForbidden
		}
		exchangeStarted = true
		result, err = provider.Exchange(ctx, parsed, proof, s.config.Authorization)
		exchanged = err == nil
		return err
	})
	borrowReturned = true
	if exchangeErr != nil {
		return result, exchangeErr
	}
	if exchanged && (borrowErr != nil || repeated) {
		return result, ErrExchangeUnsettled
	}
	if !exchanged {
		return result, sso.ErrUnavailable
	}
	return result, nil
}

func (s *Service) provider(secret []byte) (*oauth.SharedOAuth2UserInfoProvider, error) {
	base, details := s.config.Profile.Profile, s.config.Profile.Details
	provider, err := oauth.NewSharedOAuth2UserInfoProvider(oauth.OAuth2UserInfoConfig{
		ID: base.ID, Version: base.Version, Issuer: base.Issuer, AuthorizationEndpoint: base.AuthorizationEndpoint,
		TokenEndpoint: base.TokenEndpoint, UserInfoEndpoint: details.UserInfoEndpoint, RedirectURI: base.RedirectURI,
		ClientID: base.ClientID, ClientSecret: secret, ClientAuthentication: base.ClientAuthentication, Scopes: base.Scopes,
		SubjectClaim: details.SubjectClaim, SubjectEncoding: details.SubjectEncoding, ProofLifetime: details.ProofLifetime,
		Clock: s.config.Clock, HTTPClient: s.config.HTTPClient, Timeout: base.Timeout, MaxResponseBytes: base.MaxResponseBytes,
		MaxTokenBytes: base.MaxTokenBytes, MaxCodeBytes: base.MaxCodeBytes,
	}, s.claims)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(provider.Profile(), base) {
		provider.Close()
		return nil, sso.ErrForbidden
	}
	return provider, nil
}

func (s *Service) handoff(ctx context.Context, assertion sso.ProtocolAssertion, expires time.Time, tokens oauth.TokenSet) (sso.ProtocolAssertion, error) {
	evidence := CallbackEvidence{Transaction: s.config.Transaction, Assertion: assertion, ExpiresAt: expires}
	evidence.Assertion.Attributes = slices.Clone(assertion.Attributes)
	reference, err := acceptTokens(ctx, s.config.Callback.AcceptTokens, evidence, tokens)
	now := s.config.Clock.Now()
	if err != nil || ctx.Err() != nil || !s.admittedAt(now) || !now.Before(expires) {
		return sso.ProtocolAssertion{}, ErrExchangeUnsettled
	}
	if reference != (sso.TokenVersion{}) {
		spec, err := reference.Spec()
		if err != nil || spec.TenantID != s.config.Transaction.TenantID || spec.CommandID != s.config.Transaction.CommandID || spec.CredentialGeneration != s.config.CredentialGeneration {
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

func earlier(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (Config) Format(w fmt.State, _ rune)   { _, _ = io.WriteString(w, "sso/oauth2.Config(redacted)") }
func (Config) LogValue() slog.Value         { return slog.StringValue("sso/oauth2.Config(redacted)") }
func (Config) MarshalJSON() ([]byte, error) { return nil, sso.ErrSensitiveSerialization }
func (Config) MarshalText() ([]byte, error) { return nil, sso.ErrSensitiveSerialization }

func (Service) Format(w fmt.State, _ rune)   { _, _ = io.WriteString(w, "sso/oauth2.Service(redacted)") }
func (Service) LogValue() slog.Value         { return slog.StringValue("sso/oauth2.Service(redacted)") }
func (Service) MarshalJSON() ([]byte, error) { return nil, sso.ErrSensitiveSerialization }
func (Service) MarshalText() ([]byte, error) { return nil, sso.ErrSensitiveSerialization }
