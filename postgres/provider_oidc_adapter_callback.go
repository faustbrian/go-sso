package postgres

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"reflect"
	"slices"
	"time"

	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/risk"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
)

// OIDCParsedCallbackAdapter borrows the transport's already parsed query for
// one synchronous completion. It neither owns Destroy nor reserves the code.
type OIDCParsedCallbackAdapter interface {
	CompleteParsed(context.Context, sso.LoginTransaction, oauth.QueryCallback) (sso.ProtocolAssertion, error)
}

// OIDCCallbackAdapterFactory builds the configured adapter inside the
// acknowledged native generation. Hooks are usable only during CompleteParsed.
type OIDCCallbackAdapterFactory func(OIDCCallbackAdapterConfig) (OIDCParsedCallbackAdapter, error)

// OIDCCallbackEvidence is the original signed identity and mapped assertion
// for this callback. The coordinator still owns account and session policy.
type OIDCCallbackEvidence struct {
	Transaction sso.LoginTransaction
	Assertion   sso.ProtocolAssertion
	Identity    oauth.ProviderIdentity
	ExpiresAt   time.Time
}

// OIDCCallbackAdapterConfig supplies original custody and the selected static
// transport. Hooks must be called synchronously and not retained. The first
// borrows the installed secret and retained verifier once. The second borrows
// verified tokens only to prepare encrypted output for the native commit.
type OIDCCallbackAdapterConfig struct {
	Transaction            sso.LoginTransaction
	CredentialGeneration   uint64
	Profile                oauth.ProviderProfile
	Mapping                sso.AttributeMapping
	AdditionalClaims       []string
	Authorization          oauth.AuthorizationParameters
	CapabilityExpiresAt    time.Time
	Clock                  oauth.Clock
	HTTPClient             *http.Client
	KeySet                 oauth.SigningKeySet
	ObservedAt, ValidUntil time.Time
	UseSecrets             func(context.Context, func(clientSecret, verifier []byte) error) error
	AcceptTokens           func(context.Context, OIDCCallbackEvidence, oauth.TokenSet) (sso.TokenVersion, error)
}

func (OIDCCallbackAdapterConfig) Format(w fmt.State, _ rune) {
	_, _ = io.WriteString(w, "postgres.OIDCCallbackAdapterConfig(redacted)")
}
func (OIDCCallbackAdapterConfig) LogValue() slog.Value {
	return slog.StringValue("postgres.OIDCCallbackAdapterConfig(redacted)")
}
func (OIDCCallbackAdapterConfig) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}
func (OIDCCallbackAdapterConfig) MarshalText() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}

// WithOIDCCallbackAdapter selects parsed completion on a copy of the native
// owner, preserving session, link, JIT and role policy. The original owner is
// unchanged. Use SigninParsedCallback and LinkParsedCallback on the copy;
// selected callback failures never fall back to the native wire client.
func (s *ProviderLoginCompletionService) WithOIDCCallbackAdapter(factory OIDCCallbackAdapterFactory) (*ProviderLoginCompletionService, error) {
	if s == nil || s.start == nil || s.oidcCallbackFactory != nil || factory == nil || len(s.protocolProfiles) == 0 {
		return nil, sso.ErrInvalidInput
	}
	selected := *s
	selected.oidcCallbackFactory = factory
	return &selected, nil
}

// SigninParsedCallback admits the exact transport-owned query after selecting
// its original native transaction. The caller keeps and destroys custody.
func (s *ProviderLoginCompletionService) SigninParsedCallback(ctx context.Context, browser ProviderLoginBrowser, receivedRedirectURI string, parsed oauth.QueryCallback) (ProviderLoginCallbackResult, error) {
	input, ok := parsed.Input()
	if s == nil || s.oidcCallbackFactory == nil || !ok {
		return ProviderLoginCallbackResult{}, sso.ErrInvalidInput
	}
	return s.signinCallback(ctx, ProviderLoginCallbackRequest{Input: input, Browser: browser, ReceivedRedirectURI: receivedRedirectURI}, &parsed)
}

// LinkParsedCallback is the equivalent explicit account-link completion. It
// obtains code/state only from parsed and ignores request.Input. It never
// issues a session or transfers ownership of parsed.
func (s *ProviderLoginCompletionService) LinkParsedCallback(ctx context.Context, request ProviderLinkCallbackRequest, parsed oauth.QueryCallback) (ProviderLinkCallbackResult, error) {
	input, ok := parsed.Input()
	if s == nil || s.oidcCallbackFactory == nil || !ok {
		return ProviderLinkCallbackResult{}, sso.ErrInvalidInput
	}
	request.Input = input
	return s.linkCallback(ctx, request, &parsed)
}

type oidcCallbackSelection struct {
	factory OIDCCallbackAdapterFactory
	profile oauth.ProviderProfile
	parsed  oauth.QueryCallback
}

func (s *ProviderLoginCompletionService) selectOIDCCallback(key providerLoginProfileKey, parsed *oauth.QueryCallback, receivedRedirect string) (*oidcCallbackSelection, error) {
	if parsed == nil && s.oidcCallbackFactory == nil {
		return nil, nil
	}
	profile, ok := s.protocolProfiles[key]
	if parsed == nil || s.oidcCallbackFactory == nil || !ok || profile.RedirectURI != receivedRedirect || !reflect.DeepEqual(profile, parsed.Profile()) {
		return nil, sso.ErrForbidden
	}
	return &oidcCallbackSelection{factory: s.oidcCallbackFactory, profile: profile, parsed: *parsed}, nil
}

type oidcCallbackPrepare func(context.Context, uint64, risk.AuthenticationAdmission, envelope.Context, providerLoginCallbackExchange) ([]byte, error)

func (p *providerLoginCallbackPhase) generateOIDCAdapterAccepted(ctx context.Context, generation uint64, admission risk.AuthenticationAdmission, aad envelope.Context, prepare oidcCallbackPrepare) ([]byte, error) {
	if p.oidc == nil || p.authenticatedAt.IsZero() || generation == 0 {
		return nil, sso.ErrForbidden
	}
	s, selection := p.service, p.oidc
	clock := s.router.config.Clock
	check := func(ctx context.Context, now time.Time) error {
		if err := p.checkOriginal(now); err != nil {
			return err
		}
		return admission.CheckAt(ctx, now)
	}
	if err := check(ctx, clock.Now().UTC()); err != nil {
		return nil, err
	}
	binding := p.found.Binding.Metadata
	input := binding.Input
	key := providerLoginProfileKey{organization: p.original.Proof.OrganizationID, provider: p.original.ProviderID}
	profile, ok := s.profiles[key]
	if !ok || input.Protocol != "" {
		return nil, sso.ErrForbidden
	}
	material, err := s.readProviderLoginCallbackMaterial(ctx, p.found, p.original, p.authority)
	if err != nil {
		return nil, err
	}
	defer clear(material.credential)
	defer clear(material.credentialContext)
	defer clear(material.verifier)
	wire := providerLoginOIDCExchangeInput{original: binding, observedAt: p.found.ObservedAt, deadline: p.authority.deadline,
		profile: profile, metadata: material.metadata, pinnedMetadata: p.transport.metadata,
		clientAuthentication: p.transport.authentication, credentialVersion: material.credentialVersion}
	if !wire.authorizesExchangeAt(clock.Now().UTC()) || p.member != nil && !material.enabled {
		return nil, sso.ErrForbidden
	}
	transaction, err := binding.protocolTransaction(p.original)
	if err != nil {
		return nil, err
	}
	mapping, err := sso.NewAttributeMapping(material.mapping)
	if err != nil {
		return nil, sso.ErrForbidden
	}
	protocol := selection.profile
	protocol.Scopes, protocol.Algorithms = slices.Clone(protocol.Scopes), slices.Clone(protocol.Algorithms)
	cfg := OIDCCallbackAdapterConfig{
		Transaction: transaction, CredentialGeneration: input.CredentialGeneration, Profile: protocol, Mapping: mapping,
		AdditionalClaims: slices.Clone(p.transport.claims), Clock: clock, HTTPClient: p.transport.client, KeySet: p.transport.keys,
		Authorization:       oauth.AuthorizationParameters{State: binding.Public.State, Nonce: binding.Public.Nonce, PKCEChallenge: binding.Public.Challenge},
		CapabilityExpiresAt: transaction.ExpiresAt, ObservedAt: wire.observedAt, ValidUntil: wire.deadline,
	}
	var output []byte
	var expected sso.ProtocolAssertion
	active, borrowed, borrowComplete, staged, keepOutput := false, false, false, false, false
	defer func() {
		active = false
		if !keepOutput {
			clear(output)
		}
	}()
	cfg.UseSecrets = func(call context.Context, use func([]byte, []byte) error) error {
		if !active || borrowed || call == nil || use == nil {
			return sso.ErrForbidden
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		borrowed = true
		now := clock.Now().UTC()
		if err := check(call, now); err != nil {
			return err
		}
		err := s.payload.withCallbackVerifier(call, binding, now, material.verifier, func(call context.Context, verifier []byte) error {
			return withAuthenticatedStoredProviderCredential(call, s.payload.Envelope, string(input.Command.TenantID), input.OrganizationID, input.ProviderID,
				material.credential, material.credentialContext, input.CredentialGeneration, material.credentialVersion, func(call context.Context, secret []byte) error {
					if err := check(call, clock.Now().UTC()); err != nil {
						return err
					}
					return use(secret, verifier)
				})
		})
		borrowComplete = err == nil
		return err
	}
	cfg.AcceptTokens = func(call context.Context, evidence OIDCCallbackEvidence, tokens oauth.TokenSet) (sso.TokenVersion, error) {
		if !active || !borrowComplete || staged || call == nil {
			return sso.TokenVersion{}, sso.ErrForbidden
		}
		if err := ctx.Err(); err != nil {
			return sso.TokenVersion{}, err
		}
		staged = true
		if err := validateOIDCCallbackEvidence(transaction, selection.profile, clock.Now().UTC(), wire.deadline, evidence); err != nil {
			return sso.TokenVersion{}, err
		}
		var err error
		expected, err = sso.NewProtocolAssertion(evidence.Assertion)
		if err != nil {
			return sso.TokenVersion{}, err
		}
		output, err = prepare(call, generation, admission, aad, providerLoginCallbackExchange{
			ExchangeResult: oauth.ExchangeResult{Identity: evidence.Identity, Tokens: tokens}, mapping: material.mapping, providerEnabled: material.enabled,
		})
		if err != nil {
			clear(output)
			output = nil
		}
		return sso.TokenVersion{}, err
	}
	adapter, err := selection.factory(cfg)
	if err != nil || adapter == nil {
		return nil, sso.ErrUnavailable
	}
	active = true
	assertion, err := adapter.CompleteParsed(ctx, transaction, selection.parsed)
	active = false
	if err != nil {
		if terminalProviderExchangeRefusal(ctx, err, false) {
			return p.sealProviderLoginCallbackRefusal(ctx, generation)
		}
		return nil, err
	}
	if len(output) == 0 || !reflect.DeepEqual(assertion, expected) {
		return nil, sso.ErrUnavailable
	}
	keepOutput = true
	return output, nil
}

func validateOIDCCallbackEvidence(tx sso.LoginTransaction, profile oauth.ProviderProfile, now, cutoff time.Time, evidence OIDCCallbackEvidence) error {
	id, assertion := evidence.Identity, evidence.Assertion
	if evidence.Transaction != tx || tx.Protocol != providerProtocolOIDC || id.ProviderID() != profile.ID || id.Issuer() != profile.Issuer ||
		id.IDTokenIssuedAt().IsZero() || id.IDTokenExpiresAt().IsZero() || !now.Before(evidence.ExpiresAt) ||
		!evidence.ExpiresAt.Equal(earlierLoginTime(cutoff, id.IDTokenExpiresAt())) {
		return sso.ErrForbidden
	}
	if assertion.Validate() != nil || assertion.ProviderID != sso.ProviderID(tx.ProviderID) || assertion.OrganizationID != tx.OrganizationID ||
		assertion.ProviderSubject != id.Subject() || assertion.ProviderProfileVersion != tx.ProviderVersion ||
		assertion.MappingVersion != tx.MappingVersion || assertion.TokenReference != (sso.TokenVersion{}) {
		return sso.ErrForbidden
	}
	for _, attr := range assertion.Attributes {
		spec, err := attr.Spec()
		if err != nil || spec.Provenance.Issuer != profile.Issuer || spec.Provenance.Source != sso.AttributeSourceOIDCIDToken {
			return sso.ErrForbidden
		}
	}
	return nil
}
