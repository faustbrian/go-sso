package postgres

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/risk"
	organization "github.com/faustbrian/go-organization"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
)

// OAuth2ProtocolAdapterFactory constructs a trusted adapter for one locally
// reserved callback. The adapter must invoke its collaborators synchronously
// during Complete and must not reuse them after Complete returns. Factory
// configuration is selected by the application, never by a callback request.
type OAuth2ProtocolAdapterFactory func(OAuth2ProtocolAdapterConfig) (sso.ProtocolAdapter, error)

// OAuth2ProtocolEvidence is the adapter's identity evidence and original
// expiry. The adapter does not authorize a linked account or session.
type OAuth2ProtocolEvidence struct {
	Transaction sso.LoginTransaction
	Assertion   sso.ProtocolAssertion
	ExpiresAt   time.Time
}

// OAuth2ProtocolAdapterConfig binds the adapter to authenticated native
// custody. Authorization contains retained browser state; do not disclose it
// outside protocol wire processing. UseSecrets may borrow each secret once.
// AcceptTokens only prepares encrypted output. It returns no durable reference
// before the native coordinator's final commit.
type OAuth2ProtocolAdapterConfig struct {
	Transaction            sso.LoginTransaction
	CredentialGeneration   uint64
	Profile                oauth.OAuth2UserInfoProfile
	IdentityProof          sso.IdentityProofPolicy
	Mapping                sso.AttributeMapping
	Authorization          oauth.AuthorizationParameters
	CapabilityExpiresAt    time.Time
	Clock                  oauth.Clock
	HTTPClient             *http.Client
	ObservedAt, ValidUntil time.Time
	UseSecrets             func(context.Context, func(clientSecret, verifier []byte) error) error
	AcceptTokens           func(context.Context, OAuth2ProtocolEvidence, oauth.TokenSet) (sso.TokenVersion, error)
}

func (OAuth2ProtocolAdapterConfig) Format(w fmt.State, _ rune) {
	_, _ = io.WriteString(w, "postgres.OAuth2ProtocolAdapterConfig(redacted)")
}

func (OAuth2ProtocolAdapterConfig) LogValue() slog.Value {
	return slog.StringValue("postgres.OAuth2ProtocolAdapterConfig(redacted)")
}

func (OAuth2ProtocolAdapterConfig) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}
func (OAuth2ProtocolAdapterConfig) MarshalText() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}

func validateOAuth2ProtocolEvidence(tx sso.LoginTransaction, issuer string, now, cutoff time.Time, evidence OAuth2ProtocolEvidence) error {
	if _, err := tx.ValidateAt(now); err != nil || tx.Protocol != providerProtocolOAuth2 || evidence.Transaction != tx || !now.Before(evidence.ExpiresAt) || evidence.ExpiresAt.After(cutoff) {
		return sso.ErrForbidden
	}
	a := evidence.Assertion
	if a.Validate() != nil || a.ProviderID != sso.ProviderID(tx.ProviderID) || a.OrganizationID != tx.OrganizationID ||
		a.ProviderProfileVersion != tx.ProviderVersion || a.MappingVersion != tx.MappingVersion || a.TokenReference != (sso.TokenVersion{}) {
		return sso.ErrForbidden
	}
	for _, attr := range a.Attributes {
		spec, err := attr.Spec()
		if err != nil || spec.Provenance.Issuer != issuer || spec.Provenance.Source != sso.AttributeSourceOAuthIdentityEndpoint {
			return sso.ErrForbidden
		}
	}
	return nil
}

func (p *providerLoginCallbackPhase) generateOAuth2AdapterAccepted(ctx context.Context, generation uint64, admission risk.AuthenticationAdmission, aad envelope.Context) ([]byte, error) {
	if p.oauth2 == nil || p.oauthAdapter == nil || p.oauthRawQuery == "" || p.authenticatedAt.IsZero() || p.member != nil || p.roleMapping != nil || p.jitPolicy != nil {
		return nil, identity.ForbiddenError{}
	}
	s := p.service
	clock := s.router.config.Clock
	now := clock.Now().UTC()
	if err := p.checkOriginal(now); err != nil {
		return nil, err
	}
	if err := admission.CheckAt(ctx, now); err != nil {
		return nil, err
	}
	binding := p.found.Binding.Metadata
	input := binding.Input
	key := providerLoginProfileKey{organization: organization.ID(input.OrganizationID), provider: sso.ProviderID(input.ProviderID)}
	selected, ok := s.oauthProfiles[key]
	if !ok || input.Protocol != providerProtocolOAuth2 || binding.Public.Nonce != "" {
		return nil, sso.ErrForbidden
	}
	material, err := s.readProviderOAuth2CallbackMaterial(ctx, p.found, p.original, p.authority)
	if err != nil {
		return nil, err
	}
	defer clear(material.credential)
	defer clear(material.credentialContext)
	defer clear(material.verifier)
	if err := validateProviderOAuth2ExchangeProfile(p.original, selected, *p.oauth2, material.configuration); err != nil {
		return nil, err
	}
	tx, err := binding.protocolTransaction(p.original)
	if err != nil {
		return nil, err
	}
	proof, err := sso.NewIdentityProofPolicy(material.configuration.Proof)
	if err != nil {
		return nil, sso.ErrForbidden
	}
	mapping, err := sso.NewAttributeMapping(material.configuration.Mapping)
	if err != nil {
		return nil, sso.ErrForbidden
	}
	profile := p.oauth2.Profile
	profile.Profile.Scopes = slices.Clone(profile.Profile.Scopes)
	config := OAuth2ProtocolAdapterConfig{
		Transaction: tx, CredentialGeneration: selected.CredentialGeneration, Profile: profile, IdentityProof: proof, Mapping: mapping,
		Authorization:       oauth.AuthorizationParameters{State: binding.Public.State, PKCEChallenge: binding.Public.Challenge},
		CapabilityExpiresAt: input.ExpiresAt, Clock: clock, HTTPClient: p.oauth2.HTTPClient, ObservedAt: p.found.ObservedAt, ValidUntil: p.authority.deadline,
	}
	return p.completeOAuth2WithAdapter(ctx, config, material, generation, admission, aad)
}

func (p *providerLoginCallbackPhase) completeOAuth2WithAdapter(ctx context.Context, config OAuth2ProtocolAdapterConfig, material providerOAuth2CallbackMaterial, generation uint64, admission risk.AuthenticationAdmission, aad envelope.Context) ([]byte, error) {
	s := p.service
	binding := p.found.Binding.Metadata
	input := binding.Input
	var output []byte
	keepOutput := false
	defer func() {
		if !keepOutput {
			clear(output)
		}
	}()
	var expected sso.ProtocolAssertion
	var recipientErr error
	active, borrowed, borrowComplete, staged := false, false, false, false
	defer func() { active = false }()
	check := func(ctx context.Context, now time.Time) error {
		if err := p.checkOriginal(now); err != nil {
			return err
		}
		return admission.CheckAt(ctx, now)
	}
	config.UseSecrets = func(call context.Context, use func([]byte, []byte) error) error {
		if !active || borrowed || call == nil || use == nil {
			return sso.ErrForbidden
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		borrowed = true
		now := config.Clock.Now().UTC()
		if err := check(call, now); err != nil {
			return err
		}
		err := s.payload.withOAuth2CallbackVerifier(call, binding, now, material.verifier, func(call context.Context, verifier []byte) error {
			return withAuthenticatedProtocolProviderCredential(call, s.payload.Envelope, providerProtocolOAuth2, string(input.Command.TenantID), input.OrganizationID, input.ProviderID,
				material.credential, material.credentialContext, input.CredentialGeneration, material.credentialVersion, func(call context.Context, secret []byte) error {
					if err := check(call, config.Clock.Now().UTC()); err != nil {
						return err
					}
					return use(secret, verifier)
				})
		})
		borrowComplete = err == nil
		return err
	}
	config.AcceptTokens = func(call context.Context, evidence OAuth2ProtocolEvidence, tokens oauth.TokenSet) (sso.TokenVersion, error) {
		if !active || !borrowComplete || staged || call == nil {
			return sso.TokenVersion{}, sso.ErrForbidden
		}
		if err := ctx.Err(); err != nil {
			return sso.TokenVersion{}, err
		}
		staged = true
		if err := validateOAuth2ProtocolEvidence(config.Transaction, input.Issuer, config.Clock.Now().UTC(), config.ValidUntil, evidence); err != nil {
			return sso.TokenVersion{}, err
		}
		recipient, err := s.readLinkedProviderRecipient(call, p.original, evidence.Assertion.ProviderSubject, evidence.ExpiresAt, p.policy.PolicyNamespace)
		if err != nil {
			// This OAuth2 profile can sign in only an existing link. As in the
			// native path with JIT disabled, no usable link is a settled denial.
			if errors.Is(err, errProviderLoginRecipientLinkUnavailable) {
				err = errProviderLoginRecipientIneligible
			}
			recipientErr = err
			return sso.TokenVersion{}, err
		}
		output, err = p.sealAcceptedOutput(call, generation, admission, aad, recipient, nil, evidence.ExpiresAt, oauth.ExchangeResult{Tokens: tokens})
		if err != nil {
			return sso.TokenVersion{}, err
		}
		expected, err = sso.NewProtocolAssertion(evidence.Assertion)
		return sso.TokenVersion{}, err
	}
	adapter, err := p.oauthAdapter(config)
	if err != nil || adapter == nil {
		return nil, sso.ErrUnavailable
	}
	active = true
	assertion, err := adapter.Complete(ctx, sso.ProtocolCallback{
		Transaction: config.Transaction, Payload: io.NopCloser(strings.NewReader(p.oauthRawQuery)),
		MaximumBytes: uint64(3*config.Profile.Profile.MaxCodeBytes + (16 << 10) + 1),
	})
	active = false
	if err != nil {
		if terminalProviderExchangeRefusal(ctx, err, true) || terminalProviderRecipientRefusal(ctx, recipientErr, true) {
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
