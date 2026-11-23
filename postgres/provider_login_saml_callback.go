package postgres

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	"github.com/faustbrian/go-sso"
)

// SAMLSigninCallbackRequest is the bounded input for the original SP-initiated
// POST. The ACS URL comes from the trusted local route, not Host, the form or
// the response XML. This profile requires the original opaque RelayState.
type SAMLSigninCallbackRequest struct {
	ProviderID                   sso.ProviderID
	ReceivedAssertionConsumerURL string
	RelayState, SAMLResponse     string
	Browser                      ProviderLoginBrowser
}

// SAMLResponseVerificationInput selects the registered trust and original
// AuthnRequest. The verifier borrows certificate bytes during the call and
// must not retain them, log the response or perform network I/O.
type SAMLResponseVerificationInput struct {
	SPEntityID, IdentityProviderEntityID, AssertionConsumerURL string
	SigningCertificates                                        [][]byte
	SAMLResponse, RequestID                                    string
	IssuedAt, ExpiresAt, Now                                   time.Time
}

// SAMLVerifiedResponse is the selected wire adapter's verified evidence, not
// a durable replay reservation or session authority. AssertionExpiresAt is the
// original raw assertion cutoff; ValidUntil is its earliest usable cutoff.
type SAMLVerifiedResponse struct {
	ResponseID, AssertionID, ProviderSubject, SubjectFormat, SessionIndex string
	AssertionExpiresAt, ValidUntil                                        time.Time
}

// SAMLResponseVerifier is a trusted configuration dependency, not a callback
// argument. Use the SAML wire adapter with only the supplied installed metadata
// and original request. Zero or partial evidence must be denied.
type SAMLResponseVerifier func(context.Context, SAMLResponseVerificationInput) (SAMLVerifiedResponse, error)

// ProviderSAMLLoginCompletionConfig selects the exact linked-member SAML
// session profile. The existing native owner supplies the authoritative clock.
type ProviderSAMLLoginCompletionConfig struct {
	Audience, PolicyNamespace string
	Issuer                    session.IssuerConfig
	CSRFKey                   session.CSRFKey
	Verify                    SAMLResponseVerifier
}

// ProviderSAMLLoginCompletionService owns SP-initiated linked-member SAML ACS
// over the selected start. It has no network, pool, migration or route lifecycle.
type ProviderSAMLLoginCompletionService struct {
	start               *ProviderLoginService
	policy              sessionpg.IdentifierAdmissionConfig
	issuer              session.IssuerConfig
	csrfKey             session.CSRFKey
	verify              SAMLResponseVerifier
	verifyLogoutSubject SAMLResponseWithLogoutSubjectVerifier
	effect              *sessionpg.SSOSAMLSigninEffect
}

func (SAMLSigninCallbackRequest) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprint(f, "sso.postgres.SAMLSigninCallbackRequest(redacted)")
}
func (SAMLSigninCallbackRequest) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}
func (SAMLSigninCallbackRequest) MarshalText() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}
func (SAMLSigninCallbackRequest) LogValue() slog.Value {
	return slog.StringValue("sso.postgres.SAMLSigninCallbackRequest(redacted)")
}

func (SAMLResponseVerificationInput) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprint(f, "sso.postgres.SAMLResponseVerificationInput(redacted)")
}
func (SAMLResponseVerificationInput) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}
func (SAMLResponseVerificationInput) MarshalText() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}
func (SAMLResponseVerificationInput) LogValue() slog.Value {
	return slog.StringValue("sso.postgres.SAMLResponseVerificationInput(redacted)")
}

func (SAMLVerifiedResponse) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprint(f, "sso.postgres.SAMLVerifiedResponse(redacted)")
}
func (SAMLVerifiedResponse) MarshalJSON() ([]byte, error) { return nil, sso.ErrSensitiveSerialization }
func (SAMLVerifiedResponse) MarshalText() ([]byte, error) { return nil, sso.ErrSensitiveSerialization }
func (SAMLVerifiedResponse) LogValue() slog.Value {
	return slog.StringValue("sso.postgres.SAMLVerifiedResponse(redacted)")
}

// NewProviderSAMLLoginCompletionService requires a selected native SAML start,
// matching primary session storage and a trusted SAML POST verifier. Install
// the replay, preparation erasure and SAML session issuance histories first.
func NewProviderSAMLLoginCompletionService(start *ProviderLoginService, c ProviderSAMLLoginCompletionConfig) (*ProviderSAMLLoginCompletionService, error) {
	return newProviderSAMLLoginCompletionService(start, c, nil)
}

func newProviderSAMLLoginCompletionService(start *ProviderLoginService, c ProviderSAMLLoginCompletionConfig, verify SAMLResponseWithLogoutSubjectVerifier) (*ProviderSAMLLoginCompletionService, error) {
	if start == nil || start.saml == nil || start.router == nil || start.router.organizations == nil ||
		(c.Verify == nil && verify == nil) || (c.Verify != nil && verify != nil) || c.Issuer.MaximumDuration > start.config.Coordinator.MaximumDuration {
		return nil, sso.ErrInvalidInput
	}
	policy := sessionpg.IdentifierAdmissionConfig{GlobalAuthorityID: start.config.GlobalAuthorityID,
		PolicyNamespace: c.PolicyNamespace, Audience: c.Audience, AuthenticationMethod: "sso-saml",
		CredentialKind: identity.CredentialProvider, CredentialOwner: "sso"}
	effect, err := sessionpg.NewSSOSAMLSigninEffect(start.config.Session, policy, start.router.organizations)
	if err != nil {
		return nil, sso.ErrInvalidInput
	}
	c.Issuer.Clock = start.router.config.Clock
	if _, err := session.NewSSOSAMLSessionIssuerWithCSRF(&providerLoginCallbackPhase{}, c.Issuer, c.CSRFKey); err != nil {
		return nil, sso.ErrInvalidInput
	}
	return &ProviderSAMLLoginCompletionService{start: start, policy: policy, issuer: c.Issuer, csrfKey: c.CSRFKey, verify: c.Verify, verifyLogoutSubject: verify, effect: effect}, nil
}

// NewProviderSAMLLoginCompletionServiceWithLogoutSubject explicitly selects
// original signed subject custody for logout. c.Verify must be nil: one
// verifier supplies both results, never two cryptographic parses. Existing
// isolated installations may keep the original constructor unchanged.
func NewProviderSAMLLoginCompletionServiceWithLogoutSubject(start *ProviderLoginService, c ProviderSAMLLoginCompletionConfig, verify SAMLResponseWithLogoutSubjectVerifier) (*ProviderSAMLLoginCompletionService, error) {
	if c.Verify != nil || verify == nil {
		return nil, sso.ErrInvalidInput
	}
	return newProviderSAMLLoginCompletionService(start, c, verify)
}

// SigninCallback verifies the exact original prompt and browser, then commits
// the replay pair, original one-use capability and session in one native Work.
// Only the acknowledged fresh invocation discloses a normal session and CSRF.
// Invalid, terminal and ambiguous outcomes never return either credential.
func (s *ProviderSAMLLoginCompletionService) SigninCallback(ctx context.Context, request SAMLSigninCallbackRequest) (out ProviderLoginCallbackResult, err error) {
	if ctx == nil || s == nil || s.start == nil || s.effect == nil || request.ReceivedAssertionConsumerURL == "" ||
		len(request.RelayState) == 0 || len(request.RelayState) > 80 || len(request.SAMLResponse) == 0 || len(request.SAMLResponse) > base64.StdEncoding.EncodedLen(1<<20) {
		return out, sso.ErrInvalidInput
	}
	ctx, cancel := context.WithTimeout(ctx, s.start.config.Coordinator.MaximumDuration)
	defer cancel()
	var entered identity.CommandID
	defer func() {
		if recover() != nil {
			out = ProviderLoginCallbackResult{}
			if entered == "" {
				err = sso.ErrUnavailable
			} else {
				err = identity.UnknownCommitError{CommandID: entered}
			}
		}
	}()
	found, err := s.start.lookupProviderSAMLLoginCallback(ctx, request.RelayState)
	if err != nil {
		return out, err
	}
	defer clear(found.Binding.Proof)
	if found.CompletedAt != nil || found.Row.ProviderID != string(request.ProviderID) {
		return out, sso.ErrForbidden
	}
	var logoutSubject *samlStoredLogoutSubject
	verify := s.verify
	if s.verifyLogoutSubject != nil {
		verify = func(ctx context.Context, input SAMLResponseVerificationInput) (SAMLVerifiedResponse, error) {
			verified, err := s.verifyLoginResponse(ctx, input)
			if err != nil {
				return SAMLVerifiedResponse{}, err
			}
			subject := samlStoredLogoutSubject(verified.LogoutSubject)
			logoutSubject = &subject
			return verified.Evidence, nil
		}
	}
	admitted, err := s.start.admitSAMLCallback(ctx, found, request, verify, s.policy)
	if err != nil {
		return out, err
	}
	command, err := s.start.samlCallbackCommand(found, request)
	if err != nil {
		return out, providerError(ctx, err)
	}
	phase := &providerLoginCallbackPhase{
		providerLoginCallbackInvocation: providerLoginCallbackInvocation{service: s.start, found: found, original: admitted.original,
			authority: admitted.authority, flow: admitted.flow, browser: request.Browser, command: command},
		grant: admitted.grant, policy: s.policy, saml: &samlLoginCallbackPhase{effect: s.effect, admitted: admitted, logoutSubject: logoutSubject},
	}
	defer func() {
		if phase.execution != nil {
			clear(phase.execution.terminal)
		}
	}()
	phase.issuer, err = session.NewSSOSAMLSessionIssuerWithCSRF(phase, s.issuer, s.csrfKey)
	if err != nil {
		return out, sso.ErrUnavailable
	}
	coordinator, err := providerLoginCallbackCoordinator(s.start, phase)
	if err != nil {
		return out, sso.ErrUnavailable
	}
	plan, err := phase.plan()
	if err != nil {
		return out, providerError(ctx, err)
	}
	plan, err = coordinator.PrepareFeaturePreparationPlan(command, plan)
	if err != nil {
		return out, providerError(ctx, err)
	}
	entered = found.Binding.Metadata.CallbackCommand
	result, err := coordinator.ExecutePreparedFeature(ctx, command, plan)
	out.Completion = result
	if err != nil {
		var unknown identity.UnknownCommitError
		if errors.As(err, &unknown) {
			return out, unknown
		}
		return out, providerError(ctx, err)
	}
	if result.Validate() != nil || result.Binding.CommandID != entered || result.Outcome != identity.CommitOutcomeCommitted {
		return out, sso.ErrUnavailable
	}
	if phase.execution == nil || phase.prepared == (session.PreparedIssuance{}) {
		return out, nil // Recovery exposes the exact committed receipt without session custody.
	}
	bound, err := phase.issuer.BindSSOSAML(phase.prepared, phase.execution.command)
	if err != nil {
		return out, providerError(ctx, err)
	}
	phase.acknowledged, phase.canDisclose = result, true
	issued, err := phase.issuer.Issue(ctx, bound)
	if err != nil {
		return out, providerError(ctx, err)
	}
	csrf, err := bound.CSRFToken()
	if err != nil || issued.Replayed || issued.Token == (session.Token{}) {
		return out, sso.ErrUnavailable
	}
	out.Issuance, out.CSRF, out.RedirectURI = issued, csrf, admitted.original.SuccessCallback
	return out, nil
}

// Retain only a keyed digest of the exact submitted response and original
// request/browser. A different signed response cannot replace a reserved one.
func (s *ProviderLoginService) samlCallbackCommand(found providerLoginCallbackLookup, r SAMLSigninCallbackRequest) (identity.Command, error) {
	m := found.Binding.Metadata
	key, ok := s.payload.StateKeys[m.StateKey]
	if !ok || key == ([32]byte{}) || m.CallbackCommand == found.Row.StartCommandID ||
		subtle.ConstantTimeCompare([]byte(r.RelayState), []byte(m.Public.State)) != 1 {
		return identity.Command{}, sso.ErrForbidden
	}
	frame, err := providerLoginPayloadEncode(m)
	if err != nil {
		return identity.Command{}, sso.ErrUnavailable
	}
	defer clear(frame)
	response := sha256.Sum256([]byte(r.SAMLResponse))
	intent := providerLoginPayloadMAC(key, m.StateKey, "identity.sso.saml.callback-input.v1", frame,
		[]byte(r.ReceivedAssertionConsumerURL), []byte(r.Browser.Origin), []byte(r.Browser.Network.String()), []byte(r.Browser.Device), response[:])
	return newProviderLoginCallbackCommand(found, r.Browser, []identity.FeatureField{{
		Name: "sso.saml.callback-input", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: intent[:]},
	}})
}
