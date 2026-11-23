package postgres

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	"github.com/faustbrian/go-sso"
)

// StaticSAMLIDPAdmissionProfile explicitly selects one current provider for
// IdP-initiated assertion verification. Provider supplies installed metadata
// pins only; an SP-initiated start service is neither selected nor consulted.
// MaximumAge must be between one second and five minutes, inclusive.
type StaticSAMLIDPAdmissionProfile struct {
	Provider   StaticSAMLLoginProfile
	MaximumAge time.Duration
}

// SAMLIDPAdmissionRequest names the tenant, exact provider and destination
// selected by the caller's trusted listener, never its untrusted form or Host.
// SAMLResponse is the encoded form value; neither RelayState nor prior
// browser state is a source of authority here.
type SAMLIDPAdmissionRequest struct {
	TenantID                     identity.TenantID
	ProviderID                   sso.ProviderID
	ReceivedAssertionConsumerURL string
	SAMLResponse                 string
}

// SAMLIDPResponseVerificationInput borrows the authenticated, installed IdP
// trust configuration and passes the native clock, derived destination and
// selected age bound. This input conveys no prior SP request or browser data.
// The verifier must not mutate or retain the certificate slices.
type SAMLIDPResponseVerificationInput struct {
	SPEntityID, IdentityProviderEntityID, ExternalOrigin, AssertionConsumerURL string
	ProviderID                                                                 sso.ProviderID
	SigningCertificates                                                        [][]byte
	SAMLResponse                                                               string
	Now                                                                        time.Time
	MaximumAge                                                                 time.Duration
}

// SAMLIDPResponseVerifier is a trusted, bounded, concurrent-safe configuration
// dependency. Compose it with the separate IdP-initiated SAML wire verifier;
// it must not perform I/O, log input or substitute trust from the response.
type SAMLIDPResponseVerifier func(context.Context, SAMLIDPResponseVerificationInput) (SAMLVerifiedResponse, error)

// ProviderSAMLIDPAdmissionConfig selects a tenant and an explicit finite
// installed-provider allowlist. Empty or duplicate profiles are invalid.
type ProviderSAMLIDPAdmissionConfig struct {
	TenantID identity.TenantID
	Profiles []StaticSAMLIDPAdmissionProfile
	Verify   SAMLIDPResponseVerifier
}

// ProviderSAMLIDPAdmissionService verifies unsolicited assertions against
// current installed authority without requiring an SP start. It performs only
// bounded primary reads and does not expose a route, reserve replay state,
// confirm visible user intent or grant a session. The zero value denies.
type ProviderSAMLIDPAdmissionService struct {
	router              *ProviderRouter
	tenant              identity.TenantID
	profiles            map[sso.ProviderID]staticSAMLIDPAdmissionSelection
	verify              SAMLIDPResponseVerifier
	verifyLogoutSubject SAMLIDPResponseWithLogoutSubjectVerifier
	linked              *samlIDPLinkedRecipientSelection
}

type staticSAMLIDPAdmissionSelection struct {
	profile     StaticSAMLIDPAdmissionProfile
	destination string
}

// NewProviderSAMLIDPAdmissionService snapshots the allowlist and borrows the
// already composed, protocol-aware primary router. It performs no I/O.
func NewProviderSAMLIDPAdmissionService(router *ProviderRouter, config ProviderSAMLIDPAdmissionConfig) (*ProviderSAMLIDPAdmissionService, error) {
	return newProviderSAMLIDPAdmissionService(router, config, nil)
}

func newProviderSAMLIDPAdmissionService(router *ProviderRouter, config ProviderSAMLIDPAdmissionConfig, verify SAMLIDPResponseWithLogoutSubjectVerifier) (*ProviderSAMLIDPAdmissionService, error) {
	if router == nil || router.pool == nil || router.organizations == nil || router.config.Clock == nil ||
		router.config.Envelope == nil || !router.protocolRegistry || router.samlRouteValidate == nil ||
		!providerID(string(config.TenantID)) || (config.Verify == nil && verify == nil) || (config.Verify != nil && verify != nil) || len(config.Profiles) == 0 || len(config.Profiles) > 128 {
		return nil, sso.ErrInvalidInput
	}
	profiles := make(map[sso.ProviderID]staticSAMLIDPAdmissionSelection, len(config.Profiles))
	for _, candidate := range config.Profiles {
		selected, destination, err := normalizeStaticSAMLIDPAdmissionProfile(candidate)
		if err != nil {
			return nil, err
		}
		if _, exists := profiles[selected.Provider.ProviderID]; exists {
			return nil, sso.ErrInvalidInput
		}
		profiles[selected.Provider.ProviderID] = staticSAMLIDPAdmissionSelection{profile: selected, destination: destination}
	}
	return &ProviderSAMLIDPAdmissionService{router: router, tenant: config.TenantID, profiles: profiles, verify: config.Verify, verifyLogoutSubject: verify}, nil
}

// NewProviderSAMLIDPAdmissionServiceWithLogoutSubject selects one trusted
// verifier returning both assertion evidence and its exact logout subject.
// config.Verify must be nil. The original constructor retains its behavior.
func NewProviderSAMLIDPAdmissionServiceWithLogoutSubject(router *ProviderRouter, config ProviderSAMLIDPAdmissionConfig, verify SAMLIDPResponseWithLogoutSubjectVerifier) (*ProviderSAMLIDPAdmissionService, error) {
	if config.Verify != nil || verify == nil {
		return nil, sso.ErrInvalidInput
	}
	return newProviderSAMLIDPAdmissionService(router, config, verify)
}

func normalizeStaticSAMLIDPAdmissionProfile(profile StaticSAMLIDPAdmissionProfile) (StaticSAMLIDPAdmissionProfile, string, error) {
	provider, err := normalizeStaticSAMLLoginProfile(profile.Provider)
	if err != nil || profile.MaximumAge < time.Second || profile.MaximumAge > 5*time.Minute {
		return StaticSAMLIDPAdmissionProfile{}, "", sso.ErrInvalidInput
	}
	acs, ok := samlProviderCallbackURL(provider.TrustedOrigin, string(provider.ProviderID))
	if !ok {
		return StaticSAMLIDPAdmissionProfile{}, "", sso.ErrInvalidInput
	}
	return StaticSAMLIDPAdmissionProfile{Provider: provider, MaximumAge: profile.MaximumAge}, strings.TrimSuffix(acs, "/acs") + "/idp-init", nil
}

// Verify checks the exact enabled profile, authenticates its registered IdP
// certificate set, verifies the response and then checks current native
// authority again. It creates no SP start, replay reservation or command.
func (s *ProviderSAMLIDPAdmissionService) Verify(ctx context.Context, request SAMLIDPAdmissionRequest) (out ProviderSAMLIDPAdmission, err error) {
	if ctx == nil || s == nil || s.router == nil || (s.verify == nil && s.verifyLogoutSubject == nil) ||
		len(request.SAMLResponse) == 0 || len(request.SAMLResponse) > base64.StdEncoding.EncodedLen(1<<20) {
		return out, sso.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	selected, ok := s.profiles[request.ProviderID]
	if !ok || request.TenantID != s.tenant || request.ReceivedAssertionConsumerURL != selected.destination {
		return out, sso.ErrForbidden
	}
	router := s.router
	ctx, cancel := context.WithTimeout(ctx, router.config.MaximumDuration)
	defer cancel()
	defer func() {
		if recover() != nil {
			out, err = ProviderSAMLIDPAdmission{}, providerError(ctx, sso.ErrUnavailable)
		}
	}()
	routeRequest, err := sso.NewDomainRouteRequest(s.tenant, selected.profile.Provider.Domain, request.ProviderID)
	if err != nil {
		return out, sso.ErrForbidden
	}
	route, err := router.RouteSAML(ctx, routeRequest)
	if err != nil {
		return out, err
	}
	installed, err := router.readProviderSAMLLoginProfile(ctx, route, selected.profile.Provider)
	if err != nil {
		return out, err
	}
	binding, err := route.Bindings()
	if err != nil {
		return out, sso.ErrUnavailable
	}
	verifiedAt := router.config.Clock.Now().UTC()
	if verifiedAt.Before(binding.ObservedAt) || !verifiedAt.Before(binding.ValidUntil) {
		return out, sso.ErrForbidden
	}
	verified, verifyErr := s.verifyLoginResponse(ctx, SAMLIDPResponseVerificationInput{
		SPEntityID: installed.spEntityID, IdentityProviderEntityID: installed.configuration.EntityID,
		ExternalOrigin: selected.profile.Provider.TrustedOrigin, AssertionConsumerURL: selected.destination,
		ProviderID: request.ProviderID, SigningCertificates: installed.configuration.SigningCertificates,
		SAMLResponse: request.SAMLResponse, Now: verifiedAt, MaximumAge: selected.profile.MaximumAge,
	})
	wire := verified.Evidence
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if verifyErr != nil || !validSAMLResponseEvidence(wire, verifiedAt) {
		return out, sso.ErrForbidden
	}
	// Cap wire usability once at the native verification instant. A later
	// provider read cannot extend the accepted wire evidence or original route.
	wire.ValidUntil = earlierLoginTime(wire.ValidUntil, verifiedAt.Add(selected.profile.MaximumAge))
	cutoff := earlierLoginTime(wire.ValidUntil, binding.ValidUntil)
	proof, err := router.organizations.GetDomainProof(ctx, binding.Proof.Key)
	if err != nil {
		return out, providerError(ctx, err)
	}
	if organization.DomainProofKey(proof) != binding.Proof.Key || proof.ProofVersion != binding.Proof.ProofVersion || proof.Revoked {
		return out, sso.ErrForbidden
	}
	if err := router.requireCurrentRoute(ctx, binding); err != nil {
		return out, err
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	now := router.config.Clock.Now().UTC()
	if now.Before(verifiedAt) || now.Before(proof.ObservedAt) || !now.Before(cutoff) || !now.Before(proof.ExpiresAt) {
		return out, sso.ErrForbidden
	}
	var logoutSubject *samlStoredLogoutSubject
	if s.verifyLogoutSubject != nil {
		subject := samlStoredLogoutSubject(verified.LogoutSubject)
		logoutSubject = &subject
	}
	return ProviderSAMLIDPAdmission{wire: wire, route: binding, issuer: installed.configuration.EntityID, verifiedAt: verifiedAt, validUntil: cutoff, logoutSubject: logoutSubject}, nil
}

// ProviderSAMLIDPAdmission is an opaque observation, not durable replay or
// browser confirmation. In particular it is not authorization to issue a
// session, and must not renew the original route or wire observation.
type ProviderSAMLIDPAdmission struct {
	wire          SAMLVerifiedResponse
	route         sso.DomainRouteBinding
	issuer        string
	verifiedAt    time.Time
	validUntil    time.Time
	logoutSubject *samlStoredLogoutSubject
}

// Evidence returns detached verified scalars with the earliest original route,
// wire and local acceptance cutoff. A zero or denied admission has no evidence.
func (a ProviderSAMLIDPAdmission) Evidence() (SAMLVerifiedResponse, error) {
	if a.wire.AssertionID == "" || a.verifiedAt.IsZero() || !a.verifiedAt.Before(a.validUntil) || a.validUntil.After(a.route.ValidUntil) {
		return SAMLVerifiedResponse{}, sso.ErrInvalidInput
	}
	evidence := a.wire
	evidence.ValidUntil = a.validUntil
	return evidence, nil
}

func (SAMLIDPAdmissionRequest) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprint(f, "sso.postgres.SAMLIDPAdmissionRequest(redacted)")
}
func (SAMLIDPAdmissionRequest) LogValue() slog.Value {
	return slog.StringValue("sso.postgres.SAMLIDPAdmissionRequest(redacted)")
}
func (SAMLIDPAdmissionRequest) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}
func (SAMLIDPAdmissionRequest) MarshalText() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}

func (SAMLIDPResponseVerificationInput) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprint(f, "sso.postgres.SAMLIDPResponseVerificationInput(redacted)")
}
func (SAMLIDPResponseVerificationInput) LogValue() slog.Value {
	return slog.StringValue("sso.postgres.SAMLIDPResponseVerificationInput(redacted)")
}
func (SAMLIDPResponseVerificationInput) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}
func (SAMLIDPResponseVerificationInput) MarshalText() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}

func (ProviderSAMLIDPAdmission) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprint(f, "sso.postgres.ProviderSAMLIDPAdmission(redacted)")
}
func (ProviderSAMLIDPAdmission) LogValue() slog.Value {
	return slog.StringValue("sso.postgres.ProviderSAMLIDPAdmission(redacted)")
}
func (ProviderSAMLIDPAdmission) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}
func (ProviderSAMLIDPAdmission) MarshalText() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}
