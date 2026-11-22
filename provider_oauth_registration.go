package sso

import (
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

// OAuthSubjectKind selects the expected representation of the stable subject
// at the explicitly configured authenticated identity endpoint. Zero is invalid.
type OAuthSubjectKind uint8

const (
	// OAuthSubjectString preserves an exact nonempty, bounded string identifier.
	OAuthSubjectString OAuthSubjectKind = iota + 1
	// OAuthSubjectPositiveInteger selects exact positive decimal JSON integers,
	// without string or floating-point coercion.
	OAuthSubjectPositiveInteger
)

// OAuthEmailVerification selects what the identity endpoint may attest about
// a mapped email address. Zero selects no profile and is invalid.
type OAuthEmailVerification uint8

const (
	// OAuthEmailUnverified allows only unverified mail metadata.
	OAuthEmailUnverified OAuthEmailVerification = iota + 1
	// OAuthEmailBooleanClaim requires the exact configured verification claim
	// to be a JSON boolean true before the associated email can be verified.
	OAuthEmailBooleanClaim
)

// IdentityProofPolicySpec is provider-administration input, not proof. Issuer
// is the exact trusted HTTPS authorization-server identifier to retain for the
// selected callback, independently of the token and identity endpoints.
type IdentityProofPolicySpec struct {
	Version           uint64
	Issuer            string
	SubjectKind       OAuthSubjectKind
	EmailVerification OAuthEmailVerification
}

// IdentityProofPolicy is an immutable, explicitly configured trust policy for
// enterprise OAuth without an ID token. Its zero value is invalid. It performs
// no I/O and does not authenticate a response, activate a provider, or select a
// tenant or organization. Copies are safe for concurrent reads.
type IdentityProofPolicy struct{ spec IdentityProofPolicySpec }

// NewIdentityProofPolicy checks closed profile choices and preserves the issuer
// identifier byte-for-byte for the shared callback's later comparison.
func NewIdentityProofPolicy(spec IdentityProofPolicySpec) (IdentityProofPolicy, error) {
	if spec.Version == 0 || len(spec.Issuer) > 2048 ||
		(spec.SubjectKind != OAuthSubjectString && spec.SubjectKind != OAuthSubjectPositiveInteger) ||
		(spec.EmailVerification != OAuthEmailUnverified && spec.EmailVerification != OAuthEmailBooleanClaim) {
		return IdentityProofPolicy{}, ErrInvalidInput
	}
	issuer, err := staticOIDCEndpoint(spec.Issuer)
	if err != nil || issuer.RawQuery != "" || issuer.ForceQuery || issuer.String() != spec.Issuer {
		return IdentityProofPolicy{}, ErrInvalidInput
	}
	return IdentityProofPolicy{spec: spec}, nil
}

// Spec explicitly projects a scalar copy for trusted configuration persistence
// or protocol composition. The projection does not establish current authority.
func (p IdentityProofPolicy) Spec() (IdentityProofPolicySpec, error) {
	if p.spec.Version == 0 {
		return IdentityProofPolicySpec{}, ErrInvalidInput
	}
	return p.spec, nil
}

func (IdentityProofPolicy) Format(s fmt.State, _ rune) {
	_, _ = fmt.Fprint(s, "sso.IdentityProofPolicy(redacted)")
}

func (IdentityProofPolicy) LogValue() slog.Value {
	return slog.StringValue("sso.IdentityProofPolicy(redacted)")
}

func (IdentityProofPolicy) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (IdentityProofPolicy) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// ProviderRegisterOauthRequest is the configuration intent for registering a
// disabled static enterprise OAuth provider. Endpoints are explicit HTTPS
// locations without user information, queries, or fragments in this profile.
// IdentityEndpoint is separate from authorization and token exchange: an
// access token by itself cannot establish identity. No credentials are accepted.
// Domains are pending verification, never verified ownership. Callers retain
// the same command, key and input across retries, and must not mutate Domains
// during use. Only the native registration owner can authorize and persist it.
type ProviderRegisterOauthRequest struct {
	CommandID             identity.CommandID
	OrganizationID        string
	AuthorizationEndpoint url.URL
	TokenEndpoint         url.URL
	IdentityEndpoint      url.URL
	RevocationEndpoint    url.URL
	IdentityProofPolicy   IdentityProofPolicy
	Domains               []string
	Mapping               AttributeMapping
	IdempotencyKey        identity.IdempotencyKey
}

// Validate rejects incomplete or ambiguous input before any native work.
// It authenticates no caller, proves no domain, and performs no I/O.
func (r ProviderRegisterOauthRequest) Validate() error {
	if _, err := identity.ParseCommandID(string(r.CommandID)); err != nil {
		return ErrInvalidInput
	}
	if !providerClaimName(r.OrganizationID) || r.IdempotencyKey == (identity.IdempotencyKey{}) ||
		len(r.Domains) == 0 || len(r.Domains) > 128 {
		return ErrInvalidInput
	}
	policy, proofErr := r.IdentityProofPolicy.Spec()
	mapping, mappingErr := r.Mapping.Spec()
	if proofErr != nil || mappingErr != nil || !oauthProofMapping(policy, mapping) {
		return ErrInvalidInput
	}
	for _, endpoint := range [...]url.URL{r.AuthorizationEndpoint, r.TokenEndpoint, r.IdentityEndpoint} {
		if !validOAuthRegistrationEndpoint(endpoint) {
			return ErrInvalidInput
		}
	}
	if oauthRegistrationSameEndpoint(r.IdentityEndpoint, r.TokenEndpoint) ||
		oauthRegistrationSameEndpoint(r.IdentityEndpoint, r.AuthorizationEndpoint) ||
		r.RevocationEndpoint != (url.URL{}) && !validOAuthRegistrationEndpoint(r.RevocationEndpoint) {
		return ErrInvalidInput
	}
	seen := make(map[string]struct{}, len(r.Domains))
	for _, domain := range r.Domains {
		if len(domain) == 0 || len(domain) > 253 {
			return ErrInvalidInput
		}
		canonical, err := organization.CanonicalDomain(domain)
		if _, duplicate := seen[domain]; err != nil || canonical != domain || duplicate {
			return ErrInvalidInput
		}
		seen[domain] = struct{}{}
	}
	return nil
}

func oauthProofMapping(policy IdentityProofPolicySpec, mapping AttributeMappingSpec) bool {
	if policy.EmailVerification == OAuthEmailUnverified {
		return mapping.VerifiedEmailClaim == ""
	}
	verified := mapping.VerifiedEmailClaim
	return mapping.EmailClaim != "" && verified != "" && verified != mapping.SubjectClaim &&
		verified != mapping.EmailClaim && verified != mapping.DisplayNameClaim
}

func validOAuthRegistrationEndpoint(endpoint url.URL) bool {
	const maximum = 2048
	if endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.Opaque != "" ||
		endpoint.OmitHost || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" || endpoint.RawFragment != "" ||
		len(endpoint.Host) > maximum || len(endpoint.Path) > maximum || len(endpoint.RawPath) > maximum ||
		!utf8.ValidString(endpoint.Path) || strings.ContainsFunc(endpoint.Path, unicode.IsControl) {
		return false
	}
	// Caller-constructed url.URL values must not hide inconsistent raw-path
	// overrides that URL.String would otherwise silently discard.
	wire := endpoint.String()
	if len(wire) > maximum {
		return false
	}
	parsed, err := staticOIDCEndpoint(wire)
	return err == nil && *parsed == endpoint
}

func oauthRegistrationSameEndpoint(a, b url.URL) bool {
	// A case or default-port spelling change does not make the identity path
	// independent of the endpoint that would otherwise receive the bearer.
	port := func(u url.URL) string {
		if u.Port() == "" {
			return "443"
		}
		return u.Port()
	}
	path := func(u url.URL) string {
		if u.Path == "" {
			return "/"
		}
		return u.Path
	}
	return strings.EqualFold(a.Hostname(), b.Hostname()) && port(a) == port(b) && path(a) == path(b)
}

func (ProviderRegisterOauthRequest) Format(s fmt.State, _ rune) {
	_, _ = fmt.Fprint(s, "sso.ProviderRegisterOauthRequest(redacted)")
}

func (ProviderRegisterOauthRequest) LogValue() slog.Value {
	return slog.StringValue("sso.ProviderRegisterOauthRequest(redacted)")
}

func (ProviderRegisterOauthRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

func (ProviderRegisterOauthRequest) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// ProviderRegisterOauthResult reports safe disabled-provider metadata and the
// original durable completion. The requirement count is not verification or
// permission to start login.
type ProviderRegisterOauthResult struct {
	Provider                     Provider
	VerificationRequirementCount uint32
	Completion                   Completion
}
