package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/oauth"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	"github.com/faustbrian/go-sso"
)

type providerLoginCallbackRecipient struct {
	account                      kernel.ProviderAccountAdmission
	member                       organization.CredentialAuthorityObservation
	factorVersion, policyVersion uint64
}

var errProviderLoginRecipientIneligible = errors.New("provider login recipient ineligible")
var errProviderLoginRecipientLinkUnavailable = errors.New("provider login recipient link unavailable")

func (providerLoginCallbackRecipient) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.providerLoginCallbackRecipient(redacted)"))
}

// SSOOIDCAccountProviderNamespace returns the stable identity.Account.Provider
// namespace for one exact configured enterprise organization/provider pair.
// Linked-account import and callback lookup must use this same namespace; it
// neither creates nor authenticates a link. Both source identifiers must satisfy
// SSO's 1..128-byte visible-ASCII identifier contract. Invalid inputs return
// ErrInvalidInput without normalization.
//
// Version one hashes "golib.sso.oidc.account-provider.v1\x00" followed by the
// organization and provider, each prefixed by its big-endian uint16 byte length,
// and returns "sso.oidc.v1." plus lowercase hexadecimal SHA-256. Framing keeps
// delimiter-bearing IDs distinct, and hashing fits identity's 128-byte provider
// bound even when both input IDs have maximum length. Tenant isolation remains
// the account owner's independent tenant key; this value is not a secret.
func SSOOIDCAccountProviderNamespace(organizationID organization.ID, provider sso.ProviderID) (string, error) {
	return ssoAccountProviderNamespace(organizationID, provider, "oidc")
}

// SSOOAuth2AccountProviderNamespace identifies an existing enterprise OAuth2
// link under its exact organization/provider pair. It cannot select an OIDC
// or social account, and creates neither a link nor authentication authority.
func SSOOAuth2AccountProviderNamespace(organizationID organization.ID, provider sso.ProviderID) (string, error) {
	return ssoAccountProviderNamespace(organizationID, provider, "oauth2")
}

// SSOSAMLAccountProviderNamespace identifies an existing SAML account under
// the exact installed organization and provider. The issuer and NameID still
// have to match the signed assertion and the authoritative account. This
// namespace creates neither a link nor authority and is distinct from OAuth.
func SSOSAMLAccountProviderNamespace(organizationID organization.ID, provider sso.ProviderID) (string, error) {
	namespace, err := kernel.SSOSAMLAccountProviderNamespace(string(organizationID), string(provider))
	if err != nil {
		return "", sso.ErrInvalidInput
	}
	return namespace, nil
}

func ssoAccountProviderNamespace(organizationID organization.ID, provider sso.ProviderID, protocol string) (string, error) {
	if !providerID(string(organizationID)) || !providerID(string(provider)) {
		return "", sso.ErrInvalidInput
	}
	h := sha256.New()
	_, _ = h.Write([]byte("golib.sso." + protocol + ".account-provider.v1\x00"))
	for _, id := range []string{string(organizationID), string(provider)} {
		var size [2]byte
		binary.BigEndian.PutUint16(size[:], uint16(len(id)))
		_, _ = h.Write(size[:])
		_, _ = h.Write([]byte(id))
	}
	return "sso." + protocol + ".v1." + hex.EncodeToString(h.Sum(nil)), nil
}

// These are preliminary immutable observations for the original callback, not
// renewed authority or permission to issue a session. The sole callback Work
// must fence every returned owner/version, including the callback's separately
// observed organization version, before commit.
func (s *ProviderLoginService) resolveProviderLoginCallbackRecipient(ctx context.Context, original providerLoginStartInput, verified oauth.ProviderIdentity, policyNamespace string) (providerLoginCallbackRecipient, error) {
	if err := s.checkLinkedProviderRecipientContext(ctx); err != nil {
		return providerLoginCallbackRecipient{}, err
	}
	protocolID, protocolErr := ssoOIDCTransportProviderID(original.Proof.OrganizationID, original.ProviderID)
	validEvidence := !verified.IDTokenIssuedAt().IsZero() && !verified.IDTokenExpiresAt().IsZero()
	switch original.Protocol {
	case "":
	case providerProtocolOAuth2:
		protocolID, protocolErr = ssoOAuth2TransportProviderID(original.Proof.OrganizationID, original.ProviderID)
		_, hasAuthenticationTime := verified.AuthenticationTime()
		validEvidence = verified.IDTokenIssuedAt().IsZero() && verified.IDTokenExpiresAt().IsZero() && !hasAuthenticationTime
	default:
		return providerLoginCallbackRecipient{}, sso.ErrForbidden
	}
	if protocolErr != nil || verified.ProviderID() != protocolID || verified.Issuer() != original.Issuer || !validEvidence {
		return providerLoginCallbackRecipient{}, sso.ErrForbidden
	}
	return s.readLinkedProviderRecipient(ctx, original, verified.Subject(), verified.EvidenceExpiresAt(), policyNamespace)
}

// The caller must first authenticate protocol evidence for the exact original
// installation. The lookup, authority reads, and final Work fences are shared
// by the existing provider path and a selected protocol adapter.
func (s *ProviderLoginService) readLinkedProviderRecipient(ctx context.Context, original providerLoginStartInput, subject string, proofExpires time.Time, policyNamespace string) (providerLoginCallbackRecipient, error) {
	if err := s.checkLinkedProviderRecipientContext(ctx); err != nil {
		return providerLoginCallbackRecipient{}, err
	}
	now := s.router.config.Clock.Now().UTC()
	if original.Command.TenantID != s.config.TenantID || original.Proof.TenantID != s.config.TenantID ||
		original.Organization.TenantID != s.config.TenantID || original.Organization.OrganizationID != original.Proof.OrganizationID ||
		original.Organization.Version == 0 || original.Organization.CredentialVersion == 0 ||
		original.Issued.IsZero() || now.Before(original.Issued) || !now.Before(original.Expires) ||
		subject == "" || !now.Before(proofExpires) {
		return providerLoginCallbackRecipient{}, sso.ErrForbidden
	}
	return s.router.readLinkedRecipient(ctx, s.directory, linkedRecipientRequest{
		tenant: s.config.TenantID, organization: original.Proof.OrganizationID, provider: original.ProviderID,
		protocol: original.Protocol, issuer: original.Issuer, subject: subject, policyNamespace: policyNamespace,
		observedAt: now, deadline: earlierLoginTime(original.Expires, proofExpires), maximumDuration: s.config.Coordinator.MaximumDuration,
	})
}

// linkedRecipientRequest contains authenticated installed-provider scope, not
// a prior browser transaction. Its deadline is supplied by the original
// admission owner and must never be replaced by a fresh lookup clock.
type linkedRecipientRequest struct {
	tenant                                     identity.TenantID
	organization                               organization.ID
	provider                                   sso.ProviderID
	protocol, issuer, subject, policyNamespace string
	observedAt, deadline                       time.Time
	maximumDuration                            time.Duration
}

func (r *ProviderRouter) readLinkedRecipient(ctx context.Context, directory *kernel.Repository, selected linkedRecipientRequest) (providerLoginCallbackRecipient, error) {
	accountNamespace := SSOOIDCAccountProviderNamespace
	accountFields := kernel.SSOOIDCSigninAccountFields
	readFactors := mfapg.ReadSSOOIDCSigninFactors
	readAccount := directory.GetSSOOIDCSigninAccount
	switch selected.protocol {
	case "":
	case providerProtocolOAuth2:
		accountNamespace = SSOOAuth2AccountProviderNamespace
		accountFields = kernel.SSOOAuth2SigninAccountFields
		readFactors = mfapg.ReadSSOOAuth2SigninFactors
	case providerProtocolSAML:
		accountNamespace = SSOSAMLAccountProviderNamespace
		accountFields = kernel.SSOSAMLSigninAccountFields
		readFactors = mfapg.ReadSSOSAMLSigninFactors
		readAccount = directory.GetSSOSAMLSigninAccount
	default:
		return providerLoginCallbackRecipient{}, sso.ErrForbidden
	}
	now := r.config.Clock.Now().UTC()
	if selected.observedAt.IsZero() || now.Before(selected.observedAt) || !now.Before(selected.deadline) {
		return providerLoginCallbackRecipient{}, sso.ErrForbidden
	}
	provider, err := accountNamespace(selected.organization, selected.provider)
	if err != nil {
		return providerLoginCallbackRecipient{}, sso.ErrForbidden
	}
	query := kernel.ProviderSigninAccountQuery{TenantID: selected.tenant, Provider: provider, Issuer: selected.issuer, Subject: selected.subject}
	policyScope := authoritypg.AuthorityScope{TenantID: authorization.TenantID(query.TenantID), SubjectID: "scope-validation", PolicyNamespace: selected.policyNamespace}
	if query.Validate() != nil || policyScope.Validate() != nil {
		return providerLoginCallbackRecipient{}, sso.ErrForbidden
	}
	maximumDuration := min(selected.maximumDuration, 5*time.Second)
	if maximumDuration < time.Millisecond {
		return providerLoginCallbackRecipient{}, sso.ErrForbidden
	}
	ctx, cancel := context.WithTimeout(ctx, min(maximumDuration, selected.deadline.Sub(now)))
	defer cancel()

	account, err := readAccount(ctx, query)
	if err != nil {
		var forbidden identity.ForbiddenError
		if ctx.Err() == nil && errors.As(err, &forbidden) {
			if selected.protocol == providerProtocolSAML {
				return providerLoginCallbackRecipient{}, sso.ErrForbidden
			}
			// This can mean an existing unusable or retired account. The JIT
			// branch must independently prove exact subject absence.
			return providerLoginCallbackRecipient{}, errProviderLoginRecipientLinkUnavailable
		}
		return providerLoginCallbackRecipient{}, providerError(ctx, err)
	}
	if _, err := accountFields(account); err != nil || account.Account.TenantID != query.TenantID ||
		account.Account.Provider != query.Provider || account.Account.Issuer != query.Issuer || account.Account.Subject != query.Subject {
		return providerLoginCallbackRecipient{}, sso.ErrForbidden
	}
	memberQuery := organization.CredentialAuthorityQuery{TenantID: query.TenantID, OrganizationID: selected.organization, ActorID: account.Account.UserID}
	member, err := r.organizations.ObserveCredentialAuthority(ctx, memberQuery)
	if err != nil {
		if ctx.Err() == nil && errors.Is(err, organization.ErrForbidden) {
			if selected.protocol == providerProtocolSAML {
				return providerLoginCallbackRecipient{}, sso.ErrForbidden
			}
			return providerLoginCallbackRecipient{}, errProviderLoginRecipientIneligible
		}
		return providerLoginCallbackRecipient{}, providerError(ctx, err)
	}
	factors, err := readFactors(ctx, r.pool, query.TenantID, account.Account.UserID, maximumDuration)
	if err != nil {
		return providerLoginCallbackRecipient{}, providerError(ctx, err)
	}
	policy, err := authoritypg.NewAuthorityStore(r.pool.Raw(), maximumDuration)
	if err != nil {
		return providerLoginCallbackRecipient{}, sso.ErrForbidden
	}
	policyScope.SubjectID = authorization.SubjectID(account.Account.UserID)
	currentPolicy, err := policy.Get(ctx, policyScope)
	if err != nil {
		if ctx.Err() != nil {
			return providerLoginCallbackRecipient{}, ctx.Err()
		}
		if errors.Is(err, authoritypg.ErrAuthorityDenied) {
			return providerLoginCallbackRecipient{}, sso.ErrForbidden
		}
		return providerLoginCallbackRecipient{}, providerError(ctx, err)
	}
	if err := ctx.Err(); err != nil {
		return providerLoginCallbackRecipient{}, err
	}
	now = r.config.Clock.Now().UTC()
	if now.Before(selected.observedAt) || !now.Before(selected.deadline) || member.Validate(memberQuery, now) != nil || factors.Version() == 0 ||
		currentPolicy.Scope != policyScope || currentPolicy.Version == 0 {
		return providerLoginCallbackRecipient{}, sso.ErrForbidden
	}
	return providerLoginCallbackRecipient{account: account, member: member, factorVersion: factors.Version(), policyVersion: currentPolicy.Version}, nil
}

func (s *ProviderLoginService) checkLinkedProviderRecipientContext(ctx context.Context) error {
	if s == nil || s.router == nil || s.router.pool == nil || s.router.pool.Raw() == nil ||
		s.router.organizations == nil || s.router.config.Clock == nil || s.directory == nil || ctx == nil {
		return sso.ErrForbidden
	}
	return ctx.Err()
}
