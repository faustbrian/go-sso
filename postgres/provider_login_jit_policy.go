package postgres

import (
	"crypto/sha256"
	"fmt"
	"slices"
	"strings"

	"github.com/faustbrian/go-identity/email"
	"github.com/faustbrian/go-identity/oauth"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	"github.com/faustbrian/go-sso"
)

// StaticOIDCJITPolicy explicitly permits first-login provisioning for one
// installed OIDC provider and mapping version. JIT creates only ordinary
// members; the capacity settings must match the organization's admission
// configuration. Changing any setting requires a new policy version.
type StaticOIDCJITPolicy struct {
	OrganizationID                             organization.ID
	ProviderID                                 sso.ProviderID
	Version, MappingVersion, MembershipVersion uint64
	MaximumMembers, MaximumPerUser             uint64
}

// ProviderLoginJITConfig selects first-login provisioning independently of
// repeat-login role synchronization. Address must use the same normalization
// policy as the tenant's directory and identifier retirement configuration.
// Unselected providers retain the existing linked-member-only profile.
type ProviderLoginJITConfig struct {
	Address   email.AddressParser
	Directory kernel.SSOOIDCJITDomainConfig
	Profiles  []StaticOIDCJITPolicy
	RoleSync  []StaticOIDCRoleMapping
}

func (ProviderLoginJITConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.ProviderLoginJITConfig(redacted)"))
}

func (ProviderLoginJITConfig) MarshalJSON() ([]byte, error) { return nil, sso.ErrInvalidInput }

type providerLoginJITPolicy struct {
	StaticOIDCJITPolicy
	address              email.AddressParser
	directory            *kernel.SSOOIDCJITDomain
	comparisonProfile    string
	normalizationProfile string
	normalizationVersion uint32
	digest               [32]byte
}

// NewProviderLoginCompletionServiceWithJIT opts selected static OIDC profiles
// into first-login provisioning using the existing callback transaction.
// Install identity, MFA and organization JIT migrations before selection.
// No extra routes, provider fallback or automatic linking by email are added.
// Optional RoleSync applies only on later logins by already linked members.
func NewProviderLoginCompletionServiceWithJIT(start *ProviderLoginService, config ProviderLoginCompletionConfig, jit ProviderLoginJITConfig) (*ProviderLoginCompletionService, error) {
	if len(jit.Profiles) == 0 || len(jit.Profiles) > len(config.Profiles) {
		return nil, sso.ErrInvalidInput
	}
	var service *ProviderLoginCompletionService
	var err error
	if len(jit.RoleSync) == 0 {
		service, err = NewProviderLoginCompletionService(start, config)
	} else {
		service, err = NewProviderLoginCompletionServiceWithRoleSync(start, config, jit.RoleSync)
	}
	if err != nil {
		return nil, err
	}
	directory, err := kernel.NewSSOOIDCJITDomain(start.directory, jit.Directory)
	if err != nil {
		return nil, sso.ErrInvalidInput
	}
	example, err := jit.Address.Parse("identity-jit-policy@example.invalid")
	if err != nil {
		return nil, sso.ErrInvalidInput
	}
	normalization := example.Canonical().Record()
	service.jitPolicies = make(map[providerLoginProfileKey]providerLoginJITPolicy, len(jit.Profiles))
	for _, policy := range jit.Profiles {
		key := providerLoginProfileKey{organization: policy.OrganizationID, provider: policy.ProviderID}
		transport, selected := service.profiles[key]
		_, duplicate := service.jitPolicies[key]
		if !selected || duplicate || len(transport.claims) < 2 || policy.MappingVersion != start.profiles[key].MappingVersion ||
			policy.Version == 0 || policy.MembershipVersion == 0 || policy.MaximumMembers < 1 || policy.MaximumMembers > 100000 ||
			policy.MaximumPerUser < 1 || policy.MaximumPerUser > 1000 {
			return nil, sso.ErrInvalidInput
		}
		wire, err := providerLoginPayloadEncode(struct {
			Domain, Comparison, Normalization string
			NormalizationVersion              uint32
			Policy                            StaticOIDCJITPolicy
		}{"golib.sso.oidc.jit-policy.v1", jit.Directory.ComparisonProfile, string(normalization.ProfileID), normalization.ProfileVersion, policy})
		if err != nil {
			return nil, sso.ErrInvalidInput
		}
		service.jitPolicies[key] = providerLoginJITPolicy{StaticOIDCJITPolicy: policy, address: jit.Address, directory: directory,
			comparisonProfile: jit.Directory.ComparisonProfile, normalizationProfile: string(normalization.ProfileID),
			normalizationVersion: normalization.ProfileVersion, digest: sha256.Sum256(wire)}
		clear(wire)
	}
	return service, nil
}

func selectProviderLoginJITMailbox(parser email.AddressParser, mapping sso.AttributeMappingSpec, version uint64, domain string, claims []oauth.VerifiedOIDCClaim) (email.Address, error) {
	if mapping.Version == 0 || mapping.Version != version || mapping.SubjectClaim != "sub" || !providerLoginRoleClaimName(mapping.EmailClaim) ||
		!providerLoginRoleClaimName(mapping.VerifiedEmailClaim) || mapping.EmailClaim == mapping.VerifiedEmailClaim || len(claims) < 2 || len(claims) > 128 {
		return email.Address{}, sso.ErrForbidden
	}
	var mailbox string
	var observedMailbox, observedVerification bool
	for _, claim := range claims {
		switch claim.Name() {
		case mapping.EmailClaim:
			value, ok := claim.StringValue()
			if observedMailbox || !ok || value == "" {
				return email.Address{}, sso.ErrForbidden
			}
			mailbox, observedMailbox = value, true
		case mapping.VerifiedEmailClaim:
			verified, ok := claim.BoolValue()
			if observedVerification || !ok || !verified {
				return email.Address{}, sso.ErrForbidden
			}
			observedVerification = true
		}
	}
	if !observedMailbox || !observedVerification {
		return email.Address{}, sso.ErrForbidden
	}
	parsed, err := parser.Parse(email.AddressInput(mailbox))
	if err != nil {
		return email.Address{}, sso.ErrForbidden
	}
	_, mailboxDomain, ok := strings.Cut(parsed.Canonical().Record().Value, "@")
	if !ok || mailboxDomain != domain {
		return email.Address{}, sso.ErrForbidden
	}
	return parsed, nil
}

func (p providerLoginJITPolicy) selectsMapping(mapping sso.AttributeMappingSpec, transport providerLoginCallbackTransport) bool {
	return mapping.Version == p.MappingVersion && mapping.SubjectClaim == "sub" && mapping.EmailClaim != mapping.VerifiedEmailClaim &&
		slices.Contains(transport.claims, mapping.EmailClaim) && slices.Contains(transport.claims, mapping.VerifiedEmailClaim)
}
