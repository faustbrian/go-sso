package postgres

import (
	"crypto/sha256"
	"slices"
	"strings"

	organization "github.com/faustbrian/go-organization"
	"github.com/faustbrian/go-sso"
)

// StaticSAMLRoleMapping is trusted startup policy for one exact organization,
// provider and nonzero mapping version. Its 1..100 distinct rules select custom
// roles from explicit signed SAML boolean attributes, never attribute values
// interpreted as role IDs or static membership roles. Construction snapshots
// the policy; current provider and custom-role authority remain separate checks.
type StaticSAMLRoleMapping struct {
	OrganizationID organization.ID
	ProviderID     sso.ProviderID
	MappingVersion uint64
	Rules          []StaticSAMLRoleRule
}

// StaticSAMLRoleRule selects exactly RoleID for an explicit true observation
// and withdraws this provider source's grant for explicit false. ClaimName is a
// case-exact flat SAML attribute name of 1..128 printable ASCII bytes; it is not
// a path. NameID and protocol-secret names cannot select roles. Missing, null
// and string values deny the whole mapping rather than retaining earlier roles.
type StaticSAMLRoleRule struct {
	ClaimName string
	RoleID    organization.ID
}

type providerLoginSAMLRoleMapping struct {
	organizationID organization.ID
	providerID     sso.ProviderID
	mappingVersion uint64
	rules          []StaticSAMLRoleRule
	claimNames     []string
	digest         [32]byte
}

func newProviderLoginSAMLRoleMapping(config StaticSAMLRoleMapping) (providerLoginSAMLRoleMapping, error) {
	// organization.DynamicRoleConfig permits 100 roles. Native provider
	// registration separately restricts its organization/provider selectors to
	// printable ASCII; only custom-role IDs use the broader organization grammar.
	if !providerID(string(config.OrganizationID)) || !providerID(string(config.ProviderID)) || config.MappingVersion == 0 ||
		len(config.Rules) < 1 || len(config.Rules) > 100 {
		return providerLoginSAMLRoleMapping{}, sso.ErrInvalidInput
	}
	roles := make(map[organization.ID]struct{}, len(config.Rules))
	for _, rule := range config.Rules {
		if !providerLoginSAMLRoleClaimName(rule.ClaimName) || !providerLoginCustomRoleID(rule.RoleID) {
			return providerLoginSAMLRoleMapping{}, sso.ErrInvalidInput
		}
		if _, duplicate := roles[rule.RoleID]; duplicate {
			return providerLoginSAMLRoleMapping{}, sso.ErrInvalidInput
		}
		roles[rule.RoleID] = struct{}{}
	}
	config.Rules = slices.Clone(config.Rules)
	slices.SortFunc(config.Rules, func(a, b StaticSAMLRoleRule) int { return strings.Compare(a.ClaimName, b.ClaimName) })
	claimNames := make([]string, len(config.Rules))
	for i, rule := range config.Rules {
		if i > 0 && rule.ClaimName == config.Rules[i-1].ClaimName {
			return providerLoginSAMLRoleMapping{}, sso.ErrInvalidInput
		}
		claimNames[i] = rule.ClaimName
	}
	encoded, err := providerLoginPayloadEncode(struct {
		Domain  string
		Mapping StaticSAMLRoleMapping
	}{"golib.sso.saml.role-mapping.v1", config})
	defer clear(encoded)
	if err != nil {
		return providerLoginSAMLRoleMapping{}, sso.ErrInvalidInput
	}
	return providerLoginSAMLRoleMapping{organizationID: config.OrganizationID, providerID: config.ProviderID,
		mappingVersion: config.MappingVersion, rules: config.Rules, claimNames: claimNames, digest: sha256.Sum256(encoded)}, nil
}

func (p providerLoginSAMLRoleMapping) desiredRoles(assertion sso.ProtocolAssertion, expectedIssuer string, expectedProviderVersion uint64) ([]organization.ID, error) {
	if p.mappingVersion == 0 || len(p.rules) == 0 || expectedIssuer == "" || expectedProviderVersion == 0 ||
		assertion.OrganizationID != p.organizationID || assertion.ProviderID != p.providerID ||
		assertion.MappingVersion != p.mappingVersion || assertion.ProviderProfileVersion != expectedProviderVersion || assertion.Validate() != nil {
		return nil, sso.ErrForbidden
	}
	observed := make(map[string]sso.VerifiedAttributeSpec, len(p.rules))
	for _, attribute := range assertion.Attributes {
		spec, err := attribute.Spec()
		if err != nil || spec.Provenance.Issuer != expectedIssuer || spec.Provenance.Source != sso.AttributeSourceSAMLAssertion {
			return nil, sso.ErrForbidden
		}
		// The trusted verifier supplies signed identity observations alongside
		// selected roles. Only exact startup-selected names can confer privilege;
		// Verified/Authoritative assessments are not signature or role authority.
		if _, selected := slices.BinarySearch(p.claimNames, spec.Name); selected {
			observed[spec.Name] = spec
		}
	}
	desired := make([]organization.ID, 0, len(p.rules))
	for _, rule := range p.rules {
		spec, present := observed[rule.ClaimName]
		if !present || spec.Presence != sso.AttributeValue || spec.BooleanValue == nil || spec.StringValue != nil {
			return nil, sso.ErrForbidden
		}
		if *spec.BooleanValue {
			desired = append(desired, rule.RoleID)
		}
	}
	slices.Sort(desired)
	return desired, nil
}

func providerLoginSAMLRoleClaimName(name string) bool {
	// SAML attributes use AttributeMappingSpec's flat printable-ASCII grammar,
	// not OIDC projection's identifier grammar. Reserve the NameID observation
	// and the same protocol-secret aliases excluded by OIDC role policy.
	if !providerID(name) {
		return false
	}
	switch name {
	case "name_id", "nonce", "at_hash", "c_hash", "access_token", "refresh_token", "id_token":
		return false
	default:
		return true
	}
}
