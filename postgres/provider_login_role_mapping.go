package postgres

import (
	"crypto/sha256"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/faustbrian/go-identity/oauth"
	organization "github.com/faustbrian/go-organization"
	"github.com/faustbrian/go-sso"
)

// StaticOIDCRoleMapping is trusted startup policy for one exact organization,
// provider and nonzero mapping version. It selects 1..100 distinct custom roles
// through distinct projected boolean claims. It never selects static membership
// roles, interprets claim values as role IDs, or establishes current role authority.
// Completion-service construction snapshots and validates the entire policy.
type StaticOIDCRoleMapping struct {
	OrganizationID organization.ID
	ProviderID     sso.ProviderID
	MappingVersion uint64
	Rules          []StaticOIDCRoleRule
}

// StaticOIDCRoleRule grants exactly RoleID when ClaimName is verified true and
// withdraws this provider source's grant when it is verified false. Missing,
// null, duplicate or nonboolean observations deny the whole mapping. ClaimName
// uses identity/oauth's exact top-level projection grammar and forbidden names;
// RoleID must be a custom organization role, not owner, administrator or member.
type StaticOIDCRoleRule struct {
	ClaimName string
	RoleID    organization.ID
}

type providerLoginRoleMapping struct {
	organizationID      organization.ID
	providerID          sso.ProviderID
	mappingVersion      uint64
	rules               []StaticOIDCRoleRule
	projectedClaimNames []string
	digest              [32]byte
}

func newProviderLoginRoleMapping(config StaticOIDCRoleMapping, projectedClaimNames []string) (providerLoginRoleMapping, error) {
	// Match organization.DynamicRoleConfig's 100-role budget and
	// identity/oauth.OIDCClaimProjectionConfig's 128-name budget before allocation.
	if !providerID(string(config.OrganizationID)) || !providerID(string(config.ProviderID)) || config.MappingVersion == 0 ||
		len(config.Rules) < 1 || len(config.Rules) > 100 || len(projectedClaimNames) < 1 || len(projectedClaimNames) > 128 {
		return providerLoginRoleMapping{}, sso.ErrInvalidInput
	}
	for _, name := range projectedClaimNames {
		if !providerLoginRoleClaimName(name) {
			return providerLoginRoleMapping{}, sso.ErrInvalidInput
		}
	}
	projected := slices.Clone(projectedClaimNames)
	slices.Sort(projected)
	for i := 1; i < len(projected); i++ {
		if projected[i] == projected[i-1] {
			return providerLoginRoleMapping{}, sso.ErrInvalidInput
		}
	}
	roles := make(map[organization.ID]struct{}, len(config.Rules))
	for _, rule := range config.Rules {
		if !providerLoginRoleClaimName(rule.ClaimName) || !providerLoginCustomRoleID(rule.RoleID) {
			return providerLoginRoleMapping{}, sso.ErrInvalidInput
		}
		_, selected := slices.BinarySearch(projected, rule.ClaimName)
		_, duplicateRole := roles[rule.RoleID]
		if !selected || duplicateRole {
			return providerLoginRoleMapping{}, sso.ErrInvalidInput
		}
		roles[rule.RoleID] = struct{}{}
	}
	config.Rules = slices.Clone(config.Rules)
	slices.SortFunc(config.Rules, func(a, b StaticOIDCRoleRule) int { return strings.Compare(a.ClaimName, b.ClaimName) })
	for i := 1; i < len(config.Rules); i++ {
		if config.Rules[i].ClaimName == config.Rules[i-1].ClaimName {
			return providerLoginRoleMapping{}, sso.ErrInvalidInput
		}
	}
	encoded, err := providerLoginPayloadEncode(struct {
		Domain    string
		Mapping   StaticOIDCRoleMapping
		Projected []string
	}{"golib.sso.oidc.role-mapping.v1", config, projected})
	defer clear(encoded)
	if err != nil {
		return providerLoginRoleMapping{}, sso.ErrInvalidInput
	}
	return providerLoginRoleMapping{organizationID: config.OrganizationID, providerID: config.ProviderID, mappingVersion: config.MappingVersion,
		rules: config.Rules, projectedClaimNames: projected, digest: sha256.Sum256(encoded)}, nil
}

func (p providerLoginRoleMapping) desiredRoles(claims []oauth.VerifiedOIDCClaim) ([]organization.ID, error) {
	if p.mappingVersion == 0 || len(p.rules) == 0 || len(claims) < 1 || len(claims) > 128 {
		return nil, sso.ErrForbidden
	}
	observed := make(map[string]oauth.VerifiedOIDCClaim, len(claims))
	for _, claim := range claims {
		name := claim.Name()
		_, selected := slices.BinarySearch(p.projectedClaimNames, name)
		_, duplicate := observed[name]
		if !selected || duplicate {
			return nil, sso.ErrForbidden
		}
		observed[name] = claim
	}
	desired := make([]organization.ID, 0, len(p.rules))
	for _, rule := range p.rules {
		claim, present := observed[rule.ClaimName]
		grant, boolean := claim.BoolValue()
		if !present || !boolean {
			return nil, sso.ErrForbidden
		}
		if grant {
			desired = append(desired, rule.RoleID)
		}
	}
	slices.Sort(desired)
	return desired, nil
}

// Match identity/oauth.OIDCClaimProjectionConfig exactly, including its
// protocol-secret exclusions; startup mapping must not widen that boundary.
func providerLoginRoleClaimName(name string) bool {
	if len(name) < 1 || len(name) > 128 {
		return false
	}
	switch name {
	case "nonce", "at_hash", "c_hash", "access_token", "refresh_token", "id_token":
		return false
	}
	for i := 0; i < len(name); i++ {
		char := name[i]
		letter := char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z'
		if letter || char == '_' {
			continue
		}
		if i == 0 || !(char >= '0' && char <= '9' || char == '.' || char == '-') {
			return false
		}
	}
	return true
}

func providerLoginCustomRoleID(id organization.ID) bool {
	// Match organization.DynamicRole's ID contract without making the
	// provider's narrower ASCII-native identifier profile apply to custom roles.
	if len(id) < 1 || len(id) > 128 || !utf8.ValidString(string(id)) || organization.Role(id).Valid() {
		return false
	}
	for _, char := range id {
		if char <= ' ' || char == 127 {
			return false
		}
	}
	return true
}
