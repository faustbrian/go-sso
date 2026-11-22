package postgres

import (
	"slices"

	"github.com/faustbrian/go-identity/oauth"
	organization "github.com/faustbrian/go-organization"
	"github.com/faustbrian/go-sso"
)

// SigninProtocolProfile returns detached, secret-free protocol metadata and
// effective parser limits validated at completion-service construction. The
// organization and provider IDs are exact, case-sensitive native identifiers;
// the returned ID is their scoped protocol alias, not a persistent provider ID.
// Nil/zero services and unselected pairs return ErrInvalidInput and no profile.
// This concurrent-safe lookup performs no I/O and establishes no current
// provider eligibility, callback admission, authentication or session authority.
func (s *ProviderLoginCompletionService) SigninProtocolProfile(organizationID organization.ID, providerID sso.ProviderID) (oauth.ProviderProfile, error) {
	if s == nil {
		return oauth.ProviderProfile{}, sso.ErrInvalidInput
	}
	profile, available := s.protocolProfiles[providerLoginProfileKey{organization: organizationID, provider: providerID}]
	if !available {
		return oauth.ProviderProfile{}, sso.ErrInvalidInput
	}
	profile.Scopes = slices.Clone(profile.Scopes)
	profile.Algorithms = slices.Clone(profile.Algorithms)
	return profile, nil
}
