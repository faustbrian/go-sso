package postgres

import (
	"context"
	"strconv"

	organizationpg "github.com/faustbrian/go-organization/postgres"
	scim "github.com/faustbrian/go-scim"
	scimorganization "github.com/faustbrian/go-scim/organization"
	scimpostgres "github.com/faustbrian/go-scim/postgres"
	"github.com/faustbrian/go-sso"
)

// CurrentRoleSources checks 1..128 retained claims in input order against this
// exact immutable mapping, current primary provider and live direct SCIM edges.
// It is suitable for organization.Repository.WithDirectoryTeamRoles. A false
// result means an authoritative mismatch or absence; unavailable, ambiguous,
// expired or canceled reads return no results. It performs no writes and is
// safe for concurrent calls. Source observations are acquired within this call
// and never cached or renewed; the original operation deadline bounds both
// provider fences and the SCIM read.
func (s *DirectoryGroupRoleSyncService) CurrentRoleSources(ctx context.Context, claims []organizationpg.DirectoryTeamRoleSource) (out []bool, err error) {
	defer func() {
		if recover() != nil {
			out, err = nil, sso.ErrUnavailable
		}
	}()
	if s == nil || s.core == nil || s.core.pool == nil || s.core.config.Source == nil || ctx == nil ||
		len(claims) == 0 || len(claims) > 128 {
		return nil, sso.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, s.core.scope.MaximumDuration)
	defer cancel()
	out = make([]bool, len(claims))
	selected := make([]int, 0, len(claims))
	var provider sso.ProviderID
	for i, claim := range claims {
		if !s.matchesRoleSource(claim) {
			continue
		}
		// DirectoryRoleMapper selects exactly one provider partition. No
		// unselected claimed key may trigger an owner lookup or discovery.
		if provider == "" {
			provider = sso.ProviderID(claim.Scope.ProviderID)
		}
		if provider != sso.ProviderID(claim.Scope.ProviderID) {
			return nil, sso.ErrUnavailable
		}
		selected = append(selected, i)
	}
	if len(selected) == 0 {
		return out, nil
	}
	original, err := s.core.readDirectoryProviderAuthority(ctx, provider)
	if err != nil {
		return nil, err
	}
	if !original.present || !original.enabled {
		return out, nil
	}
	current := selected[:0]
	for _, index := range selected {
		claim := claims[index]
		if claim.ProviderVersion == original.version && claim.MappingVersion == original.mapping {
			current = append(current, index)
		}
	}
	if len(current) == 0 {
		return out, nil
	}
	scope := scim.Scope{TenantID: s.core.scope.TenantID, OrganizationID: s.core.scope.OrganizationID,
		ProviderID: string(provider), ConnectionID: s.core.scope.ConnectionID}
	source, err := s.core.config.Source.ObserveDirectorySource(ctx, scope)
	if err != nil {
		return nil, err
	}
	bindings, err := source.Bindings()
	if err != nil {
		return nil, err
	}
	if bindings.Scope != scope || bindings.ConnectionVersion == 0 {
		return nil, sso.ErrUnavailable
	}
	// Bound all remaining work by the same earliest deadline, including the
	// source owner's original validity. Neither final fence starts a new lease.
	ctx, cancelSource := context.WithDeadline(ctx, bindings.ValidUntil)
	defer cancelSource()
	edges := make([]scimpostgres.DirectoryGroupRoleEdge, 0, len(current))
	positions := make([]int, 0, len(current))
	for _, index := range current {
		claim := claims[index]
		if claim.ConnectionVersion != bindings.ConnectionVersion {
			continue
		}
		edges = append(edges, scimpostgres.DirectoryGroupRoleEdge{GroupID: string(claim.Scope.GroupID),
			MemberResourceID: string(claim.MemberResourceID), UserID: claim.Scope.UserID})
		positions = append(positions, index)
	}
	if len(edges) != 0 {
		live, err := s.core.config.Source.ReadDirectoryGroupRoleEdges(ctx, source, edges)
		if err != nil {
			return nil, err
		}
		if len(live) != len(positions) {
			return nil, sso.ErrUnavailable
		}
		for i, index := range positions {
			out[index] = live[i]
		}
	}
	final, err := s.core.readDirectoryProviderAuthority(ctx, provider)
	if err != nil {
		return nil, err
	}
	if final != original {
		return nil, sso.ErrForbidden
	}
	if _, err := source.Bindings(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *DirectoryGroupRoleSyncService) matchesRoleSource(claim organizationpg.DirectoryTeamRoleSource) bool {
	if claim.Scope.TenantID != s.core.scope.TenantID || claim.Scope.OrganizationID != s.core.scope.OrganizationID ||
		string(claim.Scope.ConnectionID) != s.core.scope.ConnectionID {
		return false
	}
	return s.mapping.MatchesDirectoryRoleSource(scimorganization.DirectoryRoleScope{
		TenantID: claim.Scope.TenantID, OrganizationID: claim.Scope.OrganizationID, ProviderID: sso.ProviderID(claim.Scope.ProviderID),
		ConnectionID: string(claim.Scope.ConnectionID), MappingVersion: claim.MappingVersion,
	}, scimorganization.DirectoryRoleTarget{GroupID: string(claim.Scope.GroupID), MemberID: string(claim.MemberResourceID),
		TeamID: claim.Scope.TeamID, RoleID: claim.RoleID, UserID: claim.Scope.UserID})
}

type directoryRoleProviderAuthority struct {
	present, enabled bool
	version, mapping uint64
}

func (s *DirectoryGroupSyncService) readDirectoryProviderAuthority(ctx context.Context, provider sso.ProviderID) (directoryRoleProviderAuthority, error) {
	rows, err := s.pool.Raw().Query(ctx, directoryRoleProviderAuthoritySQL,
		string(s.scope.TenantID), string(s.scope.OrganizationID), string(provider))
	if err != nil {
		return directoryRoleProviderAuthority{}, sso.ErrUnavailable
	}
	defer rows.Close()
	var authority directoryRoleProviderAuthority
	if rows.Next() {
		var version, mapping string
		if err := rows.Scan(&version, &mapping, &authority.enabled); err != nil {
			return directoryRoleProviderAuthority{}, sso.ErrUnavailable
		}
		authority.version, err = strconv.ParseUint(version, 10, 64)
		if err != nil || authority.version == 0 {
			return directoryRoleProviderAuthority{}, sso.ErrUnavailable
		}
		authority.mapping, err = strconv.ParseUint(mapping, 10, 64)
		if err != nil || authority.mapping == 0 {
			return directoryRoleProviderAuthority{}, sso.ErrUnavailable
		}
		authority.present = true
		if rows.Next() {
			return directoryRoleProviderAuthority{}, sso.ErrUnavailable
		}
	}
	if rows.Err() != nil {
		return directoryRoleProviderAuthority{}, sso.ErrUnavailable
	}
	return authority, nil
}

const directoryRoleProviderAuthoritySQL = `SELECT metadata_version::text,COALESCE(metadata_mapping_version,mapping_version)::text,enabled
 FROM sso_providers.providers WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`
