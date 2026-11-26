package postgres

import (
	"context"
	"errors"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	scimorganization "github.com/faustbrian/go-scim/organization"
	scimpostgres "github.com/faustbrian/go-scim/postgres"
	"github.com/faustbrian/go-sso"
)

const directoryRoleDriftAction = "identity.sso.directory-sync-inspect-role-drift"

// DirectoryGroupRoleDriftKind classifies one exact mapped role contribution.
// The zero value is not a successful classification.
type DirectoryGroupRoleDriftKind uint8

const (
	// DirectoryGroupRoleDriftInSync means a present source has the exact
	// current role contribution or a known absent source has none.
	DirectoryGroupRoleDriftInSync DirectoryGroupRoleDriftKind = iota + 1
	// DirectoryGroupRoleDriftMissing means the source edge and native role
	// target are current, but the selected origin has no retained role row.
	DirectoryGroupRoleDriftMissing
	// DirectoryGroupRoleDriftUnexpected means a known absent source edge has
	// a retained role row. It says nothing about the effectiveness of that row.
	DirectoryGroupRoleDriftUnexpected
	// DirectoryGroupRoleDriftStale means a present source edge has a retained
	// row that does not match the current source, grant or role binding.
	DirectoryGroupRoleDriftStale
	// DirectoryGroupRoleDriftConflict means the source relationship or native
	// target is not known to be eligible. It does not imply grant absence.
	DirectoryGroupRoleDriftConflict
)

// DirectoryGroupRoleDrift is a detached observation, not effective access,
// a command receipt or repair authority. LocalMembership is independent
// native team membership; it cannot substitute for a source role.
type DirectoryGroupRoleDrift struct {
	Kind            DirectoryGroupRoleDriftKind
	Source          scimpostgres.DirectoryGroupEdgeState
	LocalMembership bool
}

// ObserveDrift inspects one explicitly mapped role edge at the exact running
// Apply or dry-run checkpoint. Only separate service-account inspection
// authorization permits disclosure. The proposed action is not executed and
// does not determine classification. Changed observations, authority or
// checkpoint return a zero report. No write, permission decision or cursor
// advance is performed.
func (s *DirectoryGroupRoleSyncService) ObserveDrift(ctx context.Context, r DirectoryGroupRoleApplyRequest) (out DirectoryGroupRoleDrift, err error) {
	defer func() {
		if recover() != nil {
			out, err = DirectoryGroupRoleDrift{}, sso.ErrUnavailable
		}
	}()
	if s == nil || s.core == nil || ctx == nil || !providerID(string(r.ProviderID)) || r.MappingVersion == 0 || r.PredecessorCheckpoint == ([32]byte{}) {
		return out, sso.ErrInvalidInput
	}
	if _, err := identity.ParseCommandID(string(r.GenerationID)); err != nil {
		return out, sso.ErrInvalidInput
	}
	inspector := *s.core
	inspector.applyAction = directoryRoleDriftAction
	ctx, cancel := context.WithTimeout(ctx, inspector.scope.MaximumDuration)
	defer cancel()
	batch, resolved, err := inspector.resolveOpaqueBatch(ctx, r.GenerationID, sso.DirectoryDeltaBatch{
		TenantID: inspector.scope.TenantID, OrganizationID: inspector.scope.OrganizationID, ConnectionID: inspector.scope.ConnectionID,
		ProviderID: r.ProviderID, MappingVersion: r.MappingVersion, PredecessorCheckpoint: r.PredecessorCheckpoint, Deltas: []sso.DirectoryDelta{r.Delta},
	})
	if err != nil {
		return out, err
	}
	generation, admission := resolved.stored.current, resolved.admission
	if generation.State != DirectorySyncRunning || generation.Checkpoint != batch.PredecessorCheckpoint {
		return out, sso.ErrDirectoryReconciliation
	}
	ctx, finish := context.WithDeadline(ctx, admission.validUntil)
	defer finish()

	mapped, err := s.mapping.MapDirectoryRoleDelta(batch)
	if errors.Is(err, scimorganization.ErrInvalidMappingInput) {
		return out, sso.ErrInvalidInput
	}
	if err != nil || len(mapped.Roles) != 1 {
		return out, sso.ErrForbidden
	}
	provider, err := inspector.readDirectoryDriftProvider(ctx, generation)
	if err != nil {
		return out, err
	}
	role := mapped.Roles[0]
	member := role.Membership
	edge := scimpostgres.DirectoryGroupRoleEdge{GroupID: member.GroupID, MemberResourceID: member.MemberID, UserID: member.UserID}
	expected := organizationpg.DirectoryTeamRoleSource{
		Scope: organizationpg.DirectoryTeamGrantScope{
			TenantID: batch.TenantID, OrganizationID: batch.OrganizationID, ProviderID: organization.ID(batch.ProviderID),
			ConnectionID: organization.ID(batch.ConnectionID), GroupID: organization.ID(member.GroupID), TeamID: member.TeamID, UserID: member.UserID,
		},
		MemberResourceID: organization.ID(member.MemberID), RoleID: role.RoleID,
		ProviderVersion: provider.version, MappingVersion: provider.mapping, ConnectionVersion: admission.bindings.ConnectionVersion,
	}
	first, err := inspector.readDirectoryRoleDriftSource(ctx, admission.source, edge)
	if err != nil {
		return out, err
	}
	var local directoryRoleDriftAttribution
	if first == scimpostgres.DirectoryGroupEdgePresent || first == scimpostgres.DirectoryGroupEdgeAbsent {
		local, err = inspector.readDirectoryRoleDriftAttribution(ctx, expected)
		if err != nil {
			return out, err
		}
	}
	// Bracket the two native attribution reads with the original scoped SCIM
	// observation. This does not create a transaction across the two owners.
	current, err := inspector.readDirectoryRoleDriftSource(ctx, admission.source, edge)
	if err != nil {
		return out, err
	}
	if current != first {
		return out, sso.ErrDirectoryReconciliation
	}
	if err := inspector.recheckDirectoryDrift(ctx, batch, resolved, provider); err != nil {
		return out, err
	}
	return classifyDirectoryRoleDrift(current, local, expected), nil
}

func (s *DirectoryGroupSyncService) readDirectoryRoleDriftSource(ctx context.Context, observed scimpostgres.DirectorySourceObservation, edge scimpostgres.DirectoryGroupRoleEdge) (scimpostgres.DirectoryGroupEdgeState, error) {
	states, err := s.config.Source.ReadDirectoryGroupEdgeStates(ctx, observed, []scimpostgres.DirectoryGroupRoleEdge{edge})
	if err != nil {
		return 0, providerError(ctx, err)
	}
	if len(states) != 1 {
		return 0, sso.ErrUnavailable
	}
	if _, err := directoryDriftSource(states[0]); err != nil {
		return 0, err
	}
	return states[0], nil
}

type directoryRoleDriftAttribution struct {
	value    organizationpg.DirectoryTeamRoleAttribution
	observed bool
}

func (s *DirectoryGroupSyncService) readDirectoryRoleDriftAttribution(ctx context.Context, expected organizationpg.DirectoryTeamRoleSource) (directoryRoleDriftAttribution, error) {
	first, err := s.readDirectoryRoleDriftProjection(ctx, expected)
	if err != nil {
		return directoryRoleDriftAttribution{}, err
	}
	current, err := s.readDirectoryRoleDriftProjection(ctx, expected)
	if err != nil {
		return directoryRoleDriftAttribution{}, err
	}
	if first != current {
		return directoryRoleDriftAttribution{}, sso.ErrDirectoryReconciliation
	}
	return current, nil
}

func (s *DirectoryGroupSyncService) readDirectoryRoleDriftProjection(ctx context.Context, expected organizationpg.DirectoryTeamRoleSource) (directoryRoleDriftAttribution, error) {
	value, err := s.organizations.ObserveDirectoryTeamRoleAttribution(ctx, expected.Scope, expected.RoleID)
	switch {
	case err == nil:
		return directoryRoleDriftAttribution{value: value, observed: true}, nil
	case errors.Is(err, organization.ErrForbidden):
		return directoryRoleDriftAttribution{}, nil
	default:
		return directoryRoleDriftAttribution{}, providerError(ctx, err)
	}
}

func classifyDirectoryRoleDrift(source scimpostgres.DirectoryGroupEdgeState, local directoryRoleDriftAttribution, expected organizationpg.DirectoryTeamRoleSource) DirectoryGroupRoleDrift {
	report := DirectoryGroupRoleDrift{Kind: DirectoryGroupRoleDriftConflict, Source: source}
	if !local.observed {
		return report
	}
	value := local.value
	retained := value.RetainedGrantVersion != 0
	if source == scimpostgres.DirectoryGroupEdgeAbsent {
		report.LocalMembership = value.Membership.Local
		report.Kind = DirectoryGroupRoleDriftInSync
		if retained {
			report.Kind = DirectoryGroupRoleDriftUnexpected
		}
		return report
	}
	if source != scimpostgres.DirectoryGroupEdgePresent {
		return report
	}
	currentBinding := value.CurrentRoleVersion != 0 && value.CurrentBindingVersion != 0
	if !retained && !currentBinding {
		return report
	}
	report.LocalMembership = value.Membership.Local
	if !retained {
		report.Kind = DirectoryGroupRoleDriftMissing
		return report
	}
	if currentBinding && value.Membership.Source && value.Membership.Version == value.RetainedGrantVersion &&
		value.CurrentBindingVersion == value.RetainedBindingVersion && value.Retained == expected {
		report.Kind = DirectoryGroupRoleDriftInSync
	} else {
		report.Kind = DirectoryGroupRoleDriftStale
	}
	return report
}
