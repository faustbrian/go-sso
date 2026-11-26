package postgres

import (
	"context"
	"errors"
	"slices"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	scimorganization "github.com/faustbrian/go-scim/organization"
	scimpostgres "github.com/faustbrian/go-scim/postgres"
	"github.com/faustbrian/go-sso"
)

const directoryMixedDriftAction = "identity.sso.directory-sync-inspect-mixed-drift"

// DirectoryMixedDriftKind selects one report in a successful mixed preview.
// Zero is not a valid report kind.
type DirectoryMixedDriftKind uint8

const (
	DirectoryMixedDriftUser DirectoryMixedDriftKind = iota + 1
	DirectoryMixedDriftGroup
	DirectoryMixedDriftRole
)

// DirectoryMixedDrift reports one candidate in the original request order.
// Only the field selected by Kind is populated. It observes current state,
// not the projected effects of this candidate or any earlier candidate.
type DirectoryMixedDrift struct {
	Kind  DirectoryMixedDriftKind
	User  DirectoryUserDrift
	Group scimorganization.DirectoryMembershipDrift
	Role  DirectoryGroupRoleDrift
}

// ObserveBatchDrift inspects one to 128 explicitly mapped children at the
// same running Apply or dry-run checkpoint. The configured source account
// needs a separate mixed inspection decision. Do not mutate the request's
// Deltas concurrently with this call. Changed evidence or any error returns
// no report; inspection does not write, advance a cursor or authorize Apply.
func (s *DirectoryMixedSyncService) ObserveBatchDrift(ctx context.Context, request DirectoryMixedApplyRequest) (out []DirectoryMixedDrift, err error) {
	defer func() {
		if recover() != nil {
			out, err = nil, sso.ErrUnavailable
		}
	}()
	if s == nil || s.core == nil || ctx == nil || !providerID(string(request.ProviderID)) || request.MappingVersion == 0 ||
		request.PredecessorCheckpoint == ([32]byte{}) || len(request.Deltas) == 0 || len(request.Deltas) > maximumDirectoryGroupDriftBatch {
		return nil, sso.ErrInvalidInput
	}
	if _, err := identity.ParseCommandID(string(request.GenerationID)); err != nil {
		return nil, sso.ErrInvalidInput
	}
	inspector := *s.core
	inspector.applyAction = directoryMixedDriftAction
	ctx, cancel := context.WithTimeout(ctx, inspector.scope.MaximumDuration)
	defer cancel()
	batch, resolved, err := inspector.resolveOpaqueBatch(ctx, request.GenerationID, sso.DirectoryDeltaBatch{
		TenantID: inspector.scope.TenantID, OrganizationID: inspector.scope.OrganizationID, ConnectionID: inspector.scope.ConnectionID,
		ProviderID: request.ProviderID, MappingVersion: request.MappingVersion, PredecessorCheckpoint: request.PredecessorCheckpoint, Deltas: request.Deltas,
	})
	if err != nil {
		return nil, err
	}
	generation, admission := resolved.stored.current, resolved.admission
	if generation.State != DirectorySyncRunning || generation.Checkpoint != batch.PredecessorCheckpoint {
		return nil, sso.ErrDirectoryReconciliation
	}
	ctx, finish := context.WithDeadline(ctx, admission.validUntil)
	defer finish()
	mapped, err := s.mapping.MapDirectoryMixedDelta(batch)
	if errors.Is(err, scimorganization.ErrInvalidMappingInput) {
		return nil, sso.ErrInvalidInput
	}
	if err != nil {
		return nil, sso.ErrForbidden
	}
	provider, err := inspector.readDirectoryDriftProvider(ctx, generation)
	if err != nil {
		return nil, err
	}
	targets, err := planDirectoryMixedDrift(mapped, provider, admission.bindings.ConnectionVersion)
	if err != nil {
		return nil, err
	}
	firstSource, err := inspector.readMixedDriftSource(ctx, admission.source, targets)
	if err != nil {
		return nil, err
	}
	firstLocal, err := inspector.readMixedDriftLocal(ctx, targets, firstSource)
	if err != nil {
		return nil, err
	}
	currentLocal, err := inspector.readMixedDriftLocal(ctx, targets, firstSource)
	if err != nil {
		return nil, err
	}
	if !slices.Equal(firstLocal, currentLocal) {
		return nil, sso.ErrDirectoryReconciliation
	}
	// Bracket both native passes with the original bounded SCIM observation;
	// this does not create a snapshot or transaction across owners.
	currentSource, err := inspector.readMixedDriftSource(ctx, admission.source, targets)
	if err != nil {
		return nil, err
	}
	if !slices.Equal(firstSource.users, currentSource.users) || !slices.Equal(firstSource.edges, currentSource.edges) {
		return nil, sso.ErrDirectoryReconciliation
	}
	reports, err := classifyDirectoryMixedDrift(targets, currentSource, currentLocal)
	if err != nil {
		return nil, err
	}
	if err := inspector.recheckDirectoryDrift(ctx, batch, resolved, provider); err != nil {
		return nil, err
	}
	return reports, nil
}

type directoryMixedDriftCandidate struct {
	kind        DirectoryMixedDriftKind
	sourceIndex int
	userIntent  scimorganization.DirectoryUserIntent
	userSource  organizationpg.DirectoryMembershipSource
	groupScope  organizationpg.DirectoryTeamGrantScope
	roleSource  organizationpg.DirectoryTeamRoleSource
}

type directoryMixedDriftTargets struct {
	ordered []directoryMixedDriftCandidate
	users   []scimpostgres.DirectoryUserTarget
	edges   []scimpostgres.DirectoryGroupRoleEdge
}

func planDirectoryMixedDrift(mapped scimorganization.DirectoryMixedBatch, provider directoryRoleProviderAuthority, connectionVersion uint64) (directoryMixedDriftTargets, error) {
	batch := mapped.Source
	targets := directoryMixedDriftTargets{ordered: make([]directoryMixedDriftCandidate, 0, len(mapped.Children))}
	teamScope := func(member scimorganization.DirectoryMembershipIntent) organizationpg.DirectoryTeamGrantScope {
		return organizationpg.DirectoryTeamGrantScope{
			TenantID: batch.TenantID, OrganizationID: batch.OrganizationID, ProviderID: organization.ID(batch.ProviderID),
			ConnectionID: organization.ID(batch.ConnectionID), GroupID: organization.ID(member.GroupID), TeamID: member.TeamID, UserID: member.UserID,
		}
	}
	for _, child := range mapped.Children {
		if user, ok := child.User(); ok {
			targets.ordered = append(targets.ordered, directoryMixedDriftCandidate{
				kind: DirectoryMixedDriftUser, sourceIndex: len(targets.users), userIntent: user,
				userSource: organizationpg.DirectoryMembershipSource{
					TenantID: batch.TenantID, OrganizationID: batch.OrganizationID, ProviderID: organization.ID(batch.ProviderID),
					ConnectionID: organization.ID(batch.ConnectionID), ResourceID: organization.ID(user.ResourceID), UserID: user.UserID,
				},
			})
			targets.users = append(targets.users, scimpostgres.DirectoryUserTarget{ResourceID: user.ResourceID, UserID: user.UserID})
			continue
		}
		if member, ok := child.Membership(); ok {
			targets.ordered = append(targets.ordered, directoryMixedDriftCandidate{
				kind: DirectoryMixedDriftGroup, sourceIndex: len(targets.edges), groupScope: teamScope(member),
			})
			targets.edges = append(targets.edges, scimpostgres.DirectoryGroupRoleEdge{GroupID: member.GroupID, MemberResourceID: member.MemberID, UserID: member.UserID})
			continue
		}
		if role, ok := child.Role(); ok {
			member := role.Membership
			targets.ordered = append(targets.ordered, directoryMixedDriftCandidate{
				kind: DirectoryMixedDriftRole, sourceIndex: len(targets.edges),
				roleSource: organizationpg.DirectoryTeamRoleSource{
					Scope: teamScope(member), MemberResourceID: organization.ID(member.MemberID), RoleID: role.RoleID,
					ProviderVersion: provider.version, MappingVersion: provider.mapping, ConnectionVersion: connectionVersion,
				},
			})
			targets.edges = append(targets.edges, scimpostgres.DirectoryGroupRoleEdge{GroupID: member.GroupID, MemberResourceID: member.MemberID, UserID: member.UserID})
			continue
		}
		return directoryMixedDriftTargets{}, sso.ErrUnavailable
	}
	return targets, nil
}

type directoryMixedDriftSource struct {
	users []scimpostgres.DirectoryUserObservation
	edges []scimpostgres.DirectoryGroupEdgeState
}

func (s *DirectoryGroupSyncService) readMixedDriftSource(ctx context.Context, original scimpostgres.DirectorySourceObservation, targets directoryMixedDriftTargets) (directoryMixedDriftSource, error) {
	var source directoryMixedDriftSource
	var err error
	if len(targets.users) > 0 {
		source.users, err = s.config.Source.ReadDirectoryUserStates(ctx, original, targets.users)
		if err != nil {
			return directoryMixedDriftSource{}, providerError(ctx, err)
		}
	}
	if len(targets.edges) > 0 {
		source.edges, err = s.config.Source.ReadDirectoryGroupEdgeStates(ctx, original, targets.edges)
		if err != nil {
			return directoryMixedDriftSource{}, providerError(ctx, err)
		}
	}
	if len(source.users) != len(targets.users) || len(source.edges) != len(targets.edges) {
		return directoryMixedDriftSource{}, sso.ErrUnavailable
	}
	for _, candidate := range targets.ordered {
		if candidate.kind == DirectoryMixedDriftUser {
			observed := source.users[candidate.sourceIndex]
			if observed != (scimpostgres.DirectoryUserObservation{}) && !matchesDirectoryUserObservation(candidate.userIntent, observed) {
				return directoryMixedDriftSource{}, sso.ErrDirectoryReconciliation
			}
			continue
		}
		if _, err := directoryDriftSource(source.edges[candidate.sourceIndex]); err != nil {
			return directoryMixedDriftSource{}, err
		}
	}
	return source, nil
}

type directoryMixedDriftLocal struct {
	user  organizationpg.DirectoryMembershipAttribution
	group directoryDriftProjection
	role  directoryRoleDriftAttribution
}

func (s *DirectoryGroupSyncService) readMixedDriftLocal(ctx context.Context, targets directoryMixedDriftTargets, source directoryMixedDriftSource) ([]directoryMixedDriftLocal, error) {
	local := make([]directoryMixedDriftLocal, len(targets.ordered))
	for i, candidate := range targets.ordered {
		var err error
		switch candidate.kind {
		case DirectoryMixedDriftUser:
			if source.users[candidate.sourceIndex] != (scimpostgres.DirectoryUserObservation{}) {
				local[i].user, err = s.organizations.ObserveDirectoryMembershipAttribution(ctx, candidate.userSource)
				err = providerError(ctx, err)
			}
		case DirectoryMixedDriftGroup:
			local[i].group, err = s.readDirectoryDriftProjection(ctx, candidate.groupScope)
		case DirectoryMixedDriftRole:
			state := source.edges[candidate.sourceIndex]
			if state == scimpostgres.DirectoryGroupEdgePresent || state == scimpostgres.DirectoryGroupEdgeAbsent {
				local[i].role, err = s.readDirectoryRoleDriftProjection(ctx, candidate.roleSource)
			}
		}
		if err != nil {
			return nil, err
		}
	}
	return local, nil
}

func classifyDirectoryMixedDrift(targets directoryMixedDriftTargets, source directoryMixedDriftSource, local []directoryMixedDriftLocal) ([]DirectoryMixedDrift, error) {
	reports := make([]DirectoryMixedDrift, len(targets.ordered))
	for i, candidate := range targets.ordered {
		report := DirectoryMixedDrift{Kind: candidate.kind}
		switch candidate.kind {
		case DirectoryMixedDriftUser:
			report.User = classifyDirectoryUserDrift(source.users[candidate.sourceIndex], local[i].user)
		case DirectoryMixedDriftGroup:
			state, err := directoryDriftSource(source.edges[candidate.sourceIndex])
			if err != nil {
				return nil, err
			}
			group := local[i].group
			report.Group, err = scimorganization.ClassifyDirectoryMembershipDrift(state, scimorganization.DirectoryLocalMembership{
				Observed: group.observed, Attributed: group.membership.Source, Local: group.membership.Local,
			})
			if err != nil {
				return nil, err
			}
		case DirectoryMixedDriftRole:
			report.Role = classifyDirectoryRoleDrift(source.edges[candidate.sourceIndex], local[i].role, candidate.roleSource)
		default:
			return nil, sso.ErrUnavailable
		}
		reports[i] = report
	}
	return reports, nil
}
