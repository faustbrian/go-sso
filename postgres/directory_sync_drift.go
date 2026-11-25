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

const directoryGroupDriftAction = "identity.sso.directory-sync-inspect-drift"

// ObserveDrift reports the exact source and local attribution for one mapped
// Group child at the current running Apply or dry-run checkpoint. The source
// account needs an independent directory-sync-inspect-drift decision. The
// proposed action does not affect classification and is never executed.
// A report is a bounded observation, not a repair permission, command
// receipt, or checkpoint. Failure returns zero and changes no state.
func (s *DirectoryGroupSyncService) ObserveDrift(ctx context.Context, request DirectoryGroupApplyRequest) (out scimorganization.DirectoryMembershipDrift, err error) {
	defer func() {
		if recover() != nil {
			out, err = scimorganization.DirectoryMembershipDrift{}, sso.ErrUnavailable
		}
	}()
	if s == nil || s.pool == nil || ctx == nil || !providerID(string(request.ProviderID)) || request.MappingVersion == 0 ||
		request.PredecessorCheckpoint == ([32]byte{}) || len(request.Deltas) != 1 {
		return out, sso.ErrInvalidInput
	}
	if _, err := identity.ParseCommandID(string(request.GenerationID)); err != nil {
		return out, sso.ErrInvalidInput
	}
	ctx, cancel := context.WithTimeout(ctx, s.scope.MaximumDuration)
	defer cancel()
	// Reuse the scoped generation resolver with independent read authority;
	// the configured Apply selector is immutable and is not changed here.
	inspector := *s
	inspector.applyAction = directoryGroupDriftAction
	batch, resolved, err := inspector.resolveOpaqueBatch(ctx, request.GenerationID, sso.DirectoryDeltaBatch{
		TenantID: s.scope.TenantID, OrganizationID: s.scope.OrganizationID, ConnectionID: s.scope.ConnectionID,
		ProviderID: request.ProviderID, MappingVersion: request.MappingVersion, PredecessorCheckpoint: request.PredecessorCheckpoint, Deltas: request.Deltas,
	})
	if err != nil {
		return out, err
	}
	generation, admission := resolved.stored.current, resolved.admission
	if generation.State != DirectorySyncRunning || generation.Checkpoint != batch.PredecessorCheckpoint {
		return out, sso.ErrDirectoryReconciliation
	}
	ctx, cancelAdmission := context.WithDeadline(ctx, admission.validUntil)
	defer cancelAdmission()
	mapped, err := s.config.Mapping.MapDirectoryDelta(batch)
	if err != nil {
		if errors.Is(err, scimorganization.ErrInvalidMappingInput) {
			return out, sso.ErrInvalidInput
		}
		return out, sso.ErrForbidden
	}
	provider, err := s.readDirectoryProviderAuthority(ctx, generation.Provider)
	if err != nil {
		return out, err
	}
	if !provider.present || !provider.enabled || provider.version != generation.ProviderVersion || provider.mapping != generation.MappingVersion {
		return out, sso.ErrForbidden
	}
	member := mapped.Memberships[0]
	edge := scimpostgres.DirectoryGroupRoleEdge{GroupID: member.GroupID, MemberResourceID: member.MemberID, UserID: member.UserID}
	target := organizationpg.DirectoryTeamGrantScope{
		TenantID: batch.TenantID, OrganizationID: batch.OrganizationID, ProviderID: organization.ID(batch.ProviderID),
		ConnectionID: organization.ID(batch.ConnectionID), GroupID: organization.ID(member.GroupID), TeamID: member.TeamID, UserID: member.UserID,
	}
	source, err := s.readDirectoryDriftSource(ctx, admission.source, edge)
	if err != nil {
		return out, err
	}
	local, err := s.readDirectoryDriftProjection(ctx, target)
	if err != nil {
		return out, err
	}
	// Keep the report observational rather than retaining locks across
	// owners. Recheck both under the original deadline; changed inputs
	// must not become a report based on a mixed observation.
	currentSource, err := s.readDirectoryDriftSource(ctx, admission.source, edge)
	if err != nil {
		return out, err
	}
	currentLocal, err := s.readDirectoryDriftProjection(ctx, target)
	if err != nil {
		return out, err
	}
	if currentSource != source || currentLocal != local {
		return out, sso.ErrDirectoryReconciliation
	}
	currentProvider, err := s.readDirectoryProviderAuthority(ctx, generation.Provider)
	if err != nil {
		return out, err
	}
	if currentProvider != provider {
		return out, sso.ErrForbidden
	}
	current, err := readDirectoryGeneration(ctx, s.pool, generation.ID, batch.TenantID, string(batch.OrganizationID), batch.ConnectionID)
	if err != nil {
		return out, providerError(ctx, err)
	}
	if current != resolved.stored {
		return out, sso.ErrDirectoryReconciliation
	}
	epoch, err := s.authority.Get(ctx, admission.scope)
	if err != nil || epoch.Version != admission.epoch || !s.scope.Clock.Now().Before(admission.validUntil) {
		return out, sso.ErrForbidden
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	return scimorganization.ClassifyDirectoryMembershipDrift(source, scimorganization.DirectoryLocalMembership{
		Observed: local.observed, Attributed: local.membership.Source, Local: local.membership.Local,
	})
}

func (s *DirectoryGroupSyncService) readDirectoryDriftSource(ctx context.Context, observed scimpostgres.DirectorySourceObservation, edge scimpostgres.DirectoryGroupRoleEdge) (scimorganization.DirectorySourceMembership, error) {
	states, err := s.config.Source.ReadDirectoryGroupEdgeStates(ctx, observed, []scimpostgres.DirectoryGroupRoleEdge{edge})
	if err != nil {
		return 0, providerError(ctx, err)
	}
	if len(states) != 1 {
		return 0, sso.ErrUnavailable
	}
	return directoryDriftSource(states[0])
}

type directoryDriftProjection struct {
	observed   bool
	membership organizationpg.DirectoryTeamMembershipObservation
}

func (s *DirectoryGroupSyncService) readDirectoryDriftProjection(ctx context.Context, scope organizationpg.DirectoryTeamGrantScope) (directoryDriftProjection, error) {
	membership, err := s.organizations.ObserveDirectoryTeamMembership(ctx, scope)
	switch {
	case err == nil:
		return directoryDriftProjection{observed: true, membership: membership}, nil
	case errors.Is(err, organization.ErrForbidden):
		// The trusted exact target is not currently observable. This is not
		// a known absent grant, so the classifier can only report conflict.
		return directoryDriftProjection{}, nil
	default:
		return directoryDriftProjection{}, providerError(ctx, err)
	}
}

func directoryDriftSource(state scimpostgres.DirectoryGroupEdgeState) (scimorganization.DirectorySourceMembership, error) {
	switch state {
	case scimpostgres.DirectoryGroupEdgePresent:
		return scimorganization.DirectorySourceMembershipPresent, nil
	case scimpostgres.DirectoryGroupEdgeAbsent:
		return scimorganization.DirectorySourceMembershipAbsent, nil
	case scimpostgres.DirectoryGroupEdgeInactiveUser:
		return scimorganization.DirectorySourceMembershipInactiveUser, nil
	case scimpostgres.DirectoryGroupEdgeUnproven:
		return scimorganization.DirectorySourceMembershipUnproven, nil
	default:
		return 0, sso.ErrUnavailable
	}
}
