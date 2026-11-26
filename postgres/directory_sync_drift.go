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

const directoryGroupDriftAction = "identity.sso.directory-sync-inspect-drift"

// The SCIM source reads at most 128 Group edges in one primary snapshot.
// Splitting a preview into multiple source reads would lose that guarantee.
const maximumDirectoryGroupDriftBatch = 128

// ObserveDrift reports the exact source and local attribution for one mapped
// Group child at the current running Apply or dry-run checkpoint. The source
// account needs an independent directory-sync-inspect-drift decision. The
// proposed action does not affect classification and is never executed.
// A report is a bounded observation, not a repair permission, command
// receipt, or checkpoint. Failure returns zero and changes no state.
func (s *DirectoryGroupSyncService) ObserveDrift(ctx context.Context, request DirectoryGroupApplyRequest) (scimorganization.DirectoryMembershipDrift, error) {
	if len(request.Deltas) != 1 {
		return scimorganization.DirectoryMembershipDrift{}, sso.ErrInvalidInput
	}
	reports, err := s.ObserveBatchDrift(ctx, request)
	if err != nil {
		return scimorganization.DirectoryMembershipDrift{}, err
	}
	return reports[0], nil
}

// ObserveBatchDrift reports one classification per mapped Group child in input
// order. It accepts one to 128 Group children at the same running Apply or
// dry-run checkpoint, using the same read authorization as ObserveDrift.
// Do not mutate request.Deltas concurrently with this call. Proposed actions
// do not affect the report. Changed observations or authority return no
// report. Inspection never creates a repair, receipt, or cursor successor.
func (s *DirectoryGroupSyncService) ObserveBatchDrift(ctx context.Context, request DirectoryGroupApplyRequest) (out []scimorganization.DirectoryMembershipDrift, err error) {
	defer func() {
		if recover() != nil {
			out, err = nil, sso.ErrUnavailable
		}
	}()
	if s == nil || s.pool == nil || ctx == nil || !providerID(string(request.ProviderID)) || request.MappingVersion == 0 ||
		request.PredecessorCheckpoint == ([32]byte{}) || len(request.Deltas) == 0 || len(request.Deltas) > maximumDirectoryGroupDriftBatch {
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
	provider, err := s.readDirectoryDriftProvider(ctx, generation)
	if err != nil {
		return out, err
	}
	edges := make([]scimpostgres.DirectoryGroupRoleEdge, len(mapped.Memberships))
	targets := make([]organizationpg.DirectoryTeamGrantScope, len(mapped.Memberships))
	for i, member := range mapped.Memberships {
		edges[i] = scimpostgres.DirectoryGroupRoleEdge{GroupID: member.GroupID, MemberResourceID: member.MemberID, UserID: member.UserID}
		targets[i] = organizationpg.DirectoryTeamGrantScope{
			TenantID: batch.TenantID, OrganizationID: batch.OrganizationID, ProviderID: organization.ID(batch.ProviderID),
			ConnectionID: organization.ID(batch.ConnectionID), GroupID: organization.ID(member.GroupID), TeamID: member.TeamID, UserID: member.UserID,
		}
	}
	first, err := s.readDirectoryGroupDrift(ctx, admission.source, edges, targets)
	if err != nil {
		return out, err
	}
	// These are repeated bounded observations, not a transaction spanning
	// the source and organization owners.
	currentBatch, err := s.readDirectoryGroupDrift(ctx, admission.source, edges, targets)
	if err != nil {
		return out, err
	}
	if !slices.Equal(first, currentBatch) {
		return out, sso.ErrDirectoryReconciliation
	}
	if err := s.recheckDirectoryDrift(ctx, batch, resolved, provider); err != nil {
		return out, err
	}
	reports := make([]scimorganization.DirectoryMembershipDrift, len(currentBatch))
	for i, observation := range currentBatch {
		local := observation.local
		report, err := scimorganization.ClassifyDirectoryMembershipDrift(observation.source, scimorganization.DirectoryLocalMembership{
			Observed: local.observed, Attributed: local.membership.Source, Local: local.membership.Local,
		})
		if err != nil {
			return out, err
		}
		reports[i] = report
	}
	return reports, nil
}

func (s *DirectoryGroupSyncService) readDirectoryDriftProvider(ctx context.Context, generation DirectorySyncGeneration) (directoryRoleProviderAuthority, error) {
	provider, err := s.readDirectoryProviderAuthority(ctx, generation.Provider)
	if err != nil {
		return directoryRoleProviderAuthority{}, err
	}
	if !provider.present || !provider.enabled || provider.version != generation.ProviderVersion || provider.mapping != generation.MappingVersion {
		return directoryRoleProviderAuthority{}, sso.ErrForbidden
	}
	return provider, nil
}

func (s *DirectoryGroupSyncService) recheckDirectoryDrift(ctx context.Context, batch sso.DirectoryDeltaBatch, resolved directoryGroupResolution, provider directoryRoleProviderAuthority) error {
	generation, admission := resolved.stored.current, resolved.admission
	currentProvider, err := s.readDirectoryProviderAuthority(ctx, generation.Provider)
	if err != nil {
		return err
	}
	if currentProvider != provider {
		return sso.ErrForbidden
	}
	current, err := readDirectoryGeneration(ctx, s.pool, generation.ID, batch.TenantID, string(batch.OrganizationID), batch.ConnectionID)
	if err != nil {
		return providerError(ctx, err)
	}
	if current != resolved.stored {
		return sso.ErrDirectoryReconciliation
	}
	epoch, err := s.authority.Get(ctx, admission.scope)
	if err != nil || epoch.Version != admission.epoch || !s.scope.Clock.Now().Before(admission.validUntil) {
		return sso.ErrForbidden
	}
	return ctx.Err()
}

type directoryGroupDriftObservation struct {
	source scimorganization.DirectorySourceMembership
	local  directoryDriftProjection
}

func (s *DirectoryGroupSyncService) readDirectoryGroupDrift(ctx context.Context, observed scimpostgres.DirectorySourceObservation,
	edges []scimpostgres.DirectoryGroupRoleEdge, targets []organizationpg.DirectoryTeamGrantScope,
) ([]directoryGroupDriftObservation, error) {
	states, err := s.config.Source.ReadDirectoryGroupEdgeStates(ctx, observed, edges)
	if err != nil {
		return nil, providerError(ctx, err)
	}
	if len(states) != len(targets) {
		return nil, sso.ErrUnavailable
	}
	observations := make([]directoryGroupDriftObservation, len(states))
	for i, state := range states {
		source, err := directoryDriftSource(state)
		if err != nil {
			return nil, err
		}
		local, err := s.readDirectoryDriftProjection(ctx, targets[i])
		if err != nil {
			return nil, err
		}
		observations[i] = directoryGroupDriftObservation{source: source, local: local}
	}
	return observations, nil
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
