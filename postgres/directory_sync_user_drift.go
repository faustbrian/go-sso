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

const directoryUserDriftAction = "identity.sso.directory-sync-inspect-user-drift"

// DirectoryUserDrift compares the source with the current attributed grant.
// LocalGrant and OtherSource distinguish independent access, not substitutes
// for a grant from this source. Unproven source data yields Conflict and no
// attribution. The report is not a command receipt or repair authority.
type DirectoryUserDrift struct {
	Kind        scimorganization.DirectoryMembershipDriftKind
	Source      scimpostgres.DirectoryUserObservation
	LocalGrant  bool
	OtherSource bool
}

// ObserveDrift inspects one explicitly mapped User delta at the current
// running Apply or dry-run checkpoint. It requires separate service-account
// inspection permission. A changed revision, inconsistent action, or changing
// owner observation returns no report. Inspection never advances a generation.
func (s *DirectoryUserSyncService) ObserveDrift(ctx context.Context, r DirectoryUserApplyRequest) (out DirectoryUserDrift, err error) {
	defer func() {
		if recover() != nil {
			out, err = DirectoryUserDrift{}, sso.ErrUnavailable
		}
	}()
	if s == nil || s.core == nil || ctx == nil || !providerID(string(r.ProviderID)) || r.MappingVersion == 0 || r.PredecessorCheckpoint == ([32]byte{}) {
		return out, sso.ErrInvalidInput
	}
	if _, err := identity.ParseCommandID(string(r.GenerationID)); err != nil {
		return out, sso.ErrInvalidInput
	}
	inspector := *s.core
	inspector.applyAction = directoryUserDriftAction
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
	mapped, err := s.mapping.MapDirectoryUserDelta(batch)
	if errors.Is(err, scimorganization.ErrInvalidMappingInput) {
		return out, sso.ErrInvalidInput
	}
	if err != nil || len(mapped.Users) != 1 {
		return out, sso.ErrForbidden
	}
	provider, err := inspector.readDirectoryDriftProvider(ctx, generation)
	if err != nil {
		return out, err
	}
	intent := mapped.Users[0]
	target := scimpostgres.DirectoryUserTarget{ResourceID: intent.ResourceID, UserID: intent.UserID}
	first, err := inspector.readDirectoryUserSource(ctx, admission.source, target)
	if err != nil {
		return out, err
	}
	var attribution organizationpg.DirectoryMembershipAttribution
	if first != (scimpostgres.DirectoryUserObservation{}) {
		if !matchesDirectoryUserObservation(intent, first) {
			return out, sso.ErrDirectoryReconciliation
		}
		source := organizationpg.DirectoryMembershipSource{
			TenantID: batch.TenantID, OrganizationID: batch.OrganizationID, ProviderID: organization.ID(batch.ProviderID),
			ConnectionID: organization.ID(batch.ConnectionID), ResourceID: organization.ID(intent.ResourceID), UserID: intent.UserID,
		}
		attribution, err = inspector.readStableDirectoryUserAttribution(ctx, source)
		if err != nil {
			return out, err
		}
	}
	// Bracket the organization reads with the exact SCIM revision and its
	// original authority fences; this is not a cross-owner transaction.
	current, err := inspector.readDirectoryUserSource(ctx, admission.source, target)
	if err != nil {
		return out, err
	}
	if current != first {
		return out, sso.ErrDirectoryReconciliation
	}
	if err := inspector.recheckDirectoryDrift(ctx, batch, resolved, provider); err != nil {
		return out, err
	}
	return classifyDirectoryUserDrift(current, attribution), nil
}

func (s *DirectoryGroupSyncService) readDirectoryUserSource(ctx context.Context, observation scimpostgres.DirectorySourceObservation, target scimpostgres.DirectoryUserTarget) (scimpostgres.DirectoryUserObservation, error) {
	states, err := s.config.Source.ReadDirectoryUserStates(ctx, observation, []scimpostgres.DirectoryUserTarget{target})
	if err != nil {
		return scimpostgres.DirectoryUserObservation{}, providerError(ctx, err)
	}
	if len(states) != 1 {
		return scimpostgres.DirectoryUserObservation{}, sso.ErrUnavailable
	}
	return states[0], nil
}

func (s *DirectoryGroupSyncService) readStableDirectoryUserAttribution(ctx context.Context, source organizationpg.DirectoryMembershipSource) (organizationpg.DirectoryMembershipAttribution, error) {
	first, err := s.organizations.ObserveDirectoryMembershipAttribution(ctx, source)
	if err != nil {
		return organizationpg.DirectoryMembershipAttribution{}, providerError(ctx, err)
	}
	current, err := s.organizations.ObserveDirectoryMembershipAttribution(ctx, source)
	if err != nil {
		return organizationpg.DirectoryMembershipAttribution{}, providerError(ctx, err)
	}
	if current != first {
		return organizationpg.DirectoryMembershipAttribution{}, sso.ErrDirectoryReconciliation
	}
	return current, nil
}

func matchesDirectoryUserObservation(intent scimorganization.DirectoryUserIntent, source scimpostgres.DirectoryUserObservation) bool {
	if string(source.Revision) != intent.SourceRevision {
		return false
	}
	switch intent.Action {
	case scimorganization.DirectoryUserAdmit:
		return source.State == scimpostgres.DirectoryMembershipUserActive
	case scimorganization.DirectoryUserWithdrawInactive:
		return source.State == scimpostgres.DirectoryMembershipUserInactive
	case scimorganization.DirectoryUserWithdrawDeleted:
		return source.State == scimpostgres.DirectoryMembershipUserDeleted
	default:
		return false
	}
}

func classifyDirectoryUserDrift(source scimpostgres.DirectoryUserObservation, attribution organizationpg.DirectoryMembershipAttribution) DirectoryUserDrift {
	if source == (scimpostgres.DirectoryUserObservation{}) {
		return DirectoryUserDrift{Kind: scimorganization.DirectoryMembershipDriftConflict}
	}
	report := DirectoryUserDrift{Kind: scimorganization.DirectoryMembershipDriftInSync, Source: source,
		LocalGrant: attribution.Local, OtherSource: attribution.OtherSource}
	active := source.State == scimpostgres.DirectoryMembershipUserActive
	attributed := attribution.Membership.Member.Active && attribution.Membership.ContributionActive
	switch {
	case active && !attributed:
		report.Kind = scimorganization.DirectoryMembershipDriftMissingSourceGrant
	case !active && attributed:
		report.Kind = scimorganization.DirectoryMembershipDriftUnexpectedSourceGrant
	}
	return report
}
