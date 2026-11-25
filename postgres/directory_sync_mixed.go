package postgres

import (
	"context"
	"fmt"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	database "github.com/faustbrian/go-postgres"
	scimorganization "github.com/faustbrian/go-scim/organization"
	scimpostgres "github.com/faustbrian/go-scim/postgres"
	"github.com/faustbrian/go-sso"
)

const directoryMixedApplyAction = "identity.sso.directory-sync-apply-mixed"

// DirectorySyncMixedConfig explicitly opts the configured directory service
// account into ordered User, Group and custom-role children. ApplyAuthorization
// must allow the mixed generation action; Authorization separately owns exact
// child admission and receipt recovery. Capacity applies to effective members.
type DirectorySyncMixedConfig struct {
	Source             *scimpostgres.GroupsService
	Mapping            scimorganization.DirectoryMixedMapper
	Authorization      authorization.Service
	ApplyAuthorization DirectorySyncGroupAuthorization
	AuthorityNamespace string
	MaximumMembers     uint64
	MaximumPerUser     uint64
}

// DirectoryMixedSyncService borrows the native generation and original child
// owners for a mixed batch. It creates no workers, routes or replay store.
type DirectoryMixedSyncService struct {
	core    *DirectoryGroupSyncService
	mapping scimorganization.DirectoryMixedMapper
	limits  directoryUserCapacity
}

// DirectoryMixedApplyRequest binds the original typed delta order to an opaque
// generation and predecessor. Keep the exact input and child IDs for retries.
// The caller must not mutate Deltas concurrently with ApplyGeneration.
type DirectoryMixedApplyRequest DirectoryGroupApplyRequest

// NewDirectoryMixedSyncService borrows the configured source, primary and
// concurrent-safe authorizers. Install both native membership/role histories as
// selected, plus the directory membership successor history, before enabling
// this service. A role with a following child requires the role successor expansion.
// Construction performs no IO or authorization calls.
func NewDirectoryMixedSyncService(pool *database.Pool, scope DirectoryGroupSyncConfig, c DirectorySyncMixedConfig) (*DirectoryMixedSyncService, error) {
	if c.Mapping == (scimorganization.DirectoryMixedMapper{}) || c.MaximumMembers == 0 || c.MaximumPerUser == 0 {
		return nil, sso.ErrInvalidInput
	}
	core, err := NewDirectoryGroupSyncService(pool, scope, DirectorySyncGroupEdgesConfig{
		Source: c.Source, Authorization: c.Authorization, ApplyAuthorization: c.ApplyAuthorization, AuthorityNamespace: c.AuthorityNamespace,
	})
	if err != nil {
		return nil, err
	}
	core.applyAction = directoryMixedApplyAction
	return &DirectoryMixedSyncService{core: core, mapping: c.Mapping, limits: directoryUserCapacity{members: c.MaximumMembers, perUser: c.MaximumPerUser}}, nil
}

// WithMixedChildren selects mixed work for the existing exact native generation
// scope. The administration session does not authorize the directory actor.
func (s *DirectorySyncService) WithMixedChildren(c DirectorySyncMixedConfig) (*DirectoryMixedSyncService, error) {
	if s == nil || s.provider == nil {
		return nil, sso.ErrInvalidInput
	}
	p := s.provider
	return NewDirectoryMixedSyncService(p.pool, DirectoryGroupSyncConfig{
		TenantID: p.authentication.TenantID, OrganizationID: organization.ID(p.updateOrganization), ConnectionID: s.connection,
		Clock: p.config.Clock, MaximumDuration: p.config.MaximumDuration, PolicyID: p.config.PolicyID, PolicyVersion: p.config.PolicyVersion,
		Coordinator: p.config.Coordinator,
	}, c)
}

// ApplyGeneration executes the exact mapped order under the original bounded
// source and service-account evidence. A resumed batch recovers original
// child receipts and verifies its committed User and role transitions before
// new effects.
// No unresolved prefix can advance the generation checkpoint. Cancellation
// permits receipt reconciliation but no new grant.
func (s *DirectoryMixedSyncService) ApplyGeneration(ctx context.Context, r DirectoryMixedApplyRequest) (out sso.DirectoryApplyResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = sso.DirectoryApplyResult{}, sso.ErrUnavailable
		}
	}()
	if s == nil || s.core == nil || ctx == nil || !providerID(string(r.ProviderID)) || r.MappingVersion == 0 ||
		r.PredecessorCheckpoint == ([32]byte{}) || len(r.Deltas) == 0 {
		return out, sso.ErrInvalidInput
	}
	if _, err := identity.ParseCommandID(string(r.GenerationID)); err != nil {
		return out, sso.ErrInvalidInput
	}
	core := s.core
	ctx, cancel := context.WithTimeout(ctx, core.scope.MaximumDuration)
	defer cancel()
	batch, resolved, err := core.resolveOpaqueBatch(ctx, r.GenerationID, sso.DirectoryDeltaBatch{
		TenantID: core.scope.TenantID, OrganizationID: core.scope.OrganizationID, ConnectionID: core.scope.ConnectionID,
		ProviderID: r.ProviderID, MappingVersion: r.MappingVersion, PredecessorCheckpoint: r.PredecessorCheckpoint, Deltas: r.Deltas,
	})
	if err != nil {
		return out, err
	}
	mapped, err := s.mapping.MapDirectoryMixedDelta(batch)
	if err != nil {
		return out, sso.ErrForbidden
	}
	base, err := core.prepareProfileBatch(ctx, r.GenerationID, mapped.Source, &resolved, len(mapped.Children) == 1, func(commitment [32]byte) [32]byte {
		return directoryMixedCommitment(commitment, mapped.Children)
	})
	if err != nil {
		return out, err
	}
	receipts, stopped, err := s.execute(ctx, base, mapped.Children)
	return finishDirectoryMixed(ctx, base, receipts, stopped, err)
}

func (s *DirectoryMixedSyncService) execute(ctx context.Context, base *directorySyncChild, children []scimorganization.DirectoryMixedIntent) ([]sso.Completion, bool, error) {
	recoveringPrefix := true
	var historical []organizationpg.DirectorySourceCommittedChild
	beforeNew := func() error {
		if !base.mayDisclose() {
			return sso.ErrForbidden
		}
		if recoveringPrefix && len(historical) != 0 {
			if err := s.core.config.Source.ValidateDirectorySourceSuccessorPrefix(ctx, base.admission.source, historical); err != nil {
				return sso.ErrDirectoryReconciliation
			}
		}
		recoveringPrefix = false
		if !base.mayDisclose() {
			return sso.ErrForbidden
		}
		return nil
	}
	return executeDirectoryChildSequence(base, len(children), func(i int) (sso.Completion, bool, error) {
		hasSuffix := i+1 < len(children)
		child, err := s.prepare(base, children[i], hasSuffix)
		if err != nil {
			return sso.Completion{}, false, err
		}
		receipt, absent, err := child.executeOriginalAfter(ctx, beforeNew)
		changesOwner := child.user != nil || child.role != nil
		if err != nil || absent || !changesOwner || receipt.Outcome != identity.CommitOutcomeCommitted {
			return receipt, absent, err
		}
		if recoveringPrefix {
			prior, err := child.committedOwnerChild(receipt)
			if err != nil {
				return receipt, false, sso.ErrDirectoryReconciliation
			}
			historical = append(historical, prior)
		} else if hasSuffix {
			advanced, err := s.advanceSource(ctx, base.admission.source, child, receipt)
			if err != nil {
				return receipt, false, sso.ErrDirectoryReconciliation
			}
			base.admission.source = advanced
		}
		return receipt, false, nil
	})
}

func (p *directorySyncChild) committedOwnerChild(receipt sso.Completion) (organizationpg.DirectorySourceCommittedChild, error) {
	if p.user != nil {
		return organizationpg.NewDirectoryMembershipCommittedChild(p.user.source, receipt)
	}
	return organizationpg.NewDirectoryTeamRoleCommittedChild(p.role.source, receipt)
}

func (s *DirectoryMixedSyncService) advanceSource(ctx context.Context, original scimpostgres.DirectorySourceObservation, child *directorySyncChild, receipt sso.Completion) (scimpostgres.DirectorySourceObservation, error) {
	source := s.core.config.Source
	if child.user != nil {
		return source.AdvanceDirectorySourceAfterUserCommit(ctx, original, child.user.evidence.ResourceID, receipt)
	}
	return source.AdvanceDirectorySourceAfterRoleCommit(ctx, original, child.role.source, receipt)
}

func (s *DirectoryMixedSyncService) prepare(base *directorySyncChild, intent scimorganization.DirectoryMixedIntent, hasSuffix bool) (*directorySyncChild, error) {
	if user, ok := intent.User(); ok {
		child, err := base.prepareUser(user, s.limits)
		if err != nil {
			return nil, err
		}
		child.recordOwnerSuccessor = true
		return child, nil
	}
	if role, ok := intent.Role(); ok {
		child, err := base.prepareRole(role)
		if err != nil {
			return nil, err
		}
		// No child can consume a terminal role's successor. Keeping it unset
		// preserves the existing role-last profile on its installed history.
		child.recordOwnerSuccessor = hasSuffix
		return child, nil
	}
	if group, ok := intent.Membership(); ok {
		return base.prepareChild(group)
	}
	return nil, sso.ErrInvalidInput
}

func finishDirectoryMixed(ctx context.Context, base *directorySyncChild, receipts []sso.Completion, stopped bool, executionErr error) (sso.DirectoryApplyResult, error) {
	var zero sso.DirectoryApplyResult
	if len(receipts) == 0 {
		if executionErr != nil {
			return zero, executionErr
		}
		return zero, sso.ErrDirectoryReconciliation
	}
	var result sso.DirectoryApplyResult
	var err error
	if len(receipts) < len(base.batch.Deltas) {
		result, err = sso.NewDirectoryReconciliationResult(base.batch, receipts)
	} else {
		result, err = sso.NewDirectoryApplyResult(base.batch, receipts)
	}
	if err != nil {
		return zero, sso.ErrDirectoryReconciliation
	}
	if !base.mayDisclose() {
		return zero, sso.ErrForbidden
	}
	if result.Checkpoint == ([32]byte{}) {
		if stopped {
			if err := base.settleStopped(ctx); err != nil {
				if !base.mayDisclose() {
					return zero, sso.ErrForbidden
				}
				return result, err
			}
			if !base.mayDisclose() {
				return zero, sso.ErrForbidden
			}
		}
		if executionErr == nil {
			executionErr = sso.ErrDirectoryReconciliation
		}
		return result, executionErr
	}
	if executionErr != nil {
		return zero, executionErr
	}
	if err := base.settle(ctx, result); err != nil {
		return zero, err
	}
	if !base.mayDisclose() {
		return zero, sso.ErrForbidden
	}
	return result, nil
}

func (DirectorySyncMixedConfig) Format(s fmt.State, _ rune) {
	_, _ = fmt.Fprint(s, "sso.postgres.DirectorySyncMixedConfig(redacted)")
}
func (DirectoryMixedSyncService) Format(s fmt.State, _ rune) {
	_, _ = fmt.Fprint(s, "sso.postgres.DirectoryMixedSyncService(redacted)")
}
func (DirectoryMixedApplyRequest) Format(s fmt.State, _ rune) {
	_, _ = fmt.Fprint(s, "sso.postgres.DirectoryMixedApplyRequest(redacted)")
}
func (DirectorySyncMixedConfig) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}
func (DirectoryMixedSyncService) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}
func (DirectoryMixedApplyRequest) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}
