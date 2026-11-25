package postgres

import (
	"context"
	"fmt"
	"reflect"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	database "github.com/faustbrian/go-postgres"
	scimorganization "github.com/faustbrian/go-scim/organization"
	scimpostgres "github.com/faustbrian/go-scim/postgres"
	"github.com/faustbrian/go-sso"
)

// DirectoryUserSyncConfig selects the same tenant, organization, connection
// and command policy as Group Apply, without selecting the Group profile.
type DirectoryUserSyncConfig DirectoryGroupSyncConfig

// DirectorySyncUserAuthorization authorizes the exact generation Apply for the
// source service account. The supplied deadline is not refreshed within Work.
type DirectorySyncUserAuthorization interface {
	ObserveDirectoryUserAuthorization(context.Context, authorization.DecisionContext, uint64) (ProviderUpdateAuthorizationEvidence, error)
}

// DirectorySyncUsersConfig explicitly selects source-owned ordinary member
// admission and withdrawal. Mapping selects the allowed child actions;
// Authorization separately authorizes the exact child admission and recovery.
// Capacity is applied only when a new effective member is granted.
type DirectorySyncUsersConfig struct {
	Source             *scimpostgres.GroupsService
	Mapping            scimorganization.DirectoryUserMapper
	Authorization      authorization.Service
	ApplyAuthorization DirectorySyncUserAuthorization
	AuthorityNamespace string
	MaximumMembers     uint64
	MaximumPerUser     uint64
}

// DirectoryUserSyncService applies one User delta to an existing generation.
// It borrows the same generation and journal owners as Group Apply and
// creates no background worker, HTTP route or separate idempotency state.
type DirectoryUserSyncService struct {
	core    *DirectoryGroupSyncService
	mapping scimorganization.DirectoryUserMapper
	limits  directoryUserCapacity
}

type directoryUserCapacity struct {
	members uint64
	perUser uint64
}

type directoryUserApplyAuthorization struct{ DirectorySyncUserAuthorization }

func (a directoryUserApplyAuthorization) ObserveDirectoryGroupAuthorization(ctx context.Context, d authorization.DecisionContext, epoch uint64) (ProviderUpdateAuthorizationEvidence, error) {
	return a.ObserveDirectoryUserAuthorization(ctx, d, epoch)
}

// NewDirectoryUserSyncService selects User Apply without a human session.
// Install the existing native generation, SCIM and directory membership
// histories first. Construction performs no I/O; the caller retains the
// primary, source and concurrent-safe policy owners for the service lifetime.
func NewDirectoryUserSyncService(pool *database.Pool, scope DirectoryUserSyncConfig, c DirectorySyncUsersConfig) (*DirectoryUserSyncService, error) {
	if c.MaximumMembers == 0 || c.MaximumPerUser == 0 || !directoryUserPolicyPresent(c.ApplyAuthorization) {
		return nil, sso.ErrInvalidInput
	}
	core, err := NewDirectoryGroupSyncService(pool, DirectoryGroupSyncConfig(scope), DirectorySyncGroupEdgesConfig{
		Source: c.Source, Authorization: c.Authorization, ApplyAuthorization: directoryUserApplyAuthorization{c.ApplyAuthorization}, AuthorityNamespace: c.AuthorityNamespace,
	})
	if err != nil {
		return nil, err
	}
	return &DirectoryUserSyncService{core: core, mapping: c.Mapping, limits: directoryUserCapacity{members: c.MaximumMembers, perUser: c.MaximumPerUser}}, nil
}

func directoryUserPolicyPresent(owner DirectorySyncUserAuthorization) bool {
	if owner == nil {
		return false
	}
	v := reflect.ValueOf(owner)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return !v.IsNil()
	default:
		return true
	}
}

// WithUserMembership composes the opt-in User profile with this bound native
// generation. Authentication of every Apply still belongs to the source
// service account, not the human who operates the generation control plane.
func (s *DirectorySyncService) WithUserMembership(c DirectorySyncUsersConfig) (*DirectoryUserSyncService, error) {
	if s == nil || s.provider == nil {
		return nil, sso.ErrInvalidInput
	}
	p := s.provider
	return NewDirectoryUserSyncService(p.pool, DirectoryUserSyncConfig{
		TenantID: p.authentication.TenantID, OrganizationID: organization.ID(p.updateOrganization), ConnectionID: s.connection,
		Clock: p.config.Clock, MaximumDuration: p.config.MaximumDuration, PolicyID: p.config.PolicyID, PolicyVersion: p.config.PolicyVersion,
		Coordinator: p.config.Coordinator,
	}, c)
}

// DirectoryUserApplyRequest identifies one User delta by the actual opaque
// generation ID. Retry unknown work with the exact original request.
type DirectoryUserApplyRequest struct {
	GenerationID          identity.CommandID
	ProviderID            sso.ProviderID
	MappingVersion        uint64
	PredecessorCheckpoint [32]byte
	Delta                 sso.DirectoryDelta
}

// ApplyGeneration applies one selected User delta and advances the generation
// only after the authoritative receipt. An exact retry recovers the old
// command before preparing any new organization update. Multiple children
// cannot share the original organization observation after a member changes.
func (s *DirectoryUserSyncService) ApplyGeneration(ctx context.Context, r DirectoryUserApplyRequest) (out sso.DirectoryApplyResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = sso.DirectoryApplyResult{}, sso.ErrUnavailable
		}
	}()
	if s == nil || s.core == nil || ctx == nil || !providerID(string(r.ProviderID)) || r.MappingVersion == 0 || r.PredecessorCheckpoint == ([32]byte{}) {
		return out, sso.ErrInvalidInput
	}
	if _, err := identity.ParseCommandID(string(r.GenerationID)); err != nil {
		return out, sso.ErrInvalidInput
	}
	core := s.core
	ctx, cancel := context.WithTimeout(ctx, core.scope.MaximumDuration)
	defer cancel()
	batch, selected, err := core.resolveOpaqueBatch(ctx, r.GenerationID, sso.DirectoryDeltaBatch{
		TenantID: core.scope.TenantID, OrganizationID: core.scope.OrganizationID, ConnectionID: core.scope.ConnectionID,
		ProviderID: r.ProviderID, MappingVersion: r.MappingVersion, PredecessorCheckpoint: r.PredecessorCheckpoint, Deltas: []sso.DirectoryDelta{r.Delta},
	})
	if err != nil {
		return out, err
	}
	mapped, err := s.mapping.MapDirectoryUserDelta(batch)
	if err != nil || len(mapped.Users) != 1 {
		return out, sso.ErrForbidden
	}
	batch = mapped.Source
	base, err := core.prepareBatch(ctx, r.GenerationID, batch, &selected, true)
	if err != nil {
		return out, err
	}
	child, err := base.prepareUser(mapped.Users[0], s.limits)
	if err != nil {
		return out, err
	}
	receipt, absent, err := child.executeOriginal(ctx)
	if absent {
		return out, sso.ErrForbidden
	}
	if err != nil && receipt.Feature == nil {
		return out, err
	}
	result, bindErr := sso.NewDirectoryApplyResult(batch, []sso.Completion{receipt})
	if bindErr != nil || receipt.Binding != child.binding {
		return out, sso.ErrDirectoryReconciliation
	}
	if err != nil {
		if result.Checkpoint == ([32]byte{}) && child.mayDisclose() {
			return result, err
		}
		return out, err
	}
	if err := child.settle(ctx, result); err != nil {
		return out, err
	}
	if !child.mayDisclose() {
		return out, sso.ErrForbidden
	}
	return result, nil
}

func (DirectoryUserSyncConfig) Format(s fmt.State, _ rune) {
	_, _ = fmt.Fprint(s, "sso.postgres.DirectoryUserSyncConfig(redacted)")
}

func (DirectorySyncUsersConfig) Format(s fmt.State, _ rune) {
	_, _ = fmt.Fprint(s, "sso.postgres.DirectorySyncUsersConfig(redacted)")
}

func (DirectoryUserSyncService) Format(s fmt.State, _ rune) {
	_, _ = fmt.Fprint(s, "sso.postgres.DirectoryUserSyncService(redacted)")
}

func (DirectoryUserApplyRequest) Format(s fmt.State, _ rune) {
	_, _ = fmt.Fprint(s, "sso.postgres.DirectoryUserApplyRequest(redacted)")
}

func (DirectoryUserSyncConfig) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}
func (DirectorySyncUsersConfig) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}
func (DirectoryUserSyncService) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}
func (DirectoryUserApplyRequest) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}
