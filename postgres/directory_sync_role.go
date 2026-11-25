package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	database "github.com/faustbrian/go-postgres"
	scimorganization "github.com/faustbrian/go-scim/organization"
	scimpostgres "github.com/faustbrian/go-scim/postgres"
	"github.com/faustbrian/go-sso"
)

const directoryRoleApplyAction = "identity.sso.directory-sync-apply-role"

// DirectoryGroupRoleSyncConfig selects the trusted primary generation and
// command scope without enabling membership-only Group Apply.
type DirectoryGroupRoleSyncConfig DirectoryGroupSyncConfig

// DirectorySyncRoleAuthorization authorizes the exact configured source
// service account to apply a role-bearing edge to the selected generation.
// Its original deadline is preserved throughout the protected command.
type DirectorySyncRoleAuthorization interface {
	ObserveDirectoryRoleAuthorization(context.Context, authorization.DecisionContext, uint64) (ProviderUpdateAuthorizationEvidence, error)
}

// DirectorySyncGroupRolesConfig opts into explicit Group/team/custom-role
// mapping. Authorization owns child admission and original receipt recovery;
// ApplyAuthorization separately grants role-specific generation access.
type DirectorySyncGroupRolesConfig struct {
	Source             *scimpostgres.GroupsService
	Mapping            scimorganization.DirectoryRoleMapper
	Authorization      authorization.Service
	ApplyAuthorization DirectorySyncRoleAuthorization
	AuthorityNamespace string
}

// DirectoryGroupRoleSyncService applies one exact role-bearing edge to a native
// generation and supplies current source authority for opted-in organization
// permission reads. It owns no routes, goroutines or separate receipt state.
type DirectoryGroupRoleSyncService struct {
	core    *DirectoryGroupSyncService
	mapping scimorganization.DirectoryRoleMapper
}

type directoryRoleApplyAuthorization struct{ DirectorySyncRoleAuthorization }

func (a directoryRoleApplyAuthorization) ObserveDirectoryGroupAuthorization(ctx context.Context, d authorization.DecisionContext, epoch uint64) (ProviderUpdateAuthorizationEvidence, error) {
	return a.ObserveDirectoryRoleAuthorization(ctx, d, epoch)
}

// NewDirectoryGroupRoleSyncService borrows the primary and configured SCIM and
// concurrent-safe policy owners. Install the generation, SCIM Group and native
// organization team/role schemas before use. Construction performs no I/O.
func NewDirectoryGroupRoleSyncService(pool *database.Pool, scope DirectoryGroupRoleSyncConfig, c DirectorySyncGroupRolesConfig) (*DirectoryGroupRoleSyncService, error) {
	if c.Mapping == (scimorganization.DirectoryRoleMapper{}) || !directorySyncPolicyPresent(c.ApplyAuthorization) {
		return nil, sso.ErrInvalidInput
	}
	core, err := NewDirectoryGroupSyncService(pool, DirectoryGroupSyncConfig(scope), DirectorySyncGroupEdgesConfig{
		Source: c.Source, Authorization: c.Authorization, ApplyAuthorization: directoryRoleApplyAuthorization{c.ApplyAuthorization}, AuthorityNamespace: c.AuthorityNamespace,
	})
	if err != nil {
		return nil, err
	}
	core.applyAction = directoryRoleApplyAction
	return &DirectoryGroupRoleSyncService{core: core, mapping: c.Mapping}, nil
}

// WithGroupRoles selects role-bearing Apply for this native generation scope.
// The human administration session cannot authorize source role application.
func (s *DirectorySyncService) WithGroupRoles(c DirectorySyncGroupRolesConfig) (*DirectoryGroupRoleSyncService, error) {
	if s == nil || s.provider == nil {
		return nil, sso.ErrInvalidInput
	}
	p := s.provider
	return NewDirectoryGroupRoleSyncService(p.pool, DirectoryGroupRoleSyncConfig{
		TenantID: p.authentication.TenantID, OrganizationID: organization.ID(p.updateOrganization), ConnectionID: s.connection,
		Clock: p.config.Clock, MaximumDuration: p.config.MaximumDuration, PolicyID: p.config.PolicyID, PolicyVersion: p.config.PolicyVersion,
		Coordinator: p.config.Coordinator,
	}, c)
}

// DirectoryGroupRoleApplyRequest binds one exact Group delta to the opaque
// generation, mapping and predecessor. Retry with the original request.
type DirectoryGroupRoleApplyRequest struct {
	GenerationID          identity.CommandID
	ProviderID            sso.ProviderID
	MappingVersion        uint64
	PredecessorCheckpoint [32]byte
	Delta                 sso.DirectoryDelta
}

// ApplyGeneration applies one explicitly mapped role-bearing Group edge in
// the original protected command. It advances the native cursor only after an
// authoritative receipt. An exact retry can recover after the local binding
// or source edge has gone; membership-only receipts cannot settle this profile.
func (s *DirectoryGroupRoleSyncService) ApplyGeneration(ctx context.Context, r DirectoryGroupRoleApplyRequest) (out sso.DirectoryApplyResult, err error) {
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
	mapped, err := s.mapping.MapDirectoryRoleDelta(batch)
	if err != nil || len(mapped.Roles) != 1 {
		return out, sso.ErrForbidden
	}
	intent := mapped.Roles[0]
	base, err := core.prepareBatch(ctx, r.GenerationID, mapped.Source, &selected, true, &intent)
	if err != nil {
		return out, err
	}
	child, err := base.prepareRole(intent)
	if err != nil {
		return out, err
	}
	return child.finishSingle(ctx)
}

func directoryRoleCommitment(batch [32]byte, intent scimorganization.DirectoryRoleIntent) [32]byte {
	wire := append([]byte("sso/postgres/directory-role-batch/v1\x00"), batch[:]...)
	for _, target := range []string{string(intent.Membership.TeamID), string(intent.Membership.UserID), string(intent.RoleID)} {
		wire = binary.BigEndian.AppendUint64(wire, uint64(len(target)))
		wire = append(wire, target...)
	}
	return sha256.Sum256(wire)
}

func (DirectoryGroupRoleSyncConfig) Format(s fmt.State, _ rune) {
	_, _ = fmt.Fprint(s, "sso.postgres.DirectoryGroupRoleSyncConfig(redacted)")
}
func (DirectorySyncGroupRolesConfig) Format(s fmt.State, _ rune) {
	_, _ = fmt.Fprint(s, "sso.postgres.DirectorySyncGroupRolesConfig(redacted)")
}
func (DirectoryGroupRoleSyncService) Format(s fmt.State, _ rune) {
	_, _ = fmt.Fprint(s, "sso.postgres.DirectoryGroupRoleSyncService(redacted)")
}
func (DirectoryGroupRoleApplyRequest) Format(s fmt.State, _ rune) {
	_, _ = fmt.Fprint(s, "sso.postgres.DirectoryGroupRoleApplyRequest(redacted)")
}

func (DirectoryGroupRoleSyncConfig) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}
func (DirectorySyncGroupRolesConfig) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}
func (DirectoryGroupRoleSyncService) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}
func (DirectoryGroupRoleApplyRequest) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}
