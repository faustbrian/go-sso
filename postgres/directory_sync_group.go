package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	scim "github.com/faustbrian/go-scim"
	scimorganization "github.com/faustbrian/go-scim/organization"
	scimpostgres "github.com/faustbrian/go-scim/postgres"
	"github.com/faustbrian/go-sso"
	"github.com/jackc/pgx/v5"
)

const directoryApplyAction = "identity.sso.directory-sync-apply"

// DirectorySyncGroupEdgesConfig opts the organization-bound native generation
// into the direct Group-to-User profile. Source and Mapping are existing owner
// responsibilities. ApplyAuthorization supplies the time-bounded sync
// decision; Authorization separately authorizes child admission observations
// and original child recovery through the kernel's distinct decision scopes.
// A configured SCIM source by itself cannot authorize synchronization.
type DirectorySyncGroupEdgesConfig struct {
	Source             *scimpostgres.GroupsService
	Mapping            scimorganization.DirectoryMapper
	Authorization      authorization.Service
	ApplyAuthorization DirectorySyncGroupAuthorization
	AuthorityNamespace string
}

// DirectorySyncGroupAuthorization observes the configured service account's
// exact synchronization decision. The deadline is the decision's earliest
// absolute expiry, not a lease that later checks can refresh.
type DirectorySyncGroupAuthorization interface {
	ObserveDirectoryGroupAuthorization(context.Context, authorization.DecisionContext, uint64) (ProviderUpdateAuthorizationEvidence, error)
}

// DirectoryGroupSyncService applies mapped direct Group-to-User changes using
// the original stable child command. It owns no asynchronous workers or routes.
type DirectoryGroupSyncService struct {
	generation *DirectorySyncService
	config     DirectorySyncGroupEdgesConfig
	authority  *authoritypg.AuthorityStore
}

// WithGroupEdges explicitly selects exact source-team contributions. It
// borrows the source service and the primary; the caller retains both for the
// service's lifetime. It performs no writes or authorization callbacks.
func (s *DirectorySyncService) WithGroupEdges(c DirectorySyncGroupEdgesConfig) (*DirectoryGroupSyncService, error) {
	if s == nil || s.provider == nil || c.Source == nil || c.Authorization == nil || c.ApplyAuthorization == nil || !providerID(c.AuthorityNamespace) {
		return nil, sso.ErrInvalidInput
	}
	for _, owner := range []any{c.Authorization, c.ApplyAuthorization} {
		v := reflect.ValueOf(owner)
		switch v.Kind() {
		case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
			if v.IsNil() {
				return nil, sso.ErrInvalidInput
			}
		}
	}
	authority, err := authoritypg.NewAuthorityStore(s.provider.pool.Raw(), s.provider.config.MaximumDuration)
	if err != nil {
		return nil, sso.ErrInvalidInput
	}
	return &DirectoryGroupSyncService{generation: s, config: c, authority: authority}, nil
}

func (DirectorySyncGroupEdgesConfig) Format(s fmt.State, _ rune) {
	_, _ = fmt.Fprint(s, "sso.postgres.DirectorySyncGroupEdgesConfig(redacted)")
}

func (DirectoryGroupSyncService) Format(s fmt.State, _ rune) {
	_, _ = fmt.Fprint(s, "sso.postgres.DirectoryGroupSyncService(redacted)")
}

func (DirectorySyncGroupEdgesConfig) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}

func (DirectoryGroupSyncService) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}

// Apply executes a bounded, explicitly mapped batch in its original order.
// Retry unresolved work with the same generation, batch and command IDs.
// An observed prefix is not a settled cursor. After cancellation, the exact
// held batch may be reconciled but no further grant writes are admitted.
func (s *DirectoryGroupSyncService) Apply(ctx context.Context, generation identity.CommandID, batch sso.DirectoryDeltaBatch) (out sso.DirectoryApplyResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = sso.DirectoryApplyResult{}, sso.ErrUnavailable
		}
	}()
	if s == nil || s.generation == nil || ctx == nil {
		return out, sso.ErrInvalidInput
	}
	if _, err := identity.ParseCommandID(string(generation)); err != nil {
		return out, sso.ErrInvalidInput
	}
	ctx, cancel := context.WithTimeout(ctx, s.generation.provider.config.MaximumDuration)
	defer cancel()
	executor := &nativeDirectoryEdgeExecutor{service: s, generation: generation}
	reconciler, err := scimorganization.NewDirectoryReconciler(s.config.Mapping, executor)
	if err != nil {
		return out, sso.ErrInvalidInput
	}
	result, err := reconciler.ApplyDirectoryDelta(ctx, batch)
	if err != nil {
		if len(result.ChildOutcomes) != 0 && result.Checkpoint == ([32]byte{}) {
			if !executor.child.mayDisclose() {
				return out, sso.ErrForbidden
			}
			if executor.stoppedPrefix {
				stopErr := executor.child.settleStopped(ctx)
				if !executor.child.mayDisclose() {
					return out, sso.ErrForbidden
				}
				if stopErr != nil {
					return result, stopErr
				}
			}
			return result, err
		}
		return out, err
	}
	if executor.child == nil {
		return out, sso.ErrUnavailable
	}
	if err := executor.child.settle(ctx, result); err != nil {
		return out, err
	}
	// A known committed child must not be disclosed on a connection that
	// outlived the original observation while settling its cursor.
	if !executor.child.mayDisclose() {
		return out, sso.ErrForbidden
	}
	return result, nil
}

func (p *directoryGroupChild) mayDisclose() bool {
	if p == nil {
		return false
	}
	_, err := p.admission.source.Bindings()
	return err == nil && p.service.generation.provider.config.Clock.Now().Before(p.admission.validUntil)
}

// Only the configured native executor can enlist the original Work and load
// its authoritative result. The mapper retains no journal or cursor access.
type nativeDirectoryEdgeExecutor struct {
	service       *DirectoryGroupSyncService
	generation    identity.CommandID
	child         *directoryGroupChild
	stoppedPrefix bool
}

func (e *nativeDirectoryEdgeExecutor) ExecuteMappedDirectoryMemberships(ctx context.Context, mapped scimorganization.DirectoryMembershipBatch) ([]sso.Completion, error) {
	if len(mapped.Memberships) == 0 || len(mapped.Memberships) != len(mapped.Source.Deltas) {
		return nil, sso.ErrInvalidInput
	}
	batch, err := e.service.prepareBatch(ctx, e.generation, mapped.Source)
	if err != nil {
		return nil, err
	}
	e.child = batch
	stopped := batch.generation.State == DirectorySyncCanceling || batch.generation.State == DirectorySyncCanceled
	stoppedAtPredecessor := batch.generation.State == DirectorySyncCanceled && batch.generation.Checkpoint == mapped.Source.PredecessorCheckpoint
	var unstartedSuffix bool
	var lastCommitted int
	receipts := make([]sso.Completion, 0, len(mapped.Memberships))
	for _, member := range mapped.Memberships {
		child, err := batch.prepareChild(ctx, member)
		if err != nil {
			return receipts, err
		}
		receipt, absent, err := child.executeOriginal(ctx)
		if absent && stopped {
			unstartedSuffix = true
			continue
		}
		if absent {
			return receipts, sso.ErrForbidden
		}
		if receipt.Feature != nil && receipt.Validate() == nil && !unstartedSuffix {
			receipts = append(receipts, receipt)
			if receipt.Outcome == identity.CommitOutcomeCommitted {
				lastCommitted = len(receipts)
			}
		}
		if err != nil {
			if stoppedAtPredecessor && lastCommitted != 0 {
				return receipts[:lastCommitted], sso.ErrDirectoryReconciliation
			}
			return receipts, err
		}
		if unstartedSuffix {
			// A completed tail after a genuinely unstarted child is not an
			// ordered prefix. Do not close the generation on that evidence.
			return receipts, sso.ErrDirectoryReconciliation
		}
	}
	if stoppedAtPredecessor {
		// A stale worker may get an abort receipt after cancellation closed.
		// It cannot extend the applied prefix or turn it into settlement.
		if lastCommitted == 0 || lastCommitted == len(mapped.Memberships) {
			return nil, sso.ErrDirectoryReconciliation
		}
		return receipts[:lastCommitted], sso.ErrDirectoryReconciliation
	}
	if batch.generation.State == DirectorySyncCanceling && unstartedSuffix && lastCommitted != 0 {
		e.stoppedPrefix = true
		return receipts[:lastCommitted], sso.ErrDirectoryReconciliation
	}
	if len(receipts) != len(mapped.Memberships) {
		return receipts, sso.ErrDirectoryReconciliation
	}
	return receipts, nil
}

type directoryEdgeAdmission struct {
	source     scimpostgres.DirectorySourceObservation
	bindings   scimpostgres.DirectorySourceBindings
	scope      authoritypg.AuthorityScope
	epoch      uint64
	validUntil time.Time
}

func (s *DirectoryGroupSyncService) prepareBatch(ctx context.Context, id identity.CommandID, batch sso.DirectoryDeltaBatch) (*directoryGroupChild, error) {
	provider := s.generation.provider
	if batch.TenantID != provider.authentication.TenantID || string(batch.OrganizationID) != provider.updateOrganization ||
		batch.ConnectionID != s.generation.connection {
		return nil, sso.ErrForbidden
	}
	admitted, err := s.observe(ctx, id, batch)
	if err != nil {
		return nil, err
	}
	stored, err := s.generation.readGeneration(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, sso.ErrForbidden
	}
	if err != nil {
		return nil, providerError(ctx, err)
	}
	current := stored.current
	if current.Mode != DirectorySyncApply || current.Provider != batch.ProviderID || current.Number != batch.Generation ||
		current.MappingVersion != batch.MappingVersion {
		return nil, sso.ErrForbidden
	}
	switch current.State {
	case DirectorySyncRunning, DirectorySyncReconciling, DirectorySyncCanceling:
	case DirectorySyncCanceled:
		// Multi-edge replay may recover an exact stopped prefix or an
		// already-installed successor, but cannot start another child.
		if len(batch.Deltas) < 2 {
			return nil, sso.ErrForbidden
		}
	default:
		return nil, sso.ErrForbidden
	}
	commitment, err := batch.Commitment()
	if err != nil {
		return nil, err
	}
	child := &directoryGroupChild{service: s, generation: current, batch: batch, commitment: commitment, admission: admitted}
	if current.State == DirectorySyncReconciling || current.State == DirectorySyncCanceling {
		var pending bool
		err := provider.pool.Raw().QueryRow(ctx, directoryPendingGroupBatchSQL, child.generationArgs()...).Scan(&pending)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && !pending {
			return nil, sso.ErrForbidden
		}
		if err != nil {
			return nil, providerError(ctx, err)
		}
	}
	return child, nil
}

func (p *directoryGroupChild) prepareChild(ctx context.Context, m scimorganization.DirectoryMembershipIntent) (*directoryGroupChild, error) {
	batch, admitted := p.batch, p.admission
	provider := p.service.generation.provider
	grantScope := organizationpg.DirectoryTeamGrantScope{
		TenantID: batch.TenantID, OrganizationID: batch.OrganizationID, ProviderID: organization.ID(batch.ProviderID),
		ConnectionID: organization.ID(batch.ConnectionID), GroupID: organization.ID(m.GroupID), TeamID: m.TeamID, UserID: m.UserID,
	}
	target, err := provider.config.Organizations.ObserveDirectoryTeamMembership(ctx, grantScope)
	if err != nil {
		return nil, sso.ErrForbidden
	}
	edge := scimpostgres.DirectoryGroupEdge{GroupID: m.GroupID, UserID: m.MemberID, Present: m.Action == sso.DirectoryMembershipAdd}
	update, err := organizationpg.NewDirectoryTeamGrantUpdate(organizationpg.DirectoryTeamGrantInput{
		Scope: grantScope, ActorID: admitted.bindings.ActorID, User: identity.User{ID: m.UserID, TenantID: batch.TenantID, Status: identity.StatusActive, Version: target.UserVersion},
		OrganizationVersion: target.OrganizationVersion, CredentialVersion: target.CredentialVersion, MemberVersion: target.MemberVersion,
		MemberAuthorizationVersion: target.MemberAuthorizationVersion, TeamVersion: target.TeamVersion, ExpectedVersion: target.Version, Active: edge.Present,
	})
	if err != nil {
		return nil, sso.ErrForbidden
	}
	op := sso.DirectoryTeamMembershipOperation()
	correlation := sha256.Sum256(append(append([]byte("sso/postgres/directory-child/v1\x00"), p.generation.ID...), p.commitment[:]...))
	binding := identity.CommandBinding{
		CommandID: m.CommandID, TenantID: batch.TenantID, UserID: m.UserID, ActorKind: authorization.SubjectServiceAccount, ActorID: admitted.bindings.ActorID,
		OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, PolicyID: provider.config.PolicyID, PolicyVersion: provider.config.PolicyVersion,
		CorrelationID: hex.EncodeToString(correlation[:]), RecordID: update.RecordID(),
	}
	child := *p
	child.edge, child.update, child.binding = edge, update, binding
	return &child, nil
}

func (s *DirectoryGroupSyncService) observe(ctx context.Context, id identity.CommandID, batch sso.DirectoryDeltaBatch) (directoryEdgeAdmission, error) {
	source, err := s.config.Source.ObserveDirectorySource(ctx, scim.Scope{
		TenantID: batch.TenantID, OrganizationID: batch.OrganizationID, ProviderID: string(batch.ProviderID), ConnectionID: batch.ConnectionID,
	})
	if err != nil {
		return directoryEdgeAdmission{}, providerError(ctx, err)
	}
	bindings, err := source.Bindings()
	if err != nil {
		return directoryEdgeAdmission{}, providerError(ctx, err)
	}
	scope := authoritypg.AuthorityScope{TenantID: authorization.TenantID(batch.TenantID),
		PolicyNamespace: s.config.AuthorityNamespace, SubjectID: authorization.SubjectID(bindings.ActorID)}
	epoch, err := s.authority.Get(ctx, scope)
	if err != nil || epoch.Version == 0 {
		return directoryEdgeAdmission{}, sso.ErrForbidden
	}
	now := s.generation.provider.config.Clock.Now().UTC()
	decision := s.applyDecision(now, id, batch, bindings.ActorID)
	evidence, err := s.config.ApplyAuthorization.ObserveDirectoryGroupAuthorization(ctx, decision.Clone(), epoch.Version)
	if err != nil {
		return directoryEdgeAdmission{}, providerError(ctx, err)
	}
	expiry := bindings.ValidUntil
	if evidence.ValidUntil.Before(expiry) {
		expiry = evidence.ValidUntil
	}
	if !reflect.DeepEqual(evidence.Context, decision) || evidence.Decision.Outcome != authorization.Allow ||
		evidence.Decision.Revision != decision.PolicyRevision || evidence.ActorAuthorizationVersion != epoch.Version ||
		!s.generation.provider.config.Clock.Now().Before(expiry) {
		return directoryEdgeAdmission{}, sso.ErrForbidden
	}
	return directoryEdgeAdmission{source: source, bindings: bindings, scope: scope, epoch: epoch.Version, validUntil: expiry}, nil
}

func (s *DirectoryGroupSyncService) applyDecision(now time.Time, id identity.CommandID, b sso.DirectoryDeltaBatch, actor identity.ActorID) authorization.DecisionContext {
	return authorization.DecisionContext{PolicyRevision: authorization.Revision(s.generation.provider.config.PolicyVersion), Request: authorization.Request{
		Tenant: authorization.TenantID(b.TenantID), Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: authorization.SubjectID(actor)},
		Action: directoryApplyAction, Resource: authorization.Resource{Type: "sso.directory-generation", ID: authorization.ResourceID(id), Attributes: authorization.Attributes{
			"sso.organization": authorization.StringValue(string(b.OrganizationID)), "sso.provider": authorization.StringValue(string(b.ProviderID)),
			"sso.connection": authorization.StringValue(b.ConnectionID), "sso.mapping-version": authorization.StringValue(strconv.FormatUint(b.MappingVersion, 10)),
		}}, Environment: authorization.Environment{Time: now},
	}}
}
