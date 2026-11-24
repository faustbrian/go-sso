package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strconv"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	"github.com/faustbrian/go-sso"
	"github.com/jackc/pgx/v5"
)

// DirectorySyncCancelRequest selects the exact existing generation/version.
// Retain Key and the original ExpectedVersion for recovery or exact replay.
type DirectorySyncCancelRequest struct {
	GenerationID    identity.CommandID
	ExpectedVersion uint64
	Key             identity.IdempotencyKey
}

func (DirectorySyncCancelRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("sso.postgres.DirectorySyncCancelRequest(redacted)"))
}

// DirectorySyncCancelResult pairs the immutable cancellation Completion with
// current, authorized Generation status. A subsequent settlement of an
// original held child may advance Generation beyond the cancellation receipt.
// No generation is disclosed without a verified commit and fresh authority.
type DirectorySyncCancelResult struct {
	Generation DirectorySyncGeneration
	Completion identity.CommandResult
}

// CancelExact stops the exact generation/version without a caller-supplied
// idempotency key. The same authorized actor and selection recover the same
// native cancellation; a new expected version is a distinct intent. It grants
// no access to another actor's receipt and does not accept an earlier keyed
// Cancel as evidence for this separate natural-repeat operation.
func (s *DirectorySyncService) CancelExact(ctx context.Context, id identity.CommandID, version uint64) (DirectorySyncCancelResult, error) {
	if s == nil || s.provider == nil || version == 0 || version == math.MaxUint64 {
		return DirectorySyncCancelResult{}, sso.ErrInvalidInput
	}
	if _, err := identity.ParseCommandID(string(id)); err != nil {
		return DirectorySyncCancelResult{}, sso.ErrInvalidInput
	}
	// Derive only retry identity, never authority. Existing kernel custody
	// partitions it by tenant, actor and operation and retains the full intent.
	digest := sha256.New()
	for _, part := range []string{"sso-directory-cancel-exact-v1", s.provider.updateOrganization, s.connection, string(id), strconv.FormatUint(version, 10)} {
		_, _ = fmt.Fprintf(digest, "%d:%s", len(part), part)
	}
	key, err := identity.NewIdempotencyKey([]byte(hex.EncodeToString(digest.Sum(nil))))
	if err != nil {
		return DirectorySyncCancelResult{}, sso.ErrInvalidInput
	}
	// The repeat namespace cannot be selected by a caller-chosen direct key.
	// Keep the configured custody key and policy; only lookup scope changes.
	provider := *s.provider
	namespace := sha256.Sum256([]byte("sso-directory-cancel-exact-v1:" + provider.config.RequestKeys.Namespace))
	provider.config.RequestKeys.Namespace = "sso-directory-repeat-" + hex.EncodeToString(namespace[:])
	selected := *s
	selected.provider = &provider
	return selected.Cancel(ctx, DirectorySyncCancelRequest{GenerationID: id, ExpectedVersion: version, Key: key})
}

// Cancel stops new children without changing grants, checkpoints or counts. A
// generation holding an unsettled batch remains canceling until the exact
// original results can be reconciled; no suffix may acquire new grant
// effects. Cancellation is independent of whether the old provider still
// admits new work.
func (s *DirectorySyncService) Cancel(ctx context.Context, r DirectorySyncCancelRequest) (DirectorySyncCancelResult, error) {
	if s == nil || s.provider == nil || ctx == nil || r.ExpectedVersion == 0 || r.ExpectedVersion == math.MaxUint64 {
		return DirectorySyncCancelResult{}, sso.ErrInvalidInput
	}
	if _, err := identity.ParseCommandID(string(r.GenerationID)); err != nil {
		return DirectorySyncCancelResult{}, sso.ErrInvalidInput
	}
	p := s.provider
	ctx, cancel := context.WithTimeout(ctx, p.config.MaximumDuration)
	defer cancel()
	original, err := p.admitFreshProviderWrite(ctx, s.authority.ObserveDirectorySyncAuthorization)
	if err != nil {
		return DirectorySyncCancelResult{}, err
	}
	bound, err := original.session.Session.Bindings()
	if err != nil {
		return DirectorySyncCancelResult{}, sso.ErrForbidden
	}
	stored, err := s.readGeneration(ctx, r.GenerationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return DirectorySyncCancelResult{}, sso.ErrForbidden
	}
	if err != nil {
		return DirectorySyncCancelResult{}, providerError(ctx, err)
	}
	phase := &directorySyncCancelPhase{service: s, original: original, request: r}
	coordinator, registry, err := s.adminCoordinator(phase)
	if err != nil {
		return DirectorySyncCancelResult{}, err
	}
	fields := phase.intentFields()
	intent, err := identity.NewRequestIntent(fields)
	if err != nil {
		return DirectorySyncCancelResult{}, sso.ErrInvalidInput
	}
	op := directorySyncCancelOperation()
	scope := kernel.RequestKeyScope{TenantID: p.authentication.TenantID, ActorID: identity.ActorID(bound.UserID),
		ActorKind: authorization.SubjectUser, Method: "POST", RouteID: op.OperationID}
	admission, err := coordinator.ResolveRequestKey(ctx, scope, r.Key, intent, p.kernelDecisionFor(bound.UserID, "identity.request-admission", op.OperationID, op.OperationID))
	if err != nil {
		return DirectorySyncCancelResult{}, providerError(ctx, err)
	}
	phase.binding = identity.CommandBinding{CommandID: admission.CommandID, TenantID: scope.TenantID, UserID: bound.UserID,
		ActorID: scope.ActorID, ActorKind: scope.ActorKind, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion,
		RecordID: string(r.GenerationID), CorrelationID: string(admission.CommandID), PolicyID: p.config.PolicyID, PolicyVersion: p.config.PolicyVersion}
	caller := p.kernelDecisionFor(bound.UserID, "identity.user", string(bound.UserID), op.OperationID)
	completion, err := coordinator.RecoverFeatureCommand(ctx, providerRecovery(phase.binding), caller)
	var absentOrDenied identity.ForbiddenError
	if completion.Binding.CommandID == "" && errors.As(err, &absentOrDenied) {
		// A denied or absent lookup cannot establish the historical outcome.
		// The original key and version may attempt a normal fenced reservation;
		// neither a changed target nor an already stopped generation can write.
		current := stored.current
		if current.Version != r.ExpectedVersion || current.State != DirectorySyncRunning && current.State != DirectorySyncReconciling {
			return DirectorySyncCancelResult{}, sso.ErrConflict
		}
		var owned bool
		completion, owned, err = phase.execute(ctx, coordinator, registry, fields)
		if !owned && completion.Binding.CommandID != "" {
			// The reservation can observe history created since the pre-read.
			// Reapply the separate receipt policy before returning any outcome.
			completion, err = coordinator.RecoverFeatureCommand(ctx, providerRecovery(phase.binding), caller)
		}
	}
	out := DirectorySyncCancelResult{Completion: completion}
	if err != nil || completion.Outcome != identity.CommitOutcomeCommitted {
		return out, providerError(ctx, err)
	}
	if completion.Binding != phase.binding || completion.Feature == nil || completion.Feature.Operation != op ||
		completion.Feature.BeforeVersion != r.ExpectedVersion || completion.Validate() != nil {
		return DirectorySyncCancelResult{}, sso.ErrUnavailable
	}
	stored, err = s.readGeneration(ctx, r.GenerationID)
	if err != nil {
		return out, providerError(ctx, err)
	}
	current, after := stored.current, completion.Feature.AfterVersion
	if !directoryCanceledStatus(current, after) {
		return out, sso.ErrUnavailable
	}
	if _, err := p.admitFreshProviderWrite(ctx, s.authority.ObserveDirectorySyncAuthorization); err != nil {
		return DirectorySyncCancelResult{}, err
	}
	out.Generation = current
	return out, nil
}

func directoryCanceledStatus(current DirectorySyncGeneration, after uint64) bool {
	switch current.State {
	case DirectorySyncCanceling:
		return current.Version == after
	case DirectorySyncCanceled:
		return current.Version == after || after < math.MaxUint64 && current.Version == after+1
	default:
		return false
	}
}

func directorySyncCancelOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "sso", OperationID: "identity.sso.directory-sync-cancel",
		SchemaID: "sso-directory-sync-cancel-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

type directorySyncCancelPhase struct {
	service  *DirectorySyncService
	original providerAdmission
	request  DirectorySyncCancelRequest
	binding  identity.CommandBinding
	command  identity.Command
	counter  kernel.CommandCounterPlan
}

func (*directorySyncCancelPhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.directory-sync-cancel", Version: 1}
}

func (*directorySyncCancelPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{directorySyncCancelOperation()}
}

func (p *directorySyncCancelPhase) registration() kernel.FeatureRegistration {
	return kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: directorySyncCancelOperation()}
}

func (p *directorySyncCancelPhase) lifecycle() kernel.LifecyclePlan {
	return kernel.LifecyclePlan{EventType: "sso.directory_sync.cancellation_requested.v1", BeforeVersion: p.request.ExpectedVersion, AfterVersion: p.request.ExpectedVersion + 1}
}

func (p *directorySyncCancelPhase) intentFields() []identity.FeatureField {
	return []identity.FeatureField{
		{Name: "directory.source-id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: p.service.connection}},
		{Name: "directory.organization-id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: p.service.provider.updateOrganization}},
		{Name: "directory.generation-id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(p.request.GenerationID)}},
		{Name: "directory.expected-version", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: strconv.FormatUint(p.request.ExpectedVersion, 10)}},
		{Name: "directory.policy-id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: p.service.provider.config.PolicyID}},
	}
}

func (p *directorySyncCancelPhase) execute(ctx context.Context, coordinator *kernel.Coordinator, registry *kernel.ContributorRegistry, intent []identity.FeatureField) (identity.CommandResult, bool, error) {
	service := p.service.provider
	fields, err := sessionpg.OriginalSessionFields(p.original.session.Session)
	if err != nil {
		return identity.CommandResult{}, false, sso.ErrForbidden
	}
	fields = append(fields, intent...)
	command, err := identity.NewFeatureSessionCommand(identity.FeatureCommandSpec{Binding: p.binding,
		Operation: directorySyncCancelOperation(), Fields: fields}, service.authentication.Bearer)
	if err != nil {
		return identity.CommandResult{}, false, sso.ErrInvalidInput
	}
	p.command, p.counter, err = service.config.Counters.PrepareCommandCounters(command,
		risk.Subject{Actor: string(p.binding.ActorID), Resource: p.binding.RecordID, Network: service.network}, p.original.verified)
	if err != nil {
		return identity.CommandResult{}, false, err
	}
	plan, err := directoryAdminPlan(registry, p.binding, p.registration(), p.lifecycle(), p.counter, p.original.verified)
	if err != nil {
		return identity.CommandResult{}, false, err
	}
	return executeProviderFeatureCommand(ctx, coordinator, p.binding, p.command, plan)
}

func (p *directorySyncCancelPhase) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if c != p.command || plan.Feature == nil || *plan.Feature != p.registration() || plan.Lifecycle == nil ||
		*plan.Lifecycle != p.lifecycle() || plan.SubjectType != "directory_sync" || plan.CommandCounters == nil || *plan.CommandCounters != p.counter ||
		len(plan.Audits) != 1 || plan.Audits[0].EventType != directorySyncCancelOperation().OperationID || !plan.Audits[0].Required {
		return identity.ForbiddenError{}
	}
	spec, ok := c.Feature()
	if !ok || spec.Binding != p.binding || spec.Operation != directorySyncCancelOperation() {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *directorySyncCancelPhase) CheckFeatureCommit(ctx context.Context, work kernel.Work, c identity.Command) error {
	b, registration, lifecycle, err := work.FeatureScope(p)
	if err != nil || c != p.command || b != p.binding || registration != p.registration() || lifecycle != p.lifecycle() {
		return identity.ForbiddenError{}
	}
	return requireProviderAdminSession(ctx, work, p, c, p.service.provider.config, p.original, b, true)
}

// A cancel racing a child serializes on the existing generation row, without
// needing to re-admit the historical provider or touch the child's receipt.
// Leave one additional version available when an original child still holds it.
const directoryCancelGenerationSQL = `UPDATE sso_providers.directory_sync_generations
 SET state=CASE state WHEN 'running' THEN 'canceled' ELSE 'canceling' END,version=version+1
 WHERE generation_id=$1 AND tenant_id=$2 AND organization_id=$3 AND connection_id=$4 AND version=$5::numeric
 AND version<18446744073709551615 AND ((state='running' AND pending_batch IS NULL)
 OR (state='reconciling' AND pending_batch IS NOT NULL AND version<18446744073709551614))`

func (p *directorySyncCancelPhase) ApplyFeature(ctx context.Context, work kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if err := work.RequireFeatureCommand(ctx, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.CheckFeatureCommit(ctx, work, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	count, err := work.Exec(ctx, directoryCancelGenerationSQL, p.binding.RecordID, string(p.binding.TenantID),
		p.service.provider.updateOrganization, p.service.connection, strconv.FormatUint(p.request.ExpectedVersion, 10))
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if count != 1 {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	transition := p.lifecycle()
	return identity.FeatureReceipt{Operation: directorySyncCancelOperation(), BeforeVersion: transition.BeforeVersion, AfterVersion: transition.AfterVersion}, nil
}

func (p *directorySyncCancelPhase) RecoverParticipant(_ context.Context, work kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	b, registration, lifecycle, err := work.FeatureScope(p)
	if err != nil || b != p.binding || registration != p.registration() || lifecycle != p.lifecycle() {
		return kernel.RecoveryUnknown, identity.ForbiddenError{}
	}
	// All effects are in the same transaction as the kernel's terminal receipt.
	// Under its locked, expired pending journal, this exact command did not
	// commit; the current generation may have changed under another command.
	return kernel.RecoveryNotCommitted, nil
}
