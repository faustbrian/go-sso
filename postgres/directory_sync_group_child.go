package postgres

import (
	"bytes"
	"context"
	"strconv"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	scimpostgres "github.com/faustbrian/go-scim/postgres"
	"github.com/faustbrian/go-sso"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

type directorySyncChild struct {
	service    *DirectoryGroupSyncService
	generation DirectorySyncGeneration
	batch      sso.DirectoryDeltaBatch
	commitment [32]byte
	admission  directoryEdgeAdmission
	edge       scimpostgres.DirectoryGroupEdge
	teamScope  organizationpg.DirectoryTeamGrantScope
	update     organizationpg.DirectoryTeamGrantUpdate
	user       *directorySyncUserChild
	role       *directorySyncRoleChild
	binding    identity.CommandBinding
	command    identity.Command
}

func (p *directorySyncChild) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "sso/postgres", ContractID: p.operation().SchemaID, Version: 1}
}

func (p *directorySyncChild) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{p.operation()}
}

func (p *directorySyncChild) operation() identity.FeatureOperation {
	if p.user != nil {
		return p.user.operation
	}
	return sso.DirectoryTeamMembershipOperation()
}

func (p *directorySyncChild) registration() kernel.FeatureRegistration {
	return kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: p.operation()}
}

func (p *directorySyncChild) subjectType() string {
	if p.user != nil {
		return "directory_membership"
	}
	return "team_membership"
}

func (p *directorySyncChild) lifecycle() kernel.LifecyclePlan {
	if p.user != nil {
		return kernel.LifecyclePlan{EventType: "sso.directory_sync.membership_changed.v1", BeforeVersion: p.user.update.BeforeVersion(), AfterVersion: p.user.update.AfterVersion()}
	}
	event := "sso.directory_sync.team_membership_changed.v1"
	if p.role != nil {
		event = "sso.directory_sync.team_role_changed.v1"
	}
	return kernel.LifecyclePlan{EventType: event, BeforeVersion: p.update.BeforeVersion(), AfterVersion: p.update.AfterVersion()}
}

func (p *directorySyncChild) executeOriginal(ctx context.Context) (receipt sso.Completion, absent bool, err error) {
	coordinator, registry, err := p.coordinator()
	if err != nil {
		return receipt, false, providerError(ctx, err)
	}
	query, caller := providerRecovery(p.binding), p.receiptCaller()
	observed, err := coordinator.ObserveCommandAdmission(ctx, query, caller)
	if observed.Validate() != nil {
		if err == nil {
			err = identity.UnavailableError{}
		}
		return receipt, false, providerError(ctx, err)
	}
	if observed.Absent {
		if p.generation.Checkpoint != p.batch.PredecessorCheckpoint ||
			(p.generation.State != DirectorySyncRunning && p.generation.State != DirectorySyncReconciling) {
			return receipt, true, nil
		}
		var owned bool
		receipt, owned, err = p.execute(ctx, coordinator, registry)
		if !owned && receipt.Binding.CommandID != "" {
			// A concurrent reservation can change the authoritative observation.
			// On retry require scoped admission and separately authorized recovery
			// before returning its history or acting on it.
			return sso.Completion{}, false, sso.ErrDirectoryReconciliation
		}
	} else {
		if observed.Record.Binding != p.binding {
			return receipt, false, sso.ErrForbidden
		}
		if (p.user != nil || p.role != nil) && p.generation.State == DirectorySyncCanceled && observed.Record.Outcome != identity.CommitOutcomeCommitted {
			// A closed single-receipt profile has no outstanding child to reconcile.
			return receipt, false, sso.ErrForbidden
		}
		receipt, err = coordinator.RecoverFeatureCommand(ctx, query, caller)
	}
	if err != nil && receipt.Binding.CommandID == "" {
		return sso.Completion{}, false, providerError(ctx, err)
	}
	if receipt.Binding != p.binding || receipt.Feature == nil || receipt.Validate() != nil {
		return sso.Completion{}, false, sso.ErrForbidden
	}
	switch receipt.Outcome {
	case identity.CommitOutcomeCommitted:
		return receipt, false, providerError(ctx, err)
	case identity.CommitOutcomeNotCommitted:
		if len(p.batch.Deltas) == 1 && err != nil {
			return receipt, false, providerError(ctx, err)
		}
		return receipt, false, nil
	default:
		return receipt, false, sso.ErrDirectoryReconciliation
	}
}

func (p *directorySyncChild) receiptCaller() authorization.DecisionContext {
	b := p.binding
	return authorization.DecisionContext{PolicyRevision: authorization.Revision(b.PolicyVersion), Request: authorization.Request{
		Tenant: authorization.TenantID(b.TenantID), Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: authorization.SubjectID(b.ActorID)},
		Action: authorization.Action(b.OperationID), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)},
	}}
}

func (p *directorySyncChild) coordinator() (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
	service := p.service
	audits, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, nil, err
	}
	outbox, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, nil, err
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{service.directory, audits, outbox, p})
	if err != nil {
		return nil, nil, err
	}
	coordinator, err := kernel.NewCoordinator(service.pool, registry, service.scope.Coordinator)
	return coordinator, registry, err
}

func (p *directorySyncChild) execute(ctx context.Context, coordinator *kernel.Coordinator, registry *kernel.ContributorRegistry) (identity.CommandResult, bool, error) {
	fields := []identity.FeatureField{{Name: "sso.directory-batch", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: bytes.Clone(p.commitment[:])}}}
	var evidence []func() (identity.FeatureField, error)
	switch {
	case p.user != nil:
		// Only an authoritative absent admission permits preparing a new
		// update. Recovery must still work after the last grant disappeared.
		if err := p.prepareUserUpdate(ctx); err != nil {
			return identity.CommandResult{}, false, err
		}
		evidence = []func() (identity.FeatureField, error){p.admission.source.Field, p.user.evidence.Field, p.user.update.Field}
	case p.role != nil:
		// Journal lookup uses stable scope identity. Only a new command needs
		// live target versions; historical replay cannot readmit the grant.
		if err := p.prepareRoleUpdate(ctx); err != nil {
			return identity.CommandResult{}, false, err
		}
		evidence = []func() (identity.FeatureField, error){p.admission.source.Field, p.edge.Field, p.update.Field, p.role.update.Field}
	default:
		// Recovery uses the original binding even when the target is no longer
		// a member. Only a new command may observe the current grant state.
		grant, err := p.observeTeamGrant(ctx, p.teamScope, p.edge.Present)
		if err != nil || grant.RecordID() != p.binding.RecordID {
			return identity.CommandResult{}, false, sso.ErrForbidden
		}
		p.update = grant
		evidence = []func() (identity.FeatureField, error){p.admission.source.Field, p.edge.Field, p.update.Field}
	}
	for _, field := range evidence {
		value, err := field()
		if err != nil {
			return identity.CommandResult{}, false, err
		}
		fields = append(fields, value)
	}
	op := p.operation()
	cmd, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Operation: op, Binding: p.binding, Fields: fields})
	if err != nil {
		return identity.CommandResult{}, false, err
	}
	p.command = cmd
	plan, err := p.plan(registry)
	if err != nil {
		return identity.CommandResult{}, false, err
	}
	return executeProviderFeatureCommand(ctx, coordinator, p.binding, cmd, plan)
}

func (p *directorySyncChild) plan(registry *kernel.ContributorRegistry) (kernel.CommandPlan, error) {
	subject := p.subjectType()
	b, lifecycle := p.binding, p.lifecycle()
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	record, err := builder.Build(audit.RecordInput{
		OccurredAt: p.admission.bindings.ReadStartedAt, Action: b.OperationID, Outcome: audit.OutcomeSucceeded,
		Actor: audit.ActorInput{Kind: audit.ActorService, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: subject, ID: b.RecordID},
		Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID},
		Policy:  audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true},
		Attributes: map[string]string{
			"command.id": string(b.CommandID), "aggregate.type": subject, "aggregate.id": b.RecordID,
			"aggregate.before_version": strconv.FormatUint(lifecycle.BeforeVersion, 10), "aggregate.after_version": strconv.FormatUint(lifecycle.AfterVersion, 10),
			"retention.class": "protected",
		},
	})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	registration := p.registration()
	digest, err := kernel.FeatureAuditBindingDigest(b, registration.Operation, subject, record)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	return kernel.CommandPlan{Contributors: registry.Descriptors(), Feature: &registration, SubjectType: subject, Lifecycle: &lifecycle,
		Audits: []kernel.AuditPlan{{EventType: b.OperationID, SchemaVersion: 1, BindingDigest: digest, RetentionPolicyVersion: 1,
			RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionClass: "protected", Required: true}}}, nil
}

func (p *directorySyncChild) ValidateFeatureCommand(command identity.Command, plan kernel.CommandPlan) error {
	input, ok := command.Feature()
	if !ok || command != p.command || input.Binding != p.binding || input.Operation != p.operation() ||
		plan.Feature == nil || *plan.Feature != p.registration() || plan.Lifecycle == nil || *plan.Lifecycle != p.lifecycle() ||
		plan.SubjectType != p.subjectType() || len(plan.Audits) != 1 || !plan.Audits[0].Required {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *directorySyncChild) ApplyFeature(ctx context.Context, work kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	if err := work.RequireFeatureCommand(ctx, p, command); err != nil {
		return identity.FeatureReceipt{}, err
	}
	var lock organizationpg.DirectoryMembershipLock
	switch {
	case p.user != nil:
		var err error
		lock, err = p.service.config.Source.LockDirectoryUserMembership(ctx, work, p, command, p.admission.source, p.user.evidence, p.user.update)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
	case p.role != nil:
		var err error
		p.role.lock, err = p.service.config.Source.LockDirectoryGroupRole(ctx, work, p, command, p.admission.source, p.edge, p.role.source, p.role.update)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
	default:
		if err := p.service.config.Source.RequireDirectoryGroupEdge(ctx, work, p, command, p.admission.source, p.edge); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	if err := p.requireActorInWork(ctx, work); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.holdGeneration(ctx, work); err != nil {
		return identity.FeatureReceipt{}, err
	}
	switch {
	case p.user != nil:
		effect, err := p.organizations().ApplyDirectoryMembershipUpdate(ctx, work, p, command, p.user.update, lock)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		p.user.effect = effect
	case p.role != nil:
		if err := p.organizations().ApplyDirectoryTeamRoleUpdate(ctx, work, p, command, p.role.update, p.role.lock); err != nil {
			return identity.FeatureReceipt{}, err
		}
	default:
		if err := p.organizations().ApplyDirectoryTeamGrantUpdate(ctx, work, p, command, p.update); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	versions := p.lifecycle()
	return identity.FeatureReceipt{Operation: p.operation(), BeforeVersion: versions.BeforeVersion, AfterVersion: versions.AfterVersion}, nil
}

func (p *directorySyncChild) CheckFeatureCommit(ctx context.Context, work kernel.Work, command identity.Command) error {
	b, feature, _, err := work.FeatureScope(p)
	if err != nil || command != p.command || b != p.binding || feature != p.registration() {
		return identity.ForbiddenError{}
	}
	if err := p.requirePendingGeneration(ctx, work); err != nil {
		return err
	}
	switch {
	case p.user != nil:
		if err := p.organizations().RequireDirectoryMembershipEffect(ctx, work, p, command, p.user.update, p.user.effect); err != nil {
			return err
		}
		if err := p.service.config.Source.RequireDirectoryUserMembershipAtCommit(ctx, work, p, command, p.admission.source, p.user.evidence, p.user.effect); err != nil {
			return err
		}
	case p.role != nil:
		if err := p.organizations().RequireDirectoryTeamRoleUpdate(ctx, work, p, command, p.role.update, p.role.lock); err != nil {
			return err
		}
		if err := p.service.config.Source.RequireDirectoryGroupRoleAtCommit(ctx, work, p, command, p.admission.source, p.edge, p.role.source, p.role.lock); err != nil {
			return err
		}
	default:
		if err := p.organizations().RequireDirectoryTeamGrantUpdate(ctx, work, p, command, p.update); err != nil {
			return err
		}
		if err := p.service.config.Source.RequireDirectoryGroupEdgeAtCommit(ctx, work, p, command, p.admission.source, p.edge); err != nil {
			return err
		}
	}
	return p.requireActorInWork(ctx, work)
}

func (p *directorySyncChild) requireActorInWork(ctx context.Context, work kernel.Work) error {
	maximum := p.service.scope.MaximumDuration
	if err := authoritypg.RequireAuthority(ctx, work, p.admission.scope, p.admission.epoch, maximum); err != nil {
		return identity.ForbiddenError{}
	}
	now, err := work.DatabaseTime(ctx)
	if err != nil || !now.Before(p.admission.validUntil) {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *directorySyncChild) organizations() *organizationpg.Repository {
	return p.service.organizations
}
