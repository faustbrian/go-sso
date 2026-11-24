package postgres

import (
	"bytes"
	"context"
	"errors"
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

type directoryGroupChild struct {
	service    *DirectoryGroupSyncService
	generation DirectorySyncGeneration
	batch      sso.DirectoryDeltaBatch
	commitment [32]byte
	admission  directoryEdgeAdmission
	edge       scimpostgres.DirectoryGroupEdge
	update     organizationpg.DirectoryTeamGrantUpdate
	binding    identity.CommandBinding
	command    identity.Command
}

func (*directoryGroupChild) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.directory-team-membership", Version: 1}
}

func (*directoryGroupChild) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{sso.DirectoryTeamMembershipOperation()}
}

func (p *directoryGroupChild) registration() kernel.FeatureRegistration {
	return kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: sso.DirectoryTeamMembershipOperation()}
}

func (p *directoryGroupChild) lifecycle() kernel.LifecyclePlan {
	return kernel.LifecyclePlan{EventType: "sso.directory_sync.team_membership_changed.v1", BeforeVersion: p.update.BeforeVersion(), AfterVersion: p.update.AfterVersion()}
}

func (p *directoryGroupChild) executeOriginal(ctx context.Context) (sso.Completion, error) {
	coordinator, registry, err := p.coordinator()
	if err != nil {
		return sso.Completion{}, providerError(ctx, err)
	}
	receipt, err := coordinator.RecoverFeatureCommand(ctx, providerRecovery(p.binding), p.receiptCaller())
	if receipt.Binding.CommandID == "" {
		// Missing history is never proof of rollback. Only the current
		// predecessor may try reserving the original stable child. The
		// kernel rejects an already reserved ID with different input.
		var denied identity.ForbiddenError
		if !errors.As(err, &denied) || p.generation.State != DirectorySyncRunning || p.generation.Checkpoint != p.batch.PredecessorCheckpoint {
			return sso.Completion{}, providerError(ctx, err)
		}
		receipt, err = p.execute(ctx, coordinator, registry)
	}
	if err != nil && receipt.Binding.CommandID == "" {
		return sso.Completion{}, providerError(ctx, err)
	}
	if receipt.Binding != p.binding {
		return sso.Completion{}, sso.ErrForbidden
	}
	if err != nil || receipt.Outcome != identity.CommitOutcomeCommitted {
		if receipt.Outcome == identity.CommitOutcomeUnknown || receipt.Outcome == identity.CommitOutcomeInProgress {
			return receipt, sso.ErrDirectoryReconciliation
		}
		if err != nil {
			return receipt, providerError(ctx, err)
		}
		return receipt, sso.ErrConflict
	}
	return receipt, nil
}

func (p *directoryGroupChild) receiptCaller() authorization.DecisionContext {
	b := p.binding
	return authorization.DecisionContext{PolicyRevision: authorization.Revision(b.PolicyVersion), Request: authorization.Request{
		Tenant: authorization.TenantID(b.TenantID), Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: authorization.SubjectID(b.ActorID)},
		Action: authorization.Action(b.OperationID), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)},
	}}
}

func (p *directoryGroupChild) coordinator() (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
	provider := p.service.generation.provider
	audits, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, nil, err
	}
	outbox, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, nil, err
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{provider.directory, audits, outbox, p})
	if err != nil {
		return nil, nil, err
	}
	config := provider.config.Coordinator
	query := *config.QueryPolicy
	query.Authorization = p.service.config.Authorization
	config.QueryPolicy = &query
	coordinator, err := kernel.NewCoordinator(provider.pool, registry, config)
	return coordinator, registry, err
}

func (p *directoryGroupChild) execute(ctx context.Context, coordinator *kernel.Coordinator, registry *kernel.ContributorRegistry) (identity.CommandResult, error) {
	fields := []identity.FeatureField{{Name: "sso.directory-batch", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: bytes.Clone(p.commitment[:])}}}
	for _, field := range []func() (identity.FeatureField, error){p.admission.source.Field, p.edge.Field, p.update.Field} {
		value, err := field()
		if err != nil {
			return identity.CommandResult{}, err
		}
		fields = append(fields, value)
	}
	op := sso.DirectoryTeamMembershipOperation()
	cmd, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Operation: op, Binding: p.binding, Fields: fields})
	if err != nil {
		return identity.CommandResult{}, err
	}
	p.command = cmd
	plan, err := p.plan(registry)
	if err != nil {
		return identity.CommandResult{}, err
	}
	return executeProviderLogoutCommand(ctx, coordinator, p.binding, cmd, plan)
}

func (p *directoryGroupChild) plan(registry *kernel.ContributorRegistry) (kernel.CommandPlan, error) {
	const subject = "team_membership"
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

func (p *directoryGroupChild) ValidateFeatureCommand(command identity.Command, plan kernel.CommandPlan) error {
	input, ok := command.Feature()
	if !ok || command != p.command || input.Binding != p.binding || input.Operation != sso.DirectoryTeamMembershipOperation() ||
		plan.Feature == nil || *plan.Feature != p.registration() || plan.Lifecycle == nil || *plan.Lifecycle != p.lifecycle() ||
		plan.SubjectType != "team_membership" || len(plan.Audits) != 1 || !plan.Audits[0].Required {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *directoryGroupChild) ApplyFeature(ctx context.Context, work kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	if err := work.RequireFeatureCommand(ctx, p, command); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.service.config.Source.RequireDirectoryGroupEdge(ctx, work, p, command, p.admission.source, p.edge); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.requireActorInWork(ctx, work); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.holdGeneration(ctx, work); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.organizations().ApplyDirectoryTeamGrantUpdate(ctx, work, p, command, p.update); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: sso.DirectoryTeamMembershipOperation(),
		BeforeVersion: p.update.BeforeVersion(), AfterVersion: p.update.AfterVersion()}, nil
}

func (p *directoryGroupChild) CheckFeatureCommit(ctx context.Context, work kernel.Work, command identity.Command) error {
	b, feature, _, err := work.FeatureScope(p)
	if err != nil || command != p.command || b != p.binding || feature != p.registration() {
		return identity.ForbiddenError{}
	}
	if err := p.requirePendingGeneration(ctx, work); err != nil {
		return err
	}
	if err := p.organizations().RequireDirectoryTeamGrantUpdate(ctx, work, p, command, p.update); err != nil {
		return err
	}
	if err := p.service.config.Source.RequireDirectoryGroupEdgeAtCommit(ctx, work, p, command, p.admission.source, p.edge); err != nil {
		return err
	}
	return p.requireActorInWork(ctx, work)
}

func (p *directoryGroupChild) requireActorInWork(ctx context.Context, work kernel.Work) error {
	maximum := p.service.generation.provider.config.MaximumDuration
	if err := authoritypg.RequireAuthority(ctx, work, p.admission.scope, p.admission.epoch, maximum); err != nil {
		return identity.ForbiddenError{}
	}
	now, err := work.DatabaseTime(ctx)
	if err != nil || !now.Before(p.admission.validUntil) {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *directoryGroupChild) organizations() *organizationpg.Repository {
	return p.service.generation.provider.config.Organizations
}
