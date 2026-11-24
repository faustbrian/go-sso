package postgres

import (
	"bytes"
	"context"
	"strconv"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-sso"
)

func directorySyncStartOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "sso", OperationID: "identity.sso.directory-sync-start",
		SchemaID: "sso-directory-sync-start-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

type directorySyncStartPhase struct {
	service  *DirectorySyncService
	original providerAdmission
	request  DirectorySyncStartRequest
	binding  identity.CommandBinding
	command  identity.Command
	counter  kernel.CommandCounterPlan
}

func (*directorySyncStartPhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.directory-sync-start", Version: 1}
}

func (*directorySyncStartPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{directorySyncStartOperation()}
}

func (p *directorySyncStartPhase) registration() kernel.FeatureRegistration {
	return kernel.FeatureRegistration{Operation: directorySyncStartOperation(), Contributor: p.Descriptor()}
}

func (*directorySyncStartPhase) lifecycle() kernel.LifecyclePlan {
	return kernel.LifecyclePlan{EventType: "sso.directory_sync.started.v1", BeforeVersion: 0, AfterVersion: 1}
}

func (p *directorySyncStartPhase) intentFields() []identity.FeatureField {
	text := func(name, value string) identity.FeatureField {
		return identity.FeatureField{Name: name, Value: identity.FeatureValue{Kind: identity.FeatureText, Text: value}}
	}
	return []identity.FeatureField{
		text("directory.source-id", p.service.connection),
		text("directory.provider-id", string(p.request.ProviderID)),
		text("directory.organization-id", p.service.provider.updateOrganization),
		text("directory.provider-version", strconv.FormatUint(p.request.ProviderVersion, 10)),
		text("directory.mapping-version", strconv.FormatUint(p.request.MappingVersion, 10)),
		text("directory.mode", string(p.request.Mode)),
		text("directory.policy-id", p.service.provider.config.PolicyID),
		{Name: "directory.checkpoint", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: bytes.Clone(p.request.Checkpoint[:])}},
	}
}

func (p *directorySyncStartPhase) plan(registry *kernel.ContributorRegistry) (kernel.CommandPlan, error) {
	b := p.binding
	op := directorySyncStartOperation()
	const subject = "directory_sync"
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return kernel.CommandPlan{}, sso.ErrUnavailable
	}
	record, err := builder.Build(audit.RecordInput{
		OccurredAt: p.original.verified, Action: op.OperationID, Outcome: audit.OutcomeSucceeded,
		Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: subject, ID: b.RecordID},
		Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID},
		Policy:  audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)},
		Changes: audit.ChangeSetInput{Redacted: true},
		Attributes: map[string]string{
			"command.id": string(b.CommandID), "aggregate.type": subject, "aggregate.id": b.RecordID,
			"aggregate.before_version": "0", "aggregate.after_version": "1", "retention.class": "protected",
		},
	})
	if err != nil {
		return kernel.CommandPlan{}, sso.ErrInvalidInput
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, op, subject, record)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	registration, lifecycle := p.registration(), p.lifecycle()
	return kernel.CommandPlan{Contributors: registry.Descriptors(), Feature: &registration, SubjectType: subject,
		Lifecycle: &lifecycle, CommandCounters: &p.counter,
		Audits: []kernel.AuditPlan{{EventType: op.OperationID, SchemaVersion: 1, BindingDigest: digest, RetentionPolicyVersion: 1,
			RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionClass: "protected", Required: true}}}, nil
}

func (p *directorySyncStartPhase) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if c != p.command || plan.Feature == nil || *plan.Feature != p.registration() || plan.Lifecycle == nil ||
		*plan.Lifecycle != p.lifecycle() || plan.SubjectType != "directory_sync" || plan.CommandCounters == nil || *plan.CommandCounters != p.counter ||
		len(plan.Audits) != 1 || plan.Audits[0].EventType != directorySyncStartOperation().OperationID || !plan.Audits[0].Required {
		return identity.ForbiddenError{}
	}
	spec, ok := c.Feature()
	if !ok || spec.Binding != p.binding || spec.Operation != directorySyncStartOperation() {
		return identity.ForbiddenError{}
	}
	return nil
}

// The installation lock prevents disablement or a mapping edit from racing the
// admission. It is shared across different connections; the generation table's
// unique indexes resolve competing starts of the same source.
const directoryStartLockProviderSQL = `SELECT provider_id FROM sso_providers.providers
 WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND enabled
 AND metadata_version=$4::numeric AND COALESCE(metadata_mapping_version,mapping_version)=$5::numeric
 FOR SHARE`

const directoryStartInsertSQL = `INSERT INTO sso_providers.directory_sync_generations
 (tenant_id,organization_id,provider_id,connection_id,generation,generation_id,provider_version,mapping_version,mode,state,checkpoint,initial_checkpoint)
 SELECT $1,$2,$3,$4,latest.number+1,$5,$6::numeric,$7::numeric,$8,'running',$9,$9
 FROM (SELECT COALESCE((SELECT generation FROM sso_providers.directory_sync_generations
    WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4
    ORDER BY generation DESC LIMIT 1),0) AS number) latest
 WHERE latest.number<18446744073709551615 ON CONFLICT DO NOTHING`

func (p *directorySyncStartPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	binding, registration, _, err := w.FeatureScope(p)
	if err != nil || c != p.command || binding != p.binding || registration != p.registration() {
		return identity.ForbiddenError{}
	}
	s, r := p.service.provider, p.request
	if err := requireProviderAdminSession(ctx, w, p, c, s.config, p.original, binding, true); err != nil {
		return err
	}
	rows, err := w.Query(ctx, directoryStartLockProviderSQL, string(binding.TenantID), s.updateOrganization, string(r.ProviderID),
		strconv.FormatUint(r.ProviderVersion, 10), strconv.FormatUint(r.MappingVersion, 10))
	if err != nil {
		return err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return err
		}
		return identity.ForbiddenError{}
	}
	var provider string
	if err := rows.Scan(&provider); err != nil || provider != string(r.ProviderID) || rows.Next() || rows.Err() != nil {
		return identity.UnavailableError{}
	}
	return nil
}

func (p *directorySyncStartPhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if err := w.RequireFeatureCommand(ctx, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.CheckFeatureCommit(ctx, w, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	r := p.request
	count, err := w.Exec(ctx, directoryStartInsertSQL, string(p.binding.TenantID), p.service.provider.updateOrganization,
		string(r.ProviderID), p.service.connection, p.binding.RecordID, strconv.FormatUint(r.ProviderVersion, 10),
		strconv.FormatUint(r.MappingVersion, 10), string(r.Mode), r.Checkpoint[:])
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if count != 1 {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	return identity.FeatureReceipt{Operation: directorySyncStartOperation(), BeforeVersion: 0, AfterVersion: 1}, nil
}

func (p *directorySyncStartPhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	b, feature, lifecycle, err := w.FeatureScope(p)
	if err != nil || b != p.binding || feature != p.registration() || lifecycle != p.lifecycle() {
		return kernel.RecoveryUnknown, identity.ForbiddenError{}
	}
	rows, err := w.Query(ctx, directoryGenerationReadSQL, b.RecordID, string(b.TenantID), p.service.provider.updateOrganization, p.service.connection)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return kernel.RecoveryUnknown, err
		}
		return kernel.RecoveryNotCommitted, nil
	}
	stored, readErr := scanDirectoryGeneration(b.CommandID, rows.Scan)
	r := p.request
	if readErr != nil || rows.Next() || rows.Err() != nil ||
		stored.current.Provider != r.ProviderID || stored.current.ProviderVersion != r.ProviderVersion ||
		stored.current.MappingVersion != r.MappingVersion || stored.current.Mode != r.Mode || stored.initial != r.Checkpoint {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	return kernel.RecoveryCommitted, nil
}
