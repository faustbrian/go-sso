package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"strconv"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

const (
	providerLogoutCompleteKind = "provider_complete"
	providerLogoutErrorKind    = "provider_error"
	providerLogoutTimeoutKind  = "timeout"
	providerLogoutSubject      = "sso_logout_completion"
)

type providerLogoutCompletePhase struct {
	service   *ProviderLogoutService
	row       providerLogoutRow
	bound     providerLogoutBinding
	wire      []byte
	requested string
	terminal  string
}

func (*providerLogoutCompletePhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.SSOOIDCLogoutCompleteDescriptor()
}

func (*providerLogoutCompletePhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{kernel.SSOOIDCLogoutCompleteOperation()}
}

func (p *providerLogoutCompletePhase) registration() kernel.FeatureRegistration {
	return kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: kernel.SSOOIDCLogoutCompleteOperation()}
}

func (p *providerLogoutCompletePhase) binding() identity.CommandBinding {
	c, op := p.service.login, p.registration().Operation
	return identity.CommandBinding{CommandID: p.bound.CompletionCommandID, TenantID: p.row.TenantID, UserID: p.bound.UserID,
		ActorID: c.config.ActorID, ActorKind: authorization.SubjectServiceAccount, PolicyID: c.config.PolicyID,
		PolicyVersion: c.policyVersion, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion,
		RecordID: p.bound.SessionID, CorrelationID: string(p.bound.CompletionCommandID)}
}

func (*providerLogoutCompletePhase) lifecycle() kernel.LifecyclePlan {
	return kernel.LifecyclePlan{EventType: "sso.oidc.logout.completed.v1", AfterVersion: 1}
}

func (p *providerLogoutCompletePhase) command() (identity.Command, error) {
	if p.requested != providerLogoutCompleteKind && p.requested != providerLogoutErrorKind {
		return identity.Command{}, identity.ForbiddenError{}
	}
	digest := sha256.Sum256(p.wire)
	return identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: p.binding(), Operation: p.registration().Operation, Fields: []identity.FeatureField{
		{Name: "sso.logout.binding", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest[:]}},
		{Name: "sso.logout.kind", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: p.requested}},
	}})
}

func (p *providerLogoutCompletePhase) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	want, err := p.command()
	if err != nil {
		return err
	}
	expected, _ := want.Feature()
	actual, ok := c.Feature()
	if !ok || actual.Binding != expected.Binding || actual.Operation != expected.Operation || !equalProviderLogoutFields(actual.Fields, expected.Fields) ||
		plan.SubjectType != providerLogoutSubject || plan.Feature == nil || *plan.Feature != p.registration() || plan.Lifecycle == nil || *plan.Lifecycle != p.lifecycle() {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *providerLogoutCompletePhase) plan(registry *kernel.ContributorRegistry) (kernel.CommandPlan, error) {
	b, f, life := p.binding(), p.registration(), p.lifecycle()
	const action = "identity.sso.oidc.logout_complete"
	bldr, err := audit.NewBuilder(audit.BuilderConfig{IDGenerator: func() (string, error) { return "sso-oidc-logout-complete-declaration", nil }})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	// This declaration records successful custody settlement, not proof that
	// the upstream provider ended its session. The row retains that outcome.
	seed, err := bldr.Build(audit.RecordInput{Action: action, OccurredAt: p.row.IssuedAt, Outcome: audit.OutcomeSucceeded, ReasonCode: "completed",
		Actor: audit.ActorInput{Kind: audit.ActorService, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: providerLogoutSubject, ID: b.RecordID},
		Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID},
		Policy:  audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true},
		Attributes: map[string]string{"identity.profile": "identity.security.v1", "command.id": string(b.CommandID), "retention.class": "protected",
			"aggregate.type": providerLogoutSubject, "aggregate.id": b.RecordID, "aggregate.before_version": "0", "aggregate.after_version": "1"},
	})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, f.Operation, providerLogoutSubject, seed)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	return kernel.CommandPlan{Contributors: registry.Descriptors(), SubjectType: providerLogoutSubject, Feature: &f, Lifecycle: &life,
		Audits: []kernel.AuditPlan{{EventType: action, SchemaVersion: 1, BindingDigest: digest, RetentionClass: "protected",
			RetentionPolicyVersion: p.service.login.config.AuditRetentionPolicyVersion, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384}},
	}, nil
}

// Take the row lock before obtaining authoritative time. Time spent waiting
// for an application writer cannot extend the original provider deadline.
const providerLogoutCompleteSQL = `WITH locked AS MATERIALIZED (
 SELECT tenant_id,state_key_version,state_digest,issued_at,expires_at
 FROM sso_providers.logout_transactions WHERE (tenant_id,state_key_version,state_digest)=($1,$2,$3)
 AND start_command_id=$4 AND binding_envelope=$5 AND issued_at=$6 AND expires_at=$7 AND completed_at IS NULL FOR UPDATE
), observed AS MATERIALIZED (
 SELECT locked.*,clock_timestamp() AS now FROM locked
)
UPDATE sso_providers.logout_transactions t
 SET completed_at=o.now,completion_command_id=$8,
 completion_kind=CASE WHEN o.now>=o.expires_at THEN 'timeout' ELSE $9 END
 FROM observed o WHERE (t.tenant_id,t.state_key_version,t.state_digest)=(o.tenant_id,o.state_key_version,o.state_digest)
 AND o.now>=o.issued_at RETURNING t.completion_kind`

const providerLogoutCompletionEvidenceSQL = `SELECT COALESCE(completion_kind,''),COALESCE(completion_command_id,''::bytea)
 FROM sso_providers.logout_transactions WHERE (tenant_id,state_key_version,state_digest)=($1,$2,$3)
 AND start_command_id=$4 AND binding_envelope=$5 AND issued_at=$6 AND expires_at=$7`

func (p *providerLogoutCompletePhase) rowArgs() []any {
	r := p.row
	return []any{string(r.TenantID), int64(r.StateKeyVersion), r.StateDigest[:], r.commandBytes(), p.wire, r.IssuedAt, r.ExpiresAt}
}

func (p *providerLogoutCompletePhase) ApplyFeature(ctx context.Context, work kernel.Work, _ identity.Command) (identity.FeatureReceipt, error) {
	b, f, life, err := work.FeatureScope(p)
	if err != nil || b != p.binding() || f != p.registration() || life != p.lifecycle() {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	completion, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	rows, err := work.Query(ctx, providerLogoutCompleteSQL, append(p.rowArgs(), completion, p.requested)...)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return identity.FeatureReceipt{}, err
		}
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	var kind string
	if err := rows.Scan(&kind); err != nil || rows.Next() || rows.Err() != nil || !p.validTerminal(kind) {
		return identity.FeatureReceipt{}, identity.UnavailableError{}
	}
	p.terminal = kind
	return identity.FeatureReceipt{Operation: f.Operation, AfterVersion: 1}, nil
}

func (p *providerLogoutCompletePhase) validTerminal(kind string) bool {
	return kind == p.requested || kind == providerLogoutTimeoutKind
}

func (p *providerLogoutCompletePhase) RecoverParticipant(ctx context.Context, work kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	b, f, life, err := work.FeatureScope(p)
	if err != nil || b != p.binding() || f != p.registration() || life != p.lifecycle() {
		return kernel.RecoveryUnknown, identity.ForbiddenError{}
	}
	rows, err := work.Query(ctx, providerLogoutCompletionEvidenceSQL, p.rowArgs()...)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	var kind string
	var command []byte
	if !rows.Next() || rows.Scan(&kind, &command) != nil || rows.Next() || rows.Err() != nil {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	if kind == "" && len(command) == 0 {
		return kernel.RecoveryNotCommitted, nil
	}
	if p.validTerminal(kind) && base64.RawURLEncoding.EncodeToString(command) == string(b.CommandID) {
		return kernel.RecoveryCommitted, nil
	}
	return kernel.RecoveryUnknown, identity.UnavailableError{}
}

var _ kernel.FeatureExecutionContributor = (*providerLogoutCompletePhase)(nil)
