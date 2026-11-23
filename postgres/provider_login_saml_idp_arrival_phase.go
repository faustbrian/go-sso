package postgres

import (
	"context"
	"reflect"
	"strconv"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
)

type samlIDPArrivalPhase struct {
	service        *ProviderSAMLIDPArrivalService
	pending        samlIDPPendingArrival
	admitted       ProviderSAMLIDPLinkedAdmission
	mappingVersion uint64
	directory      kernel.DirectoryAuthorityAdmission
	command        identity.Command
	issuance       kernel.CapabilityIssuancePlan
	grant          capabilitypg.PreparedIssuance
}

func (*samlIDPArrivalPhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.saml-idp-arrival", Version: 1}
}

func (*samlIDPArrivalPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{samlIDPPendingArrivalOperation()}
}

func samlIDPArrivalReceipt() identity.FeatureReceipt {
	return identity.FeatureReceipt{Operation: samlIDPPendingArrivalOperation(), AfterVersion: 1}
}

func samlIDPArrivalTransition() kernel.LifecyclePlan {
	return kernel.LifecyclePlan{EventType: "sso.saml_confirmation.created.v1", AfterVersion: 1}
}

func (p *samlIDPArrivalPhase) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if p == nil || p.service == nil || p.command == (identity.Command{}) || c != p.command || plan.Feature == nil ||
		*plan.Feature != (kernel.FeatureRegistration{Operation: samlIDPPendingArrivalOperation(), Contributor: p.Descriptor()}) ||
		plan.SubjectType != "sso_saml_confirmation" || plan.Lifecycle == nil || *plan.Lifecycle != samlIDPArrivalTransition() ||
		plan.CapabilityIssuance == nil || !reflect.DeepEqual(*plan.CapabilityIssuance, p.issuance) {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *samlIDPArrivalPhase) plan(registry *kernel.ContributorRegistry) (kernel.CommandPlan, error) {
	b := p.pending.Binding
	op := samlIDPPendingArrivalOperation()
	const subject = "sso_saml_confirmation"
	bld, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	record, err := bld.Build(audit.RecordInput{OccurredAt: p.pending.IssuedAt, Action: op.OperationID, Outcome: audit.OutcomeSucceeded,
		Actor: audit.ActorInput{Kind: audit.ActorService, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: subject, ID: b.RecordID},
		Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID},
		Policy:  audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true},
		Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": subject, "aggregate.id": b.RecordID,
			"aggregate.before_version": "0", "aggregate.after_version": "1", "retention.class": "protected"}})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, op, subject, record)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	transition := samlIDPArrivalTransition()
	return kernel.CommandPlan{Contributors: registry.Descriptors(), SubjectType: subject, Feature: &kernel.FeatureRegistration{Operation: op, Contributor: p.Descriptor()},
		Lifecycle: &transition, CapabilityIssuance: &p.issuance,
		Audits: []kernel.AuditPlan{{EventType: op.OperationID, SchemaVersion: 1, BindingDigest: digest, RetentionClass: "protected",
			RetentionPolicyVersion: p.service.config.AuditRetentionPolicyVersion, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}}, nil
}

// Keep the distinction between taking a new reservation and observing an old
// result. Even a committed old receipt does not disclose a browser pair.
func (p *samlIDPArrivalPhase) execute(ctx context.Context, c *kernel.Coordinator, registry *kernel.ContributorRegistry) (result identity.CommandResult, fresh bool, err error) {
	declaration, err := p.plan(registry)
	if err != nil {
		return result, false, err
	}
	b := p.pending.Binding
	plan, err := c.PrepareCommandPlan(b, p.command, declaration)
	if err != nil {
		return result, false, err
	}
	reservation, observed, err := c.ReserveCommand(ctx, b, p.command, plan)
	if err != nil || reservation == (kernel.Reservation{}) {
		return observed, false, err
	}
	w, err := c.Begin(ctx, reservation)
	if err != nil {
		return result, false, err
	}
	defer c.Abort(w, identity.UnavailableError{})
	result, err = c.ApplyFeature(ctx, w, p.command)
	if err != nil {
		result, err = c.Abort(w, err)
		return result, false, err
	}
	result, err = c.Commit(w, result)
	return result, err == nil && result.Outcome == identity.CommitOutcomeCommitted, err
}

func (p *samlIDPArrivalPhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if err := w.RequireFeatureCommand(ctx, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.requireCurrent(ctx, w, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := insertSAMLIDPPendingArrival(ctx, w, p, c, p.pending); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.service.issuer.Stage(ctx, w, p.grant); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return samlIDPArrivalReceipt(), nil
}

func (p *samlIDPArrivalPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	return p.requireCurrent(ctx, w, c)
}

func (p *samlIDPArrivalPhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	owned := p.pending
	if owned.Binding.CommandID == "" {
		binding, _, _, err := w.FeatureScope(p)
		if err != nil {
			return kernel.RecoveryUnknown, err
		}
		// This caller is observing retained journal authority after process loss.
		// A known original primary-key miss may vote negative; an existing row
		// with no originally captured custody remains Unknown, never a receipt.
		owned.Binding = binding
	}
	return observeSAMLIDPPendingArrival(ctx, w, p, owned)
}

func (p *samlIDPArrivalPhase) requireCurrent(ctx context.Context, w kernel.Work, c identity.Command) error {
	b, f, lifecycle, err := w.FeatureScope(p)
	if err != nil || c != p.command || b != p.pending.Binding || f.Operation != samlIDPPendingArrivalOperation() || f.Contributor != p.Descriptor() || lifecycle != samlIDPArrivalTransition() {
		return identity.ForbiddenError{}
	}
	if err := w.RequireActiveDirectoryAuthority(ctx, p, p.directory); err != nil {
		return err
	}
	if _, err := w.RequireActiveProviderAccount(ctx, p, p.admitted.recipient.account); err != nil {
		return err
	}
	policy := authoritypg.AuthorityScope{TenantID: authorization.TenantID(b.TenantID), PolicyNamespace: p.service.admission.linked.namespace, SubjectID: authorization.SubjectID(b.UserID)}
	maximum := p.service.admission.router.config.MaximumDuration
	if err := authoritypg.RequireAuthority(ctx, w, policy, p.admitted.recipient.policyVersion, maximum); err != nil {
		return err
	}
	// Preserve the original organization epoch to close provider/domain races.
	// Narrowing out the member grants no substitute for the confirmation's
	// separately fenced original linked account and membership.
	owner := p.admitted.recipient.member
	owner.Actor = organization.Member{}
	if err := p.service.admission.router.organizations.RequireCredentialAuthority(ctx, w, p, owner); err != nil {
		return err
	}
	return requireProviderLoginAdmissionRow(ctx, w, providerLoginSAMLAdmissionFenceSQL, p.admitted.admission.route, p.mappingVersion, p.pending.ExpiresAt)
}
