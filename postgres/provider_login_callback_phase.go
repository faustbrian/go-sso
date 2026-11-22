package postgres

import (
	"context"
	"crypto/sha256"
	"reflect"
	"slices"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

type providerLoginCallbackPhase struct {
	providerLoginCallbackInvocation
	refusal           *providerLoginCallbackRefusal
	registry          *kernel.ContributorRegistry
	grant             kernel.CapabilityPlan
	transport         providerLoginCallbackTransport
	oauth2            *StaticOAuth2CompletionProfile
	oauthCallback     oauth.QueryCallback
	oauthInputRefused bool
	oauthAdapter      OAuth2ProtocolAdapterFactory
	oauthRawQuery     string
	input             identity.OAuthCallbackInput
	issuer            *session.SessionIssuer
	effect            *sessionpg.SSOOIDCSigninEffect
	oauthEffect       *sessionpg.SSOOAuth2SigninEffect
	policy            sessionpg.IdentifierAdmissionConfig
	prepared          session.PreparedIssuance
	execution         *providerLoginCallbackExecution
	roleMapping       *providerLoginRoleMapping
	jitPolicy         *providerLoginJITPolicy
	acknowledged      identity.CommandResult
	canDisclose       bool
}

type providerLoginCallbackExecution struct {
	command    identity.Command
	record     session.Session
	admission  risk.AuthenticationAdmission
	tokens     providerLoginPreparedTokens
	roleUpdate organizationpg.ProviderRoleGrantUpdate
	jit        *providerLoginJITExecution
	link       *kernel.SSOOIDCExplicitLinkIntent
	terminal   []byte
	generation uint64
	digest     [32]byte
	validUntil time.Time
}

func providerLoginCallbackDescriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.oidc-login-callback", Version: 1}
}

func providerOAuth2LoginCallbackDescriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.oauth2-login-callback", Version: 1}
}

func providerLoginCallbackLifecycle() kernel.LifecyclePlan {
	return kernel.LifecyclePlan{EventType: "session.created.v1", BeforeVersion: 1, AfterVersion: 2}
}

func providerLoginCallbackRegistration() kernel.FeatureRegistration {
	return kernel.FeatureRegistration{Contributor: providerLoginCallbackDescriptor(), Operation: providerOIDCCallbackOperation()}
}

func providerLoginCallbackPlan(binding identity.CommandBinding, occurred time.Time, auditRetention uint64, grant kernel.CapabilityPlan, contributors []kernel.ContributorDescriptor) (kernel.CommandPlan, error) {
	registration := providerLoginCallbackRegistration()
	lifecycle := providerLoginCallbackLifecycle()
	action, retention, actor := "identity.sso.login", "protected", audit.ActorService
	purpose := providerOIDCCallback
	if op := kernel.SSOOAuth2SigninOperation(); binding.SchemaID == op.SchemaID {
		registration = kernel.FeatureRegistration{Contributor: providerOAuth2LoginCallbackDescriptor(), Operation: op}
		purpose = op.OperationID
	}
	if op := kernel.SSOOIDCExplicitLinkCallbackOperation(); binding.SchemaID == op.SchemaID {
		if binding.ActorKind != authorization.SubjectUser || string(binding.ActorID) != string(binding.UserID) {
			return kernel.CommandPlan{}, identity.ForbiddenError{}
		}
		registration.Operation = op
		lifecycle.EventType = "enterprise_provider.account_linked.v1"
		action, retention, actor = "identity.account.link", "standard", audit.ActorHuman
	}
	oneUse := kernel.ContributorDescriptor{Owner: "capability/postgres", ContractID: "capability.one-use", Version: 1}
	if binding.ValidateFor(registration.Operation) != nil || occurred.IsZero() || auditRetention == 0 || string(grant.Purpose) != purpose ||
		grant.MaxUses != 1 || !occurred.Before(grant.ExpiresAt) || len(contributors) != 5 || contributors[3] != registration.Contributor || contributors[4] != oneUse {
		return kernel.CommandPlan{}, identity.ForbiddenError{}
	}
	builder, err := audit.NewBuilder(audit.BuilderConfig{IDGenerator: func() (string, error) { return "sso-login-callback-declaration", nil }})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	auditSeed, err := builder.Build(audit.RecordInput{OccurredAt: occurred, Action: action, Outcome: audit.OutcomeSucceeded, ReasonCode: "completed",
		Actor: audit.ActorInput{Kind: actor, ID: string(binding.ActorID)}, Subject: audit.SubjectInput{Type: providerLoginSubject, ID: binding.RecordID},
		Context: audit.ContextInput{TenantID: string(binding.TenantID), CorrelationID: binding.CorrelationID},
		Policy:  audit.PolicyMetadata{PolicyID: binding.PolicyID, Version: strconv.FormatUint(binding.PolicyVersion, 10)},
		Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{
			"identity.profile": "identity.security.v1", "command.id": string(binding.CommandID), "retention.class": retention,
			"aggregate.type": providerLoginSubject, "aggregate.id": binding.RecordID, "aggregate.before_version": "1", "aggregate.after_version": "2",
		}})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	digest, err := kernel.FeatureAuditBindingDigest(binding, registration.Operation, providerLoginSubject, auditSeed)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	return kernel.CommandPlan{Contributors: slices.Clone(contributors), Feature: &registration, SubjectType: providerLoginSubject, Capability: &grant, Lifecycle: &lifecycle,
		Audits: []kernel.AuditPlan{{EventType: action, SchemaVersion: 1, BindingDigest: digest, RetentionClass: retention, RetentionPolicyVersion: auditRetention,
			Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384}}}, nil
}

func (p *providerLoginCallbackPhase) Descriptor() kernel.ContributorDescriptor {
	if p != nil && p.oauth2 != nil {
		return providerOAuth2LoginCallbackDescriptor()
	}
	return providerLoginCallbackDescriptor()
}

func (p *providerLoginCallbackPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{p.operation()}
}

func (p *providerLoginCallbackPhase) plan() (kernel.CommandPlan, error) {
	if p == nil || p.service == nil || p.registry == nil {
		return kernel.CommandPlan{}, identity.ForbiddenError{}
	}
	original, ok := p.command.Feature()
	if !ok {
		return kernel.CommandPlan{}, identity.ForbiddenError{}
	}
	return providerLoginCallbackPlan(original.Binding, p.found.Row.IssuedAt, p.service.config.AuditRetentionPolicyVersion, p.grant, p.registry.Descriptors())
}

func (p *providerLoginCallbackPhase) ValidateSSOOIDCSigninConsumption(command identity.Command, grant kernel.CapabilityPlan) error {
	if p == nil || p.oauth2 != nil {
		return identity.ForbiddenError{}
	}
	return p.validateSigninConsumption(command, grant, sessionpg.SSOOIDCSigninSession, sessionpg.SSOOIDCSigninSessionFields)
}

func (p *providerLoginCallbackPhase) ValidateSSOOAuth2SigninConsumption(command identity.Command, grant kernel.CapabilityPlan) error {
	if p == nil || p.oauth2 == nil || p.found.Row.Protocol != providerProtocolOAuth2 {
		return identity.ForbiddenError{}
	}
	return p.validateSigninConsumption(command, grant, sessionpg.SSOOAuth2SigninSession, sessionpg.SSOOAuth2SigninSessionFields)
}

func (p *providerLoginCallbackPhase) validateSigninConsumption(command identity.Command, grant kernel.CapabilityPlan,
	decode func(identity.Command) (session.Session, error), fields func(session.Session) ([]identity.FeatureField, error)) error {
	if p.service == nil || p.member != nil || command == (identity.Command{}) || grant != p.grant {
		return identity.ForbiddenError{}
	}
	if command == p.command {
		return nil
	}
	if p.execution == nil || command != p.execution.command {
		return identity.ForbiddenError{}
	}
	record, err := decode(command)
	if err != nil || !equalProviderLoginSessionWithFields(record, p.execution.record, fields) {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *providerLoginCallbackPhase) ValidateSSOOIDCExplicitLinkConsumption(command identity.Command, grant kernel.CapabilityPlan) error {
	if p == nil || p.service == nil || p.member == nil || grant != p.grant || command == (identity.Command{}) {
		return identity.ForbiddenError{}
	}
	if command == p.command || p.execution != nil && p.execution.link != nil && command == p.execution.command {
		return nil
	}
	return identity.ForbiddenError{}
}

func equalProviderLoginSession(a, b session.Session) bool {
	return equalProviderLoginSessionWithFields(a, b, sessionpg.SSOOIDCSigninSessionFields)
}

func equalProviderLoginSessionWithFields(a, b session.Session, fields func(session.Session) ([]identity.FeatureField, error)) bool {
	af, aErr := fields(a)
	bf, bErr := fields(b)
	return aErr == nil && bErr == nil && reflect.DeepEqual(af, bf)
}

func (p *providerLoginCallbackPhase) ValidateFeatureCommand(command identity.Command, plan kernel.CommandPlan) error {
	expected, err := p.plan()
	if err != nil || plan.Feature == nil || *plan.Feature != *expected.Feature || plan.SubjectType != expected.SubjectType ||
		plan.Capability == nil || plan.Lifecycle == nil || *plan.Lifecycle != *expected.Lifecycle ||
		!reflect.DeepEqual(plan.Audits, expected.Audits) || !slices.Equal(plan.Contributors, expected.Contributors) {
		return identity.ForbiddenError{}
	}
	if p.member != nil {
		return p.ValidateSSOOIDCExplicitLinkConsumption(command, *plan.Capability)
	}
	if p.oauth2 != nil {
		return p.ValidateSSOOAuth2SigninConsumption(command, *plan.Capability)
	}
	return p.ValidateSSOOIDCSigninConsumption(command, *plan.Capability)
}

func (p *providerLoginCallbackPhase) ValidateFeaturePreparation(command identity.Command, plan kernel.CommandPlan) error {
	if p == nil || command != p.command {
		return identity.ForbiddenError{}
	}
	return p.ValidateFeatureCommand(command, plan)
}

func (p *providerLoginCallbackPhase) AdmitFeaturePreparation(ctx context.Context, work kernel.Work, command identity.Command) error {
	if p == nil {
		return identity.ForbiddenError{}
	}
	return p.admitPrimary(ctx, work, p, command)
}

type providerLoginAcknowledgedAdmission struct {
	phase     *providerLoginCallbackPhase
	admission risk.AuthenticationAdmission
}

func (a providerLoginAcknowledgedAdmission) Check(ctx context.Context) error {
	if ctx == nil || a.phase == nil || a.phase.service == nil {
		return identity.ForbiddenError{}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	now := a.phase.service.router.config.Clock.Now().UTC()
	if err := a.phase.checkOriginal(now); err != nil {
		return err
	}
	if a.phase.execution != nil && !now.Before(a.phase.execution.validUntil) {
		return identity.ForbiddenError{}
	}
	return a.admission.CheckAt(ctx, now)
}

func (a providerLoginAcknowledgedAdmission) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	if err := a.Check(ctx); err != nil {
		return nil, err
	}
	return a.phase.generateAccepted(ctx, generation, a.admission)
}

func (p *providerLoginCallbackPhase) PrepareFeatureAdmission(ctx context.Context, command identity.Command) (kernel.FeaturePreparationAdmission, error) {
	if p == nil {
		return nil, identity.ForbiddenError{}
	}
	admission, err := p.prepareRisk(ctx, command)
	if err != nil {
		return nil, err
	}
	a := providerLoginAcknowledgedAdmission{phase: p, admission: admission}
	return a, a.Check(ctx)
}

func (*providerLoginCallbackPhase) GenerateFeaturePreparation(context.Context, identity.Command, uint64) ([]byte, error) {
	return nil, identity.ForbiddenError{}
}

func (p *providerLoginCallbackPhase) RestoreFeatureAdmission(ctx context.Context, command identity.Command, generation uint64, wire []byte) (kernel.FeaturePreparationAdmission, error) {
	if _, _, err := p.RestoreFeaturePreparation(ctx, command, generation, wire); err != nil {
		return nil, err
	}
	a := providerLoginAcknowledgedAdmission{phase: p, admission: p.execution.admission}
	return a, a.Check(ctx)
}

func (p *providerLoginCallbackPhase) RestoreFeaturePreparation(ctx context.Context, command identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	if p == nil || command == (identity.Command{}) || command != p.command {
		return identity.Command{}, kernel.CommandPlan{}, identity.ForbiddenError{}
	}
	if err := p.restoreAccepted(ctx, generation, wire); err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	plan, err := p.plan()
	return p.execution.command, plan, err
}

func (p *providerLoginCallbackPhase) checkExecutionAt(ctx context.Context, work kernel.Work, command identity.Command) error {
	if p == nil || p.execution == nil || p.member == nil && p.effect == nil && p.oauthEffect == nil || command != p.execution.command {
		return identity.ForbiddenError{}
	}
	now, err := work.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	now = now.UTC()
	if !now.Before(p.execution.validUntil) {
		return identity.ForbiddenError{}
	}
	if err := p.checkOriginal(now); err != nil {
		return err
	}
	return p.execution.admission.CheckAt(ctx, now)
}

func (p *providerLoginCallbackPhase) checkProviderCurrent(ctx context.Context, work kernel.Work) error {
	// The session effect acquires its session locks before organization. Keep
	// the same ordering, then retain the exact provider disposition lock.
	owner := p.authority.organization
	if p.execution.jit != nil {
		owner = p.execution.jit.owner
		owner.Version = p.execution.jit.membership.ExpectedOrganizationVersion()
	} else if p.roleMapping != nil {
		// Apply already checked the predecessor and the bound successor in
		// this Work. Preserve the original observation's freshness window.
		owner.Version = p.execution.roleUpdate.ExpectedOrganizationVersion()
	}
	if err := p.service.router.organizations.RequireCredentialAuthority(ctx, work, p, owner); err != nil {
		return err
	}
	if p.oauth2 != nil || p.execution.jit != nil {
		return requireProviderLoginCallbackDispositionAt(ctx, work, p.found, p.execution.validUntil, false)
	}
	return requireProviderLoginCallbackDisposition(ctx, work, p.found, p.execution.validUntil)
}

func (p *providerLoginCallbackPhase) ApplyFeature(ctx context.Context, work kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	if err := p.checkExecutionAt(ctx, work, command); err != nil {
		return identity.FeatureReceipt{}, err
	}
	wire, generation, err := work.FeaturePreparationOutput(p)
	defer clear(wire)
	if err != nil || generation != p.execution.generation || sha256.Sum256(wire) != p.execution.digest {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	if p.member != nil {
		return p.applyMemberCallback(ctx, work, command)
	}
	if p.execution.jit != nil {
		if err := p.applyProviderLoginJIT(ctx, work, command); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	var receipt identity.FeatureReceipt
	if p.oauth2 != nil {
		receipt, err = p.oauthEffect.Apply(ctx, work, p, command, p.flow)
	} else if p.roleMapping == nil && p.execution.jit == nil {
		receipt, err = p.effect.Apply(ctx, work, p, command, p.flow)
	} else {
		receipt, err = p.effect.ApplyWithOrganizationUpdate(ctx, work, p, command, p.flow, p)
	}
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.checkProviderCurrent(ctx, work); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.service.persistProviderLoginTokens(ctx, work, p, command, p.execution.tokens, p.execution.digest); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.service.completeProviderLoginCallback(ctx, work, p, command, p.found, p.execution.validUntil, p.execution.terminal); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return receipt, nil
}

func (p *providerLoginCallbackPhase) UpdateSSOOIDCOrganization(ctx context.Context, work kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, record session.Session) error {
	if p == nil || p.execution == nil || owner != p || command != p.execution.command ||
		!equalProviderLoginSession(record, p.execution.record) {
		return identity.ForbiddenError{}
	}
	if p.execution.jit != nil {
		return p.service.router.organizations.ApplyProviderJITMembership(ctx, work, owner, command, p.execution.jit.membership)
	}
	if p.roleMapping == nil {
		return identity.ForbiddenError{}
	}
	return p.service.router.organizations.ApplyProviderRoleGrantUpdate(ctx, work, owner, command, p.execution.roleUpdate)
}

func (p *providerLoginCallbackPhase) CheckFeatureCommit(ctx context.Context, work kernel.Work, command identity.Command) error {
	if err := p.checkExecutionAt(ctx, work, command); err != nil {
		return err
	}
	if p.member != nil {
		return p.requireMemberCallbackAuthority(ctx, work, p, command, false)
	}
	if p.execution.jit != nil {
		if _, err := work.SSOOIDCJITUser(ctx, p, command); err != nil {
			return err
		}
	}
	var err error
	if p.oauth2 != nil {
		err = p.oauthEffect.CheckCurrent(ctx, work, p, command)
	} else {
		err = p.effect.CheckCurrent(ctx, work, p, command)
	}
	if err != nil {
		return err
	}
	if err := p.checkProviderCurrent(ctx, work); err != nil {
		return err
	}
	return p.checkExecutionAt(ctx, work, command)
}

func (p *providerLoginCallbackPhase) RecoverParticipant(ctx context.Context, work kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	if p != nil && p.oauth2 != nil && p.oauthEffect != nil {
		return p.oauthEffect.Recover(ctx, work, p)
	}
	if p == nil || p.effect == nil {
		return 0, identity.ForbiddenError{}
	}
	return p.effect.Recover(ctx, work, p)
}

func (p *providerLoginCallbackPhase) ExecuteIssue(ctx context.Context, request session.IssueRequest) (session.IssueExecution, error) {
	if ctx == nil || p == nil || !p.canDisclose || p.execution == nil || ctx.Err() != nil {
		return session.IssueExecution{}, identity.ForbiddenError{}
	}
	selectCommand := request.SSOOIDCCommand
	fields := sessionpg.SSOOIDCSigninSessionFields
	if p.oauth2 != nil {
		selectCommand, fields = request.SSOOAuth2Command, sessionpg.SSOOAuth2SigninSessionFields
	}
	command, record, selected := selectCommand()
	if !selected || command != p.execution.command || !equalProviderLoginSessionWithFields(record, p.execution.record, fields) ||
		p.acknowledged.Outcome != identity.CommitOutcomeCommitted || p.acknowledged.Validate() != nil {
		return session.IssueExecution{}, identity.ForbiddenError{}
	}
	p.canDisclose = false
	return session.IssueExecution{Receipt: p.acknowledged, Session: p.execution.record}, nil
}

func (*providerLoginCallbackPhase) RecoverIssue(context.Context, session.IssueRequest) (session.IssueExecution, error) {
	return session.IssueExecution{}, identity.ForbiddenError{}
}

var (
	_ kernel.FeatureAdmissionPreparationContributor = (*providerLoginCallbackPhase)(nil)
	_ kernel.SSOOIDCSigninContributor               = (*providerLoginCallbackPhase)(nil)
	_ kernel.SSOOAuth2SigninContributor             = (*providerLoginCallbackPhase)(nil)
	_ session.IssueExecutor                         = (*providerLoginCallbackPhase)(nil)
)
