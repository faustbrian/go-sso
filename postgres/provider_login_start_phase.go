package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

const providerLoginSubject = "sso_login_transaction"

func providerSigninOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "sso", OperationID: providerSigninStart, SchemaID: "identity.sso.signin-start.oidc-v1",
		SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
}

func providerLoginLifecycle() kernel.LifecyclePlan {
	return kernel.LifecyclePlan{EventType: "oauth.rp_transaction.created.v1", AfterVersion: 1}
}

var (
	_ kernel.FeatureAdmissionPreparationContributor = (*providerLoginPhase)(nil)
	_ kernel.RequestKeyPreparationContributor       = (*providerLoginPhase)(nil)
)

func (*providerLoginPhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.oidc-login-start", Version: 1}
}

func (p *providerLoginPhase) operation() identity.FeatureOperation {
	if p.member != nil {
		return providerExplicitLinkStartOperation()
	}
	return providerSigninOperation()
}

func (p *providerLoginPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{p.operation()}
}

func (p *providerLoginPhase) registration() kernel.FeatureRegistration {
	return kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: p.operation()}
}

func (p *providerLoginPhase) matchesIntent(field identity.FeatureField) bool {
	return field.Name == "sso.signin.intent" && field.Value.Kind == identity.FeatureBytes && bytes.Equal(field.Value.Bytes, p.intent[:])
}

func (p *providerLoginPhase) command() (identity.Command, error) {
	if p.input == nil {
		return identity.Command{}, identity.ForbiddenError{}
	}
	frame, err := json.Marshal(p.input)
	if err != nil {
		return identity.Command{}, identity.UnavailableError{}
	}
	defer clear(frame)
	digest := sha256.Sum256(frame)
	spec := identity.FeatureCommandSpec{Binding: identity.CommandBinding(p.input.Command), Operation: p.operation(),
		Fields: []identity.FeatureField{{Name: "sso.signin.input", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest[:]}}}}
	if p.member != nil {
		return identity.NewFeatureSessionCommand(spec, p.member.browser.Session)
	}
	return identity.NewFeaturePreAuthCommand(spec, p.browser.FlowCookie)
}

func (p *providerLoginPhase) ValidateFeatureCommand(command identity.Command, plan kernel.CommandPlan) error {
	expected, err := p.command()
	if err != nil {
		return err
	}
	wanted, _ := expected.Feature()
	actual, ok := command.Feature()
	cookie, hasCookie := command.PreAuthCookie()
	bearer, hasBearer := command.SessionToken()
	matchingCredential := hasCookie && !hasBearer && cookie == p.browser.FlowCookie
	if p.member != nil {
		matchingCredential = !hasCookie && hasBearer && bearer == p.member.browser.Session
	}
	if !ok || !matchingCredential || actual.Binding != wanted.Binding || actual.Operation != wanted.Operation ||
		len(actual.Fields) != 1 || actual.Fields[0].Name != wanted.Fields[0].Name || actual.Fields[0].Value.Kind != identity.FeatureBytes ||
		!bytes.Equal(actual.Fields[0].Value.Bytes, wanted.Fields[0].Value.Bytes) {
		return identity.ForbiddenError{}
	}
	if plan.Feature != nil && (*plan.Feature != p.registration() || plan.SubjectType != providerLoginSubject ||
		plan.CommandCounters != nil || plan.Lifecycle == nil || *plan.Lifecycle != providerLoginLifecycle() ||
		plan.Delivery != nil || plan.Capability != nil) {
		return identity.ForbiddenError{}
	}
	return p.requireStartBrowser(p.input, p.input.Started)
}

func (p *providerLoginPhase) ValidateFeaturePreparation(command identity.Command, plan kernel.CommandPlan) error {
	if plan.CapabilityIssuance != nil {
		return identity.ForbiddenError{}
	}
	return p.ValidateFeatureCommand(command, plan)
}

func (p *providerLoginPhase) plan(registry *kernel.ContributorRegistry, issuance *kernel.CapabilityIssuancePlan) (kernel.CommandPlan, error) {
	if p.input == nil || registry == nil {
		return kernel.CommandPlan{}, identity.ForbiddenError{}
	}
	contributors := registry.Descriptors()
	if len(contributors) != 5 || contributors[4] != p.service.payload.Issuer.Descriptor() {
		return kernel.CommandPlan{}, identity.ForbiddenError{}
	}
	if issuance == nil {
		contributors = contributors[:4]
	}
	auditPlan, err := p.auditPlan()
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	operation, lifecycle := p.registration(), providerLoginLifecycle()
	return kernel.CommandPlan{Contributors: contributors, Feature: &operation, SubjectType: providerLoginSubject,
		Audits: []kernel.AuditPlan{auditPlan}, Lifecycle: &lifecycle, CapabilityIssuance: issuance}, nil
}

func (p *providerLoginPhase) auditPlan() (kernel.AuditPlan, error) {
	// The enterprise login action is protected in the security event catalog.
	// This record targets the initiation transaction, not a successful session.
	const action = "identity.sso.login"
	b := identity.CommandBinding(p.input.Command)
	builder, err := audit.NewBuilder(audit.BuilderConfig{IDGenerator: func() (string, error) { return "sso-login-start-declaration", nil }})
	if err != nil {
		return kernel.AuditPlan{}, err
	}
	actor := audit.ActorInput{Kind: audit.ActorService, ID: string(b.ActorID)}
	if p.member != nil {
		actor.Kind = audit.ActorHuman
	}
	seed, err := builder.Build(audit.RecordInput{Action: action, OccurredAt: p.input.Started, Outcome: audit.OutcomeSucceeded,
		ReasonCode: "completed", Actor: actor,
		Subject: audit.SubjectInput{Type: providerLoginSubject, ID: b.RecordID},
		Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID},
		Policy:  audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)},
		Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{
			"identity.profile": "identity.security.v1", "command.id": string(b.CommandID), "retention.class": "protected",
			"aggregate.type": providerLoginSubject, "aggregate.id": b.RecordID, "aggregate.before_version": "0", "aggregate.after_version": "1",
		}})
	if err != nil {
		return kernel.AuditPlan{}, err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, p.operation(), providerLoginSubject, seed)
	if err != nil {
		return kernel.AuditPlan{}, err
	}
	return kernel.AuditPlan{EventType: action, SchemaVersion: 1, BindingDigest: digest, RetentionClass: "protected",
		RetentionPolicyVersion: p.service.config.AuditRetentionPolicyVersion, Required: true,
		RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384}, nil
}

func (p *providerLoginPhase) checkPrimary(ctx context.Context, work kernel.Work, command identity.Command) error {
	b, feature, lifecycle, err := work.FeatureScope(p)
	if err != nil || p.input == nil || b != identity.CommandBinding(p.input.Command) ||
		feature != p.registration() || lifecycle != providerLoginLifecycle() {
		return identity.ForbiddenError{}
	}
	if err := p.ValidateFeatureCommand(command, kernel.CommandPlan{}); err != nil {
		return err
	}
	if err := work.RequireActiveDirectoryAuthority(ctx, p, kernel.DirectoryAuthorityAdmission{Query: p.service.directoryQuery(),
		GlobalVersion: p.input.GlobalVersion, TenantVersion: p.input.TenantVersion}); err != nil {
		return err
	}
	if p.member != nil {
		if err := p.requireLinkStartAuthority(ctx, work, command); err != nil {
			return err
		}
	} else if err := sessionpg.RequirePreAuth(ctx, work, p.service.config.Session, p.flow); err != nil {
		return err
	}
	authority, err := p.input.authority()
	if err != nil {
		return err
	}
	if err := p.service.router.requireProviderLoginAuthority(ctx, work, p, authority, p.input.MappingVersion); err != nil {
		return err
	}
	now, err := work.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if now.Before(p.input.Started) || !now.Before(p.input.Expires) || p.member != nil && !now.Before(p.input.MemberReadUntil) {
		return identity.ForbiddenError{}
	}
	return p.requireStartBrowser(p.input, now)
}

func (p *providerLoginPhase) AdmitFeaturePreparation(ctx context.Context, work kernel.Work, command identity.Command) error {
	return p.checkPrimary(ctx, work, command)
}

func (p *providerLoginPhase) CheckFeatureCommit(ctx context.Context, work kernel.Work, command identity.Command) error {
	return p.checkPrimary(ctx, work, command)
}

func (p *providerLoginPhase) ApplyFeature(ctx context.Context, work kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	if err := p.checkPrimary(ctx, work, command); err != nil {
		return identity.FeatureReceipt{}, err
	}
	wire, generation, err := work.FeaturePreparationOutput(p)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	defer clear(wire)
	if !p.restored.matches(generation, wire) {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	output := p.restored.output
	authority, err := p.input.authority()
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.service.router.persistProviderLoginStart(ctx, work, p, command, authority, p.input.MappingVersion, output.State); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.service.payload.Issuer.Stage(ctx, work, output.Issuance); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: p.operation(), AfterVersion: 1}, nil
}

// Restore runs before the coordinator enters the SQL transaction. Reconfirming
// the exact attached output in Work avoids borrowing envelope-key IO under
// database locks. This is request-local state, not durable recovery evidence.
type providerLoginRestoration struct {
	generation uint64
	digest     [32]byte
	output     providerLoginPayloadOutput
}

func (r providerLoginRestoration) matches(generation uint64, wire []byte) bool {
	return r.generation != 0 && r.generation == generation && r.digest == sha256.Sum256(wire)
}

func (p *providerLoginPhase) restorePrepared(ctx context.Context, generation uint64, wire []byte) (providerLoginPayloadOutput, error) {
	if p.restored.matches(generation, wire) {
		return p.restored.output, nil
	}
	if p.restored.generation != 0 {
		return providerLoginPayloadOutput{}, identity.ForbiddenError{}
	}
	output, err := p.service.payload.restore(ctx, p.input.payload(), generation, wire)
	if err != nil {
		return providerLoginPayloadOutput{}, err
	}
	p.restored = providerLoginRestoration{generation: generation, digest: sha256.Sum256(wire), output: output}
	return output, nil
}

func (p *providerLoginPhase) riskScope() (risk.Context, risk.Subject) {
	b := identity.CommandBinding(p.input.Command)
	// At start no user is known. Give the identifier velocity dimension a stable
	// provider-scoped bucket without pretending to identify a person.
	identifier := sha256.Sum256([]byte("sso-oidc-start-provider\x00" + string(b.TenantID) + "\x00" +
		string(p.input.Proof.OrganizationID) + "\x00" + string(p.input.ProviderID)))
	return risk.Context{Tenant: string(b.TenantID), Operation: risk.Action(b.OperationID), Attempt: string(b.CommandID)},
		risk.Subject{Network: p.browser.Network.String(), Device: p.browser.Device, IdentifierDigest: hex.EncodeToString(identifier[:])}
}

type providerLoginAdmission struct {
	phase     *providerLoginPhase
	admission risk.AuthenticationAdmission
}

func (a providerLoginAdmission) Check(ctx context.Context) error {
	now := a.phase.service.router.config.Clock.Now().UTC()
	input := a.phase.input
	if now.Before(input.Started) || !now.Before(input.Expires) ||
		!now.Before(earlierLoginTime(input.RouteValidUntil, input.Organization.ValidUntil)) || a.phase.member != nil && !now.Before(input.MemberReadUntil) {
		return identity.ForbiddenError{}
	}
	return a.admission.CheckAt(ctx, now)
}

func (a providerLoginAdmission) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	if err := a.Check(ctx); err != nil {
		return nil, err
	}
	return a.phase.service.payload.generate(ctx, a.phase.input.payload(), generation, a.admission.Prepared())
}

func (p *providerLoginPhase) PrepareFeatureAdmission(ctx context.Context, command identity.Command) (kernel.FeaturePreparationAdmission, error) {
	if err := p.ValidateFeatureCommand(command, kernel.CommandPlan{}); err != nil {
		return nil, err
	}
	b := identity.CommandBinding(p.input.Command)
	scope, subject := p.riskScope()
	actor := audit.ActorInput{Kind: audit.ActorAnonymous}
	if p.member != nil {
		actor = audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}
	}
	result, err := p.service.config.Risk.Evaluation.Evaluate(ctx, risk.EvaluateRequest{Context: scope, Phase: risk.NonIssuing,
		Subject: subject, Attribution: &risk.DecisionAttribution{CommandID: b.CommandID, CorrelationID: b.CommandID,
			Actor: actor, Subject: identity.SecurityAuthenticationAttempt, SubjectID: string(b.CommandID)}})
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	admitted, err := p.service.custody.Prepare(ctx, result, scope, subject)
	if err != nil {
		return nil, identity.ForbiddenError{}
	}
	admission := providerLoginAdmission{p, admitted}
	return admission, admission.Check(ctx)
}

func (*providerLoginPhase) GenerateFeaturePreparation(context.Context, identity.Command, uint64) ([]byte, error) {
	return nil, identity.ForbiddenError{}
}

func (p *providerLoginPhase) RestoreFeatureAdmission(ctx context.Context, command identity.Command, generation uint64, wire []byte) (kernel.FeaturePreparationAdmission, error) {
	if err := p.ValidateFeatureCommand(command, kernel.CommandPlan{}); err != nil {
		return nil, err
	}
	output, err := p.restorePrepared(ctx, generation, wire)
	if err != nil {
		return nil, err
	}
	scope, subject := p.riskScope()
	admitted, err := p.service.custody.Restore(ctx, output.Risk, scope, subject)
	if err != nil {
		return nil, identity.ForbiddenError{}
	}
	admission := providerLoginAdmission{p, admitted}
	return admission, admission.Check(ctx)
}

func (p *providerLoginPhase) RestoreFeaturePreparation(ctx context.Context, command identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	if err := p.ValidateFeaturePreparation(command, kernel.CommandPlan{}); err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	output, err := p.restorePrepared(ctx, generation, wire)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	issuance, err := output.Issuance.Plan()
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	plan, err := p.plan(p.registry, &issuance)
	return command, plan, err
}
