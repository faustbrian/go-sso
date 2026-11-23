package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
)

const providerGrantRevocationSettled = "enterprise_provider.token_revocation_settled.v1"
const providerGrantRevocationSubject = "provider_grant"

type providerGrantRevokePhase struct {
	service     *ProviderGrantRevocationService
	observed    session.GetResult
	record      session.SessionSpec
	ref         sso.TokenVersionSpec
	endpoint    string
	browser     ProviderGrantRevocationBrowser
	started     time.Time
	intent      [32]byte
	input       providerGrantRevokeInput
	inputDigest [32]byte
	original    session.Session
	command     identity.Command
	plan        kernel.CommandPlan
}

var _ kernel.RequestKeyPreparationContributor = (*providerGrantRevokePhase)(nil)
var _ kernel.FeatureAdmissionPreparationContributor = (*providerGrantRevokePhase)(nil)
var _ kernel.FeatureCommitContributor = (*providerGrantRevokePhase)(nil)

func (p *providerGrantRevokePhase) binding() identity.CommandBinding {
	return identity.CommandBinding(p.input.Command)
}

func (*providerGrantRevokePhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.enterprise-token-vault", Version: 1}
}

func (p *providerGrantRevokePhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{p.registration().Operation}
}

func (p *providerGrantRevokePhase) registration() kernel.FeatureRegistration {
	return kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: identity.FeatureOperation{
		Owner: "sso", OperationID: providerGrantRevokeOperation, SchemaID: providerGrantRevokeOperation + ".native-v1",
		SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired,
	}}
}

func (*providerGrantRevokePhase) lifecycle() kernel.LifecyclePlan {
	// The immutable settlement record is being created; its version is not a
	// new token generation and says nothing about provider success.
	return kernel.LifecyclePlan{EventType: providerGrantRevocationSettled, BeforeVersion: 0, AfterVersion: 1}
}

func (p *providerGrantRevokePhase) declare(registry *kernel.ContributorRegistry) (kernel.CommandPlan, error) {
	b, feature, lifecycle := p.binding(), p.registration(), p.lifecycle()
	builder, err := audit.NewBuilder(audit.BuilderConfig{IDGenerator: func() (string, error) { return "sso-grant-revoke-declaration", nil }})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	record, err := builder.Build(audit.RecordInput{Action: providerGrantRevokeOperation, OccurredAt: p.input.StartedAt,
		Outcome: audit.OutcomeSucceeded, ReasonCode: "completed", Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)},
		Subject: audit.SubjectInput{Type: providerGrantRevocationSubject, ID: b.RecordID},
		Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID},
		Policy:  audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)},
		Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{
			"identity.profile": "identity.security.v1", "command.id": string(b.CommandID), "retention.class": "protected",
			"aggregate.type": providerGrantRevocationSubject, "aggregate.id": b.RecordID,
			"aggregate.before_version": "0", "aggregate.after_version": "1",
		}})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, feature.Operation, providerGrantRevocationSubject, record)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	return kernel.CommandPlan{Contributors: registry.Descriptors(), SubjectType: providerGrantRevocationSubject, Feature: &feature, Lifecycle: &lifecycle,
		Audits: []kernel.AuditPlan{{EventType: providerGrantRevokeOperation, SchemaVersion: 1, BindingDigest: digest, RetentionClass: "protected",
			RetentionPolicyVersion: p.service.completion.start.config.AuditRetentionPolicyVersion, RequiredRecordCount: 1, Required: true,
			MaxRecordBytes: 16384, MaxAggregateBytes: 16384}}}, nil
}

func (p *providerGrantRevokePhase) ValidateFeatureCommand(command identity.Command, plan kernel.CommandPlan) error {
	if p.inputDigest == ([32]byte{}) || command != p.command {
		return identity.ForbiddenError{}
	}
	if plan.Feature != nil && (*plan.Feature != p.registration() || plan.SubjectType != providerGrantRevocationSubject ||
		plan.Lifecycle == nil || *plan.Lifecycle != p.lifecycle()) {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *providerGrantRevokePhase) ValidateFeaturePreparation(command identity.Command, plan kernel.CommandPlan) error {
	if plan.Feature == nil || plan.Capability != nil || plan.CapabilityIssuance != nil || plan.Delivery != nil {
		return identity.ForbiddenError{}
	}
	return p.ValidateFeatureCommand(command, plan)
}

func (p *providerGrantRevokePhase) checkOriginal(ctx context.Context) error {
	if ctx == nil {
		return identity.ForbiddenError{}
	}
	now := p.service.completion.start.router.config.Clock.Now().UTC()
	original, err := sessionpg.OriginalSessionFields(p.observed.Session)
	if err != nil || !equalProviderLogoutFields(original, p.input.Session) || !p.input.validAt(now) || p.observed.ValidateAt(now) != nil {
		return identity.ForbiddenError{}
	}
	lifetime, err := p.original.Lifetime(now)
	if err != nil || !lifetime.Fresh {
		return identity.ForbiddenError{}
	}
	return ctx.Err()
}

func (p *providerGrantRevokePhase) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, command identity.Command) error {
	return p.requireCurrent(ctx, w, command)
}

func (p *providerGrantRevokePhase) requireCurrent(ctx context.Context, w kernel.Work, command identity.Command) error {
	if err := p.ValidateFeatureCommand(command, kernel.CommandPlan{}); err != nil {
		return err
	}
	b, feature, life, err := w.FeatureScope(p)
	if err != nil || b != p.binding() || feature != p.registration() || life != p.lifecycle() {
		return identity.ForbiddenError{}
	}
	start := p.service.completion.start
	spec, err := p.original.Bindings()
	if err != nil || spec.Authentication.Proof.Method != "sso-oauth2" || spec.TenantID != b.TenantID || spec.UserID != b.UserID {
		return identity.ForbiddenError{}
	}
	vector, err := spec.Authority.Bindings()
	if err != nil || vector.ActiveOrganizationID != p.input.Grant.Organization {
		return identity.ForbiddenError{}
	}
	if err := w.RequireActiveDirectoryAuthority(ctx, p, kernel.DirectoryAuthorityAdmission{
		Query:         kernel.DirectoryAuthorityQuery{TenantID: b.TenantID, GlobalAuthorityID: start.config.GlobalAuthorityID},
		GlobalVersion: vector.Global.Version, TenantVersion: vector.Tenant.Version,
	}); err != nil {
		return err
	}
	account := kernel.ProviderAccountAdmission{
		Account: identity.Account(p.input.Grant.Account), SocialLinkVersion: p.input.Grant.SocialLinkVersion,
		Credential: kernel.CredentialAdmission{Credential: identity.CredentialRef{ID: identity.CredentialID(spec.Authentication.CredentialID),
			TenantID: b.TenantID, UserID: b.UserID, Kind: identity.CredentialProvider, Owner: "sso", Version: spec.Authentication.CredentialVersion},
			UserAuthorityVersion: vector.User.Version, IdentifierAuthorityVersion: vector.Identifier.Version, CredentialAuthorityVersion: vector.Credential.Version},
	}
	if _, err := w.RequireActiveProviderAccount(ctx, p, account); err != nil {
		return err
	}
	if err := w.RequireActiveUserAuthorization(ctx, p, kernel.UserAuthorizationAdmission{
		Scope: authority.AuthorityScope{TenantID: authorization.TenantID(b.TenantID), SubjectID: authorization.SubjectID(b.UserID),
			PolicyNamespace: p.service.completion.policy.PolicyNamespace},
		Version: vector.Authorization.Version,
	}); err != nil {
		return err
	}
	if err := mfapg.RequireSSOOAuth2GrantRevocationFactors(ctx, w, p, command, p.original); err != nil {
		return err
	}
	if err := sessionpg.RequireCSRF(ctx, w, start.config.Session, p.original, p.browser.CSRF, p.service.completion.csrfKey); err != nil {
		return err
	}
	if err := start.router.organizations.RequireOrganizationSession(ctx, w, p, p.original); err != nil {
		return err
	}
	rows, err := w.Query(ctx, providerGrantRevocationEpochSQL, providerGrantRevocationEpochArgs(p.input.Grant)...)
	if err != nil {
		return err
	}
	var installed bool
	valid := rows.Next() && rows.Scan(&installed) == nil && installed && !rows.Next()
	readErr := rows.Err()
	rows.Close()
	if !valid || readErr != nil {
		return identity.ForbiddenError{}
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil || !p.input.validAt(now) {
		return identity.ForbiddenError{}
	}
	return p.checkOriginal(ctx)
}

func (p *providerGrantRevokePhase) PrepareFeatureAdmission(ctx context.Context, command identity.Command) (kernel.FeaturePreparationAdmission, error) {
	return p, p.ValidateFeatureCommand(command, kernel.CommandPlan{})
}

func (p *providerGrantRevokePhase) RestoreFeatureAdmission(ctx context.Context, command identity.Command, generation uint64, ciphertext []byte) (kernel.FeaturePreparationAdmission, error) {
	_, _, err := p.RestoreFeaturePreparation(ctx, command, generation, ciphertext)
	return p, err
}

func (p *providerGrantRevokePhase) Check(ctx context.Context) error { return p.checkOriginal(ctx) }

func (*providerGrantRevokePhase) GenerateFeaturePreparation(context.Context, identity.Command, uint64) ([]byte, error) {
	return nil, identity.ForbiddenError{}
}

func (p *providerGrantRevokePhase) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	if err := p.checkOriginal(ctx); err != nil {
		return nil, err
	}
	start := p.service.completion.start
	ctx, cancel := context.WithTimeout(ctx, p.input.ValidUntil.Sub(start.router.config.Clock.Now().UTC()))
	defer cancel()
	grant, ciphertext, err := p.readGrant(ctx)
	defer clear(ciphertext)
	if err != nil || sha256.Sum256(ciphertext) != p.input.CiphertextDigest {
		return nil, identity.ForbiddenError{}
	}
	aad, err := p.outcomeContext(generation)
	if err != nil {
		return nil, err
	}
	transport := p.service.completion.profiles[providerLoginProfileKey{p.ref.OrganizationID, p.ref.ProviderID}]
	outcome, err := start.revokeProviderGrantWithInstalledCredential(ctx, grant, ciphertext, p.binding().CommandID, generation, transport, p.endpoint)
	if err != nil {
		return nil, err
	}
	return p.service.outcomes.seal(ctx, aad, []byte(outcome), 4096)
}

func (p *providerGrantRevokePhase) outcomeContext(generation uint64) (envelope.Context, error) {
	if generation == 0 || p.inputDigest == ([32]byte{}) {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	b := p.binding()
	return envelope.NewContext(map[string]string{
		"profile": "sso-provider-grant-revoke-outcome-v1", "tenant": string(b.TenantID), "attempt": string(b.CommandID),
		"grant": b.RecordID, "generation": strconv.FormatUint(generation, 10),
		"input": base64.RawURLEncoding.EncodeToString(p.inputDigest[:]),
	})
}

func (p *providerGrantRevokePhase) openOutcome(ctx context.Context, g uint64, ciphertext []byte) (providerGrantRevocationReceipt, error) {
	aad, err := p.outcomeContext(g)
	if err != nil {
		return providerGrantRevocationReceipt{}, err
	}
	wire, err := p.service.outcomes.open(ctx, aad, ciphertext, 4096, 12)
	defer clear(wire)
	if err != nil {
		return providerGrantRevocationReceipt{}, err
	}
	b := p.binding()
	outcome := providerGrantRevocationOutcome(string(wire))
	r := providerGrantRevocationReceipt{Tenant: b.TenantID, User: b.UserID, Callback: p.ref.CommandID, Attempt: b.CommandID,
		Version: p.ref.Version, Generation: g, IntentDigest: p.intent, Outcome: outcome, LocalErased: outcome == providerGrantAcknowledged}
	if !r.valid() {
		return providerGrantRevocationReceipt{}, identity.ForbiddenError{}
	}
	return r, nil
}

func (p *providerGrantRevokePhase) RestoreFeaturePreparation(ctx context.Context, command identity.Command, generation uint64, ciphertext []byte) (identity.Command, kernel.CommandPlan, error) {
	if err := p.ValidateFeatureCommand(command, p.plan); err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	if _, err := p.openOutcome(ctx, generation, ciphertext); err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	return command, p.plan, nil
}

func (p *providerGrantRevokePhase) ApplyFeature(ctx context.Context, w kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	if err := w.RequireFeatureCommand(ctx, p, command); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.requireCurrent(ctx, w, command); err != nil {
		return identity.FeatureReceipt{}, err
	}
	wire, generation, err := w.FeaturePreparationOutput(p)
	defer clear(wire)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	receipt, err := p.openOutcome(ctx, generation, wire)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := settleProviderGrantRevocation(ctx, w, receipt, p.input.CiphertextDigest); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: p.registration().Operation, AfterVersion: 1}, nil
}

func (p *providerGrantRevokePhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, command identity.Command) error {
	return p.requireCurrent(ctx, w, command)
}

func (p *providerGrantRevokePhase) matchesReceipt(r providerGrantRevocationReceipt) bool {
	b := p.binding()
	return r.valid() && r.Tenant == b.TenantID && r.User == b.UserID && r.Callback == p.ref.CommandID &&
		r.Attempt == b.CommandID && r.Version == p.ref.Version && r.IntentDigest == p.intent
}

func (p *providerGrantRevokePhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	b, feature, life, err := w.FeatureScope(p)
	if err != nil || b != p.binding() || feature != p.registration() || life != p.lifecycle() {
		return kernel.RecoveryUnknown, identity.ForbiddenError{}
	}
	attempt, _ := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	rows, err := w.Query(ctx, readProviderGrantRevocationReceiptSQL, string(b.TenantID), string(b.UserID), attempt)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	if !rows.Next() {
		return kernel.RecoveryUnknown, rows.Err()
	}
	r, err := scanProviderGrantRevocationReceipt(rows)
	if err != nil || !p.matchesReceipt(r) || rows.Next() || rows.Err() != nil {
		return kernel.RecoveryUnknown, identity.ForbiddenError{}
	}
	return kernel.RecoveryCommitted, nil
}
