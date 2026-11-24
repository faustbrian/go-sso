package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-sso"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

func (p *samlLogoutRelayIssuePhase) coordinator() (*kernel.Coordinator, error) {
	auditing, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, err
	}
	lifecycle, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, err
	}
	p.registry, err = kernel.NewContributorRegistry([]kernel.Contributor{p.login().directory, auditing, lifecycle, p, p.login().payload.Issuer})
	if err != nil {
		return nil, err
	}
	return kernel.NewCoordinatorWithRequestKeys(p.login().router.pool, p.registry, p.login().config.Coordinator, *p.service.relayKeys)
}

func (p *samlLogoutRelayIssuePhase) plan(generated bool) (kernel.CommandPlan, error) {
	if p.input == nil || p.registry == nil {
		return kernel.CommandPlan{}, identity.ForbiddenError{}
	}
	b := identity.CommandBinding(p.input.Command)
	op := kernel.SSOSAMLLogoutRelayIssueOperation()
	lifecycle := kernel.SSOSAMLLogoutRelayIssueLifecycle()
	feature := p.registration()
	builder, err := audit.NewBuilder(audit.BuilderConfig{IDGenerator: func() (string, error) { return "sso-saml-logout-relay-declaration", nil }})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	seed, err := builder.Build(audit.RecordInput{Action: op.OperationID, OccurredAt: p.input.IssuedAt, Outcome: audit.OutcomeSucceeded, ReasonCode: "completed", Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: samlLogoutRelayIssueSubject, ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"identity.profile": "identity.security.v1", "command.id": string(b.CommandID), "retention.class": "protected", "aggregate.type": samlLogoutRelayIssueSubject, "aggregate.id": b.RecordID, "aggregate.before_version": "0", "aggregate.after_version": "1"}})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, op, samlLogoutRelayIssueSubject, seed)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	contributors := p.registry.Descriptors()
	plan := kernel.CommandPlan{Feature: &feature, Lifecycle: &lifecycle, SubjectType: samlLogoutRelayIssueSubject, Audits: []kernel.AuditPlan{{EventType: op.OperationID, SchemaVersion: 1, BindingDigest: digest, RetentionClass: "protected", RetentionPolicyVersion: p.login().config.AuditRetentionPolicyVersion, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384}}}
	if generated {
		issuance, err := p.issuance.Plan()
		if err != nil {
			return kernel.CommandPlan{}, err
		}
		plan.CapabilityIssuance = &issuance
	} else {
		contributors = contributors[:len(contributors)-1]
	}
	plan.Contributors = contributors
	return plan, nil
}

const requireSAMLLogoutRelayLocalCommitSQL = `SELECT true FROM identity.commands
 WHERE tenant_id=$1::identity.directory_id AND command_id=$2 AND purpose='identity.sso.saml-logout-start' AND state='committed'`

func (p *samlLogoutRelayIssuePhase) checkAuthority(ctx context.Context, work kernel.Work) error {
	b, feature, lifecycle, err := work.FeatureScope(p)
	if err != nil || p.input == nil || b != identity.CommandBinding(p.input.Command) || feature != p.registration() || lifecycle != kernel.SSOSAMLLogoutRelayIssueLifecycle() {
		return identity.ForbiddenError{}
	}
	local := identity.CommandBinding(p.input.LocalCommand)
	command, err := base64.RawURLEncoding.Strict().DecodeString(string(local.CommandID))
	if err != nil || len(command) != 16 {
		return identity.ForbiddenError{}
	}
	rows, err := work.Query(ctx, requireSAMLLogoutRelayLocalCommitSQL, string(local.TenantID), command)
	if err != nil {
		return err
	}
	if err := readSAMLLogoutRelayFence(rows); err != nil {
		return err
	}
	if err := p.login().router.organizations.RequireCredentialAuthority(ctx, work, p, p.input.Organization); err != nil {
		return err
	}
	if err := requireProviderLoginAdmissionRow(ctx, work, providerLoginSAMLAdmissionFenceSQL, p.input.Route.binding(), p.profile.config.Provider.MappingVersion, minSAMLLogoutTime(p.input.ExpiresAt, minSAMLLogoutTime(p.input.Route.ValidUntil, p.input.Organization.ValidUntil))); err != nil {
		return err
	}
	now, err := work.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if now.Before(p.input.IssuedAt) || !now.Before(p.input.ExpiresAt) || p.output != nil && !now.Before(p.output.Row.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	return nil
}

func readSAMLLogoutRelayFence(rows *kernel.WorkRows) error {
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return err
		}
		return identity.ForbiddenError{}
	}
	var yes bool
	if err := rows.Scan(&yes); err != nil {
		return err
	}
	if !yes || rows.Next() {
		return identity.ForbiddenError{}
	}
	return rows.Err()
}

func (p *samlLogoutRelayIssuePhase) AdmitFeaturePreparation(ctx context.Context, work kernel.Work, command identity.Command) error {
	if err := p.ValidateFeaturePreparation(command, kernel.CommandPlan{}); err != nil {
		return err
	}
	return p.checkAuthority(ctx, work)
}
func (p *samlLogoutRelayIssuePhase) CheckFeatureCommit(ctx context.Context, work kernel.Work, command identity.Command) error {
	if err := work.RequireSSOSAMLLogoutRelayIssue(ctx, p, command, p.issueIntent(true)); err != nil {
		return err
	}
	return p.checkAuthority(ctx, work)
}
func (p *samlLogoutRelayIssuePhase) ApplyFeature(ctx context.Context, work kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	if err := work.RequireSSOSAMLLogoutRelayIssue(ctx, p, command, p.issueIntent(true)); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.checkAuthority(ctx, work); err != nil {
		return identity.FeatureReceipt{}, err
	}
	retained, generation, err := work.FeaturePreparationOutput(p)
	defer clear(retained)
	if err != nil || p.output == nil || generation != p.output.Generation || p.outputDigest != sha256.Sum256(retained) {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	out := p.output
	local, err := base64.RawURLEncoding.Strict().DecodeString(string(out.Row.Command))
	if err != nil || len(local) != 16 {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	n, err := work.Exec(ctx, insertSAMLLogoutRequestSQL, string(out.Row.Tenant), out.Row.Organization, out.Row.Provider, out.Row.requestID(), local, out.Row.IssuedAt, out.Row.ExpiresAt, out.Envelope, strconv.FormatUint(out.Payload.ProviderVersion, 10), strconv.FormatUint(out.Payload.CredentialGeneration, 10))
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n != 1 {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	if err := p.login().payload.Issuer.Stage(ctx, work, p.issuance); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: kernel.SSOSAMLLogoutRelayIssueOperation(), AfterVersion: 1}, nil
}

func (p *samlLogoutRelayIssuePhase) RecoverParticipant(ctx context.Context, work kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	b, err := work.Scope()
	if err != nil || p.input == nil || b != identity.CommandBinding(p.input.Command) {
		return kernel.RecoveryUnknown, identity.ForbiddenError{}
	}
	// Recovery must not infer success from another request's existence. When
	// exact retained preparation is unavailable the authoritative result stays
	// unknown; ordinary committed retries use the kernel's terminal receipt.
	if p.output == nil {
		return kernel.RecoveryUnknown, nil
	}
	local, err := base64.RawURLEncoding.Strict().DecodeString(string(p.output.Row.Command))
	if err != nil || len(local) != 16 {
		return kernel.RecoveryUnknown, identity.ForbiddenError{}
	}
	rows, err := work.Query(ctx, selectSAMLLogoutRequestSQL, string(b.TenantID), local)
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
	var organization, provider, id string
	var issued, expires time.Time
	var wire []byte
	defer clear(wire)
	if err := rows.Scan(&organization, &provider, &id, &issued, &expires, &wire); err != nil {
		return kernel.RecoveryUnknown, err
	}
	want := p.output.Row
	if rows.Next() || rows.Err() != nil || organization != want.Organization || provider != want.Provider || id != want.requestID() || !issued.Equal(want.IssuedAt) || !expires.Equal(want.ExpiresAt) || !bytes.Equal(wire, p.output.Envelope) {
		return kernel.RecoveryUnknown, identity.ForbiddenError{}
	}
	return kernel.RecoveryCommitted, nil
}

func (s *ProviderSAMLLogoutRedirectService) reserveProviderRelayRedirect(ctx context.Context, local *providerSAMLLogoutStartPhase, result ProviderSAMLLogoutStartResult, route sso.DomainRouteBinding, profile samlLogoutSelectedProfile, payload samlLogoutRequestBinding, maximum time.Time) (string, error) {
	if !result.LocalRevocation.Committed || result.Completion.Validate() != nil || result.Completion.Binding != local.input.binding() || result.Completion.Feature == nil || result.Completion.Feature.Operation != kernel.SSOSAMLLogoutStartOperation() {
		return "", identity.ForbiddenError{}
	}
	p := &samlLogoutRelayIssuePhase{service: s, local: local, profile: profile, route: route, payload: payload, maximum: maximum}
	intent, err := p.requestIntent()
	if err != nil {
		return "", err
	}
	coordinator, err := p.coordinator()
	if err != nil {
		return "", err
	}
	k, wire, err := coordinator.ResolvePreparedRequestKey(ctx, p.scope(), local.request.IdempotencyKey, intent, p.caller("identity.request-admission", kernel.SSOSAMLLogoutRelayIssueOperation().OperationID), p.registration(), p)
	defer clear(wire)
	if err != nil {
		return "", err
	}
	if err := p.restoreRequest(ctx, k, wire); err != nil {
		return "", err
	}
	command, err := p.command(false)
	if err != nil {
		return "", err
	}
	plan, err := p.plan(false)
	if err != nil {
		return "", err
	}
	plan, err = coordinator.PrepareFeaturePreparationPlan(command, plan)
	if err != nil {
		return "", err
	}
	committed, err := coordinator.ExecutePreparedFeature(ctx, command, plan)
	if err != nil {
		return "", err
	}
	if committed.Validate() != nil || committed.Binding != identity.CommandBinding(p.input.Command) || committed.Outcome != identity.CommitOutcomeCommitted || committed.Feature == nil || committed.Feature.Operation != kernel.SSOSAMLLogoutRelayIssueOperation() || committed.Feature.AfterVersion != 1 {
		return "", identity.UnknownCommitError{CommandID: k.Admission.CommandID}
	}
	row, saved, found, err := p.login().readSAMLLogoutRequest(ctx, local.input.binding().TenantID, local.input.binding().CommandID)
	if err != nil {
		return "", err
	}
	if !found || saved.Relay == nil || saved.Relay.IssueCommand != p.input.Command || !validSAMLLogoutRelayCustody(row, saved) {
		return "", identity.ForbiddenError{}
	}
	base := saved
	base.Redirect = ""
	base.Relay = nil
	if base != payload || row.Organization != payload.Anchor.Organization || row.Provider != payload.Anchor.Provider || row.ExpiresAt.After(p.input.ExpiresAt) || !p.login().router.config.Clock.Now().Before(row.ExpiresAt) {
		return "", identity.ForbiddenError{}
	}
	if err := p.login().router.requireSAMLLogoutRoute(ctx, route); err != nil {
		return "", err
	}
	if !p.login().router.config.Clock.Now().Before(row.ExpiresAt) {
		return "", identity.ForbiddenError{}
	}
	return saved.Redirect, nil
}

var (
	_ kernel.FeatureAdmissionPreparationContributor = (*samlLogoutRelayIssuePhase)(nil)
	_ kernel.FeatureCommitContributor               = (*samlLogoutRelayIssuePhase)(nil)
	_ kernel.RequestKeyPreparationContributor       = (*samlLogoutRelayIssuePhase)(nil)
)
