package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-sso"
	"github.com/faustbrian/go-sso/saml"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

type samlLogoutRelayResponsePhase struct {
	login      *ProviderLoginService
	row        samlLogoutRequestRow
	route      sso.DomainRouteBinding
	cutoff     time.Time
	status     saml.LogoutPOSTStatus
	responseID [32]byte
	intent     kernel.SSOSAMLLogoutRelaySettlementIntent
	command    identity.Command
	grant      kernel.CapabilityPlan
}

var _ kernel.SSOSAMLLogoutRelaySettlementContributor = (*samlLogoutRelayResponsePhase)(nil)

func (s *ProviderSAMLLogoutRedirectService) settleVerifiedSAMLLogoutRelayResponse(ctx context.Context, row samlLogoutRequestRow, retained samlLogoutRequestBinding,
	route sso.DomainRouteBinding, response saml.LogoutPOSTResponseEvidence, wire string, out ProviderSAMLLogoutResponseResult,
) (ProviderSAMLLogoutResponseResult, error) {
	login, relay := s.local.login, retained.Relay
	cutoff := minSAMLLogoutTime(minSAMLLogoutTime(row.ExpiresAt, response.ValidUntil), route.ValidUntil).UTC().Truncate(time.Microsecond)
	remaining := cutoff.Sub(login.router.config.Clock.Now())
	if remaining <= 0 {
		out.Outcome = SAMLLogoutResponseTimeout
		return out, nil
	}
	ctx, cancel := context.WithTimeout(ctx, remaining)
	defer cancel()
	if err := login.router.requireSAMLLogoutRoute(ctx, route); err != nil {
		out.Outcome = SAMLLogoutResponseUnavailable
		return out, providerError(ctx, err)
	}
	original := identity.CommandBinding(relay.IssueCommand)
	op := kernel.SSOSAMLLogoutRelaySettlementOperation()
	binding := identity.CommandBinding{CommandID: relay.SettlementCommandID, TenantID: original.TenantID, UserID: original.UserID,
		ActorID: login.config.ActorID, ActorKind: authorization.SubjectServiceAccount, PolicyID: login.config.PolicyID, PolicyVersion: login.policyVersion,
		OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, RecordID: string(original.CommandID), CorrelationID: string(row.Command)}
	policy := login.config.Coordinator.AdmissionPolicy
	decision, err := policy.Authorization.Decide(ctx, authorization.DecisionContext{PolicyRevision: authorization.Revision(login.policyVersion), Request: authorization.Request{
		Tenant: authorization.TenantID(binding.TenantID), Subject: authorization.Subject{Kind: binding.ActorKind, ID: authorization.SubjectID(binding.ActorID)},
		Action: authorization.Action(op.OperationID), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(binding.UserID)},
	}})
	if err != nil || decision.Outcome != authorization.Allow || decision.Revision != authorization.Revision(login.policyVersion) {
		out.Outcome = SAMLLogoutResponseUnavailable
		if err == nil {
			err = identity.ForbiddenError{}
		}
		return out, providerError(ctx, err)
	}
	grant, err := login.samlLogoutRelayResponseGrant(ctx, original, relay)
	if err != nil {
		out.Outcome = SAMLLogoutResponseUnavailable
		return out, providerError(ctx, err)
	}
	p := &samlLogoutRelayResponsePhase{login: login, row: row, route: route, cutoff: cutoff, status: response.Status, grant: grant,
		responseID: sha256.Sum256([]byte(retained.Issuer + "\x00" + response.ID)), intent: kernel.SSOSAMLLogoutRelaySettlementIntent{
			IssueCommandID: original.CommandID, LocalCommandID: row.Command, OrganizationID: row.Organization, ProviderID: row.Provider,
			RequestDigest: relay.RequestDigest, ResponseDigest: sha256.Sum256([]byte(wire)), ExpiresAt: relay.ExpiresAt,
		}}
	fields, err := kernel.SSOSAMLLogoutRelaySettlementFields(p.intent)
	if err != nil {
		return out, providerError(ctx, err)
	}
	p.command, err = identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: binding, Operation: op, Fields: fields})
	if err != nil {
		return out, providerError(ctx, err)
	}
	result, fresh, err := p.execute(ctx)
	if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
		out.Outcome = SAMLLogoutResponseUnavailable
		var conflict identity.ConflictError
		if result.Outcome == identity.CommitOutcomeUnknown {
			out.Outcome = SAMLLogoutResponseUnknown
		} else if result.Outcome == identity.CommitOutcomeConflict || errors.As(err, &conflict) {
			out.Outcome = SAMLLogoutResponseConflict
		} else if !login.router.config.Clock.Now().Before(cutoff) {
			out.Outcome = SAMLLogoutResponseTimeout
			return out, nil
		}
		if err == nil {
			err = identity.UnavailableError{}
		}
		return out, providerError(ctx, err)
	}
	out.Status = response.Status
	if !fresh {
		out.Outcome = SAMLLogoutResponseReplayed
		return out, nil
	}
	if response.Status.Code != saml.LogoutStatusSuccess || response.Status.Subcode != "" {
		out.Outcome = SAMLLogoutResponseProviderFailure
		return out, nil
	}
	out.Outcome = SAMLLogoutResponseSettled
	if _, approved := s.local.finalRedirect[retained.FinalRedirect]; approved && ctx.Err() == nil && login.router.config.Clock.Now().Before(cutoff) {
		out.finalRedirect, _ = url.Parse(retained.FinalRedirect) // Current constructor already validated the allowlist.
	}
	return out, nil
}

func (s *ProviderLoginService) samlLogoutRelayResponseGrant(ctx context.Context, original identity.CommandBinding, retained *samlLogoutRelayIssueCustody) (kernel.CapabilityPlan, error) {
	proof, err := capability.ParseProof(string(retained.Proof), s.callbackLimits)
	if err != nil {
		return kernel.CapabilityPlan{}, identity.ForbiddenError{}
	}
	defer func() {
		_ = proof.Transfer(context.WithoutCancel(ctx), func(context.Context, []byte) error { return nil })
	}()
	want := kernel.CapabilityPlan(retained.Plan.Grant)
	verified, err := s.callbackVerifier.Verify(ctx, proof, want.Purpose, s.payload.Audience)
	if err != nil {
		return kernel.CapabilityPlan{}, err
	}
	// The exact signed proof must commit to the retained Redirect independently
	// of the encrypted row and the XML's independently signed InResponseTo.
	if verified.EnvelopeDigest() != want.ProofFingerprint || verified.Payload().Caveats["identity.sso.saml.logout.request"] != base64.RawURLEncoding.EncodeToString(retained.RequestDigest[:]) {
		return kernel.CapabilityPlan{}, identity.ForbiddenError{}
	}
	plan, err := s.payload.Issuer.PrepareSSOSAMLLogoutRelayConsumption(ctx, original, proof, want.ReplayKeyVersion)
	if err != nil {
		return kernel.CapabilityPlan{}, err
	}
	if plan != want {
		return kernel.CapabilityPlan{}, identity.ForbiddenError{}
	}
	return plan, nil
}

func (*samlLogoutRelayResponsePhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.SSOSAMLLogoutRelaySettlementDescriptor()
}
func (*samlLogoutRelayResponsePhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{kernel.SSOSAMLLogoutRelaySettlementOperation()}
}

func (p *samlLogoutRelayResponsePhase) ValidateSSOSAMLLogoutRelaySettlement(command identity.Command, grant kernel.CapabilityPlan) error {
	if p == nil || command != p.command || grant != p.grant {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *samlLogoutRelayResponsePhase) ValidateFeatureCommand(command identity.Command, plan kernel.CommandPlan) error {
	if plan.Capability == nil {
		return identity.ForbiddenError{}
	}
	return p.ValidateSSOSAMLLogoutRelaySettlement(command, *plan.Capability)
}

func (p *samlLogoutRelayResponsePhase) declaration(reg *kernel.ContributorRegistry) (kernel.CommandPlan, error) {
	spec, _ := p.command.Feature()
	b, op := spec.Binding, spec.Operation
	transition := kernel.SSOSAMLLogoutRelaySettlementLifecycle()
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	record, err := builder.Build(audit.RecordInput{Action: op.OperationID, OccurredAt: p.row.IssuedAt, Outcome: audit.OutcomeSucceeded, ReasonCode: "completed",
		Actor: audit.ActorInput{Kind: audit.ActorService, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: samlLogoutRelayIssueSubject, ID: b.RecordID},
		Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true},
		Attributes: map[string]string{"identity.profile": "identity.security.v1", "command.id": string(b.CommandID), "retention.class": "protected", "aggregate.type": samlLogoutRelayIssueSubject, "aggregate.id": b.RecordID, "aggregate.before_version": "1", "aggregate.after_version": "2"}})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, op, samlLogoutRelayIssueSubject, record)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	return kernel.CommandPlan{Contributors: reg.Descriptors(), SubjectType: samlLogoutRelayIssueSubject, Feature: &kernel.FeatureRegistration{Operation: op, Contributor: p.Descriptor()}, Lifecycle: &transition, Capability: &p.grant,
		Audits: []kernel.AuditPlan{{EventType: op.OperationID, SchemaVersion: 1, BindingDigest: digest, RetentionClass: "protected", RetentionPolicyVersion: p.login.config.AuditRetentionPolicyVersion, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384}}}, nil
}

func (p *samlLogoutRelayResponsePhase) execute(ctx context.Context) (identity.CommandResult, bool, error) {
	var empty identity.CommandResult
	auditing, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return empty, false, err
	}
	lifecycle, err := lifecyclepg.NewContributor()
	if err != nil {
		return empty, false, err
	}
	reg, err := kernel.NewContributorRegistry([]kernel.Contributor{p.login.directory, auditing, lifecycle, p, capabilitypg.NewParticipant()})
	if err != nil {
		return empty, false, err
	}
	c, err := kernel.NewCoordinator(p.login.router.pool, reg, p.login.config.Coordinator)
	if err != nil {
		return empty, false, err
	}
	declaration, err := p.declaration(reg)
	if err != nil {
		return empty, false, err
	}
	spec, _ := p.command.Feature()
	plan, err := c.PrepareCommandPlan(spec.Binding, p.command, declaration)
	if err != nil {
		return empty, false, err
	}
	reservation, observed, err := c.ReserveCommand(ctx, spec.Binding, p.command, plan)
	if err != nil || reservation == (kernel.Reservation{}) {
		return observed, false, err
	}
	w, err := c.Begin(ctx, reservation)
	if err != nil {
		return observed, false, err
	}
	defer c.Abort(w, identity.UnavailableError{})
	result, err := c.ApplyFeature(ctx, w, p.command)
	if err != nil {
		aborted, failure := c.Abort(w, err)
		return aborted, false, failure
	}
	result, err = c.Commit(w, result)
	return result, err == nil && result.Outcome == identity.CommitOutcomeCommitted, err
}

func (p *samlLogoutRelayResponsePhase) ApplyFeature(ctx context.Context, w kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	if err := w.RequireSSOSAMLLogoutRelaySettlement(ctx, p, command, p.intent); err != nil {
		return identity.FeatureReceipt{}, err
	}
	r := p.row
	rows, err := w.Query(ctx, insertSAMLLogoutRelayResponseSQL, string(r.Tenant), r.requestID(), r.Organization, r.Provider, r.ExpiresAt,
		strconv.FormatUint(p.route.ProviderVersion, 10), strconv.FormatUint(p.route.CredentialGeneration, 10), p.cutoff,
		p.responseID[:], p.intent.ResponseDigest[:], string(p.status.Code), string(p.status.Subcode), r.envelopeDigest[:])
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	defer rows.Close()
	var eligible, written bool
	if !rows.Next() || rows.Scan(&eligible, &written) != nil || rows.Next() || rows.Err() != nil {
		return identity.FeatureReceipt{}, identity.UnavailableError{}
	}
	if !eligible {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	if !written {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	return identity.FeatureReceipt{Operation: kernel.SSOSAMLLogoutRelaySettlementOperation(), BeforeVersion: 1, AfterVersion: 2}, nil
}

func (p *samlLogoutRelayResponsePhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, command identity.Command) error {
	if err := w.RequireSSOSAMLLogoutRelaySettlement(ctx, p, command, p.intent); err != nil {
		return err
	}
	// Apply held the exact immutable request and provider fence. Sample primary
	// time again after effect, audit, lifecycle and any uniqueness wait.
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if !now.Before(p.cutoff) {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *samlLogoutRelayResponsePhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	b, registration, transition, err := w.FeatureScope(p)
	if err != nil || registration.Operation != kernel.SSOSAMLLogoutRelaySettlementOperation() || transition != kernel.SSOSAMLLogoutRelaySettlementLifecycle() {
		return kernel.RecoveryUnknown, identity.ForbiddenError{}
	}
	if _, err := identity.ParseCommandID(b.CorrelationID); err != nil {
		return kernel.RecoveryUnknown, identity.ForbiddenError{}
	}
	rows, err := w.Query(ctx, readSAMLLogoutResponseSQL, string(b.TenantID), "_"+b.CorrelationID)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	if rows.Next() {
		return kernel.RecoveryUnknown, nil
	}
	if err := rows.Err(); err != nil {
		return kernel.RecoveryUnknown, err
	}
	return kernel.RecoveryNotCommitted, nil
}
