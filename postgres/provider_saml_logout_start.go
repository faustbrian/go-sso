package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

const (
	samlLogoutStartIntent = "sso.saml.logout.request-intent"
	samlLogoutStartInput  = "sso.saml.logout.prepared-input"
	samlLogoutStartAudit  = "identity.sso.logout_saml"
)

// Recheck the account association, not provider availability. A disabled IdP
// must not prevent its authenticated user from revoking the original cookie.
const samlLogoutLinkedProviderSQL = `SELECT a.provider FROM identity.account_credentials m
JOIN identity.accounts a ON (a.tenant_id,a.user_id,a.account_id)=(m.tenant_id,m.user_id,m.account_id)
WHERE m.tenant_id=$1 AND m.user_id=$2 AND m.credential_id=$3 AND a.provider=$4 AND a.linked LIMIT 2`

type providerSAMLLogoutLocalInput struct {
	Command               providerLoginStoredCommand
	Intent                [32]byte
	StartedAt, ValidUntil time.Time
}

func (i providerSAMLLogoutLocalInput) binding() identity.CommandBinding {
	return identity.CommandBinding(i.Command)
}

type providerSAMLLogoutStartPhase struct {
	service         *ProviderSAMLLogoutService
	request         ProviderLogoutStartRequest
	browser         ProviderLogoutBrowser
	historical      bool
	original        session.Session
	record          session.SessionSpec
	csrfKey         session.CSRFKey
	accountProvider string
	deadline        time.Time
	intent          [32]byte
	input           *providerSAMLLogoutLocalInput
	inputDigest     [32]byte
}

func (*providerSAMLLogoutStartPhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.SSOSAMLLogoutStartDescriptor()
}

func (*providerSAMLLogoutStartPhase) operation() identity.FeatureOperation {
	return kernel.SSOSAMLLogoutStartOperation()
}

func (p *providerSAMLLogoutStartPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{p.operation()}
}

func (p *providerSAMLLogoutStartPhase) registration() kernel.FeatureRegistration {
	return kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: p.operation()}
}

func (p *providerSAMLLogoutStartPhase) scope() kernel.RequestKeyScope {
	return kernel.RequestKeyScope{TenantID: p.record.TenantID, ActorID: identity.ActorID(p.record.UserID),
		ActorKind: authorization.SubjectUser, Method: "POST", RouteID: p.operation().OperationID}
}

func (p *providerSAMLLogoutStartPhase) caller(resource, id string) authorization.DecisionContext {
	return authorization.DecisionContext{PolicyRevision: authorization.Revision(p.service.login.policyVersion), Request: authorization.Request{
		Tenant: authorization.TenantID(p.record.TenantID), Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(p.record.UserID)},
		Action: authorization.Action(p.operation().OperationID), Resource: authorization.Resource{Type: authorization.ResourceType(resource), ID: authorization.ResourceID(id)},
	}}
}

func (p *providerSAMLLogoutStartPhase) binding(id identity.CommandID) identity.CommandBinding {
	op, record, login := p.operation(), p.record, p.service.login
	return identity.CommandBinding{CommandID: id, TenantID: record.TenantID, UserID: record.UserID, ActorID: identity.ActorID(record.UserID),
		ActorKind: authorization.SubjectUser, PolicyID: login.config.PolicyID, PolicyVersion: login.policyVersion, OperationID: op.OperationID,
		SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, RecordID: record.SessionID, CorrelationID: string(id)}
}

func (p *providerSAMLLogoutStartPhase) linkedProviderArgs() []any {
	return []any{string(p.record.TenantID), string(p.record.UserID), p.record.Authentication.CredentialID, p.accountProvider}
}

func readSAMLLogoutLinkedProvider(rows providerLogoutRows) error {
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return err
		}
		return identity.ForbiddenError{}
	}
	var provider string
	if err := rows.Scan(&provider); err != nil {
		return identity.UnavailableError{}
	}
	if provider == "" || rows.Next() || rows.Err() != nil {
		return identity.UnavailableError{}
	}
	return nil
}

func (p *providerSAMLLogoutStartPhase) requestIntent() (identity.RequestIntent, error) {
	source, err := sessionpg.OriginalSessionFields(p.original)
	if err != nil {
		return identity.RequestIntent{}, err
	}
	frame, err := json.Marshal(struct {
		Source                        []identity.FeatureField
		Provider, FinalTarget, Origin string
	}{source, p.request.ProviderID, p.request.FinalRedirect, p.browser.Origin})
	defer clear(frame)
	if err != nil {
		return identity.RequestIntent{}, identity.UnavailableError{}
	}
	p.intent = sha256.Sum256(frame)
	return identity.NewRequestIntent([]identity.FeatureField{{Name: samlLogoutStartIntent,
		Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: p.intent[:]}}})
}

func (p *providerSAMLLogoutStartPhase) requestAAD(k kernel.RequestKeyPreparationBinding) (envelope.Context, error) {
	login := p.service.login
	if k.Feature != p.registration() || k.Scope != p.scope() || k.Namespace != login.config.RequestKeys.Namespace ||
		k.PolicyVersion != login.policyVersion || k.IntentDigest == ([32]byte{}) || k.Admission.FingerprintKeyVersion == 0 ||
		p.binding(k.Admission.CommandID).ValidateFor(p.operation()) != nil {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	frame, err := json.Marshal(providerLoginStoredRequestKey(k))
	defer clear(frame)
	if err != nil {
		return envelope.Context{}, identity.UnavailableError{}
	}
	digest := sha256.Sum256(frame)
	return envelope.NewContext(map[string]string{"profile": "sso-saml-logout-request-v1", "request": base64.RawURLEncoding.EncodeToString(digest[:])})
}

func (p *providerSAMLLogoutStartPhase) PrepareRequestKey(ctx context.Context, k kernel.RequestKeyPreparationBinding, req identity.RequestIntent) ([]byte, error) {
	aad, err := p.requestAAD(k)
	if err != nil {
		return nil, err
	}
	fields, ok := req.Fields()
	if !ok || len(fields) != 1 || fields[0].Name != samlLogoutStartIntent || fields[0].Value.Kind != identity.FeatureBytes ||
		!bytes.Equal(fields[0].Value.Bytes, p.intent[:]) || p.historical {
		return nil, identity.ForbiddenError{}
	}
	login := p.service.login
	now := login.router.config.Clock.Now().UTC().Truncate(time.Microsecond)
	if !providerLogoutTime(now) || !p.deadline.After(now) || p.deadline.After(now.Add(20*time.Second)) {
		return nil, identity.ForbiddenError{}
	}
	in := providerSAMLLogoutLocalInput{Command: providerLoginStoredCommand(p.binding(k.Admission.CommandID)), Intent: p.intent, StartedAt: now, ValidUntil: p.deadline}
	frame, err := json.Marshal(in)
	defer clear(frame)
	if err != nil || len(frame) > providerLoginRequestPlainLimit {
		return nil, identity.UnavailableError{}
	}
	return login.payload.seal(ctx, aad, frame, providerLoginRequestWireLimit)
}

func (p *providerSAMLLogoutStartPhase) RestoreRequestKey(ctx context.Context, k kernel.RequestKeyPreparationBinding, wire []byte) (identity.CommandBinding, error) {
	aad, err := p.requestAAD(k)
	if err != nil {
		return identity.CommandBinding{}, err
	}
	frame, err := p.service.login.payload.open(ctx, aad, wire, providerLoginRequestWireLimit, providerLoginRequestPlainLimit)
	defer clear(frame)
	if err != nil {
		return identity.CommandBinding{}, err
	}
	var in providerSAMLLogoutLocalInput
	if json.Unmarshal(frame, &in) != nil || in.binding() != p.binding(k.Admission.CommandID) || in.Intent != p.intent ||
		!providerLogoutTime(in.StartedAt) || !providerLogoutTime(in.ValidUntil) || !in.ValidUntil.After(in.StartedAt) ||
		in.ValidUntil.After(in.StartedAt.Add(20*time.Second)) {
		return identity.CommandBinding{}, identity.ForbiddenError{}
	}
	canonical, err := json.Marshal(in)
	defer clear(canonical)
	if err != nil || !bytes.Equal(canonical, frame) {
		return identity.CommandBinding{}, identity.ForbiddenError{}
	}
	p.input, p.inputDigest = &in, sha256.Sum256(frame)
	return in.binding(), nil
}

func (p *providerSAMLLogoutStartPhase) mapped() (identity.Command, error) {
	if p.input == nil || p.inputDigest == ([32]byte{}) {
		return identity.Command{}, identity.ForbiddenError{}
	}
	fields, err := sessionpg.SSOSAMLLogoutStartFields(p.original, p.input.ValidUntil)
	if err != nil {
		return identity.Command{}, err
	}
	fields = append(fields, identity.FeatureField{Name: samlLogoutStartInput, Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: p.inputDigest[:]}})
	return identity.NewFeatureSessionCommand(identity.FeatureCommandSpec{Binding: p.input.binding(), Operation: p.operation(), Fields: fields}, p.browser.Session)
}

func (p *providerSAMLLogoutStartPhase) lifecycle() kernel.LifecyclePlan {
	return kernel.LifecyclePlan{EventType: "session.revoked.v1", BeforeVersion: p.record.Version, AfterVersion: p.record.Version + 1}
}

func (p *providerSAMLLogoutStartPhase) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	want, err := p.mapped()
	if err != nil || p.historical {
		return identity.ForbiddenError{}
	}
	wantSpec, _ := want.Feature()
	actual, ok := c.Feature()
	cookie, carried := c.SessionToken()
	if !ok || !carried || cookie != p.browser.Session || actual.Binding != wantSpec.Binding || actual.Operation != wantSpec.Operation ||
		!equalProviderLogoutFields(actual.Fields, wantSpec.Fields) || plan.SubjectType != "session" || plan.Feature == nil ||
		*plan.Feature != p.registration() || plan.Lifecycle == nil || *plan.Lifecycle != p.lifecycle() {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *providerSAMLLogoutStartPhase) execute(ctx context.Context, c *kernel.Coordinator, registry *kernel.ContributorRegistry) (identity.CommandResult, error) {
	command, err := p.mapped()
	if err != nil {
		return identity.CommandResult{}, err
	}
	binding, lifecycle, feature := p.input.binding(), p.lifecycle(), p.registration()
	const subject = "session"
	builder, err := audit.NewBuilder(audit.BuilderConfig{IDGenerator: func() (string, error) { return "sso-saml-logout-declaration", nil }})
	if err != nil {
		return identity.CommandResult{}, err
	}
	seed, err := builder.Build(audit.RecordInput{Action: samlLogoutStartAudit, OccurredAt: p.input.StartedAt, Outcome: audit.OutcomeSucceeded, ReasonCode: "completed",
		Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(binding.ActorID)}, Subject: audit.SubjectInput{Type: subject, ID: binding.RecordID},
		Context: audit.ContextInput{TenantID: string(binding.TenantID), CorrelationID: binding.CorrelationID},
		Policy:  audit.PolicyMetadata{PolicyID: binding.PolicyID, Version: strconv.FormatUint(binding.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true},
		Attributes: map[string]string{"identity.profile": "identity.security.v1", "command.id": string(binding.CommandID), "retention.class": "protected",
			"aggregate.type": subject, "aggregate.id": binding.RecordID, "aggregate.before_version": strconv.FormatUint(lifecycle.BeforeVersion, 10),
			"aggregate.after_version": strconv.FormatUint(lifecycle.AfterVersion, 10)},
	})
	if err != nil {
		return identity.CommandResult{}, err
	}
	digest, err := kernel.FeatureAuditBindingDigest(binding, feature.Operation, subject, seed)
	if err != nil {
		return identity.CommandResult{}, err
	}
	plan := kernel.CommandPlan{Contributors: registry.Descriptors(), SubjectType: subject, Feature: &feature, Lifecycle: &lifecycle,
		Audits: []kernel.AuditPlan{{EventType: samlLogoutStartAudit, SchemaVersion: 1, BindingDigest: digest, RetentionClass: "protected",
			RetentionPolicyVersion: p.service.login.config.AuditRetentionPolicyVersion, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384}},
	}
	return executeProviderLogoutCommand(ctx, c, binding, command, plan)
}

func (p *providerSAMLLogoutStartPhase) ApplyFeature(ctx context.Context, work kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	return p.service.effect.Apply(ctx, work, p, command, p.browser.CSRF, p.csrfKey)
}

func (p *providerSAMLLogoutStartPhase) CheckFeatureCommit(ctx context.Context, work kernel.Work, command identity.Command) error {
	if err := p.service.effect.Check(ctx, work, p, command); err != nil {
		return err
	}
	// The session effect already holds its linked account locks. Recheck the
	// exact route namespace under those locks before acknowledging this Work.
	rows, err := work.Query(ctx, samlLogoutLinkedProviderSQL+" FOR SHARE OF a,m", p.linkedProviderArgs()...)
	if err != nil {
		return err
	}
	return readSAMLLogoutLinkedProvider(rows)
}

func (p *providerSAMLLogoutStartPhase) RecoverParticipant(ctx context.Context, work kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return p.service.effect.Recover(ctx, work, p, p.original)
}
