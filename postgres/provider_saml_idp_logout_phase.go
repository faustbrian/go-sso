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
	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	organization "github.com/faustbrian/go-organization"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

const samlIDPLogoutSubject = "sso_saml_logout"

type samlIDPLogoutPhase struct {
	service       *ProviderSAMLIDPLogoutService
	profile       samlIDPLogoutProvider
	selected      sso.DomainRouteBinding
	organization  organization.CredentialAuthorityObservation
	probe         samlIDPLogoutProbe
	replayID      [32]byte
	messageDigest [32]byte
	requestID     string
	requestUntil  time.Time
	prepared      samlIDPLogoutPreparation
	command       identity.Command
}

// Preparation retains authenticated custody and one original command. It is
// sealed under the coordinator's request-key identity before any revocation.
// No raw XML, NameID, SessionIndex or browser credential is retained here.
type samlIDPLogoutPreparation struct {
	Command             providerLoginStoredCommand
	Intent              kernel.SSOSAMLIDPLogoutIntent
	Matches             []samlIDPLogoutMatch
	ObservedAt          time.Time
	ProofVersion        uint64
	OrganizationVersion uint64
	CredentialVersion   uint64
}

func (s samlIDPLogoutPreparation) binding() identity.CommandBinding {
	return identity.CommandBinding(s.Command)
}

func (*samlIDPLogoutPhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.SSOSAMLIDPLogoutDescriptor()
}

func (*samlIDPLogoutPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{kernel.SSOSAMLIDPLogoutOperation()}
}

func (p *samlIDPLogoutPhase) registration() kernel.FeatureRegistration {
	return kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: kernel.SSOSAMLIDPLogoutOperation()}
}

func (p *samlIDPLogoutPhase) scope() kernel.RequestKeyScope {
	c := p.service.login.config
	return kernel.RequestKeyScope{TenantID: c.TenantID, ActorID: c.ActorID, ActorKind: authorization.SubjectServiceAccount,
		Method: "POST", RouteID: kernel.SSOSAMLIDPLogoutOperation().OperationID}
}

func (p *samlIDPLogoutPhase) caller(resource, id string) authorization.DecisionContext {
	scope := p.scope()
	return authorization.DecisionContext{PolicyRevision: authorization.Revision(p.service.login.policyVersion), Request: authorization.Request{
		Tenant: authorization.TenantID(scope.TenantID), Subject: authorization.Subject{Kind: scope.ActorKind, ID: authorization.SubjectID(scope.ActorID)},
		Action: authorization.Action(scope.RouteID), Resource: authorization.Resource{Type: authorization.ResourceType(resource), ID: authorization.ResourceID(id)},
	}}
}

func (p *samlIDPLogoutPhase) binding(id identity.CommandID, user identity.UserID) identity.CommandBinding {
	scope, login := p.scope(), p.service.login
	op := kernel.SSOSAMLIDPLogoutOperation()
	return identity.CommandBinding{CommandID: id, TenantID: scope.TenantID, UserID: user, ActorID: scope.ActorID,
		ActorKind: scope.ActorKind, PolicyID: login.config.PolicyID, PolicyVersion: login.policyVersion,
		OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, RecordID: string(id), CorrelationID: string(id)}
}

func (p *samlIDPLogoutPhase) authorizeUser(ctx context.Context, user identity.UserID) error {
	login := p.service.login
	decision, err := login.config.Coordinator.AdmissionPolicy.Authorization.Decide(ctx, p.caller("identity.user", string(user)))
	if err != nil {
		return err
	}
	if decision.Outcome != authorization.Allow || decision.Revision != authorization.Revision(login.policyVersion) {
		return identity.ForbiddenError{}
	}
	return ctx.Err()
}

func (p *samlIDPLogoutPhase) requestIntent() (identity.RequestIntent, error) {
	// Configuration identity and exact enrolled response destination are part of
	// the immutable intent, not part of the replay key. A changed configuration
	// must not allocate a new command to one already authenticated signed ID.
	frame, err := json.Marshal(struct {
		Configuration   string
		Provider        ProviderSAMLIDPLogoutProfile
		Request, Replay [32]byte
	}{p.service.login.config.ConfigurationID, p.profile.config, p.messageDigest, p.replayID})
	if err != nil {
		return identity.RequestIntent{}, identity.UnavailableError{}
	}
	digest := sha256.Sum256(frame)
	return identity.NewRequestIntent([]identity.FeatureField{{Name: "sso.saml.idp-logout.request", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest[:]}}})
}

func (p *samlIDPLogoutPhase) preparationAAD(k kernel.RequestKeyPreparationBinding) (envelope.Context, error) {
	if k.Feature != p.registration() || k.Scope != p.scope() || k.Namespace != p.service.login.config.RequestKeys.Namespace ||
		k.PolicyVersion != p.service.login.policyVersion || k.IntentDigest == ([32]byte{}) || k.Admission.FingerprintKeyVersion == 0 {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	if _, err := identity.ParseCommandID(string(k.Admission.CommandID)); err != nil {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	frame, err := json.Marshal(providerLoginStoredRequestKey(k))
	if err != nil {
		return envelope.Context{}, identity.UnavailableError{}
	}
	digest := sha256.Sum256(frame)
	return envelope.NewContext(map[string]string{"profile": "sso-saml-idp-logout-v1", "request": base64.RawURLEncoding.EncodeToString(digest[:])})
}

func (p *samlIDPLogoutPhase) resolve(ctx context.Context, c *kernel.Coordinator) error {
	intent, err := p.requestIntent()
	if err != nil {
		return err
	}
	key, err := samlIDPLogoutRequestKey(p.replayID)
	if err != nil {
		return err
	}
	admission := p.caller("identity.request-admission", p.scope().RouteID)
	k, wire, err := c.ResolvePreparedRequestKey(ctx, p.scope(), key, intent, admission, p.registration(), p)
	defer clear(wire)
	if err != nil {
		return err
	}
	aad, err := p.preparationAAD(k)
	if err != nil {
		return err
	}
	frame, err := p.service.login.payload.open(ctx, aad, wire, providerLoginRequestWireLimit, providerLoginRequestPlainLimit)
	defer clear(frame)
	if err != nil {
		return err
	}
	var prepared samlIDPLogoutPreparation
	if providerLoginPayloadDecode(frame, &prepared) != nil || p.validatePreparation(k.Admission.CommandID, prepared) != nil {
		return identity.ForbiddenError{}
	}
	canonical, err := json.Marshal(prepared)
	defer clear(canonical)
	if err != nil || !bytes.Equal(frame, canonical) {
		return identity.ForbiddenError{}
	}
	op := p.registration().Operation
	fields, err := kernel.SSOSAMLIDPLogoutFields(prepared.Intent)
	if err != nil {
		return err
	}
	command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: prepared.binding(), Operation: op, Fields: fields})
	if err != nil {
		return err
	}
	p.prepared, p.command = prepared, command
	return nil
}

func (p *samlIDPLogoutPhase) PrepareRequestKey(ctx context.Context, k kernel.RequestKeyPreparationBinding, submitted identity.RequestIntent) ([]byte, error) {
	aad, err := p.preparationAAD(k)
	if err != nil {
		return nil, err
	}
	expected, err := p.requestIntent()
	want, wantOK := expected.Fields()
	got, gotOK := submitted.Fields()
	if err != nil || !wantOK || !gotOK || !equalProviderLogoutFields(want, got) {
		return nil, identity.ForbiddenError{}
	}
	prepared, err := p.prepareTargets(ctx, k.Admission.CommandID)
	if err != nil {
		return nil, err
	}
	if err := p.validatePreparation(k.Admission.CommandID, prepared); err != nil {
		return nil, err
	}
	frame, err := json.Marshal(prepared)
	defer clear(frame)
	if err != nil || len(frame) > providerLoginRequestPlainLimit {
		return nil, identity.UnavailableError{}
	}
	return p.service.login.payload.seal(ctx, aad, frame, providerLoginRequestWireLimit)
}

func (p *samlIDPLogoutPhase) prepareTargets(ctx context.Context, command identity.CommandID) (samlIDPLogoutPreparation, error) {
	var out samlIDPLogoutPreparation
	login, tenant := p.service.login, p.scope().TenantID
	now := login.router.config.Clock.Now().UTC().Truncate(time.Microsecond)
	deadline := minSAMLLogoutTime(providerLoginDeadline(p.selected, p.organization), p.requestUntil).UTC().Truncate(time.Microsecond)
	if !now.Before(deadline) {
		return out, identity.ForbiddenError{}
	}
	matches, err := p.probe.lookup(ctx, login.router.pool, login.payload.Envelope, p.service.custody, now)
	if err != nil {
		return out, err
	}
	if len(matches) == 0 {
		return out, identity.InvalidInputError{Field: "saml_logout_request"}
	}
	user := identity.UserID(matches[0].Anchor.User)
	intent := kernel.SSOSAMLIDPLogoutIntent{OrganizationID: string(p.selected.Proof.Key.OrganizationID), ProviderID: string(p.selected.ProviderID), RequestDigest: p.messageDigest}
	for _, match := range matches {
		a := match.Anchor
		deadline = minSAMLLogoutTime(deadline, a.ExpiresAt)
		stored, err := p.service.sessions.Get(ctx, tenant, a.Session)
		if err != nil {
			return out, err
		}
		spec, err := stored.Session.Bindings()
		if err != nil || spec.UserID != user || spec.SessionID != a.Session || spec.FamilyID != a.Family || string(spec.Authentication.Proof.ID) != a.Command ||
			spec.Authentication.Kind != session.AuthenticationVerified || spec.Authentication.Proof.Method != "sso-saml" || spec.Authentication.Proof.Purpose != "session-issue" {
			return out, identity.ForbiddenError{}
		}
		authority, err := spec.Authority.Bindings()
		if err != nil || authority.ActiveOrganizationID != intent.OrganizationID {
			return out, identity.ForbiddenError{}
		}
		if stored.Revoked || stored.FamilyRevoked {
			continue // Neither revocation state can become active again.
		}
		intent.Targets = append(intent.Targets, kernel.SSOSAMLIDPLogoutTarget{SessionID: spec.SessionID, FamilyID: spec.FamilyID,
			IssuanceCommandID: identity.CommandID(a.Command), Version: spec.Version})
	}
	if len(intent.Targets) == 0 || !login.router.config.Clock.Now().Before(deadline) {
		return out, identity.InvalidInputError{Field: "saml_logout_request"}
	}
	intent.ValidUntil = deadline
	out = samlIDPLogoutPreparation{Command: providerLoginStoredCommand(p.binding(command, user)), Intent: intent, Matches: matches,
		ObservedAt: now, ProofVersion: p.selected.Proof.ProofVersion, OrganizationVersion: p.organization.Version, CredentialVersion: p.organization.CredentialVersion}
	return out, nil
}

func (p *samlIDPLogoutPhase) validatePreparation(id identity.CommandID, prep samlIDPLogoutPreparation) error {
	b, in := prep.binding(), prep.Intent
	if b != p.binding(id, b.UserID) || b.ValidateFor(p.registration().Operation) != nil || prep.ProofVersion == 0 ||
		prep.OrganizationVersion == 0 || prep.CredentialVersion == 0 || !providerLogoutTime(prep.ObservedAt) || !prep.ObservedAt.Before(in.ValidUntil) ||
		in.ValidUntil.After(prep.ObservedAt.Add(20*time.Second)) || in.ValidUntil.After(p.requestUntil) || in.RequestDigest != p.messageDigest ||
		in.OrganizationID != string(p.selected.Proof.Key.OrganizationID) || in.ProviderID != string(p.selected.ProviderID) ||
		len(prep.Matches) == 0 || len(prep.Matches) > kernel.MaxSSOSAMLIDPLogoutTargets {
		return identity.ForbiddenError{}
	}
	if _, err := kernel.SSOSAMLIDPLogoutFields(in); err != nil {
		return err
	}
	var previous string
	next := 0
	for _, match := range prep.Matches {
		a := match.Anchor
		if a.Session <= previous || a.Tenant != string(b.TenantID) || a.User != string(b.UserID) || a.Organization != in.OrganizationID || a.Provider != in.ProviderID ||
			match.RowDigest == ([32]byte{}) || a.IssuedAt.After(prep.ObservedAt) || a.ExpiresAt.Before(in.ValidUntil) {
			return identity.ForbiddenError{}
		}
		previous = a.Session
		if next < len(in.Targets) && in.Targets[next].SessionID == a.Session {
			if wanted := in.Targets[next]; wanted.FamilyID != a.Family || string(wanted.IssuanceCommandID) != a.Command {
				return identity.ForbiddenError{}
			}
			next++
		}
	}
	if next != len(in.Targets) {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *samlIDPLogoutPhase) coordinator() (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
	login := p.service.login
	auditing, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, nil, err
	}
	lifecycle, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, nil, err
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{login.directory, auditing, lifecycle, p})
	if err != nil {
		return nil, nil, err
	}
	c, err := kernel.NewCoordinatorWithRequestKeys(login.router.pool, registry, login.config.Coordinator, login.config.RequestKeys)
	return c, registry, err
}

func (p *samlIDPLogoutPhase) ValidateFeatureCommand(command identity.Command, plan kernel.CommandPlan) error {
	if p.command == (identity.Command{}) || command != p.command || plan.SubjectType != samlIDPLogoutSubject || plan.Feature == nil || *plan.Feature != p.registration() ||
		plan.Lifecycle == nil || *plan.Lifecycle != kernel.SSOSAMLIDPLogoutLifecycle() {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *samlIDPLogoutPhase) commandPlan(registry *kernel.ContributorRegistry) (kernel.CommandPlan, error) {
	b, feature, lifecycle := p.prepared.binding(), p.registration(), kernel.SSOSAMLIDPLogoutLifecycle()
	bldr, err := audit.NewBuilder(audit.BuilderConfig{IDGenerator: func() (string, error) { return "sso-saml-idp-logout-declaration", nil }})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	seed, err := bldr.Build(audit.RecordInput{Action: b.OperationID, OccurredAt: p.prepared.ObservedAt, Outcome: audit.OutcomeSucceeded, ReasonCode: "completed",
		Actor: audit.ActorInput{Kind: audit.ActorService, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: samlIDPLogoutSubject, ID: b.RecordID},
		Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Changes: audit.ChangeSetInput{Redacted: true},
		Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)},
		Attributes: map[string]string{"identity.profile": "identity.security.v1", "command.id": string(b.CommandID), "retention.class": "protected",
			"aggregate.type": samlIDPLogoutSubject, "aggregate.id": b.RecordID, "aggregate.before_version": "0", "aggregate.after_version": "1"},
	})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, feature.Operation, samlIDPLogoutSubject, seed)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	return kernel.CommandPlan{Contributors: registry.Descriptors(), SubjectType: samlIDPLogoutSubject, Feature: &feature, Lifecycle: &lifecycle,
		Audits: []kernel.AuditPlan{{EventType: b.OperationID, SchemaVersion: 1, BindingDigest: digest, RetentionClass: "protected", Required: true,
			RetentionPolicyVersion: p.service.login.config.AuditRetentionPolicyVersion, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384}}}, nil
}

func (p *samlIDPLogoutPhase) execute(ctx context.Context, c *kernel.Coordinator, registry *kernel.ContributorRegistry) (identity.CommandResult, bool, error) {
	b := p.prepared.binding()
	declaration, err := p.commandPlan(registry)
	if err != nil {
		return identity.CommandResult{}, false, err
	}
	plan, err := c.PrepareCommandPlan(b, p.command, declaration)
	if err != nil {
		return identity.CommandResult{}, false, err
	}
	reservation, existing, err := c.ReserveCommand(ctx, b, p.command, plan)
	if err != nil || reservation == (kernel.Reservation{}) {
		if existing.Outcome == identity.CommitOutcomeInProgress || existing.Outcome == identity.CommitOutcomeUnknown {
			q := identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}
			result, recoverErr := c.RecoverFeatureCommand(ctx, q, p.caller("identity.user", string(b.UserID)))
			if result.Outcome != identity.CommitOutcomeInvalid {
				return result, false, recoverErr
			}
			return existing, false, recoverErr
		}
		return existing, false, err
	}
	w, err := c.Begin(ctx, reservation)
	if err != nil {
		return identity.CommandResult{}, false, err
	}
	defer c.Abort(w, identity.UnavailableError{})
	candidate, err := c.ApplyFeature(ctx, w, p.command)
	if err != nil {
		result, abortErr := c.Abort(w, err)
		return result, false, abortErr
	}
	result, err := c.Commit(w, candidate)
	return result, true, err
}

func (p *samlIDPLogoutPhase) ApplyFeature(ctx context.Context, w kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	// Keep the same lock order as native login and local logout: session owner
	// before organization/provider. No result leaves the transaction on denial.
	receipt, err := p.service.effect.Apply(ctx, w, p, command, p.prepared.Intent)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.requireRouteAndSelection(ctx, w); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return receipt, nil
}

func (p *samlIDPLogoutPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, command identity.Command) error {
	if err := p.service.effect.Check(ctx, w, p, command, p.prepared.Intent); err != nil {
		return err
	}
	return p.requireRouteAndSelection(ctx, w)
}

func (p *samlIDPLogoutPhase) requireRouteAndSelection(ctx context.Context, w kernel.Work) error {
	a, prep := p.organization, p.prepared
	if a.Version != prep.OrganizationVersion || a.CredentialVersion != prep.CredentialVersion || p.selected.Proof.ProofVersion != prep.ProofVersion {
		return identity.ForbiddenError{}
	}
	router := p.service.login.router
	if err := router.organizations.RequireCredentialAuthority(ctx, w, p, a); err != nil {
		return err
	}
	if err := requireProviderLoginAdmissionRow(ctx, w, providerLoginSAMLAdmissionFenceSQL, p.selected, p.profile.config.Provider.MappingVersion, prep.Intent.ValidUntil); err != nil {
		return err
	}
	if err := p.probe.requireInWork(ctx, w, prep.Matches); err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if !now.Before(prep.Intent.ValidUntil) {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *samlIDPLogoutPhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	if p.command == (identity.Command{}) {
		return kernel.RecoveryUnknown, identity.ForbiddenError{}
	}
	return p.service.effect.Recover(ctx, w, p, p.prepared.Intent)
}
