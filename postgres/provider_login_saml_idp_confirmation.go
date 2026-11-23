package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	"github.com/faustbrian/go-sso"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// ProviderSAMLIDPConfirmationConfig selects native linked-user confirmation.
// Remember is trusted application policy, not browser input. Migrate the owned
// preparation, replay, capability, pending and session histories before use.
type ProviderSAMLIDPConfirmationConfig struct {
	Audience string
	Session  sessionpg.Config
	Issuer   session.IssuerConfig
	CSRFKey  session.CSRFKey
	Remember session.RememberPolicy
}

func (ProviderSAMLIDPConfirmationConfig) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprint(f, "sso.postgres.ProviderSAMLIDPConfirmationConfig(redacted)")
}

func (ProviderSAMLIDPConfirmationConfig) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}
func (ProviderSAMLIDPConfirmationConfig) MarshalText() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}

// ProviderSAMLIDPConfirmationService owns explicit same-browser confirmation
// using the pending writer's primary. It never introduces an SP transaction,
// invokes the wire verifier again, or activates an HTTP route.
type ProviderSAMLIDPConfirmationService struct {
	arrival *ProviderSAMLIDPArrivalService
	config  ProviderSAMLIDPConfirmationConfig
	effect  *sessionpg.SSOSAMLIDPConfirmationEffect
}

func (*ProviderSAMLIDPConfirmationService) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprint(f, "sso.postgres.ProviderSAMLIDPConfirmationService(redacted)")
}

func (*ProviderSAMLIDPConfirmationService) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}
func (*ProviderSAMLIDPConfirmationService) MarshalText() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}

// NewProviderSAMLIDPConfirmationService borrows a selected arrival service and
// constructs the native session effect without I/O. Use the same enabled
// origin, installed provider and retained keys across in-flight confirmations.
func NewProviderSAMLIDPConfirmationService(arrival *ProviderSAMLIDPArrivalService, c ProviderSAMLIDPConfirmationConfig) (*ProviderSAMLIDPConfirmationService, error) {
	if arrival == nil || arrival.admission == nil || arrival.issuer == nil || c.Issuer.MaximumDuration > arrival.config.Coordinator.MaximumDuration {
		return nil, sso.ErrInvalidInput
	}
	if _, err := c.Remember.Bindings(); err != nil {
		return nil, sso.ErrInvalidInput
	}
	policy := sessionpg.IdentifierAdmissionConfig{GlobalAuthorityID: arrival.config.GlobalAuthorityID, PolicyNamespace: arrival.admission.linked.namespace,
		Audience: c.Audience, AuthenticationMethod: "sso-saml", CredentialKind: identity.CredentialProvider, CredentialOwner: "sso"}
	effect, err := sessionpg.NewSSOSAMLIDPConfirmationEffect(c.Session, policy, arrival.admission.router.organizations)
	if err != nil {
		return nil, sso.ErrInvalidInput
	}
	c.Issuer.Clock = arrival.admission.router.config.Clock
	if _, err := session.NewSSOSAMLIDPConfirmationSessionIssuerWithCSRF(&samlIDPConfirmationPhase{}, c.Issuer, c.CSRFKey); err != nil {
		return nil, sso.ErrInvalidInput
	}
	return &ProviderSAMLIDPConfirmationService{arrival: arrival, config: c, effect: effect}, nil
}

// Confirm authenticates both original browser values and atomically consumes
// pending custody, both SAML replay identifiers and the original one-time grant
// with the normal session. Only the acknowledged new write releases session and
// CSRF credentials. No redirect is selected by this trusted native operation.
func (s *ProviderSAMLIDPConfirmationService) Confirm(ctx context.Context, request SAMLIDPConfirmationRequest) (out ProviderLoginCallbackResult, err error) {
	if ctx == nil || s == nil || s.arrival == nil || s.effect == nil {
		return out, sso.ErrInvalidInput
	}
	ctx, cancel := context.WithTimeout(ctx, s.arrival.config.Coordinator.MaximumDuration)
	defer cancel()
	pending, original, err := s.arrival.readPendingConfirmation(ctx, request)
	if err != nil {
		return out, providerError(ctx, err)
	}
	defer clear(pending.Envelope)
	defer clear(original.Proof)
	phase := &samlIDPConfirmationPhase{arrival: s.arrival, effect: s.effect, pending: pending, original: original, audience: s.config.Audience, remember: s.config.Remember}
	command, b, err := s.confirmationCommand(pending, request)
	if err != nil {
		return out, providerError(ctx, err)
	}
	phase.command = command
	phase.grant, err = s.confirmationGrant(ctx, b, original, pending.ExpiresAt)
	if err != nil {
		return out, providerError(ctx, err)
	}
	phase.issuer, err = session.NewSSOSAMLIDPConfirmationSessionIssuerWithCSRF(phase, s.config.Issuer, s.config.CSRFKey)
	if err != nil {
		return out, sso.ErrUnavailable
	}
	coordinator, registry, err := s.coordinator(phase)
	if err != nil {
		return out, providerError(ctx, err)
	}
	declaration, err := providerLoginCallbackPlan(b, pending.IssuedAt, s.arrival.config.AuditRetentionPolicyVersion, phase.grant, registry.Descriptors())
	if err != nil {
		return out, providerError(ctx, err)
	}
	phase.declaration, err = coordinator.PrepareFeaturePreparationPlan(command, declaration)
	if err != nil {
		return out, providerError(ctx, err)
	}
	result, err := coordinator.ExecutePreparedFeature(ctx, command, phase.declaration)
	out.Completion = result
	if err != nil {
		var unknown identity.UnknownCommitError
		if errors.As(err, &unknown) {
			return out, unknown
		}
		return out, providerError(ctx, err)
	}
	if result.Validate() != nil || result.Binding != b || result.Outcome != identity.CommitOutcomeCommitted {
		return out, sso.ErrUnavailable
	}
	if phase.prepared == (session.PreparedIssuance{}) || phase.execution == (identity.Command{}) {
		return out, nil // Restored output has no original bearer to disclose.
	}
	bound, err := phase.issuer.BindSSOSAMLIDPConfirmation(phase.prepared, phase.execution)
	if err != nil {
		return out, sso.ErrUnavailable
	}
	phase.acknowledged, phase.canDisclose = result, true
	issued, err := phase.issuer.Issue(ctx, bound)
	if err != nil {
		return out, providerError(ctx, err)
	}
	csrf, err := bound.CSRFToken()
	if err != nil || issued.Replayed || issued.Token == (session.Token{}) {
		return out, sso.ErrUnavailable
	}
	out.Issuance, out.CSRF = issued, csrf
	return out, nil
}

func (s *ProviderSAMLIDPConfirmationService) confirmationCommand(pending samlIDPPendingArrival, req SAMLIDPConfirmationRequest) (identity.Command, identity.CommandBinding, error) {
	// Re-derive the same private completion ID for concurrent/exact retries.
	// The original arrival and confirmation roles have separate MAC domains.
	ob := pending.Binding
	key := s.arrival.config.ConfirmationKeys[pending.KeyVersion]
	idDigest := providerLoginPayloadMAC(key, pending.KeyVersion, "identity.sso.saml-idp.completion-command.v1", []byte(ob.TenantID), []byte(ob.CommandID))
	id, err := identity.ParseCommandID(base64.RawURLEncoding.EncodeToString(idDigest[:16]))
	if err != nil || id == ob.CommandID {
		return identity.Command{}, identity.CommandBinding{}, identity.UnavailableError{}
	}
	op := kernel.SSOSAMLIDPConfirmationOperation()
	b := ob
	b.CommandID, b.OperationID, b.SchemaID, b.SchemaVersion = id, op.OperationID, op.SchemaID, op.SchemaVersion
	wire := sha256.Sum256(pending.Envelope)
	intent := providerLoginPayloadMAC(key, pending.KeyVersion, "identity.sso.saml-idp.completion-intent.v1", wire[:], []byte(req.Origin),
		[]byte(s.config.Audience), []byte(samlIDPConfirmationRemember(s.config.Remember)))
	command, err := identity.NewFeatureSAMLIDPConfirmationCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: []identity.FeatureField{{
		Name: "saml.confirmation.intent", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: intent[:]},
	}}}, req.Browser, req.Form)
	return command, b, err
}

func samlIDPConfirmationRemember(policy session.RememberPolicy) string {
	spec, _ := policy.Bindings() // construction requires a resolved policy
	return fmt.Sprintf("%v:%d:%d:%d:%d", spec.Choice, spec.AbsoluteTTL, spec.IdleTTL, spec.RefreshAfter, spec.FreshFor)
}

func (s *ProviderSAMLIDPConfirmationService) confirmationGrant(ctx context.Context, b identity.CommandBinding, original samlIDPArrivalOrigin, cutoff time.Time) (kernel.CapabilityPlan, error) {
	proof, err := capability.ParseProof(string(original.Proof), s.arrival.proofLimits)
	if err != nil {
		return kernel.CapabilityPlan{}, identity.ForbiddenError{}
	}
	defer func() {
		_ = proof.Transfer(context.WithoutCancel(ctx), func(context.Context, []byte) error { return nil })
	}()
	want := kernel.CapabilityPlan(original.Grant)
	plan, err := s.arrival.issuer.PrepareSSOSAMLIDPConfirmationConsumption(ctx, b, proof, want.ProofFingerprint, want.ReplayKeyVersion, cutoff)
	if err != nil {
		return kernel.CapabilityPlan{}, err
	}
	if plan != want {
		return kernel.CapabilityPlan{}, identity.ForbiddenError{}
	}
	return plan, nil
}

func (s *ProviderSAMLIDPConfirmationService) coordinator(phase *samlIDPConfirmationPhase) (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
	audits, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, nil, err
	}
	lifecycle, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, nil, err
	}
	a := s.arrival
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{a.admission.linked.directory, audits, lifecycle, phase, capabilitypg.NewParticipant()})
	if err != nil {
		return nil, nil, err
	}
	coordinator, err := kernel.NewCoordinator(a.admission.router.pool, registry, a.config.Coordinator)
	return coordinator, registry, err
}

// RecoverConfirmation authorizes the original historical receipt on the
// primary. It never repeats confirmation and cannot recover session or browser
// credentials. Pass the exact linked-user recovery scope from trusted records.
func (s *ProviderSAMLIDPConfirmationService) RecoverConfirmation(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (identity.CommandResult, error) {
	if ctx == nil || s == nil || s.arrival == nil || s.arrival.config.Coordinator.QueryPolicy == nil {
		return identity.CommandResult{}, sso.ErrInvalidInput
	}
	arrival, err := identity.ParseCommandID(q.RecordID)
	op := kernel.SSOSAMLIDPConfirmationOperation()
	if err != nil || arrival == q.CommandID || q.OperationID != op.OperationID || q.TenantID != s.arrival.admission.tenant ||
		q.ActorID != s.arrival.config.ActorID || q.ActorKind != authorization.SubjectServiceAccount || q.UserID == "" || q.AnonymousFlowID != "" || q.LinkMode != 0 {
		return identity.CommandResult{}, sso.ErrForbidden
	}
	c, _, err := s.coordinator(&samlIDPConfirmationPhase{arrival: s.arrival, effect: s.effect})
	if err != nil {
		return identity.CommandResult{}, providerError(ctx, err)
	}
	result, err := c.RecoverFeatureCommand(ctx, q, caller)
	if result.Binding.CommandID != q.CommandID || result.Feature == nil || result.Feature.Operation != op {
		if err == nil {
			err = identity.ForbiddenError{}
		}
		return identity.CommandResult{}, providerError(ctx, err)
	}
	if result.Outcome == identity.CommitOutcomeInProgress && errors.Is(err, identity.UnavailableError{}) {
		result.Outcome = identity.CommitOutcomeUnknown
		return result, identity.UnknownCommitError{CommandID: q.CommandID}
	}
	var unknown identity.UnknownCommitError
	if errors.As(err, &unknown) {
		return result, unknown
	}
	return result, providerError(ctx, err)
}
