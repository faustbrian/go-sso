package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	organization "github.com/faustbrian/go-organization"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

const (
	providerConfigurationMaximumBytes         = 48 << 10
	providerConfigurationEnvelopeMaximumBytes = 64 << 10
	providerLegacyPreparationMaximumBytes     = 64 << 10
	// Update preparation JSON base64-encodes a bounded configuration envelope.
	// Its 96KiB limit leaves room for that expansion plus the scalar frame,
	// while the original registration preparation profile remains unchanged.
	providerUpdatePreparationMaximumBytes = 96 << 10
	providerEnvelopeOverheadMaximumBytes  = 4096
)

func providerOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "sso", OperationID: "identity.sso.provider.register-oidc", SchemaID: "sso-disabled-static-oidc-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// ProviderContributor is the versioned native static provider mutation owner.
// ProviderService constructs invocation-local instances from real session and
// organization observations. It borrows only generation-bound Work supplied by
// the existing coordinator and never begins, commits or retains a transaction.
// It implements the open native interfaces, not a competing command journal.
type ProviderContributor struct {
	service       *ProviderService
	update        *sso.ProviderUpdateRequest
	enable        *providerEnable
	disable       *providerDisable
	request       providerCommandInput
	admission     providerAdmission
	intent        identity.RequestIntent
	binding       identity.CommandBinding
	command       identity.Command
	counter       kernel.CommandCounterPlan
	registry      *kernel.ContributorRegistry
	coordinator   *kernel.Coordinator
	commitment    [32]byte
	configuration []byte
	outputHash    [32]byte
	generation    uint64
	failure       error
}

var _ kernel.FeaturePreparationContributor = (*ProviderContributor)(nil)
var _ kernel.RequestKeyRecoveryContributor = (*ProviderContributor)(nil)
var _ kernel.FeatureCommitContributor = (*ProviderContributor)(nil)

func (*ProviderContributor) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "sso/postgres", ContractID: "identity.sso.providers", Version: 1}
}
func (p *ProviderContributor) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{p.operation()}
}
func (ProviderContributor) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("sso.postgres.ProviderContributor(redacted)"))
}
func (ProviderContributor) MarshalJSON() ([]byte, error) { return nil, sso.ErrSensitiveSerialization }
func (ProviderContributor) MarshalText() ([]byte, error) { return nil, sso.ErrSensitiveSerialization }

type providerStoredBinding identity.CommandBinding

// The coordinator consumes the shared provider command shape, not one
// protocol's public registration request.
type providerCommandInput struct {
	CommandID      identity.CommandID
	OrganizationID string
	Issuer         string
	Domains        []string
	Mapping        sso.AttributeMapping
	protocol       string
}

type providerRegistrationResult struct {
	Provider                     sso.Provider
	VerificationRequirementCount uint32
	Completion                   sso.Completion
}

type providerConfiguration struct {
	Metadata sso.OIDCStaticMetadataSpec
	Mapping  sso.AttributeMappingSpec
	Domains  []string
}

func (s *ProviderService) composeProvider(p *ProviderContributor) error {
	audits, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return sso.ErrInvalidInput
	}
	lifecycle, err := lifecyclepg.NewContributor()
	if err != nil {
		return sso.ErrInvalidInput
	}
	p.registry, err = kernel.NewContributorRegistry([]kernel.Contributor{s.directory, s.config.Counters, audits, lifecycle, p})
	if err != nil {
		return sso.ErrInvalidInput
	}
	if p.disable != nil {
		p.coordinator, err = kernel.NewCoordinatorWithCanonicalPostRequestKeys(s.pool, p.registry, s.config.Coordinator, s.disableRequestKeys())
	} else {
		p.coordinator, err = kernel.NewCoordinatorWithRequestKeys(s.pool, p.registry, s.config.Coordinator, s.config.RequestKeys)
	}
	return providerError(nil, err)
}

// ProviderRegisterOidc admits one exact original keyed intent and atomically
// commits disabled metadata, required audit and outbox through the native Work.
// Matching retries recover only that original command; an absent journal stays
// Unknown. No proof, login, routing, discovery request or credential is created.
func (s *ProviderService) ProviderRegisterOidc(ctx context.Context, r sso.ProviderRegisterOidcRequest) (sso.ProviderRegisterOidcResult, error) {
	if s == nil || ctx == nil || validateProviderRequest(r) != nil {
		return sso.ProviderRegisterOidcResult{}, sso.ErrInvalidInput
	}
	request := providerCommandInput{CommandID: r.CommandID, OrganizationID: r.OrganizationID, Issuer: r.Issuer, Domains: r.Domains, Mapping: r.Mapping}
	result, err := s.registerDisabledProvider(ctx, request, r.IdempotencyKey, func() ([]byte, error) {
		metadata, _ := r.StaticMetadata.Spec()
		mapping, _ := r.Mapping.Spec()
		return json.Marshal(providerConfiguration{Metadata: metadata, Mapping: mapping, Domains: append([]string(nil), r.Domains...)})
	})
	return sso.ProviderRegisterOidcResult(result), err
}

func (s *ProviderService) registerDisabledProvider(ctx context.Context, r providerCommandInput, key identity.IdempotencyKey, encode func() ([]byte, error)) (providerRegistrationResult, error) {
	var out providerRegistrationResult
	ctx, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	a, err := s.admit(ctx, r.OrganizationID, "org:sso-write")
	if err != nil {
		return out, err
	}
	configuration, err := encode()
	if err != nil || len(configuration) > providerConfigurationMaximumBytes {
		return out, sso.ErrInvalidInput
	}
	defer clear(configuration)
	intentHash := sha256.Sum256(configuration)
	intent, err := identity.NewRequestIntent([]identity.FeatureField{
		{Name: "organization", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: r.OrganizationID}},
		{Name: "command", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(r.CommandID)}},
		{Name: "configuration", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: intentHash[:]}},
		{Name: "policy-id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: s.config.PolicyID}},
	})
	if err != nil {
		return out, sso.ErrInvalidInput
	}
	p := &ProviderContributor{service: s, request: r, admission: a, intent: intent, configuration: configuration}
	if err = s.composeProvider(p); err != nil {
		return out, err
	}
	bound, _ := a.session.Session.Bindings()
	op := p.operation()
	scope := kernel.RequestKeyScope{TenantID: s.authentication.TenantID, ActorID: identity.ActorID(bound.UserID), ActorKind: authorization.SubjectUser, Method: "POST", RouteID: op.OperationID}
	caller := s.kernelDecisionFor(bound.UserID, "identity.request-admission", op.OperationID, op.OperationID)
	registration := kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: op}
	keyBinding, wire, err := p.coordinator.ResolvePreparedRequestKey(ctx, scope, key, intent, caller, registration, p)
	defer clear(wire)
	if err != nil {
		if p.failure != nil {
			return out, providerError(ctx, p.failure)
		}
		return out, providerError(ctx, err)
	}
	original, err := p.RestoreRequestKey(ctx, keyBinding, wire)
	if err != nil {
		return out, providerError(ctx, err)
	}
	if p.binding != original {
		out.Completion, err = p.coordinator.RecoverPreparedFeatureCommand(ctx, providerRecovery(original), s.kernelDecisionFor(bound.UserID, "identity.user", string(bound.UserID), op.OperationID), registration, p)
	} else {
		var plan kernel.CommandPlan
		plan, err = p.plan(false)
		if err == nil {
			out.Completion, err = p.coordinator.ExecutePreparedFeature(ctx, p.command, plan)
		}
	}
	if out.Completion.Outcome == identity.CommitOutcomeCommitted {
		var mappingText string
		var pending int32
		readErr := s.pool.Raw().QueryRow(ctx, `SELECT mapping_version::text,pending_domains FROM sso_providers.providers WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`, string(original.TenantID), r.OrganizationID, original.RecordID).Scan(&mappingText, &pending)
		if readErr != nil {
			return out, storeError(ctx, readErr)
		}
		mappingVersion, parseErr := strconv.ParseUint(mappingText, 10, 64)
		if parseErr != nil || mappingVersion == 0 || pending < 1 || pending > 128 {
			return out, sso.ErrUnavailable
		}
		out.Provider = sso.Provider{ID: original.RecordID, OrganizationID: r.OrganizationID, Protocol: r.providerProtocol(), Version: 1, MappingVersion: mappingVersion, VerifiedDomains: []string{}}
		out.VerificationRequirementCount = uint32(pending)
		if _, admissionErr := s.admit(ctx, r.OrganizationID, "org:sso-write"); admissionErr != nil {
			out.Provider = sso.Provider{}
			out.VerificationRequirementCount = 0
			return out, admissionErr
		}
	}
	return out, providerError(ctx, err)
}

func providerRecovery(b identity.CommandBinding) identity.RecoveryQuery {
	return identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}
}

func providerError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	var unknown identity.UnknownCommitError
	var denied identity.ForbiddenError
	var conflict identity.ConflictError
	var invalid identity.InvalidInputError
	switch {
	case errors.As(err, &unknown):
		return unknown
	case errors.Is(err, organization.ErrForbidden):
		return sso.ErrForbidden
	case errors.Is(err, organization.ErrInvalidInput):
		return sso.ErrInvalidInput
	case errors.Is(err, organization.ErrConflict):
		return sso.ErrConflict
	case errors.As(err, &denied):
		return sso.ErrForbidden
	case errors.As(err, &conflict):
		return sso.ErrConflict
	case errors.As(err, &invalid):
		return sso.ErrInvalidInput
	default:
		return storeError(ctx, err)
	}
}

func (s *ProviderService) kernelDecision(actor identity.UserID, kind, id string) authorization.DecisionContext {
	return s.kernelDecisionFor(actor, kind, id, providerOperation().OperationID)
}

func (s *ProviderService) kernelDecisionFor(actor identity.UserID, kind, id, action string) authorization.DecisionContext {
	dc := s.decision(actor, id, action)
	dc.Request.Resource = authorization.Resource{Type: authorization.ResourceType(kind), ID: authorization.ResourceID(id)}
	return dc
}

func (p *ProviderContributor) requestContext(b kernel.RequestKeyPreparationBinding) (envelope.Context, error) {
	if p == nil || p.service == nil {
		return envelope.Context{}, sso.ErrInvalidInput
	}
	namespace := p.service.config.RequestKeys.Namespace
	if p.disable != nil {
		namespace = p.service.disableRequestKeys().Namespace
	}
	if b.Namespace != namespace || b.Scope.RouteID != p.operation().OperationID || b.Scope.Method != "POST" || b.Feature != (kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: p.operation()}) || b.PolicyVersion != p.service.config.PolicyVersion || b.Admission.CommandID == "" || b.IntentDigest == ([32]byte{}) {
		return envelope.Context{}, sso.ErrInvalidInput
	}
	// The native type deliberately rejects implicit serialization. This explicit
	// scalar frame authenticates every coordinator-owned preparation field.
	frame, err := json.Marshal(struct {
		Namespace              string
		Scope                  kernel.RequestKeyScope
		Admission              kernel.RequestKeyAdmission
		Feature                kernel.FeatureRegistration
		Policy                 uint64
		Intent                 [32]byte
		PolicyID, Organization string
	}{b.Namespace, b.Scope, b.Admission, b.Feature, b.PolicyVersion, b.IntentDigest, p.service.config.PolicyID, p.request.OrganizationID})
	if err != nil {
		return envelope.Context{}, sso.ErrInvalidInput
	}
	digest := sha256.Sum256(frame)
	owner, profile := "sso/provider-registration", "static-disabled-v1"
	if p.update != nil {
		owner, profile = "sso/provider-update", "static-disabled-update-v1"
	}
	if p.enable != nil {
		owner, profile = "sso/provider-enable", "static-oidc-enable-v1"
		if p.request.providerProtocol() == providerProtocolOAuth2 {
			profile = "static-oauth2-enable-v1"
		}
	}
	if p.disable != nil {
		owner, profile = "sso/provider-disable", "static-oidc-disable-v1"
		if p.request.providerProtocol() == providerProtocolOAuth2 {
			profile = "static-oauth2-disable-v1"
		}
	}
	return envelope.NewContext(map[string]string{"owner": owner, "profile": profile, "binding": hex.EncodeToString(digest[:])})
}

func (p *ProviderContributor) seal(ctx context.Context, aad envelope.Context, plain []byte) ([]byte, error) {
	sealed, err := p.service.config.Envelope.Encrypt(ctx, envelope.EncryptRequest{Plaintext: plain, KeyReference: p.service.config.KeyReference, Context: aad})
	if err != nil {
		return nil, sso.ErrUnavailable
	}
	return sealed.MarshalBinary()
}
func (p *ProviderContributor) open(ctx context.Context, aad envelope.Context, wire []byte, maximum int) ([]byte, error) {
	if len(wire) == 0 || len(wire) > maximum+providerEnvelopeOverheadMaximumBytes {
		return nil, sso.ErrUnavailable
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return nil, sso.ErrUnavailable
	}
	plain, err := p.service.config.Envelope.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	if err != nil || len(plain) > maximum {
		clear(plain)
		return nil, sso.ErrUnavailable
	}
	return plain, nil
}

func (p *ProviderContributor) PrepareRequestKey(ctx context.Context, b kernel.RequestKeyPreparationBinding, intent identity.RequestIntent) ([]byte, error) {
	if p == nil || p.service == nil || ctx == nil {
		return nil, sso.ErrInvalidInput
	}
	expected, _ := p.intent.Fields()
	actual, ok := intent.Fields()
	if !ok || !reflect.DeepEqual(expected, actual) {
		return nil, sso.ErrInvalidInput
	}
	if err := p.prepare(ctx, b); err != nil {
		p.failure = err
		return nil, err
	}
	aad, err := p.requestContext(b)
	if err != nil {
		return nil, err
	}
	var plain []byte
	if p.disable != nil {
		plain, err = json.Marshal(p.disable.storedBinding(providerStoredBinding(p.binding)))
	} else {
		plain, err = json.Marshal(providerStoredBinding(p.binding))
	}
	defer clear(plain)
	if err != nil {
		return nil, sso.ErrInvalidInput
	}
	return p.seal(ctx, aad, plain)
}

func (p *ProviderContributor) prepare(ctx context.Context, b kernel.RequestKeyPreparationBinding) error {
	s := p.service
	a := p.admission
	if a.session.ValidateAt(s.config.Clock.Now()) != nil {
		return sso.ErrForbidden
	}
	bound, err := a.session.Session.Bindings()
	if err != nil {
		return sso.ErrForbidden
	}
	if b.Scope.TenantID != bound.TenantID || b.Scope.ActorID != identity.ActorID(bound.UserID) || b.Scope.ActorKind != authorization.SubjectUser {
		return sso.ErrForbidden
	}
	var provider identity.SubjectID
	if p.disable != nil {
		provider = identity.SubjectID(p.disable.selection.ProviderID)
		if err := p.prepareDisable(ctx); err != nil {
			return err
		}
	} else if p.enable != nil {
		provider = identity.SubjectID(p.enable.request.ProviderID)
		if err := p.prepareEnable(ctx); err != nil {
			return err
		}
	} else {
		provider, err = identity.NewSubjectID()
		if err != nil {
			return sso.ErrUnavailable
		}
		if p.update != nil {
			provider = identity.SubjectID(p.update.ProviderID)
			if err := p.prepareUpdate(ctx); err != nil {
				return err
			}
		}
	}
	a = p.admission
	correlation := p.request.CommandID
	if p.enable != nil || p.disable != nil {
		correlation = b.Admission.CommandID
	}
	op := p.operation()
	p.binding = identity.CommandBinding{CommandID: b.Admission.CommandID, TenantID: bound.TenantID, UserID: bound.UserID, ActorID: identity.ActorID(bound.UserID), ActorKind: authorization.SubjectUser, OperationID: op.OperationID, RecordID: string(provider), SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, PolicyID: s.config.PolicyID, PolicyVersion: s.config.PolicyVersion, CorrelationID: string(correlation)}
	if p.binding.ValidateFor(op) != nil {
		return sso.ErrInvalidInput
	}
	configurationHash := sha256.Sum256(p.configuration)
	if p.enable != nil {
		// The native preparation and its generated ciphertext depend on the
		// exact acquired domain/credential authority, not merely the plaintext
		// provider configuration that will be re-sealed unchanged.
		readiness, err := json.Marshal(struct {
			Intent, Configuration, Credential, Context [32]byte
		}{b.IntentDigest, configurationHash, p.enable.predecessor.credentialHash, p.enable.predecessor.contextHash})
		if err != nil {
			return sso.ErrUnavailable
		}
		configurationHash = sha256.Sum256(readiness)
	}
	if p.disable != nil {
		// Bind the exact authenticated predecessor and canonical request intent
		// to the generated metadata successor before admitting Work.
		var frame [96]byte
		copy(frame[:32], b.IntentDigest[:])
		copy(frame[32:64], configurationHash[:])
		copy(frame[64:], p.disable.predecessorHash[:])
		configurationHash = sha256.Sum256(frame[:])
	}
	frame, err := json.Marshal(struct {
		Binding                  providerStoredBinding
		Configuration            [32]byte
		Organization             string
		Status                   identity.UserStatusRecord
		OrganizationAuthority    organization.CredentialAuthorityObservation
		Started, Verified, Until time.Time
		Network                  string
	}{providerStoredBinding(p.binding), configurationHash, p.request.OrganizationID, a.status, a.organization, a.started, a.verified, a.until, s.network})
	if err != nil {
		return sso.ErrInvalidInput
	}
	p.commitment = sha256.Sum256(frame)
	fields, err := sessionpg.OriginalSessionFields(a.session.Session)
	if err != nil {
		return sso.ErrForbidden
	}
	fields = append(fields, identity.FeatureField{Name: "provider.intent", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: p.commitment[:]}})
	command, err := identity.NewFeatureSessionCommand(identity.FeatureCommandSpec{Binding: p.binding, Operation: op, Fields: fields}, s.authentication.Bearer)
	if err != nil {
		return sso.ErrInvalidInput
	}
	p.command, p.counter, err = s.config.Counters.PrepareCommandCounters(command, risk.Subject{Actor: string(bound.UserID), Resource: p.binding.RecordID, Network: s.network}, a.verified)
	return providerError(ctx, err)
}

func (p *ProviderContributor) RestoreRequestKey(ctx context.Context, b kernel.RequestKeyPreparationBinding, wire []byte) (identity.CommandBinding, error) {
	aad, err := p.requestContext(b)
	if err != nil {
		return identity.CommandBinding{}, err
	}
	plain, err := p.open(ctx, aad, wire, 4096)
	defer clear(plain)
	if err != nil {
		return identity.CommandBinding{}, err
	}
	original, err := p.decodeStoredProviderBinding(plain)
	if err != nil {
		return identity.CommandBinding{}, err
	}
	correlation := p.request.CommandID
	if p.enable != nil {
		correlation = b.Admission.CommandID
		if original.RecordID != p.enable.request.ProviderID {
			return identity.CommandBinding{}, sso.ErrUnavailable
		}
	}
	if p.disable != nil {
		correlation = b.Admission.CommandID
		if original.RecordID != string(p.disable.selection.ProviderID) {
			return identity.CommandBinding{}, sso.ErrUnavailable
		}
	}
	if original.ValidateFor(p.operation()) != nil || original.CommandID != b.Admission.CommandID || original.TenantID != b.Scope.TenantID || original.UserID != identity.UserID(b.Scope.ActorID) || original.ActorID != b.Scope.ActorID || original.ActorKind != b.Scope.ActorKind || original.PolicyID != p.service.config.PolicyID || original.PolicyVersion != b.PolicyVersion || original.CorrelationID != string(correlation) {
		return identity.CommandBinding{}, sso.ErrUnavailable
	}
	return original, nil
}

func (p *ProviderContributor) decodeStoredProviderBinding(plain []byte) (identity.CommandBinding, error) {
	var binding providerStoredBinding
	var canonical []byte
	if p.disable != nil {
		var saved storedDisableBinding
		if json.Unmarshal(plain, &saved) != nil {
			return identity.CommandBinding{}, sso.ErrUnavailable
		}
		canonical, _ = json.Marshal(saved)
		defer clear(canonical)
		if !bytes.Equal(canonical, plain) {
			return identity.CommandBinding{}, sso.ErrUnavailable
		}
		if saved != p.disable.storedBinding(saved.Binding) {
			return identity.CommandBinding{}, sso.ErrConflict
		}
		return identity.CommandBinding(saved.Binding), nil
	}
	if json.Unmarshal(plain, &binding) != nil {
		return identity.CommandBinding{}, sso.ErrUnavailable
	}
	canonical, _ = json.Marshal(binding)
	defer clear(canonical)
	if !bytes.Equal(canonical, plain) {
		return identity.CommandBinding{}, sso.ErrUnavailable
	}
	return identity.CommandBinding(binding), nil
}

func (p *ProviderContributor) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if p == nil || p.service == nil || p.command != c || p.binding.ValidateFor(p.operation()) != nil || plan.Feature == nil || *plan.Feature != (kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: p.operation()}) || plan.SubjectType != "sso_provider" || plan.CommandCounters == nil || *plan.CommandCounters != p.counter || plan.Lifecycle == nil || *plan.Lifecycle != p.lifecycle() || len(plan.Audits) != 1 || plan.Audits[0].EventType != p.operation().OperationID || !plan.Audits[0].Required || plan.Audits[0].RequiredRecordCount != 1 || plan.Audits[0].RetentionClass != "protected" || plan.Capability != nil || plan.CapabilityIssuance != nil || plan.OTP != nil || plan.Delivery != nil {
		return sso.ErrInvalidInput
	}
	spec, ok := c.Feature()
	if !ok || spec.Binding != p.binding || spec.Operation != p.operation() {
		return sso.ErrInvalidInput
	}
	for _, field := range spec.Fields {
		if field.Name == "provider.intent" && field.Value.Kind == identity.FeatureBytes && bytes.Equal(field.Value.Bytes, p.commitment[:]) {
			return nil
		}
	}
	return sso.ErrInvalidInput
}
func (p *ProviderContributor) ValidateFeaturePreparation(c identity.Command, plan kernel.CommandPlan) error {
	return p.ValidateFeatureCommand(c, plan)
}

func (p *ProviderContributor) plan(final bool) (kernel.CommandPlan, error) {
	b := p.binding
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return kernel.CommandPlan{}, sso.ErrUnavailable
	}
	seed, err := builder.Build(audit.RecordInput{OccurredAt: p.admission.verified, Action: p.operation().OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "sso_provider", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "sso_provider", "aggregate.id": b.RecordID, "aggregate.before_version": strconv.FormatUint(p.beforeVersion(), 10), "aggregate.after_version": strconv.FormatUint(p.afterVersion(), 10), "retention.class": "protected"}})
	if err != nil {
		return kernel.CommandPlan{}, sso.ErrInvalidInput
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, p.operation(), "sso_provider", seed)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	lifecycle := p.lifecycle()
	plan := kernel.CommandPlan{Contributors: p.registry.Descriptors(), Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: p.operation()}, SubjectType: "sso_provider", Lifecycle: &lifecycle, CommandCounters: &p.counter, Audits: []kernel.AuditPlan{{EventType: p.operation().OperationID, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}}
	if final {
		return p.coordinator.PrepareCommandPlan(b, p.command, plan)
	}
	return p.coordinator.PrepareFeaturePreparationPlan(p.command, plan)
}

func (p *ProviderContributor) admit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if c != p.command {
		return identity.ForbiddenError{}
	}
	b, feature, _, err := w.FeatureScope(p)
	if err != nil || b != p.binding || feature != (kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: p.operation()}) {
		return identity.ForbiddenError{}
	}
	a := p.admission
	config := p.service.config
	spec, err := a.session.Session.Bindings()
	if err != nil {
		return identity.ForbiddenError{}
	}
	bearer, ok := c.SessionToken()
	if !ok {
		return identity.ForbiddenError{}
	}
	token, err := session.ParseToken(bearer.Token())
	if err != nil {
		return identity.ForbiddenError{}
	}
	key, ok := config.LookupKeys[spec.Lookup.KeyVersion]
	if !ok {
		return identity.ForbiddenError{}
	}
	digest, err := token.Digest(key, string(spec.TenantID))
	if err != nil || digest.KeyVersion != spec.Lookup.KeyVersion || subtle.ConstantTimeCompare(digest.Sum[:], spec.Lookup.Sum[:]) != 1 {
		return identity.ForbiddenError{}
	}
	directory, credential, policy, err := sessionpg.OriginalSessionAdmission(config.Profile, a.session.Session, p.binding)
	if err != nil {
		return identity.ForbiddenError{}
	}
	if err = w.RequireActiveDirectoryAuthority(ctx, p, directory); err != nil {
		return err
	}
	if _, err = w.RequireActiveActorCredential(ctx, p, credential); err != nil {
		return err
	}
	if err = w.RequireActiveUserStatus(ctx, p, a.status); err != nil {
		return err
	}
	if err = w.RequireActiveActorAuthorization(ctx, p, policy); err != nil {
		return err
	}
	if err = sessionpg.RequireSession(ctx, w, config.Session, a.session.Session); err != nil {
		return err
	}
	if err = config.Organizations.RequireCredentialAuthority(ctx, w, p, a.organization); err != nil {
		return err
	}
	at, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if a.session.ValidateAt(at) != nil || at.Before(a.verified) || !at.Before(a.until) {
		return identity.ForbiddenError{}
	}
	if p.enable != nil || p.disable != nil {
		lifetime, err := a.session.Session.Lifetime(at)
		if err != nil || !lifetime.Fresh {
			return identity.ForbiddenError{}
		}
	}
	return nil
}
func (p *ProviderContributor) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, c identity.Command) error {
	return p.admit(ctx, w, c)
}
func (p *ProviderContributor) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	return p.admit(ctx, w, c)
}

func (p *ProviderContributor) configurationContext() (envelope.Context, error) {
	return envelope.NewContext(map[string]string{"owner": "sso/provider", "tenant": string(p.binding.TenantID), "organization": p.request.OrganizationID, "provider": p.binding.RecordID, "protocol": p.request.providerProtocol(), "purpose": "static-configuration", "version": strconv.FormatUint(p.afterVersion(), 10)})
}
func (p *ProviderContributor) outputContext(generation uint64) (envelope.Context, error) {
	frame, err := json.Marshal(struct {
		Binding    providerStoredBinding
		Commitment [32]byte
		Generation uint64
	}{providerStoredBinding(p.binding), p.commitment, generation})
	if err != nil {
		return envelope.Context{}, sso.ErrInvalidInput
	}
	digest := sha256.Sum256(frame)
	return envelope.NewContext(map[string]string{"owner": "sso/provider-preparation", "binding": hex.EncodeToString(digest[:])})
}

type providerPreparationOutput struct {
	Generation    uint64
	Commitment    [32]byte
	Configuration []byte
	EnableProof   []byte `json:",omitempty"`
}

func (p *ProviderContributor) GenerateFeaturePreparation(ctx context.Context, c identity.Command, generation uint64) ([]byte, error) {
	if p == nil || p.service == nil || ctx == nil || c != p.command || generation == 0 || p.generation != 0 {
		return nil, sso.ErrInvalidInput
	}
	aad, err := p.configurationContext()
	if err != nil {
		return nil, err
	}
	configuration, err := p.seal(ctx, aad, p.configuration)
	if err != nil {
		return nil, err
	}
	versioned := p.update != nil || p.enable != nil || p.disable != nil
	if versioned && len(configuration) > providerConfigurationEnvelopeMaximumBytes {
		return nil, sso.ErrUnavailable
	}
	output := providerPreparationOutput{Generation: generation, Commitment: p.commitment, Configuration: configuration}
	if p.enable != nil {
		output.EnableProof, err = p.sealEnableProof(ctx)
		if err != nil {
			return nil, err
		}
	}
	plain, err := json.Marshal(output)
	defer clear(plain)
	if err != nil {
		return nil, sso.ErrUnavailable
	}
	if versioned && len(plain) > p.preparationMaximumBytes() {
		return nil, sso.ErrUnavailable
	}
	aad, err = p.outputContext(generation)
	if err != nil {
		return nil, err
	}
	wire, err := p.seal(ctx, aad, plain)
	if err != nil {
		return nil, err
	}
	if versioned && len(wire) > p.preparationMaximumBytes()+providerEnvelopeOverheadMaximumBytes {
		clear(wire)
		return nil, sso.ErrUnavailable
	}
	return wire, nil
}

func (p *ProviderContributor) preparationMaximumBytes() int {
	if p.enable != nil {
		// The proof envelope adds a second base64 field to the existing
		// metadata frame and must fit within the native preparation limit.
		return 112 << 10
	}
	if p.update != nil || p.disable != nil {
		return providerUpdatePreparationMaximumBytes
	}
	return providerLegacyPreparationMaximumBytes
}
func (p *ProviderContributor) RestoreFeaturePreparation(ctx context.Context, c identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	if p == nil || p.service == nil || ctx == nil || c != p.command || generation == 0 {
		return identity.Command{}, kernel.CommandPlan{}, sso.ErrInvalidInput
	}
	aad, err := p.outputContext(generation)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	plain, err := p.open(ctx, aad, wire, p.preparationMaximumBytes())
	defer clear(plain)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	var output providerPreparationOutput
	if json.Unmarshal(plain, &output) != nil || output.Generation != generation || output.Commitment != p.commitment || len(output.Configuration) == 0 || len(output.Configuration) > providerConfigurationEnvelopeMaximumBytes {
		return identity.Command{}, kernel.CommandPlan{}, sso.ErrUnavailable
	}
	if p.enable != nil {
		if len(output.EnableProof) == 0 || len(output.EnableProof) > providerEnableProofMaximumBytes {
			return identity.Command{}, kernel.CommandPlan{}, sso.ErrUnavailable
		}
		p.enable.sealedProof = output.EnableProof
	} else if len(output.EnableProof) != 0 {
		return identity.Command{}, kernel.CommandPlan{}, sso.ErrUnavailable
	}
	if p.disable != nil {
		clear(p.configuration)
	}
	p.configuration = output.Configuration
	p.generation = generation
	p.outputHash = sha256.Sum256(wire)
	plan, err := p.plan(true)
	return p.command, plan, err
}

func (p *ProviderContributor) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if err := w.RequireFeatureCommand(ctx, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.admit(ctx, w, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	wire, generation, err := w.FeaturePreparationOutput(p)
	defer clear(wire)
	if err != nil || generation != p.generation || p.outputHash == ([32]byte{}) || sha256.Sum256(wire) != p.outputHash {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	b, fingerprint, executionGeneration, err := w.FeatureCommandIdentity(p)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err = p.writeProvider(ctx, w, b); err != nil {
		return identity.FeatureReceipt{}, err
	}
	bound, err := json.Marshal(providerStoredBinding(b))
	if err != nil {
		return identity.FeatureReceipt{}, sso.ErrUnavailable
	}
	n, err := w.Exec(ctx, `INSERT INTO sso_providers.command_effects(command_id,tenant_id,organization_id,provider_id,binding,fingerprint,generation) VALUES($1,$2,$3,$4,$5,$6,$7::numeric)`, string(b.CommandID), string(b.TenantID), p.request.OrganizationID, b.RecordID, bound, fingerprint[:], strconv.FormatUint(executionGeneration, 10))
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n != 1 {
		return identity.FeatureReceipt{}, sso.ErrUnavailable
	}
	if p.enable != nil {
		n, err = w.Exec(ctx, insertProviderEnableReceiptSQL, string(b.CommandID), strconv.FormatUint(p.enable.predecessor.mappingVersion, 10))
		if err != nil || n != 1 {
			return identity.FeatureReceipt{}, sso.ErrUnavailable
		}
	}
	if p.disable != nil {
		if _, err = recordProviderLoginDisposition(ctx, w, p.request.OrganizationID, p.beforeVersion(), string(p.disable.selection.Mode)); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	return identity.FeatureReceipt{Operation: p.operation(), BeforeVersion: p.beforeVersion(), AfterVersion: p.afterVersion()}, nil
}

func (p *ProviderContributor) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	b, feature, life, err := w.FeatureScope(p)
	if err != nil || feature != (kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: p.operation()}) || life != p.lifecycle() {
		return kernel.RecoveryUnknown, sso.ErrUnavailable
	}
	if p.disable != nil {
		return p.recoverDisable(ctx, w, b)
	}
	rows, err := w.Query(ctx, `SELECT binding,organization_id,provider_id FROM sso_providers.command_effects WHERE command_id=$1 AND tenant_id=$2`, string(b.CommandID), string(b.TenantID))
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err = rows.Err(); err != nil {
			return kernel.RecoveryUnknown, err
		}
		return kernel.RecoveryNotCommitted, nil
	}
	var binding []byte
	var organizationID, providerID string
	if err = rows.Scan(&binding, &organizationID, &providerID); err != nil {
		return kernel.RecoveryUnknown, err
	}
	want, _ := json.Marshal(providerStoredBinding(b))
	if rows.Next() || rows.Err() != nil || !bytes.Equal(binding, want) || organizationID != p.request.OrganizationID || providerID != b.RecordID {
		return kernel.RecoveryUnknown, sso.ErrUnavailable
	}
	return kernel.RecoveryCommitted, nil
}
