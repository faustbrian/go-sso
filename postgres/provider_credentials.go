package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
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
	credentialRequestBindingMaximumBytes = 4096
	credentialPreparationMaximumBytes    = 128 << 10
	// Envelope v2 permits provider-owned wrapped keys up to 64KiB. Keep wire
	// overhead independent of the plaintext bounds, using that format's complete
	// framing/key/nonce/tag allowance rather than a legacy 4KiB-key assumption.
	credentialEnvelopeOverheadMaximumBytes = envelope.MaxEnvelopeSize - envelope.MaxPlaintextSize
)

func credentialsOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "sso", OperationID: "identity.sso.provider.credentials-rotate", SchemaID: "sso-disabled-static-oidc-credentials-rotate-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// ProviderCredentialsContributor is the invocation-local native credentials
// participant. Only ProviderCredentialsService composes it; zero is unusable.
// It owns no transaction or journal and is never shared across invocations.
type ProviderCredentialsContributor struct {
	service                            *ProviderCredentialsService
	request                            sso.ProviderCredentialsRotateRequest
	admission                          providerAdmission
	intent                             identity.RequestIntent
	binding                            identity.CommandBinding
	command                            identity.Command
	counter                            kernel.CommandCounterPlan
	registry                           *kernel.ContributorRegistry
	coordinator                        *kernel.Coordinator
	metadata, credentialWire           []byte
	mappingVersion, previousGeneration uint64
	commitment, outputHash             [32]byte
	generation                         uint64
	failure                            error
}

var _ kernel.FeaturePreparationContributor = (*ProviderCredentialsContributor)(nil)
var _ kernel.RequestKeyRecoveryContributor = (*ProviderCredentialsContributor)(nil)
var _ kernel.FeatureCommitContributor = (*ProviderCredentialsContributor)(nil)

func (*ProviderCredentialsContributor) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "sso/postgres", ContractID: "identity.sso.provider-credentials", Version: 1}
}
func (*ProviderCredentialsContributor) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{credentialsOperation()}
}
func (ProviderCredentialsContributor) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("sso.postgres.ProviderCredentialsContributor(redacted)"))
}
func (ProviderCredentialsContributor) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}
func (ProviderCredentialsContributor) MarshalText() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}

func (p *ProviderCredentialsContributor) compose() error {
	s := p.service.base
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
	p.coordinator, err = kernel.NewCoordinatorWithRequestKeys(s.pool, p.registry, s.config.Coordinator, s.config.RequestKeys)
	return providerError(nil, err)
}

func (p *ProviderCredentialsContributor) lifecycle() kernel.LifecyclePlan {
	return kernel.LifecyclePlan{EventType: "sso.provider_credentials_rotated.v1", BeforeVersion: p.request.ExpectedVersion, AfterVersion: p.request.ExpectedVersion + 1}
}

func (p *ProviderCredentialsContributor) requestContext(b kernel.RequestKeyPreparationBinding) (envelope.Context, error) {
	if p == nil || p.service == nil || b.Namespace != p.service.base.config.RequestKeys.Namespace || b.Scope.RouteID != credentialsOperation().OperationID || b.Scope.Method != "POST" || b.Feature != (kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: credentialsOperation()}) || b.PolicyVersion != p.service.base.config.PolicyVersion || b.Admission.CommandID == "" || b.IntentDigest == ([32]byte{}) {
		return envelope.Context{}, sso.ErrInvalidInput
	}
	frame, err := json.Marshal(struct {
		Namespace                            string
		Scope                                kernel.RequestKeyScope
		Admission                            kernel.RequestKeyAdmission
		Feature                              kernel.FeatureRegistration
		Policy                               uint64
		Intent                               [32]byte
		PolicyID, Organization, IngressKeyID string
		MaximumLifetime                      time.Duration
	}{b.Namespace, b.Scope, b.Admission, b.Feature, b.PolicyVersion, b.IntentDigest, p.service.base.config.PolicyID, p.service.base.updateOrganization, p.service.profile.IngressKeyID, p.service.profile.MaximumReferenceLifetime})
	if err != nil {
		return envelope.Context{}, sso.ErrInvalidInput
	}
	digest := sha256.Sum256(frame)
	return envelope.NewContext(map[string]string{"owner": "sso/provider-credentials-request", "profile": "disabled-static-oidc-no-overlap-v1", "binding": hex.EncodeToString(digest[:])})
}

func (p *ProviderCredentialsContributor) codec() *ProviderContributor {
	return &ProviderContributor{service: p.service.base}
}

// sealCustody enforces the same explicit plaintext/wire profile as openCustody
// before immutable native request/preparation custody can be persisted.
func (p *ProviderCredentialsContributor) sealCustody(ctx context.Context, aad envelope.Context, plain []byte, maximum int) ([]byte, error) {
	if len(plain) == 0 || len(plain) > maximum {
		return nil, sso.ErrUnavailable
	}
	sealed, err := p.service.base.config.Envelope.Encrypt(ctx, envelope.EncryptRequest{Plaintext: plain, KeyReference: p.service.base.config.KeyReference, Context: aad})
	if err != nil {
		return nil, providerError(ctx, err)
	}
	wire, err := sealed.MarshalBinary()
	if err != nil || len(wire) == 0 || len(wire) > maximum+credentialEnvelopeOverheadMaximumBytes {
		clear(wire)
		return nil, sso.ErrUnavailable
	}
	return wire, nil
}

// openCustody bounds the full supported envelope before parsing/allocation,
// then authenticates and independently bounds its plaintext. The registration
// codec remains unchanged and cannot define this credentials profile's limit.
func (p *ProviderCredentialsContributor) openCustody(ctx context.Context, aad envelope.Context, wire []byte, maximum int) ([]byte, error) {
	if len(wire) == 0 || len(wire) > maximum+credentialEnvelopeOverheadMaximumBytes {
		return nil, sso.ErrUnavailable
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return nil, sso.ErrUnavailable
	}
	plain, err := p.service.base.config.Envelope.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	if err != nil || len(plain) == 0 || len(plain) > maximum {
		clear(plain)
		return nil, providerError(ctx, sso.ErrUnavailable)
	}
	return plain, nil
}

func (p *ProviderCredentialsContributor) PrepareRequestKey(ctx context.Context, b kernel.RequestKeyPreparationBinding, intent identity.RequestIntent) ([]byte, error) {
	if p == nil || p.service == nil || ctx == nil {
		return nil, sso.ErrInvalidInput
	}
	expected, _ := p.intent.Fields()
	actual, valid := intent.Fields()
	if !valid || !reflect.DeepEqual(expected, actual) {
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
	plain, err := json.Marshal(providerStoredBinding(p.binding))
	if err != nil {
		return nil, sso.ErrInvalidInput
	}
	defer clear(plain)
	return p.sealCustody(ctx, aad, plain, credentialRequestBindingMaximumBytes)
}

func (p *ProviderCredentialsContributor) prepare(ctx context.Context, b kernel.RequestKeyPreparationBinding) error {
	s := p.service.base
	bound, err := p.admission.session.Session.Bindings()
	if err != nil || b.Scope.TenantID != bound.TenantID || b.Scope.ActorID != identity.ActorID(bound.UserID) || b.Scope.ActorKind != authorization.SubjectUser {
		return sso.ErrForbidden
	}
	// The public factory's service is not native authority: authenticate again
	// using only this configured owner, exact immutable ingress key/profile and
	// original primary-time window before any native command is admitted.
	native := p.request.CredentialReference
	binding := native.Context()
	if binding.Protocol != providerProtocolSAML {
		native, err = sso.NewEncryptedCredentialReference(ctx, s.config.Envelope, p.credentialWire, binding)
		if err != nil {
			return providerError(ctx, err)
		}
	}
	if native.ValidateAt(p.admission.verified) != nil || native.ValidateAt(s.config.Clock.Now()) != nil {
		return sso.ErrForbidden
	}
	if native.Context().ExpiresAt.Before(p.admission.until) {
		p.admission.until = native.Context().ExpiresAt
	}
	if err = p.loadConfiguration(ctx); err != nil {
		return err
	}
	if binding.Protocol == providerProtocolSAML {
		contextWire, err := json.Marshal(binding)
		if err != nil {
			return sso.ErrInvalidInput
		}
		// Check the admitted, exact provider before borrowing its credential.
		// The same bound marks the absolute deadline for protected Work.
		until, err := s.validateSAMLSigningExpiry(ctx, binding.TenantID, binding.OrganizationID, binding.ProviderID,
			p.credentialWire, contextWire, binding.Generation, binding.ProviderVersion+1, p.admission.verified)
		if err != nil {
			return providerError(ctx, err)
		}
		if until.Before(p.admission.until) {
			p.admission.until = until
		}
	}
	op := credentialsOperation()
	p.binding = identity.CommandBinding{CommandID: b.Admission.CommandID, TenantID: bound.TenantID, UserID: bound.UserID, ActorID: identity.ActorID(bound.UserID), ActorKind: authorization.SubjectUser, OperationID: op.OperationID, RecordID: p.request.ProviderID, SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, PolicyID: s.config.PolicyID, PolicyVersion: s.config.PolicyVersion, CorrelationID: string(p.request.CommandID)}
	if p.binding.ValidateFor(op) != nil {
		return sso.ErrInvalidInput
	}
	metadataHash, credentialHash := sha256.Sum256(p.metadata), sha256.Sum256(p.credentialWire)
	frame, err := json.Marshal(struct {
		Binding              providerStoredBinding
		Metadata, Credential [32]byte
		Context              sso.CredentialReferenceContext
		Organization         string
		Admission            providerCredentialsAdmissionFrame
		Network              string
	}{providerStoredBinding(p.binding), metadataHash, credentialHash, native.Context(), s.updateOrganization, credentialsAdmissionFrame(p.admission), s.network})
	if err != nil {
		return sso.ErrInvalidInput
	}
	p.commitment = sha256.Sum256(frame)
	fields, err := sessionpg.OriginalSessionFields(p.admission.session.Session)
	if err != nil {
		return sso.ErrForbidden
	}
	fields = append(fields, identity.FeatureField{Name: "provider.intent", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: p.commitment[:]}})
	command, err := identity.NewFeatureSessionCommand(identity.FeatureCommandSpec{Binding: p.binding, Operation: op, Fields: fields}, s.authentication.Bearer)
	if err != nil {
		return sso.ErrInvalidInput
	}
	p.command, p.counter, err = s.config.Counters.PrepareCommandCounters(command, risk.Subject{Actor: string(bound.UserID), Resource: p.binding.RecordID, Network: s.network}, p.admission.verified)
	return providerError(ctx, err)
}

// Preserve the same existing native admission commitment used by provider
// metadata, without serializing a session bearer or inventing policy authority.
type providerCredentialsAdmissionFrame struct {
	Status                   identity.UserStatusRecord
	Organization             organization.CredentialAuthorityObservation
	Started, Verified, Until time.Time
}

func credentialsAdmissionFrame(a providerAdmission) providerCredentialsAdmissionFrame {
	return providerCredentialsAdmissionFrame{a.status, a.organization, a.started, a.verified, a.until}
}

func (p *ProviderCredentialsContributor) loadConfiguration(ctx context.Context) error {
	s := p.service.base
	var versionText, mappingText, generationText string
	var ciphertext []byte
	var pending int32
	var enabled bool
	err := s.pool.Raw().QueryRow(ctx, `SELECT p.metadata_version::text,COALESCE(p.metadata_mapping_version,p.mapping_version)::text,COALESCE(p.metadata_configuration_envelope,p.configuration_envelope),p.pending_domains,p.enabled,COALESCE(c.generation,0)::text FROM sso_providers.providers p LEFT JOIN sso_providers.credentials c USING(tenant_id,organization_id,provider_id) WHERE p.tenant_id=$1 AND p.organization_id=$2 AND p.provider_id=$3`, string(s.authentication.TenantID), s.updateOrganization, p.request.ProviderID).Scan(&versionText, &mappingText, &ciphertext, &pending, &enabled, &generationText)
	if err != nil {
		return providerError(ctx, err)
	}
	version, err := strconv.ParseUint(versionText, 10, 64)
	if err != nil || version == 0 {
		return sso.ErrUnavailable
	}
	if version != p.request.ExpectedVersion {
		return sso.ErrConflict
	}
	if enabled {
		return sso.ErrInvalidInput
	}
	p.previousGeneration, err = strconv.ParseUint(generationText, 10, 64)
	if err != nil || p.previousGeneration == math.MaxUint64 {
		return sso.ErrUnavailable
	}
	if p.request.CredentialReference.Context().Generation != p.previousGeneration+1 {
		return sso.ErrConflict
	}
	p.mappingVersion, err = strconv.ParseUint(mappingText, 10, 64)
	if err != nil || p.mappingVersion == 0 {
		return sso.ErrUnavailable
	}
	// The independent encrypted metadata authenticates the selected protocol;
	// a reference minted for the same IDs cannot reclassify an existing row.
	aad, err := p.configurationContext(versionText)
	if err != nil {
		return sso.ErrUnavailable
	}
	p.metadata, err = p.codec().openUpdateConfiguration(ctx, aad, ciphertext)
	if err != nil {
		return err
	}
	if pending < 1 || pending > 128 {
		return sso.ErrUnavailable
	}
	protocol := p.request.CredentialReference.Context().Protocol
	if protocol == providerProtocolSAML {
		_, err = s.readProviderSAMLConfiguration(p.metadata, p.mappingVersion, int(pending))
		return err
	}
	_, err = readProviderConfigurationDomains(protocol, p.metadata, p.mappingVersion, int(pending))
	return err
}

func (p *ProviderCredentialsContributor) configurationContext(version string) (envelope.Context, error) {
	s := p.service.base
	return envelope.NewContext(map[string]string{
		"owner": "sso/provider", "tenant": string(s.authentication.TenantID),
		"organization": s.updateOrganization, "provider": p.request.ProviderID,
		"protocol": p.request.CredentialReference.Context().Protocol,
		"purpose":  "static-configuration", "version": version,
	})
}

// readProviderConfigurationDomains checks the authenticated metadata against
// the selected protocol and its row projections without re-encoding it for use.
func readProviderConfigurationDomains(protocol string, plain []byte, version uint64, pending int) ([]string, error) {
	var domains []string
	var decoded any
	switch protocol {
	case providerProtocolOIDC:
		var current providerConfiguration
		if json.Unmarshal(plain, &current) != nil || current.Mapping.Version != version || len(current.Domains) != pending {
			return nil, sso.ErrUnavailable
		}
		domains, decoded = current.Domains, current
	case providerProtocolOAuth2:
		var current providerOAuthConfiguration
		if json.Unmarshal(plain, &current) != nil || current.Mapping.Version != version || len(current.Domains) != pending {
			return nil, sso.ErrUnavailable
		}
		domains, decoded = current.Domains, current
	case providerProtocolSAML:
		var current providerSAMLConfiguration
		if json.Unmarshal(plain, &current) != nil || current.Mapping.Version != version || len(current.Domains) != pending {
			return nil, sso.ErrUnavailable
		}
		domains, decoded = current.Domains, current
	default:
		return nil, sso.ErrUnavailable
	}
	canonical, err := json.Marshal(decoded)
	defer clear(canonical)
	if err != nil || !bytes.Equal(canonical, plain) {
		return nil, sso.ErrUnavailable
	}
	return domains, nil
}

func (p *ProviderCredentialsContributor) RestoreRequestKey(ctx context.Context, b kernel.RequestKeyPreparationBinding, wire []byte) (identity.CommandBinding, error) {
	aad, err := p.requestContext(b)
	if err != nil {
		return identity.CommandBinding{}, err
	}
	plain, err := p.openCustody(ctx, aad, wire, credentialRequestBindingMaximumBytes)
	defer clear(plain)
	if err != nil {
		return identity.CommandBinding{}, err
	}
	var saved providerStoredBinding
	if json.Unmarshal(plain, &saved) != nil {
		return identity.CommandBinding{}, sso.ErrUnavailable
	}
	canonical, _ := json.Marshal(saved)
	original := identity.CommandBinding(saved)
	if !bytes.Equal(canonical, plain) || original.ValidateFor(credentialsOperation()) != nil || original.CommandID != b.Admission.CommandID || original.TenantID != b.Scope.TenantID || original.UserID != identity.UserID(b.Scope.ActorID) || original.ActorID != b.Scope.ActorID || original.ActorKind != authorization.SubjectUser || original.RecordID != p.request.ProviderID || original.PolicyID != p.service.base.config.PolicyID || original.PolicyVersion != b.PolicyVersion || original.CorrelationID != string(p.request.CommandID) {
		return identity.CommandBinding{}, sso.ErrUnavailable
	}
	return original, nil
}

func (p *ProviderCredentialsContributor) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if p == nil || p.service == nil || p.command != c || p.binding.ValidateFor(credentialsOperation()) != nil || plan.Feature == nil || *plan.Feature != (kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: credentialsOperation()}) || plan.SubjectType != "sso_provider" || plan.CommandCounters == nil || *plan.CommandCounters != p.counter || plan.Lifecycle == nil || *plan.Lifecycle != p.lifecycle() || len(plan.Audits) != 1 || plan.Audits[0].EventType != credentialsOperation().OperationID || !plan.Audits[0].Required || plan.Audits[0].RequiredRecordCount != 1 || plan.Audits[0].RetentionClass != "protected" || plan.Capability != nil || plan.CapabilityIssuance != nil || plan.OTP != nil || plan.Delivery != nil {
		return sso.ErrInvalidInput
	}
	spec, valid := c.Feature()
	if !valid || spec.Binding != p.binding || spec.Operation != credentialsOperation() {
		return sso.ErrInvalidInput
	}
	for _, field := range spec.Fields {
		if field.Name == "provider.intent" && field.Value.Kind == identity.FeatureBytes && bytes.Equal(field.Value.Bytes, p.commitment[:]) {
			return nil
		}
	}
	return sso.ErrInvalidInput
}
func (p *ProviderCredentialsContributor) ValidateFeaturePreparation(c identity.Command, plan kernel.CommandPlan) error {
	return p.ValidateFeatureCommand(c, plan)
}

func (p *ProviderCredentialsContributor) plan(final bool) (kernel.CommandPlan, error) {
	b := p.binding
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return kernel.CommandPlan{}, sso.ErrUnavailable
	}
	seed, err := builder.Build(audit.RecordInput{OccurredAt: p.admission.verified, Action: credentialsOperation().OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "sso_provider", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "sso_provider", "aggregate.id": b.RecordID, "aggregate.before_version": strconv.FormatUint(p.request.ExpectedVersion, 10), "aggregate.after_version": strconv.FormatUint(p.request.ExpectedVersion+1, 10), "retention.class": "protected"}})
	if err != nil {
		return kernel.CommandPlan{}, sso.ErrInvalidInput
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, credentialsOperation(), "sso_provider", seed)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	lifecycle := p.lifecycle()
	plan := kernel.CommandPlan{Contributors: p.registry.Descriptors(), Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: credentialsOperation()}, SubjectType: "sso_provider", Lifecycle: &lifecycle, CommandCounters: &p.counter, Audits: []kernel.AuditPlan{{EventType: credentialsOperation().OperationID, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}}
	if final {
		return p.coordinator.PrepareCommandPlan(b, p.command, plan)
	}
	return p.coordinator.PrepareFeaturePreparationPlan(p.command, plan)
}

func (p *ProviderCredentialsContributor) admit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if c != p.command {
		return identity.ForbiddenError{}
	}
	b, feature, _, err := w.FeatureScope(p)
	if err != nil || b != p.binding || feature != (kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: credentialsOperation()}) {
		return identity.ForbiddenError{}
	}
	a, config := p.admission, p.service.base.config
	spec, err := a.session.Session.Bindings()
	if err != nil {
		return identity.ForbiddenError{}
	}
	bearer, valid := c.SessionToken()
	if !valid {
		return identity.ForbiddenError{}
	}
	token, err := session.ParseToken(bearer.Token())
	if err != nil {
		return identity.ForbiddenError{}
	}
	key, valid := config.LookupKeys[spec.Lookup.KeyVersion]
	if !valid {
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
	lifetime, err := a.session.Session.Lifetime(at)
	if err != nil || !lifetime.Fresh || a.session.ValidateAt(at) != nil || at.Before(a.verified) || !at.Before(a.until) || p.request.CredentialReference.ValidateAt(at) != nil {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *ProviderCredentialsContributor) requireProvider(ctx context.Context, w kernel.Work, after bool) error {
	version, generation := p.request.ExpectedVersion, p.previousGeneration
	if after {
		version++
		generation++
	}
	rows, err := w.Query(ctx, `SELECT p.metadata_version::text,p.enabled,COALESCE(c.generation,0)::text FROM sso_providers.providers p LEFT JOIN sso_providers.credentials c USING(tenant_id,organization_id,provider_id) WHERE p.tenant_id=$1 AND p.organization_id=$2 AND p.provider_id=$3 FOR UPDATE OF p`, string(p.binding.TenantID), p.service.base.updateOrganization, p.binding.RecordID)
	if err != nil {
		return err
	}
	defer rows.Close()
	if !rows.Next() {
		return identity.ForbiddenError{}
	}
	var actualVersion, actualGeneration string
	var enabled bool
	if err = rows.Scan(&actualVersion, &enabled, &actualGeneration); err != nil {
		return err
	}
	if rows.Next() || rows.Err() != nil || enabled || actualVersion != strconv.FormatUint(version, 10) || actualGeneration != strconv.FormatUint(generation, 10) {
		return identity.ConflictError{}
	}
	return nil
}

func (p *ProviderCredentialsContributor) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, c identity.Command) error {
	if err := p.admit(ctx, w, c); err != nil {
		return err
	}
	return p.requireProvider(ctx, w, false)
}
func (p *ProviderCredentialsContributor) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if err := p.requireProvider(ctx, w, true); err != nil {
		return err
	}
	return p.admit(ctx, w, c)
}

func (p *ProviderCredentialsContributor) outputContext(generation uint64) (envelope.Context, error) {
	frame, err := json.Marshal(struct {
		Binding    providerStoredBinding
		Commitment [32]byte
		Generation uint64
	}{providerStoredBinding(p.binding), p.commitment, generation})
	if err != nil {
		return envelope.Context{}, sso.ErrInvalidInput
	}
	digest := sha256.Sum256(frame)
	return envelope.NewContext(map[string]string{"owner": "sso/provider-credentials-preparation", "binding": hex.EncodeToString(digest[:])})
}

func (p *ProviderCredentialsContributor) GenerateFeaturePreparation(ctx context.Context, c identity.Command, generation uint64) ([]byte, error) {
	if p == nil || p.service == nil || ctx == nil || c != p.command || generation == 0 || p.generation != 0 {
		return nil, sso.ErrInvalidInput
	}
	aad, err := p.configurationContext(strconv.FormatUint(p.request.ExpectedVersion+1, 10))
	if err != nil {
		return nil, err
	}
	metadata, err := p.codec().seal(ctx, aad, p.metadata)
	if err != nil || len(metadata) > providerConfigurationEnvelopeMaximumBytes {
		return nil, sso.ErrUnavailable
	}
	plain, err := json.Marshal(struct {
		Generation     uint64
		Commitment     [32]byte
		Metadata       []byte
		MappingVersion uint64
	}{generation, p.commitment, metadata, p.mappingVersion})
	defer clear(plain)
	if err != nil || len(plain) > credentialPreparationMaximumBytes {
		return nil, sso.ErrUnavailable
	}
	aad, err = p.outputContext(generation)
	if err != nil {
		return nil, err
	}
	return p.sealCustody(ctx, aad, plain, credentialPreparationMaximumBytes)
}

func (p *ProviderCredentialsContributor) RestoreFeaturePreparation(ctx context.Context, c identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	if p == nil || p.service == nil || ctx == nil || c != p.command || generation == 0 {
		return identity.Command{}, kernel.CommandPlan{}, sso.ErrInvalidInput
	}
	aad, err := p.outputContext(generation)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	plain, err := p.openCustody(ctx, aad, wire, credentialPreparationMaximumBytes)
	defer clear(plain)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	var output struct {
		Generation     uint64
		Commitment     [32]byte
		Metadata       []byte
		MappingVersion uint64
	}
	if json.Unmarshal(plain, &output) != nil || output.Generation != generation || output.Commitment != p.commitment || output.MappingVersion != p.mappingVersion || len(output.Metadata) == 0 || len(output.Metadata) > providerConfigurationEnvelopeMaximumBytes {
		return identity.Command{}, kernel.CommandPlan{}, sso.ErrUnavailable
	}
	clear(p.metadata)
	p.metadata = output.Metadata
	p.generation, p.outputHash = generation, sha256.Sum256(wire)
	plan, err := p.plan(true)
	return p.command, plan, err
}

func (p *ProviderCredentialsContributor) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if err := w.RequireFeatureCommand(ctx, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.admit(ctx, w, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.requireProvider(ctx, w, false); err != nil {
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
	s := p.service.base
	n, err := w.Exec(ctx, `UPDATE sso_providers.providers SET metadata_version=$4::numeric,metadata_configuration_envelope=$5,metadata_mapping_version=$6::numeric WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND metadata_version=$7::numeric AND NOT enabled`, string(b.TenantID), s.updateOrganization, b.RecordID, strconv.FormatUint(p.request.ExpectedVersion+1, 10), p.metadata, strconv.FormatUint(p.mappingVersion, 10), strconv.FormatUint(p.request.ExpectedVersion, 10))
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n != 1 {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	contextWire, err := json.Marshal(p.request.CredentialReference.Context())
	if err != nil {
		return identity.FeatureReceipt{}, sso.ErrUnavailable
	}
	credentialGeneration := p.request.CredentialReference.Context().Generation
	n, err = w.Exec(ctx, `INSERT INTO sso_providers.credentials(tenant_id,organization_id,provider_id,generation,provider_version,envelope,credential_context) VALUES($1,$2,$3,$4::numeric,$5::numeric,$6,$7) ON CONFLICT(tenant_id,organization_id,provider_id) DO UPDATE SET generation=EXCLUDED.generation,provider_version=EXCLUDED.provider_version,envelope=EXCLUDED.envelope,credential_context=EXCLUDED.credential_context WHERE sso_providers.credentials.generation=$8::numeric`, string(b.TenantID), s.updateOrganization, b.RecordID, strconv.FormatUint(credentialGeneration, 10), strconv.FormatUint(p.request.ExpectedVersion+1, 10), p.credentialWire, contextWire, strconv.FormatUint(p.previousGeneration, 10))
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n != 1 {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	bound, err := json.Marshal(providerStoredBinding(b))
	if err != nil {
		return identity.FeatureReceipt{}, sso.ErrUnavailable
	}
	n, err = w.Exec(ctx, `INSERT INTO sso_providers.credential_effects(command_id,tenant_id,organization_id,provider_id,binding,fingerprint,generation) VALUES($1,$2,$3,$4,$5,$6,$7::numeric)`, string(b.CommandID), string(b.TenantID), s.updateOrganization, b.RecordID, bound, fingerprint[:], strconv.FormatUint(executionGeneration, 10))
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n != 1 {
		return identity.FeatureReceipt{}, sso.ErrUnavailable
	}
	return identity.FeatureReceipt{Operation: credentialsOperation(), BeforeVersion: p.request.ExpectedVersion, AfterVersion: p.request.ExpectedVersion + 1}, nil
}

func (p *ProviderCredentialsContributor) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	b, feature, lifecycle, err := w.FeatureScope(p)
	if err != nil || feature != (kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: credentialsOperation()}) || lifecycle != p.lifecycle() {
		return kernel.RecoveryUnknown, sso.ErrUnavailable
	}
	rows, err := w.Query(ctx, `SELECT binding,organization_id,provider_id FROM sso_providers.credential_effects WHERE command_id=$1 AND tenant_id=$2`, string(b.CommandID), string(b.TenantID))
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
	if rows.Next() || rows.Err() != nil || !bytes.Equal(binding, want) || organizationID != p.service.base.updateOrganization || providerID != b.RecordID {
		return kernel.RecoveryUnknown, sso.ErrUnavailable
	}
	return kernel.RecoveryCommitted, nil
}
