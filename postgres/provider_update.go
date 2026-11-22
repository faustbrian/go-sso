package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"math"
	"strconv"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
)

// ForOrganization binds a detached service copy to an organization selector
// supplied by trusted composition/transport before ProviderUpdate. The selector
// grants no authority: every invocation observes current native owner/admin and
// org:sso-write policy, rechecks them in Work, and uses exact tenant/org/provider
// predicates. Empty or malformed selectors fail closed. The source is unchanged.
func (s *ProviderService) ForOrganization(organizationID string) (*ProviderService, error) {
	if s == nil || s.pool == nil || !providerID(organizationID) {
		return nil, sso.ErrInvalidInput
	}
	bound := *s
	bound.updateOrganization = organizationID
	return &bound, nil
}

func (p *ProviderContributor) operation() identity.FeatureOperation {
	if p.enable != nil {
		return identity.FeatureOperation{Owner: "sso", OperationID: "identity.sso.provider.enable", SchemaID: "sso-static-oidc-enable-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	}
	if p.update != nil {
		return identity.FeatureOperation{Owner: "sso", OperationID: "identity.sso.provider.update", SchemaID: "sso-disabled-static-oidc-update-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	}
	return providerOperation()
}
func (p *ProviderContributor) beforeVersion() uint64 {
	if p.enable != nil {
		return p.enable.request.ExpectedVersion
	}
	if p.update != nil {
		return p.update.ExpectedVersion
	}
	return 0
}
func (p *ProviderContributor) afterVersion() uint64 { return p.beforeVersion() + 1 }
func (p *ProviderContributor) lifecycle() kernel.LifecyclePlan {
	event := "sso.provider_registered.v1"
	if p.update != nil {
		event = "sso.provider_updated.v1"
	}
	if p.enable != nil {
		event = "sso.provider_enabled.v1"
	}
	return kernel.LifecyclePlan{EventType: event, BeforeVersion: p.beforeVersion(), AfterVersion: p.afterVersion()}
}

// ProviderUpdate atomically replaces only disabled static-OIDC metadata and
// compatible mapping through the existing native coordinator/key owners.
// The separately bound organization is mandatory. Matching keys recover only
// their original command and response; stale/new inputs never become retries.
func (s *ProviderService) ProviderUpdate(ctx context.Context, r sso.ProviderUpdateRequest) (sso.ProviderUpdateResult, error) {
	var out sso.ProviderUpdateResult
	_, commandErr := identity.ParseCommandID(string(r.CommandID))
	metadata, metadataErr := r.Configuration.StaticOIDC()
	mapping, mappingErr := r.Mapping.Spec()
	if s == nil || ctx == nil || !providerID(s.updateOrganization) || !providerID(r.ProviderID) || commandErr != nil || metadataErr != nil || mappingErr != nil || r.ExpectedVersion == 0 || r.ExpectedVersion == math.MaxUint64 {
		return out, sso.ErrInvalidInput
	}
	ctx, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	a, err := s.admitUpdate(ctx)
	if err != nil {
		return out, err
	}
	spec, _ := metadata.Spec()
	configuration, err := json.Marshal(providerConfiguration{Metadata: spec, Mapping: mapping})
	if err != nil || len(configuration) > providerConfigurationMaximumBytes {
		return out, sso.ErrInvalidInput
	}
	defer clear(configuration)
	digest := sha256.Sum256(configuration)
	intent, err := identity.NewRequestIntent([]identity.FeatureField{
		{Name: "organization", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: s.updateOrganization}},
		{Name: "provider", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: r.ProviderID}},
		{Name: "command", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(r.CommandID)}},
		{Name: "expected-version", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: strconv.FormatUint(r.ExpectedVersion, 10)}},
		{Name: "configuration", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest[:]}},
		{Name: "policy-id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: s.config.PolicyID}},
	})
	if err != nil {
		return out, sso.ErrInvalidInput
	}
	p := &ProviderContributor{service: s, update: &r, request: sso.ProviderRegisterOidcRequest{CommandID: r.CommandID, OrganizationID: s.updateOrganization, Issuer: spec.Issuer, Mapping: r.Mapping, IdempotencyKey: r.IdempotencyKey}, admission: a, intent: intent, configuration: configuration}
	if err = s.composeProvider(p); err != nil {
		return out, err
	}
	bound, _ := a.session.Session.Bindings()
	op := p.operation()
	scope := kernel.RequestKeyScope{TenantID: s.authentication.TenantID, ActorID: identity.ActorID(bound.UserID), ActorKind: authorization.SubjectUser, Method: "POST", RouteID: op.OperationID}
	caller := s.kernelDecision(bound.UserID, "identity.request-admission", op.OperationID)
	caller.Request.Action = authorization.Action(op.OperationID)
	registration := kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: op}
	binding, wire, err := p.coordinator.ResolvePreparedRequestKey(ctx, scope, r.IdempotencyKey, intent, caller, registration, p)
	defer clear(wire)
	if err != nil {
		if p.failure != nil {
			return out, providerError(ctx, p.failure)
		}
		return out, providerError(ctx, err)
	}
	original, err := p.RestoreRequestKey(ctx, binding, wire)
	if err != nil {
		return out, providerError(ctx, err)
	}
	if p.binding != original {
		query := s.kernelDecision(bound.UserID, "identity.user", string(bound.UserID))
		query.Request.Action = authorization.Action(op.OperationID)
		out.Completion, err = p.coordinator.RecoverPreparedFeatureCommand(ctx, providerRecovery(original), query, registration, p)
	} else {
		var plan kernel.CommandPlan
		plan, err = p.plan(false)
		if err == nil {
			out.Completion, err = p.coordinator.ExecutePreparedFeature(ctx, p.command, plan)
		}
	}
	if out.Completion.Outcome == identity.CommitOutcomeCommitted {
		if _, admissionErr := s.admitUpdate(ctx); admissionErr != nil {
			return out, admissionErr
		}
		out.Provider = sso.Provider{ID: original.RecordID, OrganizationID: s.updateOrganization, Protocol: "oidc", Version: r.ExpectedVersion + 1, MappingVersion: mapping.Version, VerifiedDomains: []string{}}
	}
	return out, providerError(ctx, err)
}

func (p *ProviderContributor) prepareUpdate(ctx context.Context) error {
	r := p.update
	var ciphertext []byte
	var versionText, mappingText string
	var pending int32
	var enabled bool
	err := p.service.pool.Raw().QueryRow(ctx, `SELECT metadata_version::text,COALESCE(metadata_mapping_version,mapping_version)::text,COALESCE(metadata_configuration_envelope,configuration_envelope),pending_domains,enabled FROM sso_providers.providers WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`, string(p.service.authentication.TenantID), p.request.OrganizationID, r.ProviderID).Scan(&versionText, &mappingText, &ciphertext, &pending, &enabled)
	if err != nil {
		return providerError(ctx, err)
	}
	version, err := strconv.ParseUint(versionText, 10, 64)
	if err != nil || version == 0 {
		return sso.ErrUnavailable
	}
	if version != r.ExpectedVersion {
		return sso.ErrConflict
	}
	if enabled {
		return sso.ErrInvalidInput
	}
	aad, err := envelope.NewContext(map[string]string{"owner": "sso/provider", "tenant": string(p.service.authentication.TenantID), "organization": p.request.OrganizationID, "provider": r.ProviderID, "protocol": "oidc", "purpose": "static-configuration", "version": versionText})
	if err != nil {
		return sso.ErrUnavailable
	}
	plain, err := p.openUpdateConfiguration(ctx, aad, ciphertext)
	defer clear(plain)
	if err != nil {
		return err
	}
	var old providerConfiguration
	if json.Unmarshal(plain, &old) != nil {
		return sso.ErrUnavailable
	}
	canonical, _ := json.Marshal(old)
	defer clear(canonical)
	if !bytes.Equal(canonical, plain) || old.Mapping.Version == 0 || strconv.FormatUint(old.Mapping.Version, 10) != mappingText || len(old.Domains) != int(pending) || pending < 1 || pending > 128 {
		return sso.ErrUnavailable
	}
	metadata, _ := r.Configuration.StaticOIDC()
	nextMetadata, _ := metadata.Spec()
	nextMapping, _ := r.Mapping.Spec()
	if old.Metadata.Issuer != nextMetadata.Issuer || old.Mapping.SubjectClaim != nextMapping.SubjectClaim || old.Mapping.Version == math.MaxUint64 || nextMapping.Version != old.Mapping.Version+1 {
		return sso.ErrInvalidInput
	}
	p.configuration, err = json.Marshal(providerConfiguration{Metadata: nextMetadata, Mapping: nextMapping, Domains: old.Domains})
	if err != nil || len(p.configuration) > providerConfigurationMaximumBytes {
		clear(p.configuration)
		return sso.ErrInvalidInput
	}
	return nil
}

func (p *ProviderContributor) openUpdateConfiguration(ctx context.Context, aad envelope.Context, wire []byte) ([]byte, error) {
	// Envelope v2's opaque wrapped data key can exceed 4KiB. The stored
	// configuration therefore has independent schema wire and plaintext bounds;
	// request-key and legacy preparation readers keep their existing limits.
	if len(wire) == 0 || len(wire) > providerConfigurationEnvelopeMaximumBytes {
		return nil, sso.ErrUnavailable
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return nil, sso.ErrUnavailable
	}
	plain, err := p.service.config.Envelope.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	if err != nil || len(plain) > providerConfigurationMaximumBytes {
		clear(plain)
		return nil, sso.ErrUnavailable
	}
	return plain, nil
}

func (p *ProviderContributor) writeProvider(ctx context.Context, w kernel.Work, b identity.CommandBinding) error {
	if p.enable != nil {
		return p.writeEnable(ctx, w, b)
	}
	mapping, _ := p.request.Mapping.Spec()
	var n int64
	var err error
	if p.update == nil {
		issuer := sha256.Sum256([]byte(p.request.Issuer))
		n, err = w.Exec(ctx, `INSERT INTO sso_providers.providers(tenant_id,organization_id,provider_id,issuer_digest,configuration_envelope,mapping_version,pending_domains) VALUES($1,$2,$3,$4,$5,$6::numeric,$7) ON CONFLICT DO NOTHING`, string(b.TenantID), p.request.OrganizationID, b.RecordID, issuer[:], p.configuration, strconv.FormatUint(mapping.Version, 10), int32(len(p.request.Domains)))
	} else {
		n, err = w.Exec(ctx, `UPDATE sso_providers.providers SET metadata_version=$4::numeric,metadata_configuration_envelope=$5,metadata_mapping_version=$6::numeric WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND metadata_version=$7::numeric AND NOT enabled`, string(b.TenantID), p.request.OrganizationID, b.RecordID, strconv.FormatUint(p.afterVersion(), 10), p.configuration, strconv.FormatUint(mapping.Version, 10), strconv.FormatUint(p.beforeVersion(), 10))
	}
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}
