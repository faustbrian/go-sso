package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"time"

	organization "github.com/faustbrian/go-organization"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
)

// This is encrypted custody, not permission to decrypt or exchange. The caller
// owns clearing all three slices and may borrow their plaintext only after the
// native coordinator has acknowledged this callback's original reservation.
type providerLoginCallbackMaterial struct {
	metadata          sso.OIDCStaticMetadataSpec
	mapping           sso.AttributeMappingSpec
	enabled           bool
	credential        []byte
	credentialContext []byte
	credentialVersion uint64
	verifier          []byte
}

func (providerLoginCallbackMaterial) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.providerLoginCallbackMaterial(redacted)")
}

// Reuse the installed-custody projection, but select its exact pending login in
// the same statement. No current route or caller-supplied issuer participates.
// A drain changes the metadata envelope AAD to the immediate successor version;
// it must not change the original login's mapping or installed credential.
const providerLoginCallbackMaterialSQL = `WITH installed
 (version,mapping,configuration,pending,enabled,generation,credential_version,credential,credential_context) AS (` + providerEnablePredecessorSQL + `
 AND p.pending_domains=1 AND c.generation=$5::numeric
 AND COALESCE(p.metadata_mapping_version,p.mapping_version)=$6::numeric
 AND c.provider_version BETWEEN 2 AND $4::numeric AND p.issuer_digest=$16
 AND ((p.enabled AND p.metadata_version=$4::numeric AND p.enablement_credential_generation=$5::numeric)
  OR (NOT p.enabled AND p.metadata_version=$4::numeric+1))
 AND octet_length(COALESCE(p.metadata_configuration_envelope,p.configuration_envelope)) BETWEEN 1 AND 65536
 AND octet_length(c.envelope) BETWEEN 1 AND 32768 AND octet_length(c.credential_context) BETWEEN 1 AND 4096
 )
 SELECT i.*,l.verifier_envelope FROM installed i
 JOIN sso_providers.login_transactions l ON l.tenant_id=$1 AND l.organization_id=$2 AND l.provider_id=$3
 WHERE l.provider_version=$4::numeric AND l.credential_generation=$5::numeric AND l.mapping_version=$6::numeric
 AND l.start_command_id=$7 AND l.callback_command_id=$8 AND l.protocol='oidc'
 AND l.state_key_version=$9 AND l.state_digest=$10 AND l.pkce_key_version=$11 AND l.pkce_commitment=$12
 AND l.issued_at=$13::timestamptz AND l.expires_at=$14::timestamptz AND l.completed_at IS NULL
 AND octet_length(l.verifier_envelope) BETWEEN 1 AND 4096
 AND clock_timestamp()>=$13::timestamptz AND clock_timestamp()<LEAST($14::timestamptz,$15::timestamptz)`

func providerLoginCallbackMaterialArgs(found providerLoginCallbackLookup, original providerLoginStartInput, authority providerLoginCallbackAuthority) []any {
	row, metadata := found.Row, found.Binding.Metadata
	issuer := sha256.Sum256([]byte(original.Issuer))
	return []any{string(row.TenantID), row.OrganizationID, row.ProviderID,
		strconv.FormatUint(row.ProviderVersion, 10), strconv.FormatUint(row.CredentialGeneration, 10), strconv.FormatUint(row.MappingVersion, 10),
		string(row.StartCommandID), string(metadata.CallbackCommand), int64(metadata.StateKey), metadata.StateDigest[:],
		int64(metadata.PKCEKey), metadata.PKCECommitment[:], row.IssuedAt, row.ExpiresAt, authority.deadline, issuer[:]}
}

func (s *ProviderLoginService) readProviderLoginCallbackMaterial(ctx context.Context, found providerLoginCallbackLookup, original providerLoginStartInput, authority providerLoginCallbackAuthority) (material providerLoginCallbackMaterial, err error) {
	if s == nil || ctx == nil || s.router == nil || s.router.pool == nil || s.router.pool.Raw() == nil || s.router.config.Clock == nil || s.router.config.Envelope == nil {
		return providerLoginCallbackMaterial{}, sso.ErrForbidden
	}
	if err := ctx.Err(); err != nil {
		return providerLoginCallbackMaterial{}, err
	}
	now := s.router.config.Clock.Now()
	if found.Row.TenantID != s.config.TenantID || original.RoutePolicy != s.router.config.PolicyVersion || !validProviderLoginCallbackMaterialInput(found, original, authority, now) {
		return providerLoginCallbackMaterial{}, sso.ErrForbidden
	}
	duration := min(s.config.Coordinator.MaximumDuration, authority.deadline.Sub(now))
	ctx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()

	var stored providerEnableStored
	var verifier []byte
	defer func() {
		clear(stored.configuration)
		if err != nil {
			clear(stored.credential)
			clear(stored.credentialContext)
			clear(verifier)
			material = providerLoginCallbackMaterial{}
		}
	}()
	err = s.router.pool.Raw().QueryRow(ctx, providerLoginCallbackMaterialSQL, providerLoginCallbackMaterialArgs(found, original, authority)...).
		Scan(&stored.version, &stored.mapping, &stored.configuration, &stored.pending, &stored.enabled,
			&stored.generation, &stored.credentialVersion, &stored.credential, &stored.credentialContext, &verifier)
	if err != nil {
		return providerLoginCallbackMaterial{}, providerError(ctx, err)
	}
	if !stored.enabled {
		var command string
		var binding []byte
		err = s.router.pool.Raw().QueryRow(ctx, providerLoginCallbackDrainSQL,
			string(found.Row.TenantID), found.Row.OrganizationID, found.Row.ProviderID, strconv.FormatUint(found.Row.ProviderVersion, 10), authority.deadline).
			Scan(&command, &binding)
		defer clear(binding)
		if err != nil {
			return providerLoginCallbackMaterial{}, providerError(ctx, err)
		}
		if !validProviderLoginCallbackDisableBinding(found.Row, command, binding) {
			return providerLoginCallbackMaterial{}, sso.ErrForbidden
		}
	}
	installed, err := strconv.ParseUint(stored.credentialVersion, 10, 64)
	if err != nil || installed < 2 || installed > original.ProviderVersion {
		return providerLoginCallbackMaterial{}, sso.ErrUnavailable
	}
	if err := validateProviderLoginCallbackCredential(original, installed, stored.credential, stored.credentialContext); err != nil {
		return providerLoginCallbackMaterial{}, err
	}
	configuration, err := openProviderLoginCallbackConfiguration(ctx, s.router.config.Envelope, original, stored.version, stored.configuration)
	if err != nil {
		return providerLoginCallbackMaterial{}, err
	}
	if err := ctx.Err(); err != nil {
		return providerLoginCallbackMaterial{}, err
	}
	if !validProviderLoginCallbackMaterialInput(found, original, authority, s.router.config.Clock.Now()) {
		return providerLoginCallbackMaterial{}, sso.ErrForbidden
	}
	return providerLoginCallbackMaterial{metadata: configuration.Metadata, mapping: configuration.Mapping, enabled: stored.enabled,
		credential: stored.credential, credentialContext: stored.credentialContext, credentialVersion: installed, verifier: verifier}, nil
}

func validProviderLoginCallbackMaterialInput(found providerLoginCallbackLookup, original providerLoginStartInput, authority providerLoginCallbackAuthority, now time.Time) bool {
	input := found.Binding.Metadata.Input
	if input.validate() != nil || found.CompletedAt != nil || found.Row != input.rowIdentity() || found.ObservedAt.IsZero() ||
		found.ObservedAt.Before(found.Row.IssuedAt) || now.Before(found.ObservedAt) || !now.Before(authority.deadline) {
		return false
	}
	if !equalProviderLoginPayloadInput(original.payload(), input) || original.Proof.TenantID != found.Row.TenantID || original.Proof.Domain == "" || original.AuthorizationEndpoint == "" {
		return false
	}
	if authority.deadline.After(found.ObservedAt.Add(20*time.Second)) || authority.deadline.After(original.Expires) || authority.deadline.After(original.Proof.ExpiresAt) || authority.deadline.After(authority.organization.ValidUntil) {
		return false
	}
	query := organization.CredentialAuthorityQuery{TenantID: original.Proof.TenantID, OrganizationID: original.Proof.OrganizationID}
	return authority.organization.Validate(query, now) == nil
}

func validateProviderLoginCallbackCredential(original providerLoginStartInput, installed uint64, wire, contextWire []byte) error {
	if installed < 2 || len(wire) == 0 || len(wire) > 32768 || len(contextWire) == 0 || len(contextWire) > 4096 {
		return sso.ErrUnavailable
	}
	var binding sso.CredentialReferenceContext
	if json.Unmarshal(contextWire, &binding) != nil || binding.TenantID != string(original.Proof.TenantID) || binding.OrganizationID != string(original.Proof.OrganizationID) || binding.ProviderID != string(original.ProviderID) || binding.Generation != original.Generation || binding.ProviderVersion != installed-1 {
		return sso.ErrUnavailable
	}
	canonical, err := json.Marshal(binding)
	defer clear(canonical)
	if err != nil || !bytes.Equal(canonical, contextWire) {
		return sso.ErrUnavailable
	}
	if _, err := binding.EncryptionContext(); err != nil {
		return sso.ErrUnavailable
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil || sealed.KeyReference() != binding.EnvelopeKeyID {
		return sso.ErrForbidden
	}
	return nil
}

func openProviderLoginCallbackConfiguration(ctx context.Context, crypto *envelope.Service, original providerLoginStartInput, storedVersion string, wire []byte) (providerConfiguration, error) {
	if ctx == nil || crypto == nil || len(wire) == 0 || len(wire) > providerConfigurationEnvelopeMaximumBytes {
		return providerConfiguration{}, sso.ErrUnavailable
	}
	aad, err := envelope.NewContext(map[string]string{"owner": "sso/provider", "tenant": string(original.Proof.TenantID), "organization": string(original.Proof.OrganizationID), "provider": string(original.ProviderID), "protocol": "oidc", "purpose": "static-configuration", "version": storedVersion})
	if err != nil {
		return providerConfiguration{}, sso.ErrUnavailable
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return providerConfiguration{}, sso.ErrUnavailable
	}
	plain, err := crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	defer clear(plain)
	if err != nil || len(plain) == 0 || len(plain) > providerConfigurationMaximumBytes {
		return providerConfiguration{}, providerError(ctx, sso.ErrUnavailable)
	}
	var stored providerConfiguration
	if json.Unmarshal(plain, &stored) != nil {
		return providerConfiguration{}, sso.ErrUnavailable
	}
	canonical, err := json.Marshal(stored)
	defer clear(canonical)
	if err != nil || !bytes.Equal(canonical, plain) || len(stored.Domains) != 1 || stored.Domains[0] != original.Proof.Domain || stored.Mapping.Version != original.MappingVersion || stored.Metadata.Issuer != original.Issuer || stored.Metadata.AuthorizationEndpoint != original.AuthorizationEndpoint {
		return providerConfiguration{}, sso.ErrForbidden
	}
	if _, err := sso.NewAttributeMapping(stored.Mapping); err != nil {
		return providerConfiguration{}, sso.ErrUnavailable
	}
	if _, err := sso.NewOIDCStaticMetadata(stored.Metadata); err != nil {
		return providerConfiguration{}, sso.ErrUnavailable
	}
	if _, _, err := providerLoginAuthorizationEndpoint(stored.Metadata.AuthorizationEndpoint); err != nil {
		return providerConfiguration{}, sso.ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return providerConfiguration{}, err
	}
	return stored, nil
}
