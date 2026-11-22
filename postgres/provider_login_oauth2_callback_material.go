package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"time"

	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
)

// The caller owns clearing these ciphertext slices. Reading this projection
// grants no authority to decrypt credentials, borrow a verifier or exchange a
// code; those effects require the original callback reservation.
type providerOAuth2CallbackMaterial struct {
	configuration     providerOAuthConfiguration
	credential        []byte
	credentialContext []byte
	credentialVersion uint64
	verifier          []byte
}

func (providerOAuth2CallbackMaterial) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.providerOAuth2CallbackMaterial(redacted)")
}

// The selected linked-signin OAuth profile permits only the current enabled
// installation, not OIDC's disabled-provider drain. Read all ciphertext against
// the exact original pending row in one primary statement.
const providerOAuth2CallbackMaterialSQL = `WITH exact_login AS MATERIALIZED (
 SELECT organization_id,provider_id,provider_version,credential_generation,mapping_version,
 start_command_id,callback_command_id,protocol,pkce_key_version,pkce_commitment,issued_at,expires_at,completed_at,verifier_envelope
 FROM sso_providers.login_transactions
 WHERE tenant_id=$1 AND state_key_version=$9 AND state_digest=$10
 ), installed
 (version,mapping,configuration,pending,enabled,generation,credential_version,credential,credential_context) AS (` + providerEnablePredecessorSQL + `
 AND p.protocol='oauth2' AND p.pending_domains=1 AND p.enabled
 AND p.metadata_version=$4::numeric AND p.enablement_credential_generation=$5::numeric
 AND c.generation=$5::numeric AND COALESCE(p.metadata_mapping_version,p.mapping_version)=$6::numeric
 AND c.provider_version BETWEEN 2 AND $4::numeric AND p.issuer_digest=$16
 AND octet_length(COALESCE(p.metadata_configuration_envelope,p.configuration_envelope)) BETWEEN 1 AND 65536
 AND octet_length(c.envelope) BETWEEN 1 AND 32768 AND octet_length(c.credential_context) BETWEEN 1 AND 4096
 )
 SELECT i.*,l.verifier_envelope FROM installed i CROSS JOIN exact_login l
 WHERE l.organization_id=$2 AND l.provider_id=$3
 AND l.provider_version=$4::numeric AND l.credential_generation=$5::numeric AND l.mapping_version=$6::numeric
 AND l.start_command_id=$7 AND l.callback_command_id=$8 AND l.protocol='oauth2'
 AND l.pkce_key_version=$11 AND l.pkce_commitment=$12
 AND l.issued_at=$13::timestamptz AND l.expires_at=$14::timestamptz AND l.completed_at IS NULL
 AND octet_length(l.verifier_envelope) BETWEEN 1 AND 4096
 AND clock_timestamp()>=$13::timestamptz AND clock_timestamp()<LEAST($14::timestamptz,$15::timestamptz)`

func (s *ProviderLoginService) readProviderOAuth2CallbackMaterial(ctx context.Context, found providerLoginCallbackLookup, original providerLoginStartInput, authority providerLoginCallbackAuthority) (material providerOAuth2CallbackMaterial, err error) {
	if s == nil || ctx == nil || s.router == nil || s.router.pool == nil || s.router.pool.Raw() == nil || s.router.config.Clock == nil || s.router.config.Envelope == nil || !s.router.protocolRegistry {
		return providerOAuth2CallbackMaterial{}, sso.ErrForbidden
	}
	if err := ctx.Err(); err != nil {
		return providerOAuth2CallbackMaterial{}, err
	}
	now := s.router.config.Clock.Now()
	if found.Row.TenantID != s.config.TenantID || original.RoutePolicy != s.router.config.PolicyVersion || !validProviderOAuth2CallbackMaterialInput(found, original, authority, now) {
		return providerOAuth2CallbackMaterial{}, sso.ErrForbidden
	}
	ctx, cancel := context.WithTimeout(ctx, min(s.config.Coordinator.MaximumDuration, authority.deadline.Sub(now)))
	defer cancel()

	var stored providerEnableStored
	var verifier []byte
	defer func() {
		clear(stored.configuration)
		if err != nil {
			clear(stored.credential)
			clear(stored.credentialContext)
			clear(verifier)
			material = providerOAuth2CallbackMaterial{}
		}
	}()
	err = s.router.pool.Raw().QueryRow(ctx, providerOAuth2CallbackMaterialSQL, providerLoginCallbackMaterialArgs(found, original, authority)...).
		Scan(&stored.version, &stored.mapping, &stored.configuration, &stored.pending, &stored.enabled,
			&stored.generation, &stored.credentialVersion, &stored.credential, &stored.credentialContext, &verifier)
	if err != nil {
		return providerOAuth2CallbackMaterial{}, providerError(ctx, err)
	}
	if !stored.enabled || stored.pending != 1 || stored.version != strconv.FormatUint(original.ProviderVersion, 10) || stored.mapping != strconv.FormatUint(original.MappingVersion, 10) || stored.generation != strconv.FormatUint(original.Generation, 10) || len(verifier) == 0 || len(verifier) > 4096 {
		return providerOAuth2CallbackMaterial{}, sso.ErrForbidden
	}
	installed, err := strconv.ParseUint(stored.credentialVersion, 10, 64)
	if err != nil {
		return providerOAuth2CallbackMaterial{}, sso.ErrUnavailable
	}
	if err := validateProviderOAuth2CallbackCredential(original, installed, stored.credential, stored.credentialContext); err != nil {
		return providerOAuth2CallbackMaterial{}, err
	}
	configuration, err := openProviderOAuth2CallbackConfiguration(ctx, s.router.config.Envelope, original, stored.version, stored.configuration)
	if err != nil {
		return providerOAuth2CallbackMaterial{}, err
	}
	if err := ctx.Err(); err != nil {
		return providerOAuth2CallbackMaterial{}, err
	}
	if !validProviderOAuth2CallbackMaterialInput(found, original, authority, s.router.config.Clock.Now()) {
		return providerOAuth2CallbackMaterial{}, sso.ErrForbidden
	}
	return providerOAuth2CallbackMaterial{configuration: configuration, credential: stored.credential, credentialContext: stored.credentialContext, credentialVersion: installed, verifier: verifier}, nil
}

func validProviderOAuth2CallbackMaterialInput(found providerLoginCallbackLookup, original providerLoginStartInput, authority providerLoginCallbackAuthority, now time.Time) bool {
	if original.Protocol != providerProtocolOAuth2 || found.Row.Protocol != providerProtocolOAuth2 || found.Binding.Metadata.Input.Protocol != providerProtocolOAuth2 || original.Link != nil || found.Binding.Metadata.Input.Link != nil {
		return false
	}
	return validProviderLoginCallbackMaterialInput(found, original, authority, now)
}

func validateProviderOAuth2CallbackCredential(original providerLoginStartInput, installed uint64, wire, contextWire []byte) error {
	if original.Protocol != providerProtocolOAuth2 || installed < 2 || installed > original.ProviderVersion || len(wire) == 0 || len(wire) > 32768 || len(contextWire) == 0 || len(contextWire) > 4096 {
		return sso.ErrUnavailable
	}
	var binding sso.CredentialReferenceContext
	if json.Unmarshal(contextWire, &binding) != nil || binding.Protocol != providerProtocolOAuth2 || binding.TenantID != string(original.Proof.TenantID) || binding.OrganizationID != string(original.Proof.OrganizationID) || binding.ProviderID != string(original.ProviderID) || binding.Generation != original.Generation || binding.ProviderVersion != installed-1 {
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

func openProviderOAuth2CallbackConfiguration(ctx context.Context, crypto *envelope.Service, original providerLoginStartInput, storedVersion string, wire []byte) (providerOAuthConfiguration, error) {
	if ctx == nil || crypto == nil || original.Protocol != providerProtocolOAuth2 || storedVersion != strconv.FormatUint(original.ProviderVersion, 10) || len(wire) == 0 || len(wire) > providerConfigurationEnvelopeMaximumBytes {
		return providerOAuthConfiguration{}, sso.ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return providerOAuthConfiguration{}, err
	}
	aad, err := envelope.NewContext(map[string]string{"owner": "sso/provider", "tenant": string(original.Proof.TenantID), "organization": string(original.Proof.OrganizationID), "provider": string(original.ProviderID), "protocol": providerProtocolOAuth2, "purpose": "static-configuration", "version": storedVersion})
	if err != nil {
		return providerOAuthConfiguration{}, sso.ErrUnavailable
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return providerOAuthConfiguration{}, sso.ErrUnavailable
	}
	plain, err := crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	defer clear(plain)
	if err != nil || len(plain) == 0 || len(plain) > providerConfigurationMaximumBytes {
		return providerOAuthConfiguration{}, providerError(ctx, sso.ErrUnavailable)
	}
	var stored providerOAuthConfiguration
	if json.Unmarshal(plain, &stored) != nil {
		return providerOAuthConfiguration{}, sso.ErrUnavailable
	}
	canonical, err := json.Marshal(stored)
	defer clear(canonical)
	if err != nil || !bytes.Equal(canonical, plain) || len(stored.Domains) != 1 || stored.Domains[0] != original.Proof.Domain || stored.Mapping.Version != original.MappingVersion || stored.Proof.Issuer != original.Issuer || stored.AuthorizationEndpoint != original.AuthorizationEndpoint {
		return providerOAuthConfiguration{}, sso.ErrForbidden
	}
	if err := validateProviderOAuth2LoginConfiguration(stored); err != nil {
		return providerOAuthConfiguration{}, err
	}
	if err := ctx.Err(); err != nil {
		return providerOAuthConfiguration{}, err
	}
	return stored, nil
}
