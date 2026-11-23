package postgres

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-sso"
)

const providerSAMLInsertSQL = `INSERT INTO sso_providers.providers(tenant_id,organization_id,provider_id,issuer_digest,configuration_envelope,mapping_version,pending_domains,protocol) VALUES($1,$2,$3,$4,$5,$6::numeric,$7,'saml') ON CONFLICT DO NOTHING`

func providerSAMLRegistrationOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "sso", OperationID: "identity.sso.provider.register-saml", SchemaID: "sso-disabled-static-saml-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// WithSAMLRegistration returns an opt-in copy using a deployment-owned HTTPS
// origin and the selected SAML module's local validator. Apply both SAML
// protocol migrations and upgrade all registry users
// to protocol-aware readers and writers before registering actual SAML rows.
// This never changes the original service, enables a provider or installs a
// route. Org administrators cannot supply the SP entity or callback origin.
func (s *ProviderService) WithSAMLRegistration(trustedOrigin string, validate sso.SAMLRegistrationValidator) (*ProviderService, error) {
	if s == nil || s.pool == nil || validate == nil || !validSAMLProviderOrigin(trustedOrigin) {
		return nil, sso.ErrInvalidInput
	}
	selected := *s
	selected.samlOrigin = strings.Clone(trustedOrigin)
	selected.samlValidator = validate
	return &selected, nil
}

func validSAMLProviderOrigin(raw string) bool {
	// Leave room in the selected SAML profile's 1024-byte SP entity for the
	// generated provider ID and the metadata route.
	if len(raw) > 512 || strings.ContainsAny(raw, "\\#%") {
		return false
	}
	parsed, err := url.Parse(raw)
	return err == nil && parsed.Scheme == "https" && parsed.Hostname() != "" && parsed.Host == strings.ToLower(parsed.Host) &&
		parsed.User == nil && parsed.Opaque == "" && parsed.Path == "" && parsed.RawQuery == "" && !parsed.ForceQuery && parsed.String() == raw
}

type providerSAMLConfiguration struct {
	IdP     sso.SAMLConfigurationSpec
	Origin  string
	Mapping sso.AttributeMappingSpec
	Domains []string
}

// ProviderRegisterSaml validates explicit pinned IdP configuration through the
// selected native SAML profile and registers only disabled metadata. It uses
// the ordinary org:sso-write and keyed coordinator, including audit/outbox and
// original-intent recovery. No metadata fetch, egress, proof or login occurs.
func (s *ProviderService) ProviderRegisterSaml(ctx context.Context, r sso.ProviderRegisterSamlRequest) (sso.ProviderRegisterSamlResult, error) {
	if s == nil || ctx == nil || r.Validate() != nil {
		return sso.ProviderRegisterSamlResult{}, sso.ErrInvalidInput
	}
	if s.samlOrigin == "" || s.samlValidator == nil {
		return sso.ProviderRegisterSamlResult{}, sso.ErrForbidden
	}
	spec, _ := r.Configuration.Spec()
	mapping, _ := r.Mapping.Spec()
	request := providerCommandInput{CommandID: r.CommandID, OrganizationID: r.OrganizationID,
		Issuer: spec.EntityID, Domains: r.Domains, Mapping: r.Mapping, protocol: providerProtocolSAML}
	result, err := s.registerDisabledProvider(ctx, request, r.IdempotencyKey, func(ctx context.Context) ([]byte, error) {
		validation, _ := r.Configuration.Spec()
		if err := s.samlValidator(ctx, validation.EntityID, validation.RedirectEndpoint, validation.SigningCertificates); err != nil {
			return nil, err
		}
		return json.Marshal(providerSAMLConfiguration{IdP: spec, Origin: s.samlOrigin, Mapping: mapping, Domains: r.Domains})
	})
	return sso.ProviderRegisterSamlResult(result), err
}
