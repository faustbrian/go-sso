package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"strconv"

	organization "github.com/faustbrian/go-organization"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
)

// StaticSAMLLoginProfile pins one trusted deployment's SP-initiated selection.
// TrustedOrigin is the exact HTTPS origin used at registration; the native owner
// derives the provider's ACS and metadata entity paths from it. Versions select
// the current enabled provider, installed signer generation and mapping exactly.
// This profile grants no routing, transaction or authentication authority and
// contains no OAuth client, scope or PKCE configuration.
type StaticSAMLLoginProfile struct {
	ProviderID           sso.ProviderID
	OrganizationID       organization.ID
	Domain               string
	TrustedOrigin        string
	ProviderVersion      uint64
	CredentialGeneration uint64
	MappingVersion       uint64
}

type providerSAMLLoginProfile struct {
	configured    StaticSAMLLoginProfile
	configuration sso.SAMLConfigurationSpec
	mapping       sso.AttributeMappingSpec
	spEntityID    string
	acsURL        string
}

func normalizeStaticSAMLLoginProfile(p StaticSAMLLoginProfile) (StaticSAMLLoginProfile, error) {
	domain, err := organization.CanonicalDomain(p.Domain)
	if err != nil || domain != p.Domain || !providerID(string(p.ProviderID)) || !providerID(string(p.OrganizationID)) ||
		p.ProviderVersion == 0 || p.CredentialGeneration == 0 || p.MappingVersion == 0 {
		return StaticSAMLLoginProfile{}, sso.ErrInvalidInput
	}
	if _, ok := samlProviderCallbackURL(p.TrustedOrigin, string(p.ProviderID)); !ok {
		return StaticSAMLLoginProfile{}, sso.ErrInvalidInput
	}
	return p, nil
}

// RouteSAML authenticated the exact installed signer and domain proof. This
// metadata-only projection neither borrows the private signer nor renews that
// route's original deadline; transaction admission remains a separate owner.
const providerSAMLLoginProfileSQL = providerLoginProfileSQL + ` AND p.protocol='saml'`

func (r *ProviderRouter) readProviderSAMLLoginProfile(ctx context.Context, route sso.DomainRoute, configured StaticSAMLLoginProfile) (providerSAMLLoginProfile, error) {
	if r == nil || r.pool == nil || r.config.Envelope == nil || r.config.Clock == nil || ctx == nil {
		return providerSAMLLoginProfile{}, sso.ErrInvalidInput
	}
	configured, err := normalizeStaticSAMLLoginProfile(configured)
	if err != nil {
		return providerSAMLLoginProfile{}, err
	}
	binding, err := route.Bindings()
	if err != nil {
		return providerSAMLLoginProfile{}, sso.ErrInvalidInput
	}
	if !r.protocolRegistry || r.samlRouteValidate == nil || route.Protocol() != providerProtocolSAML {
		return providerSAMLLoginProfile{}, sso.ErrForbidden
	}
	proof := binding.Proof.Key
	now := r.config.Clock.Now()
	if binding.ProviderID != configured.ProviderID || proof.OrganizationID != configured.OrganizationID || proof.Domain != configured.Domain ||
		binding.ProviderVersion != configured.ProviderVersion || binding.CredentialGeneration != configured.CredentialGeneration ||
		now.Before(binding.ObservedAt) || !now.Before(binding.ValidUntil) {
		return providerSAMLLoginProfile{}, sso.ErrForbidden
	}
	ctx, cancel := context.WithTimeout(ctx, r.config.MaximumDuration)
	defer cancel()
	version := strconv.FormatUint(configured.ProviderVersion, 10)
	var issuerDigest, wire []byte
	if err := r.pool.Raw().QueryRow(ctx, providerSAMLLoginProfileSQL, string(proof.TenantID), string(configured.OrganizationID), string(configured.ProviderID),
		version, strconv.FormatUint(configured.CredentialGeneration, 10), strconv.FormatUint(configured.MappingVersion, 10)).Scan(&issuerDigest, &wire); err != nil {
		return providerSAMLLoginProfile{}, providerError(ctx, err)
	}
	if len(issuerDigest) != sha256.Size || len(wire) == 0 || len(wire) > providerConfigurationEnvelopeMaximumBytes {
		return providerSAMLLoginProfile{}, sso.ErrUnavailable
	}
	aad, err := envelope.NewContext(map[string]string{"owner": "sso/provider", "tenant": string(proof.TenantID),
		"organization": string(configured.OrganizationID), "provider": string(configured.ProviderID),
		"protocol": providerProtocolSAML, "purpose": "static-configuration", "version": version})
	if err != nil {
		return providerSAMLLoginProfile{}, sso.ErrUnavailable
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return providerSAMLLoginProfile{}, sso.ErrUnavailable
	}
	plain, err := r.config.Envelope.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	defer clear(plain)
	if err != nil {
		return providerSAMLLoginProfile{}, providerError(ctx, sso.ErrUnavailable)
	}
	profile, err := decodeProviderSAMLLoginProfile(plain, issuerDigest, configured)
	if err != nil {
		return providerSAMLLoginProfile{}, err
	}
	if err := ctx.Err(); err != nil {
		return providerSAMLLoginProfile{}, err
	}
	if !r.config.Clock.Now().Before(binding.ValidUntil) {
		return providerSAMLLoginProfile{}, sso.ErrForbidden
	}
	return profile, nil
}

func decodeProviderSAMLLoginProfile(plain, issuerDigest []byte, configured StaticSAMLLoginProfile) (providerSAMLLoginProfile, error) {
	if len(plain) == 0 || len(plain) > providerConfigurationMaximumBytes || len(issuerDigest) != sha256.Size {
		return providerSAMLLoginProfile{}, sso.ErrUnavailable
	}
	domains, err := readProviderConfigurationDomains(providerProtocolSAML, plain, configured.MappingVersion, 1)
	if err != nil || domains[0] != configured.Domain {
		return providerSAMLLoginProfile{}, sso.ErrUnavailable
	}
	var stored providerSAMLConfiguration
	if json.Unmarshal(plain, &stored) != nil {
		return providerSAMLLoginProfile{}, sso.ErrUnavailable
	}
	if stored.Origin != configured.TrustedOrigin {
		return providerSAMLLoginProfile{}, sso.ErrForbidden
	}
	if _, err := sso.NewAttributeMapping(stored.Mapping); err != nil {
		return providerSAMLLoginProfile{}, sso.ErrUnavailable
	}
	// Reuse the root registration shape contract; DER/signature policy belongs
	// to the optional SAML adapter, not a second implementation in persistence.
	if _, err := sso.NewSAMLConfiguration(stored.IdP); err != nil {
		return providerSAMLLoginProfile{}, sso.ErrUnavailable
	}
	expectedIssuer := sha256.Sum256([]byte(stored.IdP.EntityID))
	if !bytes.Equal(issuerDigest, expectedIssuer[:]) {
		return providerSAMLLoginProfile{}, sso.ErrUnavailable
	}
	acsURL, ok := samlProviderCallbackURL(configured.TrustedOrigin, string(configured.ProviderID))
	if !ok {
		return providerSAMLLoginProfile{}, sso.ErrUnavailable
	}
	return providerSAMLLoginProfile{configured: configured, configuration: stored.IdP, mapping: stored.Mapping,
		spEntityID: configured.TrustedOrigin + "/saml2/" + string(configured.ProviderID) + "/metadata", acsURL: acsURL}, nil
}
