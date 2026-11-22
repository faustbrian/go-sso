package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	organization "github.com/faustbrian/go-organization"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
)

// StaticOIDCLoginProfile pins one trusted deployment's native login selection.
// It supplies no authentication authority or caller-selectable scope grant.
// Construction snapshots Scopes; all versions must select the current enabled
// provider, credential generation and mapping exactly.
type StaticOIDCLoginProfile struct {
	ProviderID           sso.ProviderID
	OrganizationID       organization.ID
	Domain               string
	ClientID             string
	ProtocolRedirectURI  string
	ProviderVersion      uint64
	CredentialGeneration uint64
	MappingVersion       uint64
	Scopes               []string
}

type providerLoginProfile struct {
	configured                    StaticOIDCLoginProfile
	issuer, authorizationEndpoint string
	protocol                      string
	oauthConfiguration            providerOAuthConfiguration
}

func normalizeStaticOIDCLoginProfile(p StaticOIDCLoginProfile) (StaticOIDCLoginProfile, error) {
	domain, err := organization.CanonicalDomain(p.Domain)
	if err != nil || domain != p.Domain || !providerID(string(p.ProviderID)) || !providerID(string(p.OrganizationID)) || p.ProviderVersion == 0 || p.CredentialGeneration == 0 || p.MappingVersion == 0 {
		return StaticOIDCLoginProfile{}, sso.ErrInvalidInput
	}
	if !providerLoginVisible(p.ClientID, 1024) || !providerLoginVisible(p.ProtocolRedirectURI, 2048) || strings.ContainsAny(p.ProtocolRedirectURI, "\\#* ") {
		return StaticOIDCLoginProfile{}, sso.ErrInvalidInput
	}
	redirect, err := url.Parse(p.ProtocolRedirectURI)
	if err != nil || redirect.Scheme != "https" || redirect.Hostname() == "" || redirect.User != nil || redirect.Opaque != "" || redirect.RawQuery != "" || redirect.ForceQuery || redirect.Fragment != "" || redirect.String() != p.ProtocolRedirectURI {
		return StaticOIDCLoginProfile{}, sso.ErrInvalidInput
	}
	// Match the selected identity/oauth authorization-code profile: RFC 6749
	// scope tokens, at most 32 tokens of 128 bytes, and explicit OIDC selection.
	if len(p.Scopes) == 0 || len(p.Scopes) > 32 || !slices.Contains(p.Scopes, "openid") {
		return StaticOIDCLoginProfile{}, sso.ErrInvalidInput
	}
	seen := make(map[string]struct{}, len(p.Scopes))
	for _, scope := range p.Scopes {
		if !providerLoginVisible(scope, 128) || strings.ContainsAny(scope, " \"\\") {
			return StaticOIDCLoginProfile{}, sso.ErrInvalidInput
		}
		if _, duplicate := seen[scope]; duplicate {
			return StaticOIDCLoginProfile{}, sso.ErrInvalidInput
		}
		seen[scope] = struct{}{}
	}
	p.Scopes = slices.Clone(p.Scopes)
	return p, nil
}

// Custody was authenticated by Route. This read selects only the exact current
// configuration and credential generation; it never fetches a client secret.
const providerLoginProfileSQL = `SELECT p.issuer_digest,COALESCE(p.metadata_configuration_envelope,p.configuration_envelope)
 FROM sso_providers.providers p JOIN sso_providers.credentials c USING(tenant_id,organization_id,provider_id)
 WHERE p.tenant_id=$1 AND p.organization_id=$2 AND p.provider_id=$3
 AND p.metadata_version=$4::numeric AND p.enabled
 AND p.enablement_credential_generation=$5::numeric AND c.generation=p.enablement_credential_generation
 AND c.provider_version BETWEEN 2 AND p.metadata_version
 AND COALESCE(p.metadata_mapping_version,p.mapping_version)=$6::numeric AND p.pending_domains=1
 AND octet_length(COALESCE(p.metadata_configuration_envelope,p.configuration_envelope)) BETWEEN 1 AND 65536`

func (r *ProviderRouter) readProviderLoginProfile(ctx context.Context, route sso.DomainRoute, configured StaticOIDCLoginProfile) (providerLoginProfile, error) {
	if r == nil || r.pool == nil || r.config.Envelope == nil || r.config.Clock == nil || ctx == nil {
		return providerLoginProfile{}, sso.ErrInvalidInput
	}
	configured, err := normalizeStaticOIDCLoginProfile(configured)
	if err != nil {
		return providerLoginProfile{}, err
	}
	binding, err := route.Bindings()
	if err != nil {
		return providerLoginProfile{}, sso.ErrInvalidInput
	}
	proof := binding.Proof.Key
	now := r.config.Clock.Now()
	if binding.ProviderID != configured.ProviderID || proof.OrganizationID != configured.OrganizationID || proof.Domain != configured.Domain || binding.ProviderVersion != configured.ProviderVersion || binding.CredentialGeneration != configured.CredentialGeneration || now.Before(binding.ObservedAt) || !now.Before(binding.ValidUntil) {
		return providerLoginProfile{}, sso.ErrForbidden
	}
	ctx, cancel := context.WithTimeout(ctx, r.config.MaximumDuration)
	defer cancel()
	version := strconv.FormatUint(configured.ProviderVersion, 10)
	var issuerDigest, wire []byte
	if err := r.pool.Raw().QueryRow(ctx, providerLoginProfileSQL, string(proof.TenantID), string(configured.OrganizationID), string(configured.ProviderID), version, strconv.FormatUint(configured.CredentialGeneration, 10), strconv.FormatUint(configured.MappingVersion, 10)).Scan(&issuerDigest, &wire); err != nil {
		return providerLoginProfile{}, providerError(ctx, err)
	}
	if len(issuerDigest) != sha256.Size || len(wire) == 0 || len(wire) > providerConfigurationEnvelopeMaximumBytes {
		return providerLoginProfile{}, sso.ErrUnavailable
	}
	aad, err := envelope.NewContext(map[string]string{"owner": "sso/provider", "tenant": string(proof.TenantID), "organization": string(configured.OrganizationID), "provider": string(configured.ProviderID), "protocol": "oidc", "purpose": "static-configuration", "version": version})
	if err != nil {
		return providerLoginProfile{}, sso.ErrUnavailable
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return providerLoginProfile{}, sso.ErrUnavailable
	}
	plain, err := r.config.Envelope.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	defer clear(plain)
	if err != nil || len(plain) == 0 || len(plain) > providerConfigurationMaximumBytes {
		return providerLoginProfile{}, providerError(ctx, sso.ErrUnavailable)
	}
	var stored providerConfiguration
	if json.Unmarshal(plain, &stored) != nil {
		return providerLoginProfile{}, sso.ErrUnavailable
	}
	canonical, err := json.Marshal(stored)
	defer clear(canonical)
	if err != nil || !bytes.Equal(canonical, plain) || stored.Mapping.Version != configured.MappingVersion || len(stored.Domains) != 1 || stored.Domains[0] != configured.Domain {
		return providerLoginProfile{}, sso.ErrUnavailable
	}
	if _, err := sso.NewAttributeMapping(stored.Mapping); err != nil {
		return providerLoginProfile{}, sso.ErrUnavailable
	}
	if _, err := sso.NewOIDCStaticMetadata(stored.Metadata); err != nil {
		return providerLoginProfile{}, sso.ErrUnavailable
	}
	expectedIssuer := sha256.Sum256([]byte(stored.Metadata.Issuer))
	if !bytes.Equal(issuerDigest, expectedIssuer[:]) {
		return providerLoginProfile{}, sso.ErrUnavailable
	}
	if _, _, err := providerLoginAuthorizationEndpoint(stored.Metadata.AuthorizationEndpoint); err != nil {
		return providerLoginProfile{}, sso.ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return providerLoginProfile{}, err
	}
	if !r.config.Clock.Now().Before(binding.ValidUntil) {
		return providerLoginProfile{}, sso.ErrForbidden
	}
	return providerLoginProfile{configured: configured, issuer: stored.Metadata.Issuer, authorizationEndpoint: stored.Metadata.AuthorizationEndpoint}, nil
}

func (p providerLoginProfile) authorizationRedirect(state providerLoginPublicState) (url.URL, error) {
	if p.protocol == providerProtocolOAuth2 {
		return (providerOAuth2LoginProfile{configured: StaticOAuth2LoginProfile(p.configured), issuer: p.issuer,
			authorizationEndpoint: p.authorizationEndpoint}).authorizationRedirect(state)
	}
	configured, err := normalizeStaticOIDCLoginProfile(p.configured)
	if err != nil {
		return url.URL{}, err
	}
	for _, value := range []string{state.State, state.Nonce, state.Challenge} {
		if len(value) != 43 {
			return url.URL{}, sso.ErrInvalidInput
		}
		raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
		if err != nil || len(raw) != 32 {
			return url.URL{}, sso.ErrInvalidInput
		}
	}
	redirect, query, err := providerLoginAuthorizationEndpoint(p.authorizationEndpoint)
	if err != nil {
		return url.URL{}, err
	}
	query.Set("response_type", "code")
	query.Set("response_mode", "query")
	query.Set("client_id", configured.ClientID)
	query.Set("redirect_uri", configured.ProtocolRedirectURI)
	query.Set("scope", strings.Join(configured.Scopes, " "))
	query.Set("state", state.State)
	query.Set("nonce", state.Nonce)
	query.Set("code_challenge", state.Challenge)
	query.Set("code_challenge_method", "S256")
	redirect.RawQuery = query.Encode()
	// Native login's transport projection is bounded independently of the
	// stored endpoint/profile limits because query escaping expands their bytes.
	if len(redirect.String()) > 8192 {
		return url.URL{}, sso.ErrInvalidInput
	}
	return *redirect, nil
}

func providerLoginAuthorizationEndpoint(raw string) (*url.URL, url.Values, error) {
	if len(raw) == 0 || len(raw) > 4096 || !utf8.ValidString(raw) || strings.ContainsAny(raw, "\r\n\t #\\") {
		return nil, nil, sso.ErrInvalidInput
	}
	endpoint, err := url.Parse(raw)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil || endpoint.Opaque != "" || endpoint.Fragment != "" {
		return nil, nil, sso.ErrInvalidInput
	}
	query, err := url.ParseQuery(endpoint.RawQuery)
	if err != nil {
		return nil, nil, sso.ErrInvalidInput
	}
	for name, values := range query {
		if len(values) != 1 {
			return nil, nil, sso.ErrInvalidInput
		}
		// A configured request object or protocol parameter must not substitute
		// another authorization request for the selected query/code/S256 profile.
		switch strings.ToLower(name) {
		case "response_type", "response_mode", "client_id", "client_secret", "redirect_uri", "scope", "state", "nonce", "code_challenge", "code_challenge_method", "request", "request_uri", "claims", "prompt", "login_hint", "issuer", "iss", "max_age", "id_token_hint", "acr_values", "resource", "audience", "authorization_details", "dpop_jkt":
			return nil, nil, sso.ErrInvalidInput
		}
	}
	return endpoint, query, nil
}

func providerLoginVisible(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum {
		return false
	}
	for i := range len(value) {
		if value[i] < 0x20 || value[i] > 0x7e {
			return false
		}
	}
	return true
}
