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

	organization "github.com/faustbrian/go-organization"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
)

// StaticOAuth2LoginProfile pins one trusted deployment's native OAuth login
// selection. It has the same fields as StaticOIDCLoginProfile but cannot select
// the openid scope or confer authentication authority. Normalization snapshots
// Scopes without adding, removing or reordering the selected OAuth scope tokens.
// Versions must select the current enabled provider, credential and mapping.
type StaticOAuth2LoginProfile StaticOIDCLoginProfile

type providerOAuth2LoginProfile struct {
	configured                    StaticOAuth2LoginProfile
	issuer, authorizationEndpoint string
}

func normalizeStaticOAuth2LoginProfile(p StaticOAuth2LoginProfile) (StaticOAuth2LoginProfile, error) {
	domain, err := organization.CanonicalDomain(p.Domain)
	if err != nil || domain != p.Domain || !providerID(string(p.ProviderID)) || !providerID(string(p.OrganizationID)) || p.ProviderVersion == 0 || p.CredentialGeneration == 0 || p.MappingVersion == 0 {
		return StaticOAuth2LoginProfile{}, sso.ErrInvalidInput
	}
	if !providerLoginVisible(p.ClientID, 1024) || !providerLoginVisible(p.ProtocolRedirectURI, 2048) || strings.ContainsAny(p.ProtocolRedirectURI, "\\#* ") {
		return StaticOAuth2LoginProfile{}, sso.ErrInvalidInput
	}
	redirect, err := url.Parse(p.ProtocolRedirectURI)
	if err != nil || redirect.Scheme != "https" || redirect.Hostname() == "" || redirect.User != nil || redirect.Opaque != "" || redirect.RawQuery != "" || redirect.ForceQuery || redirect.Fragment != "" || redirect.String() != p.ProtocolRedirectURI {
		return StaticOAuth2LoginProfile{}, sso.ErrInvalidInput
	}
	// Match the selected identity/oauth authorization-code scope bounds, while
	// forbidding the OIDC selection token rather than silently dropping it.
	if len(p.Scopes) == 0 || len(p.Scopes) > 32 || slices.Contains(p.Scopes, "openid") {
		return StaticOAuth2LoginProfile{}, sso.ErrInvalidInput
	}
	seen := make(map[string]struct{}, len(p.Scopes))
	for _, scope := range p.Scopes {
		if !providerLoginVisible(scope, 128) || strings.ContainsAny(scope, " \"\\") {
			return StaticOAuth2LoginProfile{}, sso.ErrInvalidInput
		}
		if _, duplicate := seen[scope]; duplicate {
			return StaticOAuth2LoginProfile{}, sso.ErrInvalidInput
		}
		seen[scope] = struct{}{}
	}
	p.Scopes = slices.Clone(p.Scopes)
	return p, nil
}

// RouteOAuth2 already authenticated credential custody. This exact current
// registry projection reads metadata only and never retrieves the client secret.
const providerOAuth2LoginProfileSQL = providerLoginProfileSQL + ` AND p.protocol='oauth2'`

func (r *ProviderRouter) readProviderOAuth2LoginProfile(ctx context.Context, route sso.DomainRoute, configured StaticOAuth2LoginProfile) (providerOAuth2LoginProfile, error) {
	if r == nil || r.pool == nil || r.config.Envelope == nil || r.config.Clock == nil || ctx == nil {
		return providerOAuth2LoginProfile{}, sso.ErrInvalidInput
	}
	configured, err := normalizeStaticOAuth2LoginProfile(configured)
	if err != nil {
		return providerOAuth2LoginProfile{}, err
	}
	binding, err := route.Bindings()
	if err != nil {
		return providerOAuth2LoginProfile{}, sso.ErrInvalidInput
	}
	if !r.protocolRegistry || route.Protocol() != providerProtocolOAuth2 {
		return providerOAuth2LoginProfile{}, sso.ErrForbidden
	}
	proof := binding.Proof.Key
	now := r.config.Clock.Now()
	if binding.ProviderID != configured.ProviderID || proof.OrganizationID != configured.OrganizationID || proof.Domain != configured.Domain || binding.ProviderVersion != configured.ProviderVersion || binding.CredentialGeneration != configured.CredentialGeneration || now.Before(binding.ObservedAt) || !now.Before(binding.ValidUntil) {
		return providerOAuth2LoginProfile{}, sso.ErrForbidden
	}
	ctx, cancel := context.WithTimeout(ctx, r.config.MaximumDuration)
	defer cancel()
	version := strconv.FormatUint(configured.ProviderVersion, 10)
	var issuerDigest, wire []byte
	if err := r.pool.Raw().QueryRow(ctx, providerOAuth2LoginProfileSQL, string(proof.TenantID), string(configured.OrganizationID), string(configured.ProviderID), version, strconv.FormatUint(configured.CredentialGeneration, 10), strconv.FormatUint(configured.MappingVersion, 10)).Scan(&issuerDigest, &wire); err != nil {
		return providerOAuth2LoginProfile{}, providerError(ctx, err)
	}
	if len(issuerDigest) != sha256.Size || len(wire) == 0 || len(wire) > providerConfigurationEnvelopeMaximumBytes {
		return providerOAuth2LoginProfile{}, sso.ErrUnavailable
	}
	aad, err := envelope.NewContext(map[string]string{"owner": "sso/provider", "tenant": string(proof.TenantID), "organization": string(configured.OrganizationID), "provider": string(configured.ProviderID), "protocol": providerProtocolOAuth2, "purpose": "static-configuration", "version": version})
	if err != nil {
		return providerOAuth2LoginProfile{}, sso.ErrUnavailable
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return providerOAuth2LoginProfile{}, sso.ErrUnavailable
	}
	plain, err := r.config.Envelope.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	defer clear(plain)
	if err != nil || len(plain) == 0 || len(plain) > providerConfigurationMaximumBytes {
		return providerOAuth2LoginProfile{}, providerError(ctx, sso.ErrUnavailable)
	}
	domains, err := readProviderConfigurationDomains(providerProtocolOAuth2, plain, configured.MappingVersion, 1)
	if err != nil || domains[0] != configured.Domain {
		return providerOAuth2LoginProfile{}, sso.ErrUnavailable
	}
	var stored providerOAuthConfiguration
	if json.Unmarshal(plain, &stored) != nil || validateProviderOAuth2LoginConfiguration(stored) != nil {
		return providerOAuth2LoginProfile{}, sso.ErrUnavailable
	}
	expectedIssuer := sha256.Sum256([]byte(stored.Proof.Issuer))
	if !bytes.Equal(issuerDigest, expectedIssuer[:]) {
		return providerOAuth2LoginProfile{}, sso.ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return providerOAuth2LoginProfile{}, err
	}
	if !r.config.Clock.Now().Before(binding.ValidUntil) {
		return providerOAuth2LoginProfile{}, sso.ErrForbidden
	}
	return providerOAuth2LoginProfile{configured: configured, issuer: stored.Proof.Issuer, authorizationEndpoint: stored.AuthorizationEndpoint}, nil
}

func validateProviderOAuth2LoginConfiguration(stored providerOAuthConfiguration) error {
	if _, err := sso.NewAttributeMapping(stored.Mapping); err != nil {
		return sso.ErrUnavailable
	}
	if _, err := sso.NewIdentityProofPolicy(stored.Proof); err != nil {
		return sso.ErrUnavailable
	}
	// Retain the registration contract: a verified-email policy cannot borrow
	// another mapped claim, and unverified policy cannot upgrade mail evidence.
	mapping := stored.Mapping
	if stored.Proof.EmailVerification == sso.OAuthEmailUnverified {
		if mapping.VerifiedEmailClaim != "" {
			return sso.ErrUnavailable
		}
	} else if mapping.EmailClaim == "" || mapping.VerifiedEmailClaim == "" || mapping.VerifiedEmailClaim == mapping.SubjectClaim || mapping.VerifiedEmailClaim == mapping.EmailClaim || mapping.VerifiedEmailClaim == mapping.DisplayNameClaim {
		return sso.ErrUnavailable
	}
	var endpoints [4]*url.URL
	for i, raw := range []string{stored.AuthorizationEndpoint, stored.TokenEndpoint, stored.IdentityEndpoint, stored.RevocationEndpoint} {
		if i == 3 && raw == "" {
			continue
		}
		endpoint, query, err := providerLoginAuthorizationEndpoint(raw)
		if err != nil || len(raw) > 2048 || len(query) != 0 || endpoint.ForceQuery || endpoint.String() != raw {
			return sso.ErrUnavailable
		}
		endpoints[i] = endpoint
	}
	identity := endpoints[2]
	for _, endpoint := range endpoints[:2] {
		if strings.EqualFold(identity.Hostname(), endpoint.Hostname()) && oauthLoginEndpointPort(identity) == oauthLoginEndpointPort(endpoint) && oauthLoginEndpointPath(identity) == oauthLoginEndpointPath(endpoint) {
			return sso.ErrUnavailable
		}
	}
	return nil
}

func oauthLoginEndpointPath(endpoint *url.URL) string {
	if endpoint.Path == "" {
		return "/"
	}
	return endpoint.Path
}

func oauthLoginEndpointPort(endpoint *url.URL) string {
	if port := endpoint.Port(); port != "" {
		return port
	}
	return "443"
}

func (p providerOAuth2LoginProfile) authorizationRedirect(state providerLoginPublicState) (url.URL, error) {
	configured, err := normalizeStaticOAuth2LoginProfile(p.configured)
	if err != nil {
		return url.URL{}, err
	}
	if state.Nonce != "" {
		return url.URL{}, sso.ErrInvalidInput
	}
	for _, value := range []string{state.State, state.Challenge} {
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
	query.Set("code_challenge", state.Challenge)
	query.Set("code_challenge_method", "S256")
	redirect.RawQuery = query.Encode()
	if len(redirect.String()) > 8192 {
		return url.URL{}, sso.ErrInvalidInput
	}
	return *redirect, nil
}
