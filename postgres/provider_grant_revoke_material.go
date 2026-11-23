package postgres

import (
	"context"
	"crypto/sha256"
	"reflect"
	"slices"
	"strconv"
	"strings"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	organization "github.com/faustbrian/go-organization"
	"github.com/faustbrian/go-sso"
)

const providerGrantRevocationCurrentSQL = ` AND p.protocol='oauth2' AND p.enabled AND p.pending_domains=1
 AND p.metadata_version=$4::numeric AND p.enablement_credential_generation=$5::numeric
 AND c.generation=$5::numeric AND COALESCE(p.metadata_mapping_version,p.mapping_version)=$6::numeric
 AND c.provider_version BETWEEN 2 AND $4::numeric AND p.issuer_digest=$7
 AND octet_length(COALESCE(p.metadata_configuration_envelope,p.configuration_envelope)) BETWEEN 1 AND 65536
 AND octet_length(c.envelope) BETWEEN 1 AND 32768 AND octet_length(c.credential_context) BETWEEN 1 AND 4096`

const providerGrantRevocationMaterialSQL = providerEnablePredecessorSQL + providerGrantRevocationCurrentSQL

// The final coordinator must require this exact row even if the grant has
// already disappeared. Lock both registry owners until commit without changing
// either; the connection role therefore needs row-locking privileges on both.
const providerGrantRevocationEpochSQL = `SELECT true
 FROM sso_providers.providers p JOIN sso_providers.credentials c USING(tenant_id,organization_id,provider_id)
 WHERE p.tenant_id=$1 AND p.organization_id=$2 AND p.provider_id=$3` + providerGrantRevocationCurrentSQL + ` FOR UPDATE OF p,c`

func providerGrantRevocationEpochArgs(binding providerLoginStoredTokenBinding) []any {
	issuer := sha256.Sum256([]byte(binding.Account.Issuer))
	return []any{string(binding.Account.TenantID), binding.Organization, binding.Provider,
		strconv.FormatUint(binding.ProviderVersion, 10), strconv.FormatUint(binding.CredentialGeneration, 10),
		strconv.FormatUint(binding.MappingVersion, 10), issuer[:]}
}

// revokeProviderGrantWithInstalledCredential consumes no callback authority.
// Its caller owns the original revocation reservation and deadline. Only the
// exact currently enabled installation can open its credential, and the secret
// and provider remain inside the synchronous credential owner's closure.
func (s *ProviderLoginService) revokeProviderGrantWithInstalledCredential(ctx context.Context, binding providerLoginStoredTokenBinding, ciphertext []byte,
	attempt identity.CommandID, generation uint64, transport StaticOAuth2CompletionProfile, endpoint string,
) (providerGrantRevocationOutcome, error) {
	if ctx == nil || s == nil || s.router == nil || s.router.pool == nil || s.router.pool.Raw() == nil ||
		s.router.config.Clock == nil || s.router.config.Envelope == nil || !s.router.protocolRegistry ||
		binding.Account.TenantID != s.config.TenantID {
		return "", identity.ForbiddenError{}
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if _, err := binding.aad(); err != nil {
		return "", err
	}
	selected, ok := s.oauthProfiles[providerLoginProfileKey{
		organization: organization.ID(binding.Organization), provider: sso.ProviderID(binding.Provider),
	}]
	if !ok {
		return "", identity.ForbiddenError{}
	}
	original, err := providerGrantRevocationProfileInput(binding, selected, transport)
	if err != nil {
		return "", err
	}

	var stored providerEnableStored
	defer func() {
		clear(stored.configuration)
		clear(stored.credential)
		clear(stored.credentialContext)
	}()
	if err := stored.scan(s.router.pool.Raw().QueryRow(ctx, providerGrantRevocationMaterialSQL, providerGrantRevocationEpochArgs(binding)...)); err != nil {
		return "", providerError(ctx, err)
	}
	if !stored.enabled || stored.pending != 1 || stored.version != strconv.FormatUint(binding.ProviderVersion, 10) ||
		stored.mapping != strconv.FormatUint(binding.MappingVersion, 10) || stored.generation != strconv.FormatUint(binding.CredentialGeneration, 10) {
		return "", identity.ForbiddenError{}
	}
	installed, err := strconv.ParseUint(stored.credentialVersion, 10, 64)
	if err != nil {
		return "", sso.ErrUnavailable
	}
	if err := validateProviderOAuth2CallbackCredential(original, installed, stored.credential, stored.credentialContext); err != nil {
		return "", err
	}
	configuration, err := openProviderOAuth2CallbackConfiguration(ctx, s.router.config.Envelope, original, stored.version, stored.configuration)
	if err != nil {
		return "", err
	}
	if err := validateProviderOAuth2ExchangeProfile(original, selected, transport, configuration); err != nil {
		return "", err
	}
	if endpoint == "" || configuration.RevocationEndpoint != endpoint {
		return "", identity.ForbiddenError{}
	}

	var outcome providerGrantRevocationOutcome
	err = withAuthenticatedProtocolProviderCredential(ctx, s.router.config.Envelope, providerProtocolOAuth2,
		string(binding.Account.TenantID), binding.Organization, binding.Provider,
		stored.credential, stored.credentialContext, binding.CredentialGeneration, installed,
		func(ctx context.Context, secret []byte) error {
			provider, err := newProviderOAuth2Transport(transport, s.router.config.Clock, secret, providerOAuth2MappedClaimNames(configuration.Mapping))
			if err != nil {
				return err
			}
			defer provider.Close()
			if !reflect.DeepEqual(provider.Profile(), transport.Profile.Profile) {
				return identity.ForbiddenError{}
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			outcome, err = s.revokeProviderGrant(ctx, binding, ciphertext, attempt, generation, provider, endpoint)
			return err
		})
	if err != nil {
		return "", err
	}
	return outcome, nil
}

// Reuse the authenticated configuration codec without reconstructing a login
// transaction, PKCE custody, route proof or expired callback reservation.
func providerGrantRevocationProfileInput(binding providerLoginStoredTokenBinding, selected StaticOAuth2LoginProfile, transport StaticOAuth2CompletionProfile) (providerLoginStartInput, error) {
	base := transport.Profile.Profile
	namespace, err := SSOOAuth2AccountProviderNamespace(selected.OrganizationID, selected.ProviderID)
	if err != nil || binding.Account.Provider != namespace || binding.Organization != string(selected.OrganizationID) || binding.Provider != string(selected.ProviderID) ||
		binding.ProviderVersion != selected.ProviderVersion || binding.CredentialGeneration != selected.CredentialGeneration || binding.MappingVersion != selected.MappingVersion ||
		transport.OrganizationID != selected.OrganizationID || transport.ProviderID != selected.ProviderID || base.ID != strings.ReplaceAll(namespace, ".", "-") ||
		base.Version != binding.ProviderVersion || base.Issuer != binding.Account.Issuer || base.ClientID != selected.ClientID || base.RedirectURI != selected.ProtocolRedirectURI ||
		base.ClientAuthentication != oauth.ClientSecretPost || !slices.Equal(base.Scopes, selected.Scopes) || !slices.Equal(selected.Scopes, binding.RequestedScopes) {
		return providerLoginStartInput{}, identity.ForbiddenError{}
	}
	return providerLoginStartInput{
		Protocol: providerProtocolOAuth2, ProviderID: selected.ProviderID, ProviderVersion: selected.ProviderVersion,
		Generation: selected.CredentialGeneration, MappingVersion: selected.MappingVersion,
		Proof:  organization.DomainProofKey{TenantID: binding.Account.TenantID, OrganizationID: selected.OrganizationID, Domain: selected.Domain},
		Issuer: binding.Account.Issuer, AuthorizationEndpoint: base.AuthorizationEndpoint,
		ClientID: selected.ClientID, ProtocolRedirectURI: selected.ProtocolRedirectURI,
	}, nil
}
