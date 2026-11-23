package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	organization "github.com/faustbrian/go-organization"
	"github.com/faustbrian/go-sso"
)

type providerGrantRevocationOutcome string

const (
	providerGrantAcknowledged providerGrantRevocationOutcome = "acknowledged"
	providerGrantRefused      providerGrantRevocationOutcome = "refused"
	providerGrantUnknown      providerGrantRevocationOutcome = "unknown"
	providerGrantNotSent      providerGrantRevocationOutcome = "not_sent"
)

// revokeProviderGrant sends only after the original coordinator generation
// and the grant fence are acknowledged. Its caller must currently authorize
// the exact original grant, and build provider from the authenticated installed
// credential generation. This helper settles no local grant or command; an
// upstream result is not proof of local removal, access-token invalidation or
// session revocation. The original deadline must enclose this entire call.
func (s *ProviderLoginService) revokeProviderGrant(ctx context.Context, binding providerLoginStoredTokenBinding, ciphertext []byte,
	attempt identity.CommandID, generation uint64, provider *oauth.SharedOAuth2UserInfoProvider, endpoint string,
) (providerGrantRevocationOutcome, error) {
	if ctx == nil || s == nil || s.router == nil || s.router.pool == nil || provider == nil || binding.Account.TenantID != s.config.TenantID {
		return "", identity.ForbiddenError{}
	}
	org, id := organization.ID(binding.Organization), sso.ProviderID(binding.Provider)
	selected, ok := s.oauthProfiles[providerLoginProfileKey{organization: org, provider: id}]
	namespace, err := SSOOAuth2AccountProviderNamespace(org, id)
	profile := provider.Profile()
	if err != nil || !ok || namespace != binding.Account.Provider || profile.ID != strings.ReplaceAll(namespace, ".", "-") ||
		profile.Issuer != binding.Account.Issuer || profile.ClientID != selected.ClientID || profile.RedirectURI != selected.ProtocolRedirectURI ||
		profile.Version != binding.ProviderVersion || selected.ProviderVersion != binding.ProviderVersion ||
		selected.CredentialGeneration != binding.CredentialGeneration || selected.MappingVersion != binding.MappingVersion ||
		!slices.Equal(profile.Scopes, binding.RequestedScopes) || !slices.Equal(selected.Scopes, binding.RequestedScopes) {
		return "", identity.ForbiddenError{}
	}
	revoker, err := oauth.NewSharedOAuth2RefreshRevocationProvider(provider, endpoint)
	if err != nil {
		return "", identity.ForbiddenError{}
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var outcome providerGrantRevocationOutcome
	err = s.borrowStoredOAuth2Tokens(ctx, binding, ciphertext, func(ctx context.Context, _ []byte, refresh []byte) error {
		custody, err := oauth.NewRefreshToken(refresh, profile, binding.GrantedScopes)
		if err != nil {
			return identity.ForbiddenError{}
		}
		defer custody.Destroy()
		claim := providerGrantFenceClaim{
			Tenant: binding.Account.TenantID, Callback: binding.Callback, TokenVersion: binding.Version,
			CiphertextDigest: sha256.Sum256(ciphertext), Attempt: attempt, Operation: providerGrantRevokeOperation, Generation: generation,
		}
		if err := claimProviderGrantFence(ctx, s.router.pool.Raw(), claim); err != nil {
			return err
		}
		outcome = providerGrantRevocationResult(revoker.Revoke(ctx, custody))
		return nil
	})
	if err != nil {
		return "", err
	}
	return outcome, nil
}

func providerGrantRevocationResult(err error) providerGrantRevocationOutcome {
	if err == nil {
		return providerGrantAcknowledged
	}
	var providerErr *oauth.Error
	if errors.As(err, &providerErr) {
		switch providerErr.Kind() {
		case oauth.Refused:
			return providerGrantRefused
		case oauth.InvalidInput, oauth.Unavailable:
			return providerGrantNotSent
		}
	}
	return providerGrantUnknown
}
