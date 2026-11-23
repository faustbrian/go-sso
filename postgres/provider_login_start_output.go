package postgres

import (
	"context"
	"net/url"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-sso"
)

const loginStartExactRowSQL = ` FROM sso_providers.login_transactions
 WHERE start_command_id=$1 AND tenant_id=$2 AND organization_id=$3 AND provider_id=$4
 AND provider_version=$5::numeric AND credential_generation=$6::numeric AND mapping_version=$7::numeric
 AND issued_at=$8 AND expires_at=$9`

const loginStartRedirectPendingSQL = `
 AND completed_at IS NULL AND expires_at>statement_timestamp()`

const loginStartRedirectSQL = `SELECT binding_envelope` + loginStartExactRowSQL + ` AND protocol='oidc'` + loginStartRedirectPendingSQL
const loginStartRecoverySQL = `SELECT callback_command_id` + loginStartExactRowSQL + ` AND protocol='oidc'`

// Resolve the unique original command before the remaining scope checks. At
// high active concurrency the partial provider/expiry index must not turn
// redirect recovery into a scan of that provider's pending transactions.
const loginStartByCommandSQL = `,tenant_id,organization_id,provider_id,provider_version,credential_generation,mapping_version,issued_at,expires_at,protocol
 FROM sso_providers.login_transactions WHERE start_command_id=$1
) `

const loginStartScopeSQL = ` WHERE tenant_id=$2 AND organization_id=$3 AND provider_id=$4
 AND provider_version=$5::numeric AND credential_generation=$6::numeric AND mapping_version=$7::numeric
 AND issued_at=$8 AND expires_at=$9`
const loginOAuth2StartScopeSQL = ` FROM exact_oauth_login
` + loginStartScopeSQL + ` AND protocol='oauth2'`
const loginSAMLStartScopeSQL = ` FROM exact_saml_login
` + loginStartScopeSQL + ` AND protocol='saml'`

const loginOAuth2StartRedirectSQL = `WITH exact_oauth_login AS MATERIALIZED (
 SELECT binding_envelope,completed_at` + loginStartByCommandSQL + `SELECT binding_envelope` + loginOAuth2StartScopeSQL + loginStartRedirectPendingSQL
const loginOAuth2StartRecoverySQL = `WITH exact_oauth_login AS MATERIALIZED (
 SELECT callback_command_id` + loginStartByCommandSQL + `SELECT callback_command_id` + loginOAuth2StartScopeSQL

const loginSAMLStartRedirectSQL = `WITH exact_saml_login AS MATERIALIZED (
 SELECT binding_envelope,completed_at` + loginStartByCommandSQL + `SELECT binding_envelope` + loginSAMLStartScopeSQL + loginStartRedirectPendingSQL
const loginSAMLStartRecoverySQL = `WITH exact_saml_login AS MATERIALIZED (
 SELECT callback_command_id` + loginStartByCommandSQL + `SELECT callback_command_id` + loginSAMLStartScopeSQL

func (i providerLoginStartInput) transactionArgs() []any {
	return []any{string(i.Command.CommandID), string(i.Command.TenantID), string(i.Proof.OrganizationID), string(i.ProviderID),
		strconv.FormatUint(i.ProviderVersion, 10), strconv.FormatUint(i.Generation, 10), strconv.FormatUint(i.MappingVersion, 10), i.Issued, i.Expires}
}

func (p *providerLoginPhase) committedRedirect(ctx context.Context, out sso.SigninStartResult) (sso.SigninStartResult, error) {
	s, input := p.service, p.input
	query := loginStartRedirectSQL
	switch input.Protocol {
	case providerProtocolOAuth2:
		query = loginOAuth2StartRedirectSQL
	case providerProtocolSAML:
		query = loginSAMLStartRedirectSQL
	}
	var wire []byte
	if err := s.router.pool.Raw().QueryRow(ctx, query, input.transactionArgs()...).Scan(&wire); err != nil {
		return out, providerError(ctx, err)
	}
	defer clear(wire)
	// Read fresh authority for this disclosure, separately from the original
	// execution evidence. None of these reads renews the stored state lifetime.
	fresh := *p
	if err := fresh.readOriginalBrowser(ctx); err != nil {
		return out, providerError(ctx, err)
	}
	if _, err := fresh.requestIntent(); err != nil || fresh.intent != input.Intent {
		return out, sso.ErrForbidden
	}
	directory, err := s.directory.GetDirectoryAuthority(ctx, s.directoryQuery())
	if err != nil {
		return out, providerError(ctx, err)
	}
	if !directory.Enabled || directory.GlobalVersion != input.GlobalVersion || directory.TenantVersion != input.TenantVersion {
		return out, sso.ErrForbidden
	}
	route, profile, err := p.selectRoute(ctx)
	if err != nil {
		return out, providerError(ctx, err)
	}
	selected, err := route.Bindings()
	if err != nil || !input.matchesSelectedRoute(selected, profile) {
		return out, sso.ErrForbidden
	}
	deadline := earlierLoginTime(selected.ValidUntil, input.Expires)
	if fresh.member != nil {
		authority, err := s.checkRetainedMember(ctx, input.Proof.OrganizationID, fresh.member.user, input.Link)
		if err != nil {
			return out, providerError(ctx, err)
		}
		deadline = earlierLoginTime(deadline, earlierLoginTime(authority.ValidUntil, fresh.member.observed.ValidUntil()))
	}
	var redirect url.URL
	if input.Protocol == providerProtocolSAML {
		redirect, err = s.payload.samlRedirect(ctx, input.payload(), wire)
		if err == nil && !matchesSAMLRedirectEndpoint(redirect, profile.authorizationEndpoint) {
			err = sso.ErrForbidden
		}
	} else {
		binding, readErr := s.payload.redirectBinding(ctx, input.payload(), wire)
		if readErr != nil {
			return out, providerError(ctx, readErr)
		}
		redirect, err = s.selectedOAuthRedirect(ctx, input, binding, profile, deadline)
	}
	if err != nil {
		return out, providerError(ctx, err)
	}
	if now := s.router.config.Clock.Now(); !now.Before(deadline) {
		return out, sso.ErrForbidden
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	protocol, _ := providerLoginCryptoProtocol(input.Protocol)
	out.RedirectURI, out.TransactionID, out.ProviderID, out.Protocol = redirect, string(input.Command.CommandID), string(input.ProviderID), protocol
	return out, nil
}

func (s *ProviderLoginService) selectedOAuthRedirect(ctx context.Context, input *providerLoginStartInput, binding providerLoginBindingMetadata, profile providerLoginProfile, deadline time.Time) (url.URL, error) {
	if input.Protocol == providerProtocolOAuth2 && s.oauthStartAdapter != nil {
		return s.oauthStartAdapter.redirect(ctx, *input, binding, profile, s.router.config.Clock, deadline)
	}
	if adapter := s.oidcStartAdapter; input.Protocol == "" && adapter != nil {
		key := providerLoginProfileKey{organization: input.Proof.OrganizationID, provider: input.ProviderID}
		if wire, selected := adapter.profiles[key]; selected {
			return adapter.redirect(ctx, wire, *input, binding, profile, s.router.config.Clock, deadline)
		}
	}
	return profile.authorizationRedirect(binding.Public)
}

func (p *providerLoginPhase) RecoverParticipant(ctx context.Context, work kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	binding, err := work.Scope()
	if err != nil || p.input == nil || binding != identity.CommandBinding(p.input.Command) {
		return kernel.RecoveryUnknown, identity.ForbiddenError{}
	}
	query := loginStartRecoverySQL
	switch p.input.Protocol {
	case providerProtocolOAuth2:
		query = loginOAuth2StartRecoverySQL
	case providerProtocolSAML:
		query = loginSAMLStartRecoverySQL
	}
	rows, err := work.Query(ctx, query, p.input.transactionArgs()...)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return kernel.RecoveryUnknown, err
		}
		return kernel.RecoveryNotCommitted, nil
	}
	var callback string
	if err := rows.Scan(&callback); err != nil {
		return kernel.RecoveryUnknown, err
	}
	parsed, err := identity.ParseCommandID(callback)
	if err != nil || parsed == binding.CommandID || rows.Next() || rows.Err() != nil {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	return kernel.RecoveryCommitted, nil
}
