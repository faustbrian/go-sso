package postgres

import (
	"context"
	"strconv"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-sso"
)

const loginStartRedirectSQL = `SELECT binding_envelope FROM sso_providers.login_transactions
 WHERE start_command_id=$1 AND tenant_id=$2 AND organization_id=$3 AND provider_id=$4
 AND provider_version=$5::numeric AND credential_generation=$6::numeric AND mapping_version=$7::numeric
 AND issued_at=$8 AND expires_at=$9 AND protocol='oidc'
 AND completed_at IS NULL AND expires_at>statement_timestamp()`

const loginStartRecoverySQL = `SELECT callback_command_id FROM sso_providers.login_transactions
 WHERE start_command_id=$1 AND tenant_id=$2 AND organization_id=$3 AND provider_id=$4
 AND provider_version=$5::numeric AND credential_generation=$6::numeric AND mapping_version=$7::numeric
 AND issued_at=$8 AND expires_at=$9 AND protocol='oidc'`

func (i providerLoginStartInput) transactionArgs() []any {
	return []any{string(i.Command.CommandID), string(i.Command.TenantID), string(i.Proof.OrganizationID), string(i.ProviderID),
		strconv.FormatUint(i.ProviderVersion, 10), strconv.FormatUint(i.Generation, 10), strconv.FormatUint(i.MappingVersion, 10), i.Issued, i.Expires}
}

func (p *providerLoginPhase) committedRedirect(ctx context.Context, out sso.SigninStartResult) (sso.SigninStartResult, error) {
	s, input := p.service, p.input
	var wire []byte
	if err := s.router.pool.Raw().QueryRow(ctx, loginStartRedirectSQL, input.transactionArgs()...).Scan(&wire); err != nil {
		return out, providerError(ctx, err)
	}
	defer clear(wire)
	state, err := s.payload.redirectState(ctx, input.payload(), wire)
	if err != nil {
		return out, providerError(ctx, err)
	}
	// Read fresh authority for this disclosure, separately from the original
	// execution evidence. None of these reads renews the stored state lifetime.
	fresh := *p
	if err := fresh.readBrowser(ctx); err != nil {
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
	route, profile, err := s.selectRoute(ctx, p.request)
	if err != nil {
		return out, providerError(ctx, err)
	}
	selected, err := route.Bindings()
	if err != nil || selected.Proof.Key != input.Proof || selected.ProviderID != input.ProviderID ||
		selected.ProviderVersion != input.ProviderVersion || selected.CredentialGeneration != input.Generation ||
		selected.PolicyVersion != input.RoutePolicy || profile.configured.MappingVersion != input.MappingVersion ||
		profile.issuer != input.Issuer || profile.authorizationEndpoint != input.AuthorizationEndpoint {
		return out, sso.ErrForbidden
	}
	redirect, err := profile.authorizationRedirect(state)
	if err != nil {
		return out, providerError(ctx, err)
	}
	if now := s.router.config.Clock.Now(); !now.Before(earlierLoginTime(selected.ValidUntil, input.Expires)) {
		return out, sso.ErrForbidden
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	out.RedirectURI, out.TransactionID, out.ProviderID, out.Protocol = redirect, string(input.Command.CommandID), string(input.ProviderID), "oidc"
	return out, nil
}

func (p *providerLoginPhase) RecoverParticipant(ctx context.Context, work kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	binding, err := work.Scope()
	if err != nil || p.input == nil || binding != identity.CommandBinding(p.input.Command) {
		return kernel.RecoveryUnknown, identity.ForbiddenError{}
	}
	rows, err := work.Query(ctx, loginStartRecoverySQL, p.input.transactionArgs()...)
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
