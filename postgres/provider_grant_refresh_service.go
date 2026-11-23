package postgres

import (
	"context"
	"encoding/base64"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	organization "github.com/faustbrian/go-organization"
	"github.com/faustbrian/go-sso"
)

// ProviderGrantRefreshProvider opts an installed enterprise OAuth2 provider
// into refresh at its existing, exact token endpoint.
type ProviderGrantRefreshProvider struct {
	OrganizationID organization.ID
	ProviderID     sso.ProviderID
}

// ProviderGrantRefreshConfig selects uncached cookie validation and the
// bounded set of installed providers eligible for native refresh.
type ProviderGrantRefreshConfig struct {
	Session   session.ServiceConfig
	Providers []ProviderGrantRefreshProvider
}

// ProviderGrantRefreshBrowser carries the current enterprise cookie, trusted
// origin and bound CSRF token. Its implicit representations are redacted.
type ProviderGrantRefreshBrowser = ProviderGrantRevocationBrowser

// ProviderGrantRefreshResult separates local commit acknowledgement from the
// provider result. Successor is nonzero only for a locally committed successful
// refresh. It is a grant reference, never provider token bytes.
type ProviderGrantRefreshResult struct {
	Completion      kernel.CommandRecord
	ProviderOutcome ProviderGrantRefreshOutcome
	Successor       sso.TokenVersion
}

// ProviderGrantRefreshService owns the opt-in native grant rotation workflow.
// It does not install HTTP routes, issue sessions or maintain token copies.
type ProviderGrantRefreshService struct{ native *providerGrantService }

// NewProviderGrantRefreshService selects refresh for linked OAuth2 members.
// Install the grant fence, refresh history and terminal preparation-erasure
// history before use. Construction opens no database or provider connection.
func NewProviderGrantRefreshService(login *ProviderOAuth2LoginCompletionService, cfg ProviderGrantRefreshConfig) (*ProviderGrantRefreshService, error) {
	if login == nil || login.start == nil || len(cfg.Providers) == 0 || len(cfg.Providers) > 128 || cfg.Session.Audience != login.policy.Audience {
		return nil, sso.ErrInvalidInput
	}
	endpoints := make(map[providerLoginProfileKey]string, len(cfg.Providers))
	for _, selected := range cfg.Providers {
		key := providerLoginProfileKey{selected.OrganizationID, selected.ProviderID}
		profile, ok := login.profiles[key]
		if !ok || endpoints[key] != "" || profile.Profile.Profile.TokenEndpoint == "" {
			return nil, sso.ErrInvalidInput
		}
		endpoints[key] = profile.Profile.Profile.TokenEndpoint
	}
	native, err := newProviderGrantService(login, cfg.Session, endpoints, providerGrantRefreshOperation)
	if err != nil {
		return nil, err
	}
	return &ProviderGrantRefreshService{native: native}, nil
}

// Refresh authorizes the exact original grant and calls the provider at most
// once per generation, sharing the fence with revocation. Retry the same
// request key to recover its committed outcome, never to resend.
func (s *ProviderGrantRefreshService) Refresh(ctx context.Context, request sso.RefreshEnterpriseToken, browser ProviderGrantRefreshBrowser) (ProviderGrantRefreshResult, error) {
	if ctx == nil || s == nil || s.native == nil {
		return ProviderGrantRefreshResult{}, sso.ErrInvalidInput
	}
	grant, key, err := request.Bindings()
	if err != nil {
		return ProviderGrantRefreshResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, s.native.completion.start.config.Coordinator.MaximumDuration)
	defer cancel()
	p, record, err := s.native.execute(ctx, grant, key, browser)
	if err != nil {
		return ProviderGrantRefreshResult{}, err
	}
	return p.refreshResult(ctx, record)
}

func (p *providerGrantPhase) refreshResult(ctx context.Context, record kernel.CommandRecord) (ProviderGrantRefreshResult, error) {
	b := p.binding()
	if record.Outcome != identity.CommitOutcomeCommitted || record.Binding != b {
		return ProviderGrantRefreshResult{}, identity.UnknownCommitError{CommandID: b.CommandID}
	}
	id, _ := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	row := p.service.completion.start.router.pool.Raw().QueryRow(ctx, readProviderGrantRefreshReceiptSQL, string(b.TenantID), string(b.UserID), id)
	version, outcome, err := p.scanRefreshReceipt(row)
	if err != nil {
		return ProviderGrantRefreshResult{}, identity.UnavailableError{}
	}
	result := ProviderGrantRefreshResult{Completion: record, ProviderOutcome: outcome}
	if version != 0 {
		spec := p.ref
		spec.Version = version
		result.Successor, err = sso.NewTokenVersion(spec)
		if err != nil {
			return ProviderGrantRefreshResult{}, identity.UnavailableError{}
		}
	}
	return result, nil
}
