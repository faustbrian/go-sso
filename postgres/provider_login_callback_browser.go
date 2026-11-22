package postgres

import (
	"context"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	"github.com/faustbrian/go-sso"
)

// Browser authentication is independent of finding the state. Neither this
// primary observation nor the opaque cookie alone grants permission to consume
// the flow, read the verifier or exchange a provider code. The coordinator
// must fence the exact original flow before granting that authority.
func (s *ProviderLoginService) authenticateProviderLoginCallbackBrowser(ctx context.Context, found providerLoginCallbackLookup, browser ProviderLoginBrowser) (session.PreAuthTransaction, error) {
	if s == nil || ctx == nil || s.router == nil || s.router.pool == nil || s.router.pool.Raw() == nil || found.CompletedAt != nil || found.ObservedAt.IsZero() {
		return session.PreAuthTransaction{}, sso.ErrForbidden
	}
	input := found.Binding.Metadata.Input
	original := input.Command
	flowID, err := identity.ParsePreAuthTransactionID(original.AnonymousFlowID)
	if err != nil || original.ValidateFor(providerSigninOperation()) != nil || original.ActorKind != authorization.SubjectServiceAccount || original.ActorID != s.config.ActorID ||
		original.CommandID != found.Row.StartCommandID || original.TenantID != s.config.TenantID || found.Row.TenantID != s.config.TenantID ||
		original.PolicyID != s.config.PolicyID || original.PolicyVersion != s.policyVersion || flowID != browser.FlowID {
		return session.PreAuthTransaction{}, sso.ErrForbidden
	}
	if browser.Origin != s.config.Origin || browser.Origin != input.BrowserOrigin || !browser.Network.IsValid() ||
		browser.Network.Is4In6() || browser.Network.Zone() != "" || !providerID(browser.Device) {
		return session.PreAuthTransaction{}, sso.ErrForbidden
	}
	if _, allowed := s.callbacks[input.SuccessCallback]; !allowed {
		return session.PreAuthTransaction{}, sso.ErrForbidden
	}
	if _, allowed := s.callbacks[input.ErrorCallback]; !allowed {
		return session.PreAuthTransaction{}, sso.ErrForbidden
	}
	remember, err := session.NewRememberPolicy(input.Remember)
	if err != nil {
		return session.PreAuthTransaction{}, sso.ErrForbidden
	}
	ctx, cancel := context.WithTimeout(ctx, s.config.Coordinator.MaximumDuration)
	defer cancel()
	pool := s.router.pool.Raw()
	flow, err := sessionpg.ReadPreAuth(ctx, pool, s.config.Session, original.TenantID, flowID)
	if err != nil {
		return session.PreAuthTransaction{}, providerError(ctx, err)
	}
	var now time.Time
	if err := pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return session.PreAuthTransaction{}, providerError(ctx, err)
	}
	if now.Before(found.ObservedAt) || !now.Before(found.ObservedAt.Add(20*time.Second)) || !now.Before(found.Row.ExpiresAt) {
		return session.PreAuthTransaction{}, sso.ErrForbidden
	}
	if err := s.requireProviderLoginBrowser(flow, now.UTC(), browser, input.SuccessCallback, remember); err != nil {
		return session.PreAuthTransaction{}, providerError(ctx, err)
	}
	return flow, nil
}
