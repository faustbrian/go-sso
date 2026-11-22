package postgres

import (
	"context"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	"github.com/faustbrian/go-sso"
)

// A callback recovers its exact historical route here, without renewing that
// route's authority. The authenticated login row intentionally omits the full
// organization-owned proof; selecting today's route could substitute it.
func (s *ProviderLoginService) readProviderLoginCallbackOrigin(ctx context.Context, found providerLoginCallbackLookup, authenticatedBrowser session.PreAuthTransaction) (providerLoginStartInput, error) {
	if s == nil || ctx == nil || found.CompletedAt != nil {
		return providerLoginStartInput{}, sso.ErrForbidden
	}
	flow, err := authenticatedBrowser.Bindings()
	if err != nil {
		return providerLoginStartInput{}, sso.ErrForbidden
	}
	phase := &providerLoginPhase{service: s, browser: ProviderLoginBrowser{FlowID: flow.Binding.ID}}
	want := found.Binding.Metadata.Input
	start := want.Command
	if start != phase.commandBinding(found.Row.StartCommandID) || start.ValidateFor(providerSigninOperation()) != nil {
		return providerLoginStartInput{}, sso.ErrForbidden
	}
	coordinator, _, err := s.coordinator(phase)
	if err != nil {
		return providerLoginStartInput{}, providerError(ctx, err)
	}
	query := identity.RecoveryQuery{
		CommandID: start.CommandID, TenantID: start.TenantID, ActorID: start.ActorID, ActorKind: start.ActorKind,
		AnonymousFlowID: start.AnonymousFlowID, OperationID: start.OperationID, RecordID: start.RecordID,
	}
	caller := s.caller()
	caller.Request.Resource = authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(start.AnonymousFlowID)}
	key, wire, err := coordinator.QueryRequestPreparation(ctx, query, caller, phase.registration(), phase)
	if err != nil {
		return providerLoginStartInput{}, providerError(ctx, err)
	}
	defer clear(wire)
	original, err := phase.openOriginalInput(ctx, key, wire)
	if err != nil {
		return providerLoginStartInput{}, providerError(ctx, err)
	}
	got := original.payload()
	got.IssuedAt, got.ExpiresAt = got.IssuedAt.UTC(), got.ExpiresAt.UTC()
	want.IssuedAt, want.ExpiresAt = want.IssuedAt.UTC(), want.ExpiresAt.UTC()
	if got != want {
		return providerLoginStartInput{}, sso.ErrForbidden
	}
	return original, nil
}
