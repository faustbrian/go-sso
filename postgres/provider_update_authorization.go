package postgres

import (
	"context"
	"reflect"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-sso"
)

// ProviderUpdateAuthorization is the trusted native policy owner for the
// update-only opt-in. It evaluates the exact context at its supplied primary
// database time and returns the earliest absolute time the decision could
// change, including activation/condition boundaries. Before that deadline,
// policy changes that invalidate its evidence MUST advance the existing native
// actor authorization epoch. The expected epoch is an observation to verify,
// not authority to echo caller-owned evidence. Calls run outside Work and must
// be bounded, concurrency-safe and cancellation-aware. No transaction is lent.
type ProviderUpdateAuthorization interface {
	ObserveProviderUpdateAuthorization(context.Context, authorization.DecisionContext, uint64) (ProviderUpdateAuthorizationEvidence, error)
}

// ProviderUpdateAuthorizationEvidence is one owner observation, not reusable
// bearer authority. Context must exactly match the supplied detached context,
// including its revision, action, tenant, actor, resource and evaluation time.
// The native session epoch must match ActorAuthorizationVersion. Missing,
// expired, denied or mismatched evidence fails closed before keyed admission.
// Owner mutations must not alias Context or Decision after returning.
type ProviderUpdateAuthorizationEvidence struct {
	Context                   authorization.DecisionContext
	Decision                  authorization.Decision
	ActorAuthorizationVersion uint64
	ValidUntil                time.Time
}

// WithProviderUpdateAuthorization selects the update-only policy owner on a
// detached service copy. Registration and ordinary Get/List remain unchanged.
// The existing generic authorization.Service alone cannot describe decision
// expiry and is insufficient for mutation admission. Nil owners are rejected.
func (s *ProviderService) WithProviderUpdateAuthorization(owner ProviderUpdateAuthorization) (*ProviderService, error) {
	if s == nil || s.pool == nil || owner == nil {
		return nil, sso.ErrInvalidInput
	}
	bound := *s
	bound.updateAuthorization = owner
	return &bound, nil
}

func (s *ProviderService) admitUpdate(ctx context.Context) (providerAdmission, error) {
	if s.updateAuthorization == nil {
		return providerAdmission{}, sso.ErrForbidden
	}
	a, err := s.admit(ctx, s.updateOrganization, "org:sso-write")
	if err != nil {
		return providerAdmission{}, err
	}
	bound, err := a.session.Session.Bindings()
	if err != nil {
		return providerAdmission{}, sso.ErrForbidden
	}
	authority, err := bound.Authority.Bindings()
	if err != nil || authority.Authorization.Version == 0 {
		return providerAdmission{}, sso.ErrForbidden
	}
	dc := s.decision(bound.UserID, s.updateOrganization, "org:sso-write")
	// This is the existing admission's primary time, not a fresh local-clock
	// lease anchor. Work later compares database time to its unchanged minimum.
	dc.Request.Environment.Time = a.verified
	evidence, err := s.updateAuthorization.ObserveProviderUpdateAuthorization(ctx, dc.Clone(), authority.Authorization.Version)
	if err != nil {
		return providerAdmission{}, providerError(ctx, err)
	}
	if !reflect.DeepEqual(evidence.Context, dc) || evidence.Decision.Outcome != authorization.Allow || evidence.Decision.Revision != dc.PolicyRevision || evidence.ActorAuthorizationVersion != authority.Authorization.Version || evidence.ValidUntil.IsZero() || !a.verified.Before(evidence.ValidUntil) {
		return providerAdmission{}, sso.ErrForbidden
	}
	if evidence.ValidUntil.Before(a.until) {
		a.until = evidence.ValidUntil
	}
	if !s.config.Clock.Now().Before(a.until) {
		return providerAdmission{}, sso.ErrForbidden
	}
	return a, nil
}
