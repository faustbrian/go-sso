//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	organization "github.com/faustbrian/go-organization"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestProviderLoginCallbackOriginRecoversExactCommittedStart(t *testing.T) {
	x := newProviderLoginStartFixture(t)
	state, _ := startProviderLoginCallbackLookup(t, x)
	ctx := x.enable.f.ctx
	before := nativeProviderLoginCounts(t, x)
	proof, observed, err := ssopg.ReadProviderLoginCallbackOriginForTest(ctx, x.service, state, x.browser)
	if err != nil || proof != organization.DomainProofKey(x.enable.proof) || observed.IsZero() {
		t.Fatalf("callback did not recover the exact verified domain and route from its committed start: %v", err)
	}
	if nativeProviderLoginCounts(t, x) != before {
		t.Fatal("restoring the start must not reserve, consume or write")
	}

	config := x.config
	query := *config.Coordinator.QueryPolicy
	query.Authorization = denyProviderLoginOriginRecovery{}
	config.Coordinator.QueryPolicy = &query
	denied, err := ssopg.NewProviderLoginService(newProviderRouter(t, x.enable, 4), config)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ssopg.ReadProviderLoginCallbackOriginForTest(ctx, denied, state, x.browser); !errors.Is(err, sso.ErrForbidden) {
		t.Fatalf("valid state and browser cannot replace current read authorization for the original input: %v", err)
	}
}

type denyProviderLoginOriginRecovery struct{}

func (denyProviderLoginOriginRecovery) Decide(ctx context.Context, request authorization.DecisionContext) (authorization.Decision, error) {
	if request.Request.Action == "identity.sso.signin-start" && request.Request.Resource.Type == "identity.anonymous-flow" {
		return authorization.Decision{Outcome: authorization.Deny, Revision: request.PolicyRevision}, nil
	}
	return (providerLoginPolicy{}).Decide(ctx, request)
}

func TestProviderLoginCallbackAuthorityRequiresOriginalProofToRemainCurrent(t *testing.T) {
	x := newProviderLoginStartFixture(t)
	state, _ := startProviderLoginCallbackLookup(t, x)
	ctx := x.enable.f.ctx
	before := nativeProviderLoginCounts(t, x)
	organization, deadline, err := ssopg.ObserveProviderLoginCallbackAuthorityForTest(ctx, x.service, state, x.browser)
	if err != nil || organization.TenantID != x.config.TenantID || organization.OrganizationID != x.enable.proof.OrganizationID ||
		organization.Actor.UserID != "" || organization.Version == 0 || !deadline.After(organization.ReadStartedAt) ||
		deadline.After(organization.ReadStartedAt.Add(20*time.Second)) || deadline.After(x.enable.proof.ExpiresAt) {
		t.Fatalf("fresh authority must be bounded to the exact current original organization and proof: %v", err)
	}
	if nativeProviderLoginCounts(t, x) != before {
		t.Fatal("current authority observation mutated sign-in custody")
	}
	revokeEnableTestProof(t, x.enable)
	if _, _, err := ssopg.ReadProviderLoginCallbackOriginForTest(ctx, x.service, state, x.browser); err != nil {
		t.Fatal("historical original still needs to be recoverable after revocation", err)
	}
	if _, _, err := ssopg.ObserveProviderLoginCallbackAuthorityForTest(ctx, x.service, state, x.browser); !errors.Is(err, sso.ErrForbidden) {
		t.Fatalf("historical possession of state and proof survived actual domain proof revocation: %v", err)
	}
}
