package postgres

import (
	"reflect"
	"testing"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestProviderLoginCallbackDeclaresOneUseAndAtomicSession(t *testing.T) {
	_, start, now, _ := providerLoginPayloadFixture(t)
	callback, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	binding := providerLoginTokenCallback(start, callback)
	grant := kernel.CapabilityPlan{Purpose: providerOIDCCallback, MaxUses: 1, CapabilityID: "native-state", ReplayKeyVersion: 1,
		ReplayDigest: [32]byte{2}, ProofFingerprint: [32]byte{3}, ExpiresAt: start.ExpiresAt}
	contributors := []kernel.ContributorDescriptor{
		{Owner: "identity/postgres", ContractID: "identity.postgres", Version: 1},
		{Owner: "audit/postgres", ContractID: "identity.audit", Version: 1},
		{Owner: "outbox/postgres", ContractID: "identity.lifecycle", Version: 1},
		{Owner: "sso/postgres", ContractID: "sso.oidc-login-callback", Version: 1},
		{Owner: "capability/postgres", ContractID: "capability.one-use", Version: 1},
	}
	plan, err := providerLoginCallbackPlan(binding, *now, 1, grant, contributors)
	if err != nil || plan.Feature == nil || plan.Feature.Operation != providerOIDCCallbackOperation() || plan.Feature.Contributor != contributors[3] ||
		plan.SubjectType != providerLoginSubject || plan.Capability == nil || *plan.Capability != grant ||
		plan.Lifecycle == nil || *plan.Lifecycle != (kernel.LifecyclePlan{EventType: "session.created.v1", BeforeVersion: 1, AfterVersion: 2}) ||
		len(plan.Audits) != 1 || !plan.Audits[0].Required || plan.Audits[0].RetentionClass != "protected" || plan.Audits[0].EventType != "identity.sso.login" {
		t.Fatalf("callback did not enlist its exact original capability and effects: %v", err)
	}
	if !reflect.DeepEqual(plan.Contributors, contributors) {
		t.Fatal("callback did not preserve selected transaction owners")
	}
	foreign := grant
	foreign.Purpose = "identity.oauth.signin-callback"
	if _, err := providerLoginCallbackPlan(binding, *now, 1, foreign, contributors); err == nil {
		t.Fatal("enterprise callback accepted foreign state purpose")
	}
	if _, err := providerLoginCallbackPlan(binding, *now, 1, grant, contributors[:4]); err == nil {
		t.Fatal("enterprise callback accepted a declaration without the one-use participant")
	}
}
