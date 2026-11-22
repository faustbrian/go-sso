package postgres

import (
	"net/netip"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
)

func TestProviderLoginCallbackRiskBindsOriginalCommandAndTrustedNetwork(t *testing.T) {
	_, start, now, _ := providerLoginPayloadFixture(t)
	callback, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	p := providerLoginCallbackInvocation{
		found:   providerLoginCallbackLookup{Row: start.rowIdentity(), ObservedAt: *now, Binding: providerLoginStoredBinding{Metadata: providerLoginBindingMetadata{Input: start, CallbackCommand: callback}}},
		browser: ProviderLoginBrowser{Network: netip.MustParseAddr("192.0.2.17"), Device: "original-device"},
	}
	scope, subject := p.riskScope()
	if scope.Tenant != string(start.Command.TenantID) || scope.Attempt != string(callback) || scope.Operation != risk.Action(providerOIDCCallback) ||
		subject.Network != p.browser.Network.String() || subject.Device != p.browser.Device || len(subject.IdentifierDigest) != 64 {
		t.Fatalf("risk scope did not preserve the exact original login: %+v", scope)
	}
	other := p
	other.found.Row.OrganizationID = "different-org"
	_, otherSubject := other.riskScope()
	if otherSubject.IdentifierDigest == subject.IdentifierDigest {
		t.Fatal("another organization shared this callback's provider velocity bucket")
	}
	shifted := p
	shifted.found.ObservedAt = now.Add(time.Second)
	shiftedScope, shiftedSubject := shifted.riskScope()
	if scope != shiftedScope || subject != shiftedSubject {
		t.Fatal("same callback changed risk dimensions when observed again")
	}
}
