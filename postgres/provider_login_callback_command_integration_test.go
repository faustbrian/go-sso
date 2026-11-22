//go:build integration

package postgres_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestProviderLoginCallbackCommandKeepsOriginalFlowAndCodeIntent(t *testing.T) {
	x := newProviderLoginStartFixture(t)
	state, started := startProviderLoginCallbackLookup(t, x)
	ctx := x.enable.f.ctx
	redirect := x.config.Profiles[0].ProtocolRedirectURI
	before := nativeProviderLoginCounts(t, x)
	prepare := func(code, wireState, receivedOn string) (identity.Command, error) {
		t.Helper()
		input, err := identity.NewOAuthCallbackInput([]byte(code), wireState, identity.OAuthCallbackLimits{MaxCodeBytes: 4096, StateBytes: 32})
		if err != nil {
			t.Fatal(err)
		}
		defer input.Destroy()
		return ssopg.PrepareProviderLoginCallbackCommandForTest(ctx, x.service, state, receivedOn, x.browser, input)
	}
	first, err := prepare("provider-code-one", state, redirect)
	if err != nil {
		t.Fatal(err)
	}
	second, err := prepare("provider-code-one", state, redirect)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := prepare("provider-code-two", state, redirect)
	if err != nil {
		t.Fatal(err)
	}
	a, ok := first.Feature()
	b, _ := second.Feature()
	c, _ := changed.Feature()
	if !ok || a.Binding.CommandID == identity.CommandID(started) || a.Binding.RecordID != started || a.Binding.UserID != "" || a.Binding.AnonymousFlowID != string(x.browser.FlowID) || a.Binding.ActorID != x.config.ActorID || a.Operation.OperationID != "identity.sso.oidc-callback" || a.Binding != b.Binding || a.Binding != c.Binding {
		t.Fatal("callback changed original account-free command or flow scope")
	}
	if len(a.Fields) != 1 || len(b.Fields) != 1 || len(c.Fields) != 1 || len(a.Fields[0].Value.Bytes) != 32 || !bytes.Equal(a.Fields[0].Value.Bytes, b.Fields[0].Value.Bytes) || bytes.Equal(a.Fields[0].Value.Bytes, c.Fields[0].Value.Bytes) {
		t.Fatal("callback intent is not stable for the original code and distinct for a changed code")
	}
	if _, ok := first.PreAuthCookie(); !ok {
		t.Fatal("native callback lost separate browser custody")
	}
	foreign := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x74}, 32))
	if _, err := prepare("provider-code-one", foreign, redirect); !errors.Is(err, sso.ErrForbidden) {
		t.Fatalf("foreign callback state selected the original command: %v", err)
	}
	if _, err := prepare("provider-code-one", state, redirect+"/wrong"); !errors.Is(err, sso.ErrForbidden) {
		t.Fatalf("foreign callback route selected the original command: %v", err)
	}
	if nativeProviderLoginCounts(t, x) != before {
		t.Fatal("preparing callback intent reserved or consumed primary state")
	}
}
