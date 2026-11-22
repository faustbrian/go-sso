//go:build integration

package postgres_test

import (
	"errors"
	"net/url"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-sso"
)

func TestNativeOAuth2LoginCallbackProviderDenialErasesCustodyWithoutExchange(t *testing.T) {
	x := newNativeOAuth2JourneyFixture(t, "linked-member")
	request := x.request
	values, err := url.ParseQuery(request.RawQuery)
	if err != nil {
		t.Fatal(err)
	}
	values.Del("code")
	values.Set("error", "access_denied")
	request.RawQuery = values.Encode()
	before := nativeOAuth2JourneySuccessEffects(t, x)
	got, err := x.completion.SigninCallbackOAuth2(x.start.enable.f.ctx, request)
	assertNativeOAuth2JourneyNoDisclosure(t, got)
	if !errors.Is(err, sso.ErrForbidden) || got.Completion.Outcome != identity.CommitOutcomeNotCommitted ||
		x.posts.Load() != 0 || x.identities.Load() != 0 || nativeOAuth2JourneySuccessEffects(t, x) != before {
		t.Fatalf("authenticated provider denial was not a terminal refusal: %v outcome=%v", err, got.Completion.Outcome)
	}
	var terminal bool
	err = x.start.enable.f.pool.Raw().QueryRow(x.start.enable.f.ctx, `SELECT completed_at IS NOT NULL AND verifier_envelope IS NULL FROM sso_providers.login_transactions WHERE start_command_id=$1`, x.startedID).Scan(&terminal)
	if err != nil || !terminal {
		t.Fatal("definitive refusal retained executable browser custody", err)
	}
	_, err = x.completion.SigninCallbackOAuth2(x.start.enable.f.ctx, x.request)
	if !errors.Is(err, sso.ErrForbidden) || x.posts.Load() != 0 {
		t.Fatal("terminal refusal accepted a substituted code", err)
	}
}
