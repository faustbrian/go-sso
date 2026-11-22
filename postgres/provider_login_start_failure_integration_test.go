//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestNativeProviderSigninStartRejectsOversizedRedirectBeforeGeneratingState(t *testing.T) {
	x := newProviderLoginStartFixture(t)
	profile := x.config.Profiles[0]
	profile.ProtocolRedirectURI = "https://identity.example.test/" + strings.Repeat(":", 2000)
	profile.Scopes = []string{"openid"}
	for i := range 30 {
		profile.Scopes = append(profile.Scopes, fmt.Sprintf("scope-%02d-%s", i, strings.Repeat("a", 113)))
	}
	config := x.config
	config.Profiles = []ssopg.StaticOIDCLoginProfile{profile}
	service, err := ssopg.NewProviderLoginService(newProviderRouter(t, x.enable, 4), config)
	if err != nil {
		t.Fatal("compose individually valid profile with oversized combined redirect", err)
	}
	before := nativeProviderLoginCounts(t, x)
	result, err := service.SigninStart(x.enable.f.ctx, x.request, x.browser)
	if !errors.Is(err, sso.ErrForbidden) || result.RedirectURI != (url.URL{}) || result.TransactionID != "" ||
		nativeProviderLoginCounts(t, x) != before {
		t.Fatal("oversized redirect reached counted admission or native state generation", err)
	}
}

func TestNativeProviderSigninStartRequiredEffectFailureRollsBackLogin(t *testing.T) {
	for _, boundary := range []string{"audit", "outbox"} {
		t.Run(boundary, func(t *testing.T) {
			x := newProviderLoginStartFixture(t)
			f := x.enable.f
			sql := `CREATE SEQUENCE sso_providers.login_required_effect_fault;
CREATE FUNCTION sso_providers.reject_login_effect() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 PERFORM nextval('sso_providers.login_required_effect_fault');
 RAISE EXCEPTION 'controlled native login required-effect rollback';
END $$;
CREATE TRIGGER reject_login_effect BEFORE INSERT ON audit.records FOR EACH ROW
 WHEN (NEW.action='identity.sso.login' AND NEW.outcome=1)
 EXECUTE FUNCTION sso_providers.reject_login_effect()`
			if boundary == "outbox" {
				sql = `CREATE SEQUENCE sso_providers.login_required_effect_fault;
CREATE FUNCTION sso_providers.reject_login_effect() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 PERFORM nextval('sso_providers.login_required_effect_fault');
 RAISE EXCEPTION 'controlled native login required-effect rollback';
END $$;
CREATE TRIGGER reject_login_effect BEFORE INSERT ON public.outbox_messages FOR EACH ROW
 WHEN (NEW.topic='oauth.rp_transaction.created.v1')
 EXECUTE FUNCTION sso_providers.reject_login_effect()`
			}
			if _, err := f.pool.Raw().Exec(f.ctx, sql); err != nil {
				t.Fatal("install native login required-effect fault", err)
			}
			before := nativeProviderLoginCounts(t, x)
			out, err := x.service.SigninStart(f.ctx, x.request, x.browser)
			if err == nil || out.Completion.Outcome == identity.CommitOutcomeCommitted || out.RedirectURI != (url.URL{}) || out.TransactionID != "" {
				t.Fatal("failed required effect disclosed a native login redirect", err)
			}
			var faultReached bool
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT is_called FROM sso_providers.login_required_effect_fault`).Scan(&faultReached); err != nil || !faultReached {
				t.Fatal("required-effect failure was not reached by native login", err)
			}
			after := nativeProviderLoginCounts(t, x)
			if after.transactions != before.transactions || after.capabilities != before.capabilities || after.events != before.events {
				t.Fatal("required-effect failure left partial login state, capability or lifecycle effects")
			}
			if nativeProviderLoginSuccessAudits(t, x) != 0 {
				t.Fatal("rolled-back login left a successful transactional audit")
			}
		})
	}
}

func nativeProviderLoginSuccessAudits(t *testing.T, x providerLoginStartFixture) int {
	t.Helper()
	var count int
	if err := x.enable.f.pool.Raw().QueryRow(x.enable.f.ctx, `SELECT count(*) FROM audit.records WHERE action='identity.sso.login' AND outcome=1`).Scan(&count); err != nil {
		t.Fatal("inspect native login transactional audit", err)
	}
	return count
}

func providerLoginLossService(t *testing.T, x providerLoginStartFixture) (*ssopg.ProviderLoginService, *providerCommitFault) {
	t.Helper()
	f := x.enable.f
	fault := &providerCommitFault{target: "INSERT INTO sso_providers.login_transactions"}
	pool, err := database.Connect(f.ctx, database.Config{DSN: f.dsn, MaxConns: 2, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database = f.database
		c.ConnConfig.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			return &providerLossConn{Conn: conn, fault: fault}, nil
		}
		return nil
	}})
	if err != nil {
		t.Fatal("connect native login commit-response fault pool", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := pool.Close(ctx); err != nil {
			t.Error("native login fault pool cleanup failed")
		}
	})
	faultFixture := *f
	faultFixture.pool = pool
	enable := x.enable
	enable.f = &faultFixture
	service, err := ssopg.NewProviderLoginService(newProviderRouter(t, enable, 4), x.config)
	if err != nil {
		t.Fatal("compose native login on commit-response fault pool", err)
	}
	return service, fault
}

type providerLoginStoredCustody struct {
	stateDigest, commitment, binding, verifier []byte
	issued, expires                            time.Time
}

func nativeProviderLoginCustody(t *testing.T, x providerLoginStartFixture, command identity.CommandID) providerLoginStoredCustody {
	t.Helper()
	var custody providerLoginStoredCustody
	err := x.enable.f.pool.Raw().QueryRow(x.enable.f.ctx, `SELECT state_digest,pkce_commitment,binding_envelope,verifier_envelope,issued_at,expires_at FROM sso_providers.login_transactions WHERE start_command_id=$1`, string(command)).Scan(&custody.stateDigest, &custody.commitment, &custody.binding, &custody.verifier, &custody.issued, &custody.expires)
	if err != nil || len(custody.stateDigest) != 32 || len(custody.commitment) != 32 || len(custody.binding) == 0 || len(custody.verifier) == 0 || !custody.expires.After(custody.issued) {
		t.Fatal("inspect actual committed native login custody", err)
	}
	return custody
}

func TestNativeProviderSigninStartLostCommitRecoversOnlyOriginalRedirect(t *testing.T) {
	x := newProviderLoginStartFixture(t)
	service, fault := providerLoginLossService(t, x)
	ctx := x.enable.f.ctx
	before := nativeProviderLoginCounts(t, x)
	out, err := service.SigninStart(ctx, x.request, x.browser)
	var unknown identity.UnknownCommitError
	if !fault.seen.Load() || !fault.lost.Load() || !errors.As(err, &unknown) || out.Completion.Outcome != identity.CommitOutcomeUnknown || out.RedirectURI != (url.URL{}) || out.TransactionID != "" {
		t.Fatal("lost commit response disclosed a redirect or failed to preserve unknown outcome", err)
	}
	command, err := identity.ParseCommandID(string(out.Completion.Binding.CommandID))
	if err != nil || out.Completion.Binding.RecordID != string(command) || command == x.request.CommandID {
		t.Fatal("lost commit response lost the canonical original command", err)
	}
	committed := nativeProviderLoginCounts(t, x)
	if committed.transactions != before.transactions+1 || committed.capabilities != before.capabilities+1 || committed.events != before.events+1 || committed.attempts != before.attempts+1 || nativeProviderLoginSuccessAudits(t, x) != 1 {
		t.Fatal("lost response did not leave exactly one actual committed login")
	}
	originalCustody := nativeProviderLoginCustody(t, x, command)
	recovered, err := x.service.SigninStart(ctx, x.request, x.browser)
	if err != nil || recovered.Completion.Outcome != identity.CommitOutcomeCommitted || recovered.Completion.Binding != out.Completion.Binding || recovered.TransactionID != string(command) || recovered.ProviderID != x.request.ProviderID || recovered.Protocol != "oidc" || recovered.RedirectURI.Scheme != "https" || recovered.RedirectURI.Query().Get("state") == "" {
		t.Fatal("same original key did not recover its committed native redirect", err)
	}
	replayed, err := x.service.SigninStart(ctx, x.request, x.browser)
	if err != nil || !reflect.DeepEqual(recovered, replayed) {
		t.Fatal("same original key changed the recovered redirect or completion", err)
	}
	if nativeProviderLoginCounts(t, x) != committed || nativeProviderLoginSuccessAudits(t, x) != 1 {
		t.Fatal("commit-response recovery repeated login, capability, risk, audit or lifecycle effects")
	}
	if !reflect.DeepEqual(nativeProviderLoginCustody(t, x, command), originalCustody) {
		t.Fatal("commit-response recovery replaced or renewed original state and PKCE custody")
	}
}
