//go:build integration

package postgres_test

import (
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func startProviderLoginCallbackLookup(t *testing.T, x providerLoginStartFixture) (string, string) {
	t.Helper()
	started, err := x.service.SigninStart(x.enable.f.ctx, x.request, x.browser)
	if err != nil || started.Completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("commit genuine original provider login", err)
	}
	return started.RedirectURI.Query().Get("state"), started.TransactionID
}

func TestProviderLoginCallbackLookupAuthenticatesOriginalPendingBinding(t *testing.T) {
	x := newProviderLoginStartFixture(t)
	state, command := startProviderLoginCallbackLookup(t, x)
	before := nativeProviderLoginCounts(t, x)
	got, err := ssopg.LookupProviderLoginCallbackForTest(x.enable.f.ctx, x.service, state)
	remember, rememberErr := x.originalFlow.Intent.Remember.Bindings()
	if err != nil || rememberErr != nil || got.TenantID != string(x.config.TenantID) ||
		got.OrganizationID != string(x.enable.proof.OrganizationID) || got.ProviderID != x.request.ProviderID ||
		got.StartCommandID != command || got.CallbackCommandID == command ||
		got.ProviderVersion != 3 || got.CredentialGeneration != 1 || got.MappingVersion != 1 ||
		got.Origin != x.browser.Origin || got.Success != x.request.SuccessCallback.String() ||
		got.Failure != x.request.ErrorCallback.String() || got.Remember != remember ||
		got.CompletedAt != nil || !got.HasProof || !got.HasPlan || got.ObservedAt.Before(got.IssuedAt) || !got.ObservedAt.Before(got.ExpiresAt) {
		t.Fatal("lookup lost authenticated original browser intent or exact pending identity", err)
	}
	if _, err := identity.ParseCommandID(got.CallbackCommandID); err != nil {
		t.Fatal("lookup lost original callback command", err)
	}
	var issued, expires time.Time
	if err := x.enable.f.pool.Raw().QueryRow(x.enable.f.ctx, `SELECT issued_at,expires_at FROM sso_providers.login_transactions WHERE start_command_id=$1`, command).Scan(&issued, &expires); err != nil || !got.IssuedAt.Equal(issued) || !got.ExpiresAt.Equal(expires) {
		t.Fatal("lookup changed immutable durable times", err)
	}
	if after := nativeProviderLoginCounts(t, x); after != before {
		t.Fatal("read-only callback lookup performed durable work")
	}
	var pending bool
	if err := x.enable.f.pool.Raw().QueryRow(x.enable.f.ctx, `SELECT completed_at IS NULL AND verifier_envelope IS NOT NULL FROM sso_providers.login_transactions WHERE start_command_id=$1`, command).Scan(&pending); err != nil || !pending {
		t.Fatal("lookup consumed state or erased verifier custody", err)
	}
}

func TestProviderLoginCallbackLookupRetainsOldStateKeyAndRejectsAmbiguity(t *testing.T) {
	x := newProviderLoginStartFixture(t)
	state, command := startProviderLoginCallbackLookup(t, x)
	x.config.StateKeys[2], x.config.CurrentStateKey = [32]byte{0xb1}, 2
	reader, err := ssopg.NewProviderLoginService(newProviderRouter(t, x.enable, 4), x.config)
	if err != nil {
		t.Fatal("compose retained-key callback reader", err)
	}
	if got, err := ssopg.LookupProviderLoginCallbackForTest(x.enable.f.ctx, reader, state); err != nil || got.StartCommandID != command {
		t.Fatal("rotation lost the original retained-key login", err)
	}
	digest, err := ssopg.ProviderLoginCallbackStateDigestForTest(reader, 2, state)
	if err != nil {
		t.Fatal(err)
	}
	_, err = x.enable.f.pool.Raw().Exec(x.enable.f.ctx, `INSERT INTO sso_providers.login_transactions
 (tenant_id,organization_id,provider_id,provider_version,credential_generation,mapping_version,
 start_command_id,callback_command_id,protocol,state_key_version,state_digest,pkce_key_version,
 pkce_commitment,binding_envelope,verifier_envelope,issued_at,expires_at)
 SELECT tenant_id,organization_id,provider_id,provider_version,credential_generation,mapping_version,
 $2,$3,protocol,2,$4,pkce_key_version,pkce_commitment,binding_envelope,verifier_envelope,issued_at,expires_at
 FROM sso_providers.login_transactions WHERE start_command_id=$1`, command, string(commandID(t)), string(commandID(t)), digest)
	if err != nil {
		t.Fatal("seed second retained-version match", err)
	}
	assertProviderLoginCallbackDenied(t, x, reader, state)
}

func TestProviderLoginCallbackLookupUniformlyDeniesUntrustedStateAndTenant(t *testing.T) {
	x := newProviderLoginStartFixture(t)
	state, _ := startProviderLoginCallbackLookup(t, x)
	for name, value := range map[string]string{
		"absent": base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		"empty":  "", "oversized": strings.Repeat("A", 8192), "padding": state + "=",
		"newline": state[:20] + "\n" + state[20:], "short": state[:42], "alphabet": "+" + state[1:],
	} {
		t.Run(name, func(t *testing.T) { assertProviderLoginCallbackDenied(t, x, x.service, value) })
	}
	x.config.TenantID = "foreign-login-tenant"
	foreign, err := ssopg.NewProviderLoginService(newProviderRouter(t, x.enable, 4), x.config)
	if err != nil {
		t.Fatal("compose exact foreign service scope", err)
	}
	assertProviderLoginCallbackDenied(t, x, foreign, state)
}

func TestProviderLoginCallbackLookupRejectsEveryDurableBindingMismatch(t *testing.T) {
	for name, mutation := range map[string]string{
		"provider version":      "provider_version=provider_version+1",
		"credential generation": "credential_generation=credential_generation+1",
		"mapping version":       "mapping_version=mapping_version+1",
		"callback command":      "callback_command_id=$2",
		"PKCE key":              "pkce_key_version=2",
		"PKCE commitment":       "pkce_commitment=decode(repeat('b2',32),'hex')",
		"binding ciphertext":    "binding_envelope=decode('010203','hex')",
		"issued time":           "issued_at=issued_at-interval '1 second'",
		"expiry time":           "expires_at=expires_at-interval '1 second'",
	} {
		t.Run(name, func(t *testing.T) {
			x := newProviderLoginStartFixture(t)
			state, command := startProviderLoginCallbackLookup(t, x)
			args := []any{command}
			if name == "callback command" {
				args = append(args, string(commandID(t)))
			}
			if _, err := x.enable.f.pool.Raw().Exec(x.enable.f.ctx, "UPDATE sso_providers.login_transactions SET "+mutation+" WHERE start_command_id=$1", args...); err != nil {
				t.Fatal("mutate one durable binding field", err)
			}
			assertProviderLoginCallbackDenied(t, x, x.service, state)
		})
	}
}

func TestProviderLoginCallbackLookupTerminalRetainsHistoricalCorrelationWithoutProof(t *testing.T) {
	x := newProviderLoginStartFixture(t)
	state, _ := startProviderLoginCallbackLookup(t, x)
	before, err := ssopg.LookupProviderLoginCallbackForTest(x.enable.f.ctx, x.service, state)
	if err != nil {
		t.Fatal(err)
	}
	completed, err := ssopg.RecordProviderLoginCallbackTerminalForTest(x.enable.f.ctx, x.service, state)
	if err != nil {
		t.Fatal("record terminal original transaction", err)
	}
	got, err := ssopg.LookupProviderLoginCallbackForTest(x.enable.f.ctx, x.service, state)
	if err != nil || got.CompletedAt == nil || !got.CompletedAt.Equal(completed) || got.HasProof || got.HasPlan ||
		got.StartCommandID != before.StartCommandID || got.CallbackCommandID != before.CallbackCommandID ||
		!got.IssuedAt.Equal(before.IssuedAt) || !got.ExpiresAt.Equal(before.ExpiresAt) || got.Remember != before.Remember {
		t.Fatal("terminal lookup lost historical correlation or returned execution proof", err)
	}
}

func TestProviderLoginCallbackLookupExpiryDeniesPendingButRetainsTerminalHistory(t *testing.T) {
	for _, terminal := range []bool{false, true} {
		name := "pending"
		if terminal {
			name = "terminal"
		}
		t.Run(name, func(t *testing.T) {
			x := newProviderLoginStartFixture(t)
			state, command := startProviderLoginCallbackLookup(t, x)
			if err := ssopg.AgeProviderLoginCallbackForTest(x.enable.f.ctx, x.service, state, terminal); err != nil {
				t.Fatal("age genuine authenticated original binding", err)
			}
			if !terminal {
				assertProviderLoginCallbackDenied(t, x, x.service, state)
				return
			}
			got, err := ssopg.LookupProviderLoginCallbackForTest(x.enable.f.ctx, x.service, state)
			if err != nil || got.CompletedAt == nil || got.HasProof || got.HasPlan || got.StartCommandID != command || !got.ExpiresAt.Before(got.ObservedAt) {
				t.Fatal("retained terminal history lost correlation or gained live proof", err)
			}
		})
	}
}

func TestProviderLoginCallbackLookupRejectsMalformedStateBeforeDatabaseIO(t *testing.T) {
	x := newProviderLoginStartFixture(t)
	state, _ := startProviderLoginCallbackLookup(t, x)
	x.enable.f.pool.Raw().Close()
	assertProviderLoginCallbackDenied(t, x, x.service, state+"=")
	if _, err := ssopg.LookupProviderLoginCallbackForTest(x.enable.f.ctx, x.service, state); err == nil || errors.Is(err, sso.ErrForbidden) {
		t.Fatal("closed database did not distinguish a canonical state read failure")
	}
}

func TestProviderLoginCallbackLookupBoundsRetainedKeysBeforeDatabaseIO(t *testing.T) {
	x := newProviderLoginStartFixture(t)
	state, _ := startProviderLoginCallbackLookup(t, x)
	tooMany := make(map[uint32][32]byte)
	for version := uint32(1); version <= 33; version++ {
		tooMany[version] = [32]byte{byte(version)}
	}
	x.enable.f.pool.Raw().Close()
	for name, keys := range map[string]map[uint32][32]byte{
		"empty": {}, "too many": tooMany,
		"zero version": {0: {0xa7}, 1: {0xa7}}, "zero key": {1: {0xa7}, 2: {}},
	} {
		t.Run(name, func(t *testing.T) {
			reader := ssopg.ProviderLoginCallbackWithStateKeysForTest(x.service, keys)
			assertProviderLoginCallbackDenied(t, x, reader, state)
		})
	}
}

func assertProviderLoginCallbackDenied(t *testing.T, x providerLoginStartFixture, service *ssopg.ProviderLoginService, state string) {
	t.Helper()
	got, err := ssopg.LookupProviderLoginCallbackForTest(x.enable.f.ctx, service, state)
	if !errors.Is(err, sso.ErrForbidden) || !reflect.DeepEqual(got, ssopg.ProviderLoginCallbackLookupForTest{}) {
		t.Fatal("callback lookup did not uniformly deny without returning a continuation")
	}
}
