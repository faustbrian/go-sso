//go:build integration

package postgres_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

type directoryBrowserPolicyFunc func(context.Context, authorization.DecisionContext, uint64) (ssopg.ProviderUpdateAuthorizationEvidence, error)

func (f directoryBrowserPolicyFunc) ObserveDirectorySyncAuthorization(ctx context.Context, dc authorization.DecisionContext, epoch uint64) (ssopg.ProviderUpdateAuthorizationEvidence, error) {
	return f(ctx, dc, epoch)
}

func TestNativeDirectorySyncBrowserAdministration(t *testing.T) {
	const tenant = "org-test-basic"
	x := newProviderEnableFixtureForTenant(t, tenant, sessionpg.CSRFMigrationSource{Schema: "organization_sessions", Version: 319})
	f := x.f
	installNativeDirectoryGeneration(t, f, ssopg.ProviderCredentialsMigrationSource{Version: 322}, ssopg.ProviderEnableMigrationSource{Version: 323})
	enabled, err := x.service.ProviderEnable(f.ctx, x.request)
	if err != nil || !enabled.Provider.Enabled {
		t.Fatal("enable native directory provider", err)
	}
	key, err := session.NewCSRFKey(1, []byte("directory-admin-fixture-csrf-key"))
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := session.NewCSRFToken()
	if err != nil {
		t.Fatal(err)
	}
	setCSRF := func(ctx context.Context, token session.CSRFToken) error {
		state, err := token.Digest(key, session.CSRFBinding{TenantID: tenant, SessionID: "session-owner", SessionVersion: 1})
		if err != nil {
			return err
		}
		projection, err := state.Bindings()
		if err != nil {
			return err
		}
		wire, err := json.Marshal(projection)
		if err != nil {
			return err
		}
		_, err = f.pool.Raw().Exec(ctx, `UPDATE organization_sessions.sessions
 SET record = record || jsonb_build_object('Schema', 2, 'CSRF', $1::jsonb)
 WHERE tenant_id=$2 AND session_id='session-owner'`, wire, tenant)
		return err
	}
	if err := setCSRF(f.ctx, csrf); err != nil {
		t.Fatal("select digest-only cookie state in the native session fixture", err)
	}
	readConfig := ssopg.DirectorySyncBrowserConfig{
		TenantID: tenant, Cookie: f.auth(tenant, "owner").Bearer,
		Network: "127.0.0.1", OrganizationID: string(x.proof.OrganizationID),
		ConnectionID: "browser-source", Authority: directoryAdminPolicy{}, CSRFKeys: []session.CSRFKey{key},
	}
	selectBrowser := func(config ssopg.DirectorySyncBrowserConfig) *ssopg.DirectorySyncService {
		t.Helper()
		s, err := ssopg.NewDirectorySyncBrowserService(f.pool, x.config, config)
		if err != nil {
			t.Fatal("configure selected native directory browser administration", err)
		}
		return s
	}
	start := ssopg.DirectorySyncStartRequest{ProviderID: sso.ProviderID(enabled.Provider.ID),
		ProviderVersion: enabled.Provider.Version, MappingVersion: 1, Mode: ssopg.DirectorySyncApply,
		Key: directoryGenerationKey(t, "directory-browser-original-start")}
	read := selectBrowser(readConfig)
	if result, err := read.Start(f.ctx, start); !errors.Is(err, sso.ErrForbidden) || result.Generation.ID != "" {
		t.Fatal("cookie without CSRF entered native write", err)
	}
	wrong, err := session.NewCSRFToken()
	if err != nil {
		t.Fatal(err)
	}
	wrongConfig := readConfig
	wrongConfig.CSRF = wrong
	if result, err := selectBrowser(wrongConfig).Start(f.ctx, start); !errors.Is(err, sso.ErrForbidden) || result.Generation.ID != "" {
		t.Fatal("wrong CSRF entered native write", err)
	}
	legacy, err := x.base.DirectorySync("browser-source", directoryAdminPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	if result, err := legacy.Start(f.ctx, start); !errors.Is(err, sso.ErrForbidden) || result.Generation.ID != "" {
		t.Fatal("legacy bearer entry accepted cookie custody", err)
	}
	writeConfig := readConfig
	writeConfig.CSRF = csrf
	rotatingConfig := writeConfig
	rotatingConfig.Authority = directoryBrowserPolicyFunc(func(ctx context.Context, dc authorization.DecisionContext, epoch uint64) (ssopg.ProviderUpdateAuthorizationEvidence, error) {
		if err := setCSRF(ctx, wrong); err != nil {
			return ssopg.ProviderUpdateAuthorizationEvidence{}, err
		}
		return (directoryAdminPolicy{}).ObserveDirectorySyncAuthorization(ctx, dc, epoch)
	})
	rotatingStart := start
	rotatingStart.Key = directoryGenerationKey(t, "directory-browser-stale-csrf-start")
	stale, err := selectBrowser(rotatingConfig).Start(f.ctx, rotatingStart)
	if !errors.Is(err, sso.ErrForbidden) || stale.Generation.ID != "" || stale.Completion.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("changed primary CSRF record was not rejected inside Work", err)
	}
	if err := setCSRF(f.ctx, csrf); err != nil {
		t.Fatal("restore fixture CSRF state", err)
	}
	write := selectBrowser(writeConfig)
	created, err := write.Start(f.ctx, start)
	if err != nil || created.Completion.Outcome != identity.CommitOutcomeCommitted || created.Generation.ID == "" {
		t.Fatal("native cookie/CSRF start did not commit", err)
	}
	status, err := read.Status(f.ctx, created.Generation.ID)
	if err != nil || status != created.Generation || status.Version != 1 || status.State != ssopg.DirectorySyncRunning {
		t.Fatal("cookie read did not return the original safe projection", err)
	}
	keylessCancel := func(s *ssopg.DirectorySyncService) (ssopg.DirectorySyncCancelResult, error) {
		return s.CancelExact(f.ctx, created.Generation.ID, status.Version)
	}
	if result, err := keylessCancel(read); !errors.Is(err, sso.ErrForbidden) || result.Generation.ID != "" {
		t.Fatal("cookie without CSRF entered native cancellation", err)
	}
	canceled, err := keylessCancel(write)
	if err != nil || canceled.Completion.Outcome != identity.CommitOutcomeCommitted ||
		canceled.Generation.State != ssopg.DirectorySyncCanceled || canceled.Generation.Version != status.Version+1 ||
		canceled.Generation.Checkpoint != status.Checkpoint {
		t.Fatal("exact keyless native cancel did not retain the checkpoint", err)
	}
	repeated, err := keylessCancel(write)
	if err != nil || repeated.Generation != canceled.Generation || repeated.Completion.Binding != canceled.Completion.Binding ||
		repeated.Completion.AuditEventID != canceled.Completion.AuditEventID {
		t.Fatal("keyless native cancel replay did not recover original custody", err)
	}
}
