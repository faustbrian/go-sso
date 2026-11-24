//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
)

type directoryAdminPolicy struct{ deny bool }

func (p directoryAdminPolicy) ObserveDirectorySyncAuthorization(ctx context.Context, dc authorization.DecisionContext, epoch uint64) (ssopg.ProviderUpdateAuthorizationEvidence, error) {
	return (enablePolicy{deny: p.deny}).ObserveProviderEnableAuthorization(ctx, dc, epoch)
}

func TestNativeDirectorySyncStartsAndReadsExactGeneration(t *testing.T) {
	x := newProviderEnableFixture(t)
	f := x.f
	installNativeDirectoryGeneration(t, f, ssopg.ProviderCredentialsMigrationSource{Version: 322}, ssopg.ProviderEnableMigrationSource{Version: 323})
	service, err := x.base.DirectorySync("source-a", directoryAdminPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	disabled := ssopg.DirectorySyncStartRequest{
		ProviderID: sso.ProviderID(x.request.ProviderID), ProviderVersion: 2,
		MappingVersion: 1, Mode: ssopg.DirectorySyncApply, Key: directoryGenerationKey(t, "directory-disabled"),
	}
	if out, err := service.Start(f.ctx, disabled); err == nil || out.Generation.ID != "" {
		t.Fatal("disabled provider started directory sync", err)
	}
	enabled, err := x.service.ProviderEnable(f.ctx, x.request)
	if err != nil || !enabled.Provider.Enabled {
		t.Fatal("enable native predecessor", err)
	}
	req := disabled
	req.ProviderVersion = enabled.Provider.Version
	req.Key = directoryGenerationKey(t, "directory-start-one")
	req.Checkpoint[0] = 0xab
	denied, err := x.base.DirectorySync("source-a", directoryAdminPolicy{deny: true})
	if err != nil {
		t.Fatal(err)
	}
	if out, err := denied.Start(f.ctx, req); !errors.Is(err, sso.ErrForbidden) || out.Generation.ID != "" {
		t.Fatal("policy denial exposed or created a generation", err)
	}
	first, err := service.Start(f.ctx, req)
	if err != nil || first.Completion.Outcome != identity.CommitOutcomeCommitted ||
		first.Generation.ID == "" || first.Generation.Number != 1 || first.Generation.State != ssopg.DirectorySyncRunning ||
		first.Generation.Provider != req.ProviderID || first.Generation.Checkpoint != req.Checkpoint {
		t.Fatalf("start: %#v, %v", first, err)
	}
	buckets, charges := directoryGenerationResourceCounters(t, f)
	replayed, err := service.Start(f.ctx, req)
	if err != nil || replayed.Generation != first.Generation || replayed.Completion.Binding != first.Completion.Binding {
		t.Fatal("same keyed intent did not replay original creation", err)
	}
	if gotBuckets, gotCharges := directoryGenerationResourceCounters(t, f); gotBuckets != buckets || gotCharges != charges {
		t.Fatal("original replay charged another protected counter")
	}
	mismatch := req
	mismatch.Checkpoint[0]++
	if out, err := service.Start(f.ctx, mismatch); !errors.Is(err, sso.ErrConflict) || out.Generation.ID != "" {
		t.Fatal("same key attached to changed cursor", err)
	}
	mismatch = req
	mismatch.Key = directoryGenerationKey(t, "directory-start-two")
	if out, err := service.Start(f.ctx, mismatch); !errors.Is(err, sso.ErrConflict) || out.Generation.ID != "" {
		t.Fatal("a second key attached while the source was live", err)
	}
	if gotBuckets, gotCharges := directoryGenerationResourceCounters(t, f); gotBuckets != buckets || gotCharges != charges+1 {
		t.Fatal("new attempt did not charge the same source budget")
	}
	status, err := service.Status(f.ctx, first.Generation.ID)
	if err != nil || status != first.Generation {
		t.Fatal("status did not read the admitted generation", err)
	}
	other, err := x.base.DirectorySync("source-b", directoryAdminPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	if status, err := other.Status(f.ctx, first.Generation.ID); !errors.Is(err, sso.ErrForbidden) || status.ID != "" {
		t.Fatal("cross-connection generation disclosure", err)
	}
	mismatch.Mode = ssopg.DirectorySyncDryRun
	mismatch.Key = directoryGenerationKey(t, "directory-start-source-b")
	separate, err := other.Start(f.ctx, mismatch)
	if err != nil || separate.Generation.ID == first.Generation.ID || separate.Generation.Mode != ssopg.DirectorySyncDryRun {
		t.Fatal("independent connection did not get its own dry-run generation", err)
	}
	if gotBuckets, gotCharges := directoryGenerationResourceCounters(t, f); gotBuckets != buckets+1 || gotCharges != charges+2 {
		t.Fatal("independent connection did not acquire its distinct resource budget")
	}
}

func TestNativeDirectorySyncLostCommitRecoversOriginalStart(t *testing.T) {
	x := newProviderEnableFixture(t)
	f := x.f
	installNativeDirectoryGeneration(t, f, ssopg.ProviderCredentialsMigrationSource{Version: 322}, ssopg.ProviderEnableMigrationSource{Version: 323})
	enabled, err := x.service.ProviderEnable(f.ctx, x.request)
	if err != nil || !enabled.Provider.Enabled {
		t.Fatal("enable native directory provider", err)
	}
	lossy, fault := providerLossService(t, f, x.config, "INSERT INTO sso_providers.directory_sync_generations")
	lossy, err = lossy.ForOrganization(string(x.proof.OrganizationID))
	if err != nil {
		t.Fatal(err)
	}
	start, err := lossy.DirectorySync("source-loss", directoryAdminPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	request := ssopg.DirectorySyncStartRequest{
		ProviderID: sso.ProviderID(enabled.Provider.ID), ProviderVersion: enabled.Provider.Version, MappingVersion: 1,
		Mode: ssopg.DirectorySyncApply, Key: directoryGenerationKey(t, "directory-start-lost-commit"),
	}
	unknown, err := start.Start(f.ctx, request)
	if !fault.seen.Load() || !fault.lost.Load() || err == nil || unknown.Completion.Outcome != identity.CommitOutcomeUnknown ||
		unknown.Completion.Binding.CommandID == "" || unknown.Generation != (ssopg.DirectorySyncGeneration{}) {
		t.Fatal("lost acknowledgement disclosed a generation or lost the original command", unknown.Completion.Outcome, err)
	}
	service, err := x.base.DirectorySync("source-loss", directoryAdminPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := service.Start(f.ctx, request)
	if err != nil || recovered.Completion.Outcome != identity.CommitOutcomeCommitted ||
		recovered.Completion.Binding != unknown.Completion.Binding || recovered.Generation.ID != unknown.Completion.Binding.CommandID ||
		recovered.Generation.Number != 1 || recovered.Generation.State != ssopg.DirectorySyncRunning {
		t.Fatal("original key did not recover the exact creation", recovered.Completion.Outcome, err)
	}
	var generations, audits, events int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT count(*) FROM sso_providers.directory_sync_generations WHERE connection_id='source-loss'),
 (SELECT count(*) FROM audit.records WHERE action='identity.sso.directory-sync-start' AND outcome=1),
 (SELECT count(*) FROM outbox_messages WHERE topic='sso.directory_sync.started.v1')`).Scan(&generations, &audits, &events); err != nil ||
		generations != 1 || audits != 1 || events != 1 {
		t.Fatal("recovery repeated the protected effects", generations, audits, events, err)
	}
}

func directoryGenerationResourceCounters(t *testing.T, f *orgFixture) (int, int) {
	t.Helper()
	var buckets, charges int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*),COALESCE(sum(value),0)::integer
 FROM organization_risk.counter_windows WHERE tenant_id='org-test-basic'
 AND operation='identity.sso.directory-sync-start' AND dimension='target_or_resource'`).Scan(&buckets, &charges); err != nil {
		t.Fatal("read real resource budget", err)
	}
	return buckets, charges
}

func directoryGenerationKey(t *testing.T, text string) identity.IdempotencyKey {
	t.Helper()
	key, err := identity.NewIdempotencyKey([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestNativeDirectoryGenerationSerializesOneActiveSource(t *testing.T) {
	f, providers, _ := newProviderFixture(t)
	request := providerRequest(t, "https://directory-generation.example.com", "directory-generation-provider")
	provider, err := providers.ProviderRegisterOidc(f.ctx, request)
	if err != nil || provider.Completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("seed installed provider", err)
	}

	installNativeDirectoryGeneration(t, f)

	const tenant = "org-test-basic"
	checkpoint := make([]byte, 32)
	checkpoint[0] = 1
	const insert = `INSERT INTO sso_providers.directory_sync_generations
 (tenant_id,organization_id,provider_id,connection_id,generation,generation_id,provider_version,mapping_version,mode,state,checkpoint,initial_checkpoint)
 VALUES($1,$2,$3,$4,$5::numeric,$6,1,1,'apply',$7,$8,$8)`
	write := func(connection, generation, state string, checkpoint []byte) (identity.CommandID, error) {
		t.Helper()
		command, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.pool.Raw().Exec(f.ctx, insert, tenant, request.OrganizationID, provider.Provider.ID, connection, generation, string(command), state, checkpoint)
		return command, err
	}
	failed := func(err error, code string) {
		t.Helper()
		var pgerr *pgconn.PgError
		if !errors.As(err, &pgerr) || pgerr.Code != code {
			t.Fatalf("expected durable admission error %s: %v", code, err)
		}
	}
	first, err := write("source-a", "1", "running", checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	_, err = write("source-a", "2", "running", checkpoint)
	failed(err, "23505")
	if _, err := write("source-b", "1", "running", checkpoint); err != nil {
		t.Fatal("other connection was serialized against source-a", err)
	}
	_, err = write("source-c", "1", "running", make([]byte, 32))
	failed(err, "23514")
	_, err = write("source-c", "1", "reconciling", checkpoint)
	failed(err, "23514")

	tag, err := f.pool.Raw().Exec(f.ctx, `UPDATE sso_providers.directory_sync_generations
 SET state='canceled',version=version+1 WHERE generation_id=$1 AND state='running'`, string(first))
	if err != nil || tag.RowsAffected() != 1 {
		t.Fatal("close original generation", err)
	}
	if _, err := write("source-a", "2", "running", checkpoint); err != nil {
		t.Fatal("same source could not open its successor", err)
	}
	var retainedState string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT state FROM sso_providers.directory_sync_generations WHERE generation_id=$1`, string(first)).Scan(&retainedState); err != nil || retainedState != "canceled" {
		t.Fatal("successor erased original source status", err)
	}
}

func installNativeDirectoryGeneration(t *testing.T, f *orgFixture, prior ...migrations.Source) {
	t.Helper()
	additions, err := (ssopg.DirectorySyncGenerationMigrationSource{Version: 699}).Load(f.ctx)
	if err != nil || len(additions) != 1 {
		t.Fatal("load directory generation migration", err)
	}
	cfg, err := pgx.ParseConfig(f.dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Database = f.database
	db := stdlib.OpenDB(*cfg)
	defer db.Close()
	backend, err := migrationpg.New(db)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := (ssopg.ProviderUpdateMigrationSource{Version: 321}).Load(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	history := append(append(migrationList(nil), f.history...), metadata...)
	for _, src := range prior {
		loaded, err := src.Load(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		history = append(history, loaded...)
	}
	history = append(history, additions...)
	runner, err := migrations.NewRunner(history, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(f.ctx); err != nil {
		t.Fatal("install directory generations over existing provider", err)
	}

}
