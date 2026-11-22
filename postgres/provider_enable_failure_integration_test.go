//go:build integration

package postgres_test

import (
	"reflect"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-sso"
)

func TestNativeProviderEnableAuditOutboxFailureRollsBackEntireSuccessor(t *testing.T) {
	for _, boundary := range []string{"audit", "outbox"} {
		t.Run(boundary, func(t *testing.T) {
			x := newProviderEnableFixture(t)
			f := x.f
			sql := `CREATE FUNCTION sso_providers.reject_enable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'controlled enable audit rollback'; END $$; CREATE TRIGGER reject_enable BEFORE INSERT ON audit.records FOR EACH ROW WHEN (NEW.action='identity.sso.provider.enable' AND NEW.outcome=1) EXECUTE FUNCTION sso_providers.reject_enable()`
			if boundary == "outbox" {
				sql = `CREATE FUNCTION sso_providers.reject_enable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'controlled enable outbox rollback'; END $$; CREATE TRIGGER reject_enable BEFORE INSERT ON outbox_messages FOR EACH ROW WHEN (NEW.topic='sso.provider_enabled.v1') EXECUTE FUNCTION sso_providers.reject_enable()`
			}
			if _, err := f.pool.Raw().Exec(f.ctx, sql); err != nil {
				t.Fatal("install required-effect failure", err)
			}

			out, err := x.service.ProviderEnable(f.ctx, x.request)
			if err == nil || out.Completion.Outcome == identity.CommitOutcomeCommitted || !reflect.DeepEqual(out.Provider, sso.Provider{}) {
				t.Fatal("failed required effect disclosed enabled successor", out.Completion.Outcome, err)
			}
			var enabled bool
			var version string
			var audits, events int
			if err = f.pool.Raw().QueryRow(f.ctx, `SELECT enabled,metadata_version::text,(SELECT count(*) FROM audit.records WHERE action='identity.sso.provider.enable' AND outcome=1),(SELECT count(*) FROM outbox_messages WHERE topic='sso.provider_enabled.v1') FROM sso_providers.providers WHERE provider_id=$1`, x.request.ProviderID).Scan(&enabled, &version, &audits, &events); err != nil || enabled || version != "2" || audits != 0 || events != 0 {
				t.Fatal("required-effect failure left partial enablement", enabled, version, audits, events, err)
			}
		})
	}
}

func TestNativeProviderEnableLostCommitRecoversOnlyOriginalSuccessor(t *testing.T) {
	x := newProviderEnableFixture(t)
	f := x.f
	lossy, fault := providerLossService(t, f, x.config, "UPDATE sso_providers.providers SET enabled=true")
	lossy, err := lossy.ForOrganization(string(x.proof.OrganizationID))
	if err != nil {
		t.Fatal("bind lossy service to original organization", err)
	}
	lossy, err = lossy.WithProviderEnableAuthorization(enablePolicy{})
	if err != nil {
		t.Fatal("configure lossy enablement authorization", err)
	}

	out, err := lossy.ProviderEnable(f.ctx, x.request)
	if !fault.seen.Load() || !fault.lost.Load() || err == nil || out.Completion.Outcome != identity.CommitOutcomeUnknown || !reflect.DeepEqual(out.Provider, sso.Provider{}) || out.Completion.Binding.CommandID == "" || out.Completion.Binding.RecordID != x.request.ProviderID {
		t.Fatal("lost acknowledged commit disclosed successor or lost original binding", fault.seen.Load(), fault.lost.Load(), out.Completion.Outcome, err)
	}

	recovered, err := x.service.ProviderEnable(f.ctx, x.request)
	if err != nil || recovered.Completion.Outcome != identity.CommitOutcomeCommitted || recovered.Completion.Binding != out.Completion.Binding || recovered.Provider.ID != x.request.ProviderID || !recovered.Provider.Enabled || recovered.Provider.Version != 3 || recovered.Provider.MappingVersion != 1 || !reflect.DeepEqual(recovered.Provider.VerifiedDomains, []string{x.proof.Domain}) {
		t.Fatal("same-key retry did not recover original enabled successor", recovered.Completion.Outcome, err)
	}
	replay, err := x.service.ProviderEnable(f.ctx, x.request)
	if err != nil || replay.Completion.Outcome != identity.CommitOutcomeCommitted || !reflect.DeepEqual(replay.Provider, recovered.Provider) || replay.Completion.Binding != recovered.Completion.Binding || replay.Completion.AuditEventID != recovered.Completion.AuditEventID {
		t.Fatal("original replay changed committed result", err)
	}
	var enabled bool
	var version string
	var providers, credentials, audits, events int
	if err = f.pool.Raw().QueryRow(f.ctx, `SELECT enabled,metadata_version::text,(SELECT count(*) FROM sso_providers.providers),(SELECT count(*) FROM sso_providers.credentials),(SELECT count(*) FROM audit.records WHERE action='identity.sso.provider.enable' AND outcome=1),(SELECT count(*) FROM outbox_messages WHERE topic='sso.provider_enabled.v1') FROM sso_providers.providers WHERE provider_id=$1`, x.request.ProviderID).Scan(&enabled, &version, &providers, &credentials, &audits, &events); err != nil || !enabled || version != "3" || providers != 1 || credentials != 1 || audits != 1 || events != 1 {
		t.Fatal("original recovery repeated durable enablement effects", enabled, version, providers, credentials, audits, events, err)
	}
}
