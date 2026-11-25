//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	database "github.com/faustbrian/go-postgres"
	scimorganization "github.com/faustbrian/go-scim/organization"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/jackc/pgx/v5"
)

type directoryDriftProviderFenceTrace struct {
	read func(context.Context, pgx.TraceQueryStartData)
}

func (t directoryDriftProviderFenceTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, query pgx.TraceQueryStartData) context.Context {
	if strings.HasPrefix(query.SQL, "SELECT metadata_version::text,COALESCE(metadata_mapping_version,mapping_version)::text,enabled") {
		t.read(ctx, query)
	}
	return ctx
}

func (directoryDriftProviderFenceTrace) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {
}

func TestNativeDirectoryDriftRejectsProviderDisabledDuringObservation(t *testing.T) {
	x := newDirectoryGroupApplyFixture(t)
	f := x.provider.f
	generation := x.start(t)
	batch := x.batch(t, generation, sso.DirectoryMembershipAdd)
	request := ssopg.DirectoryGroupApplyRequest{GenerationID: generation.ID, ProviderID: generation.Provider,
		MappingVersion: generation.MappingVersion, PredecessorCheckpoint: generation.Checkpoint, Deltas: batch.Deltas}
	grant := organizationpg.DirectoryTeamGrantScope{
		TenantID: x.scope.TenantID, OrganizationID: x.scope.OrganizationID,
		ProviderID: organization.ID(x.scope.ProviderID), ConnectionID: organization.ID(x.scope.ConnectionID),
		GroupID: organization.ID(x.groupID), TeamID: directoryTestTeam, UserID: identity.UserID(x.userID),
	}
	repository, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	beforeTarget, err := repository.ObserveDirectoryTeamMembership(f.ctx, grant)
	if err != nil || beforeTarget.Source || !beforeTarget.Local || beforeTarget.Version != 0 {
		t.Fatal("fixture must begin with only an independent local grant", err)
	}
	readGeneration := func() string {
		t.Helper()
		var retained string
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT row_to_json(g)::text FROM sso_providers.directory_sync_generations g
 WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4 AND generation_id=$5`,
			string(x.scope.TenantID), string(x.scope.OrganizationID), x.scope.ProviderID, x.scope.ConnectionID, string(generation.ID)).Scan(&retained); err != nil {
			t.Fatal("read the full retained generation, including pending work", err)
		}
		return retained
	}
	beforeGeneration := readGeneration()

	const providerAuthoritySQL = `SELECT metadata_version::text,COALESCE(metadata_mapping_version,mapping_version)::text,enabled
 FROM sso_providers.providers WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`
	reads, changed, invalidProviderQuery := 0, false, false
	var changeErr error
	trace := directoryDriftProviderFenceTrace{read: func(ctx context.Context, query pgx.TraceQueryStartData) {
		reads++
		if query.SQL != providerAuthoritySQL || !reflect.DeepEqual(query.Args, []any{
			string(x.scope.TenantID), string(x.scope.OrganizationID), x.scope.ProviderID,
		}) {
			invalidProviderQuery = true
			return
		}
		if reads != 2 {
			return
		}
		result, err := f.pool.Raw().Exec(ctx, `UPDATE sso_providers.providers SET enabled=false,enablement_proof=NULL,enablement_credential_generation=NULL
 WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`,
			string(x.scope.TenantID), string(x.scope.OrganizationID), x.scope.ProviderID)
		changeErr = err
		changed = err == nil && result.RowsAffected() == 1
	}}
	pool, err := database.Connect(f.ctx, database.Config{DSN: f.dsn, MaxConns: 2, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database, c.ConnConfig.Tracer = f.database, trace
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := pool.Close(ctx); err != nil {
			t.Error("close isolated drift provider-fence pool", err)
		}
	})
	policy := directoryServicePolicy(func(d authorization.DecisionContext) bool {
		return d.Request.Tenant == authorization.TenantID(x.scope.TenantID) &&
			d.Request.Subject.Kind == authorization.SubjectServiceAccount && d.Request.Subject.ID == directoryTestActor &&
			d.Request.Action == "identity.sso.directory-sync-inspect-drift"
	})
	inspections := 0
	edges := x.workerConfig(t)
	edges.Authorization = policy
	edges.ApplyAuthorization = directoryGroupPolicy(func(ctx context.Context, d authorization.DecisionContext, version uint64) (ssopg.ProviderUpdateAuthorizationEvidence, error) {
		inspections++
		decision, err := policy.Decide(ctx, d)
		return ssopg.ProviderUpdateAuthorizationEvidence{Context: d, Decision: decision, ActorAuthorizationVersion: version,
			ValidUntil: d.Request.Environment.Time.Add(5 * time.Second)}, err
	})
	providerConfig := x.provider.config
	worker, err := ssopg.NewDirectoryGroupSyncService(pool, ssopg.DirectoryGroupSyncConfig{
		TenantID: x.scope.TenantID, OrganizationID: x.scope.OrganizationID, ConnectionID: x.scope.ConnectionID,
		Clock: providerConfig.Clock, MaximumDuration: providerConfig.MaximumDuration,
		PolicyID: providerConfig.PolicyID, PolicyVersion: providerConfig.PolicyVersion, Coordinator: providerConfig.Coordinator,
	}, edges)
	if err != nil {
		t.Fatal("compose the native drift inspector", err)
	}

	report, err := worker.ObserveDrift(f.ctx, request)
	if reads != 2 || invalidProviderQuery || !changed || changeErr != nil || inspections == 0 {
		t.Fatal("provider disable must occur at the final exact-key fence after valid inspection authorization", reads, inspections, changeErr)
	}
	if !errors.Is(err, sso.ErrForbidden) || report != (scimorganization.DirectoryMembershipDrift{}) {
		t.Fatal("provider disabled during observation disclosed a usable drift report", err)
	}
	if readGeneration() != beforeGeneration {
		t.Fatal("denied drift inspection changed the generation or pending work")
	}
	afterTarget, err := repository.ObserveDirectoryTeamMembership(f.ctx, grant)
	if err != nil || afterTarget != beforeTarget {
		t.Fatal("denied drift inspection changed source attribution, the local grant or target versions", err)
	}
}
