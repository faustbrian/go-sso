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
	database "github.com/faustbrian/go-postgres"
	scim "github.com/faustbrian/go-scim"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/jackc/pgx/v5"
)

type directoryBatchDriftProjectionTrace struct {
	read func(context.Context, pgx.TraceQueryStartData)
}

func (t directoryBatchDriftProjectionTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, query pgx.TraceQueryStartData) context.Context {
	if strings.HasPrefix(query.SQL, "SELECT\n EXISTS(SELECT 1 FROM organization.team_memberships local ") {
		t.read(ctx, query)
	}
	return ctx
}

func (directoryBatchDriftProjectionTrace) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {
}

func TestNativeDirectoryBatchDriftRejectsSecondSourceEdgeChangedDuringObservation(t *testing.T) {
	multi, _ := newDirectoryBatchDriftFixture(t)
	fixture := multi.fixture
	f := fixture.provider.f
	request := directoryDriftRequest(multi.generation, multi.batch)
	current, err := fixture.groups.Execute(f.ctx, scim.Request{
		Operation: scim.GroupGet, Credential: fixture.bearer, ResourceID: multi.secondGroupID,
	})
	if err != nil || current.Status != 200 || current.ETag == "" {
		t.Fatal("read the initially absent second source edge", err)
	}
	before := captureDirectoryBatchDriftState(t, multi)
	var afterMutation directoryBatchDriftState
	reads, changed, invalidTarget := 0, false, false
	var changeErr error
	trace := directoryBatchDriftProjectionTrace{read: func(ctx context.Context, query pgx.TraceQueryStartData) {
		reads++
		if reads != 1 {
			return
		}
		if !reflect.DeepEqual(query.Args, []any{
			string(fixture.scope.TenantID), string(fixture.scope.OrganizationID), fixture.scope.ProviderID,
			fixture.scope.ConnectionID, fixture.groupID, directoryTestTeam, fixture.userID,
		}) {
			invalidTarget = true
			return
		}
		assertDirectoryBatchDriftUnchanged(t, multi, before)
		// The source batch has been observed before the first local projection.
		// Use the original pool so this public SCIM write cannot reenter the tracer.
		response, err := fixture.groups.Execute(ctx, scim.Request{
			Operation: scim.GroupReplace, Credential: fixture.bearer, ResourceID: multi.secondGroupID, IfMatch: current.ETag,
			IdempotencyKey: "native-directory-batch-drift-second-race", ContentType: "application/scim+json",
			Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Second directory group","members":[{"type":"User","value":"` + fixture.userID + `"}]}`),
		})
		changeErr = err
		changed = err == nil && response.Status == 200 && response.ETag != "" && response.ETag != current.ETag
		afterMutation = captureDirectoryBatchDriftState(t, multi)
	}}
	pool, err := database.Connect(f.ctx, database.Config{DSN: f.dsn, MaxConns: 2, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database, c.ConnConfig.Tracer = f.database, trace
		return nil
	}})
	if err != nil {
		t.Fatal("connect the isolated batch-preview observation pool", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := pool.Close(ctx); err != nil {
			t.Error("close isolated batch drift source-fence pool", err)
		}
	})

	config := multi.config
	inspection := directoryServicePolicy(func(d authorization.DecisionContext) bool {
		return d.Request.Tenant == authorization.TenantID(fixture.scope.TenantID) &&
			d.Request.Subject.Kind == authorization.SubjectServiceAccount && d.Request.Subject.ID == directoryTestActor &&
			d.Request.Action == "identity.sso.directory-sync-inspect-drift"
	})
	config.ApplyAuthorization = directoryGroupPolicy(func(ctx context.Context, d authorization.DecisionContext, epoch uint64) (ssopg.ProviderUpdateAuthorizationEvidence, error) {
		decision, err := inspection.Decide(ctx, d)
		return ssopg.ProviderUpdateAuthorizationEvidence{Context: d, Decision: decision, ActorAuthorizationVersion: epoch,
			ValidUntil: d.Request.Environment.Time.Add(5 * time.Second)}, err
	})
	providerConfig := fixture.provider.config
	inspector, err := ssopg.NewDirectoryGroupSyncService(pool, ssopg.DirectoryGroupSyncConfig{
		TenantID: fixture.scope.TenantID, OrganizationID: fixture.scope.OrganizationID, ConnectionID: fixture.scope.ConnectionID,
		Clock: providerConfig.Clock, MaximumDuration: providerConfig.MaximumDuration,
		PolicyID: providerConfig.PolicyID, PolicyVersion: providerConfig.PolicyVersion, Coordinator: providerConfig.Coordinator,
	}, config)
	if err != nil {
		t.Fatal("compose separately authorized batch inspection on the traced pool", err)
	}

	report, err := inspector.ObserveBatchDrift(f.ctx, request)
	if reads == 0 || invalidTarget || !changed || changeErr != nil {
		t.Fatal("the second real SCIM edge did not change after the source snapshot and before local observation", reads, changeErr)
	}
	if !errors.Is(err, sso.ErrDirectoryReconciliation) || report != nil {
		t.Fatal("a changed second source edge disclosed a complete or partial drift report", err)
	}
	if afterMutation.original.generation != before.original.generation ||
		afterMutation.original.membership != before.original.membership || afterMutation.secondMembership != before.secondMembership {
		t.Fatal("the fixture's source-only mutation changed the generation or either local/source grant")
	}
	assertDirectoryBatchDriftUnchanged(t, multi, afterMutation)
}
