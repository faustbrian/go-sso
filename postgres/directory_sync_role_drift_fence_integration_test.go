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
	database "github.com/faustbrian/go-postgres"
	scim "github.com/faustbrian/go-scim"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/jackc/pgx/v5"
)

type directoryRoleDriftAttributionTrace struct {
	read func(context.Context, pgx.TraceQueryStartData)
}

func (t directoryRoleDriftAttributionTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, query pgx.TraceQueryStartData) context.Context {
	if strings.HasPrefix(query.SQL, "SELECT\n EXISTS(SELECT 1 FROM organization.team_memberships local ") &&
		strings.Contains(query.SQL, "LEFT JOIN organization.directory_team_role_grants d ") {
		t.read(ctx, query)
	}
	return ctx
}

func (directoryRoleDriftAttributionTrace) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {
}

func TestNativeDirectoryRoleDriftRejectsOwnerChangedDuringObservation(t *testing.T) {
	for _, test := range []struct {
		name         string
		mutationRead int
	}{
		{name: "selected source edge", mutationRead: 1},
		{name: "retained binding epoch", mutationRead: 2},
		{name: "current binding epoch", mutationRead: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			x, config, _ := newDirectoryRoleJourney(t)
			f := x.provider.f
			worker, _ := directoryRoleDriftWorkers(t, x, config)
			generation := x.start(t)
			request := directoryRoleDriftRequest(generation, x.batch(t, generation, sso.DirectoryMembershipAdd))
			applied, err := worker.ApplyGeneration(f.ctx, request)
			if err != nil || len(applied.ChildOutcomes) != 1 || applied.ChildOutcomes[0].Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("establish the exact retained role through ordinary Apply", err)
			}
			request.PredecessorCheckpoint = applied.Checkpoint
			before := captureDirectoryRoleDriftState(t, x, generation.ID)
			if !before.attribution.Membership.Source || before.attribution.RetainedGrantVersion == 0 ||
				before.attribution.CurrentBindingVersion != before.attribution.RetainedBindingVersion {
				t.Fatal("fixture must begin with current source and matching retained/native role binding")
			}

			var afterMutation directoryRoleDriftState
			reads, changed, invalidTarget := 0, false, false
			var changeErr error
			var changedRevision scim.Version
			trace := directoryRoleDriftAttributionTrace{read: func(ctx context.Context, query pgx.TraceQueryStartData) {
				reads++
				if !reflect.DeepEqual(query.Args, []any{
					string(x.scope.TenantID), string(x.scope.OrganizationID), x.scope.ProviderID, x.scope.ConnectionID,
					x.groupID, directoryTestTeam, directoryRoleReader, "directory-reader",
				}) {
					invalidTarget = true
					return
				}
				if reads != test.mutationRead {
					return
				}
				assertDirectoryRoleDriftUnchanged(t, x, generation.ID, before)
				// The source keeps the original pool, so neither this SCIM write
				// nor fixture snapshots can reenter the traced owner observation.
				switch test.name {
				case "selected source edge":
					response, err := x.groups.Execute(ctx, scim.Request{
						Operation: scim.GroupReplace, Credential: x.bearer, ResourceID: x.groupID, IfMatch: x.groupETag,
						IdempotencyKey: "native-directory-role-drift-source-fence", ContentType: "application/scim+json",
						Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Directory group","members":[]}`),
					})
					changeErr, changedRevision = err, response.ETag
					changed = err == nil && response.Status == 200 && response.ETag != "" && response.ETag != x.groupETag
				case "retained binding epoch":
					result, err := f.pool.Raw().Exec(ctx, `UPDATE organization.directory_team_role_grants SET binding_version=binding_version+1
 WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$3 AND provider_id=$4 AND connection_id=$5 AND group_id=$6 AND team_id=$7`,
						string(x.scope.TenantID), string(x.scope.OrganizationID), directoryRoleReader, x.scope.ProviderID, x.scope.ConnectionID, x.groupID, directoryTestTeam)
					changeErr, changed = err, err == nil && result.RowsAffected() == 1
				case "current binding epoch":
					result, err := f.pool.Raw().Exec(ctx, `UPDATE organization.team_role_bindings SET version=version+1
 WHERE tenant_id=$1 AND organization_id=$2 AND team_id=$3 AND role_id=$4 AND state='active'`,
						string(x.scope.TenantID), string(x.scope.OrganizationID), directoryTestTeam, "directory-reader")
					changeErr, changed = err, err == nil && result.RowsAffected() == 1
				}
				afterMutation = captureDirectoryRoleDriftState(t, x, generation.ID)
			}}
			pool, err := database.Connect(f.ctx, database.Config{DSN: f.dsn, MaxConns: 2, Configure: func(c *database.PoolConfig) error {
				c.ConnConfig.Database, c.ConnConfig.Tracer = f.database, trace
				return nil
			}})
			if err != nil {
				t.Fatal("connect the isolated role-attribution observation pool", err)
			}
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := pool.Close(ctx); err != nil {
					t.Error("close the isolated role drift owner-fence pool", err)
				}
			})
			inspection := directoryServicePolicy(func(d authorization.DecisionContext) bool {
				return d.Request.Tenant == authorization.TenantID(x.scope.TenantID) &&
					d.Request.Subject.Kind == authorization.SubjectServiceAccount && d.Request.Subject.ID == directoryTestActor &&
					d.Request.Action == "identity.sso.directory-sync-inspect-role-drift"
			})
			config.ApplyAuthorization = directoryRolePolicy(func(ctx context.Context, d authorization.DecisionContext, epoch uint64) (ssopg.ProviderUpdateAuthorizationEvidence, error) {
				decision, err := inspection.Decide(ctx, d)
				return ssopg.ProviderUpdateAuthorizationEvidence{Context: d, Decision: decision, ActorAuthorizationVersion: epoch,
					ValidUntil: d.Request.Environment.Time.Add(5 * time.Second)}, err
			})
			provider := x.provider.config
			inspector, err := ssopg.NewDirectoryGroupRoleSyncService(pool, ssopg.DirectoryGroupRoleSyncConfig{
				TenantID: x.scope.TenantID, OrganizationID: x.scope.OrganizationID, ConnectionID: x.scope.ConnectionID,
				Clock: provider.Clock, MaximumDuration: provider.MaximumDuration,
				PolicyID: provider.PolicyID, PolicyVersion: provider.PolicyVersion, Coordinator: provider.Coordinator,
			}, config)
			if err != nil {
				t.Fatal("compose separately authorized role drift inspection on the traced pool", err)
			}

			report, err := inspector.ObserveDrift(f.ctx, request)
			if reads != 2 || invalidTarget || !changed || changeErr != nil {
				t.Fatal("the selected owner did not change at the intended exact-key observation fence", reads, changeErr)
			}
			if !errors.Is(err, sso.ErrDirectoryReconciliation) || report != (ssopg.DirectoryGroupRoleDrift{}) {
				t.Fatal("owner changed during observation disclosed a complete or partial role drift report", err)
			}
			expectedAttribution := before.attribution
			switch test.name {
			case "selected source edge":
				current, err := x.groups.Execute(f.ctx, scim.Request{Operation: scim.GroupGet, Credential: x.bearer, ResourceID: x.groupID})
				if err != nil || current.Status != 200 || current.ETag != changedRevision || afterMutation.organization != before.organization {
					t.Fatal("the source-only fixture mutation did not preserve its changed revision and organization state", err)
				}
			case "retained binding epoch":
				expectedAttribution.RetainedBindingVersion++
			case "current binding epoch":
				expectedAttribution.CurrentBindingVersion++
			}
			if afterMutation.generation != before.generation || afterMutation.attribution != expectedAttribution {
				t.Fatal("fixture mutation changed the generation or unrelated role attribution")
			}
			if test.name != "selected source edge" &&
				(afterMutation.audits != before.audits || afterMutation.events != before.events ||
					afterMutation.commands != before.commands || afterMutation.claims != before.claims) {
				t.Fatal("the isolated binding epoch mutation created protected effects")
			}
			assertDirectoryRoleDriftUnchanged(t, x, generation.ID, afterMutation)
		})
	}
}
