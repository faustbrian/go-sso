//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	database "github.com/faustbrian/go-postgres"
	scim "github.com/faustbrian/go-scim"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/jackc/pgx/v5"
)

func TestNativeDirectoryMixedDriftRejectsLateRoleOwnerChangeWithoutPartialReport(t *testing.T) {
	for _, test := range []struct {
		name         string
		mutationRead int
	}{
		{name: "selected role source edge", mutationRead: 1},
		{name: "current role binding epoch", mutationRead: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			journey := newDirectoryMixedJourney(t)
			x, f := journey.fixture, journey.fixture.provider.f
			applied, err := journey.worker(t, f.pool).ApplyGeneration(f.ctx, journey.request)
			if err != nil {
				t.Fatal("establish the exact mixed User/User/Group/role attribution", err)
			}
			journey.assertSettled(t, applied)
			request, _ := directoryMixedDriftCurrentRequest(t, journey, applied.Checkpoint)
			roleGroup, err := x.groups.Execute(f.ctx, scim.Request{
				Operation: scim.GroupGet, Credential: x.bearer, ResourceID: journey.groups[1],
			})
			if err != nil || roleGroup.Status != 200 || roleGroup.ETag == "" {
				t.Fatal("read the selected late role source Group", err)
			}
			repository, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			readRole := func() organizationpg.DirectoryTeamRoleAttribution {
				t.Helper()
				role, err := repository.ObserveDirectoryTeamRoleAttribution(f.ctx, organizationpg.DirectoryTeamGrantScope{
					TenantID: x.scope.TenantID, OrganizationID: x.scope.OrganizationID,
					ProviderID: organization.ID(x.scope.ProviderID), ConnectionID: organization.ID(x.scope.ConnectionID),
					GroupID: organization.ID(journey.groups[1]), TeamID: directoryTestTeam, UserID: identity.UserID(journey.users[0]),
				}, "directory-reader")
				if err != nil {
					t.Fatal("observe the independently retained late role attribution", err)
				}
				return role
			}
			beforeRole := readRole()
			before := captureDirectoryMixedDriftState(t, journey)
			var afterMutation string
			var afterMutationRole organizationpg.DirectoryTeamRoleAttribution
			reads, changed, invalidTarget := 0, false, false
			var changeErr error
			var changedRevision scim.Version
			trace := directoryRoleDriftAttributionTrace{read: func(ctx context.Context, query pgx.TraceQueryStartData) {
				reads++
				if !reflect.DeepEqual(query.Args, []any{
					string(x.scope.TenantID), string(x.scope.OrganizationID), x.scope.ProviderID, x.scope.ConnectionID,
					journey.groups[1], directoryTestTeam, journey.users[0], "directory-reader",
				}) {
					invalidTarget = true
					return
				}
				if reads != test.mutationRead {
					return
				}
				assertDirectoryMixedDriftUnchanged(t, journey, before)
				// The late role is observed after the typed User/User/Group prefix.
				// Original-pool writes and snapshots cannot reenter this tracer.
				switch test.name {
				case "selected role source edge":
					response, err := x.groups.Execute(ctx, scim.Request{
						Operation: scim.GroupReplace, Credential: x.bearer, ResourceID: journey.groups[1], IfMatch: roleGroup.ETag,
						IdempotencyKey: "native-directory-mixed-drift-role-fence", ContentType: "application/scim+json",
						Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Mixed explicit role","members":[]}`),
					})
					changeErr, changedRevision = err, response.ETag
					changed = err == nil && response.Status == 200 && response.ETag != "" && response.ETag != roleGroup.ETag
				case "current role binding epoch":
					result, err := f.pool.Raw().Exec(ctx, `UPDATE organization.team_role_bindings SET version=version+1
 WHERE tenant_id=$1 AND organization_id=$2 AND team_id=$3 AND role_id=$4 AND state='active'`,
						string(x.scope.TenantID), string(x.scope.OrganizationID), directoryTestTeam, "directory-reader")
					changeErr, changed = err, err == nil && result.RowsAffected() == 1
				}
				afterMutationRole = readRole()
				afterMutation = captureDirectoryMixedDriftState(t, journey)
			}}
			pool, err := database.Connect(f.ctx, database.Config{DSN: f.dsn, MaxConns: 2, Configure: func(c *database.PoolConfig) error {
				c.ConnConfig.Database, c.ConnConfig.Tracer = f.database, trace
				return nil
			}})
			if err != nil {
				t.Fatal("connect the isolated mixed role-observation pool", err)
			}
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := pool.Close(ctx); err != nil {
					t.Error("close the isolated mixed late-role fence pool", err)
				}
			})
			inspection := directoryServicePolicy(func(d authorization.DecisionContext) bool {
				return d.Request.Tenant == authorization.TenantID(x.scope.TenantID) &&
					d.Request.Subject.Kind == authorization.SubjectServiceAccount && d.Request.Subject.ID == directoryTestActor &&
					d.Request.Action == "identity.sso.directory-sync-inspect-mixed-drift"
			})
			config := journey.config
			config.ApplyAuthorization = directoryGroupPolicy(func(ctx context.Context, d authorization.DecisionContext, epoch uint64) (ssopg.ProviderUpdateAuthorizationEvidence, error) {
				decision, err := inspection.Decide(ctx, d)
				return ssopg.ProviderUpdateAuthorizationEvidence{Context: d, Decision: decision, ActorAuthorizationVersion: epoch,
					ValidUntil: d.Request.Environment.Time.Add(5 * time.Second)}, err
			})
			inspector, err := ssopg.NewDirectoryMixedSyncService(pool, journey.scope, config)
			if err != nil {
				t.Fatal("compose separately authorized mixed inspection on the traced pool", err)
			}

			report, err := inspector.ObserveBatchDrift(f.ctx, request)
			if reads != 2 || invalidTarget || !changed || changeErr != nil {
				t.Fatal("the late exact role owner did not change at the selected snapshot fence", reads, changeErr)
			}
			if !errors.Is(err, sso.ErrDirectoryReconciliation) || report != nil {
				t.Fatal("a changed late role disclosed a complete mixed report or its valid prefix", err)
			}
			expectedRole := beforeRole
			switch test.name {
			case "selected role source edge":
				current, err := x.groups.Execute(f.ctx, scim.Request{
					Operation: scim.GroupGet, Credential: x.bearer, ResourceID: journey.groups[1],
				})
				if err != nil || current.Status != 200 || current.ETag != changedRevision {
					t.Fatal("the selected late source Group did not retain its fixture mutation", err)
				}
			case "current role binding epoch":
				expectedRole.CurrentBindingVersion++
			}
			if afterMutationRole != expectedRole {
				t.Fatal("fixture mutation changed unrelated native role attribution")
			}
			assertDirectoryMixedDriftUnchanged(t, journey, afterMutation)
		})
	}
}
