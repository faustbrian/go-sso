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
	organizationpg "github.com/faustbrian/go-organization/postgres"
	database "github.com/faustbrian/go-postgres"
	scim "github.com/faustbrian/go-scim"
	scimorganization "github.com/faustbrian/go-scim/organization"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/jackc/pgx/v5"
)

type directoryUserDriftAttributionTrace struct {
	read func(context.Context, pgx.TraceQueryStartData)
}

func (t directoryUserDriftAttributionTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, query pgx.TraceQueryStartData) context.Context {
	if strings.HasPrefix(query.SQL, "SELECT COALESCE(m.role,''),COALESCE(m.version::text,'0'),COALESCE(m.authorization_version::text,'0'),COALESCE(m.state='active',false),COALESCE(g.resource_id,''),COALESCE(g.version::text,'0'),COALESCE(g.active,false),o.version::text,o.credential_version::text,") {
		t.read(ctx, query)
	}
	return ctx
}

func (directoryUserDriftAttributionTrace) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {
}

func TestNativeDirectoryUserDriftRejectsSourceChangedDuringAttribution(t *testing.T) {
	x := newDirectoryGroupApplyFixture(t, organizationpg.DirectoryMembershipMigrationSource{Version: 687})
	f := x.provider.f
	created, err := x.native.Execute(f.ctx, scim.Request{
		Operation: scim.UserCreate, Credential: x.bearer, ContentType: "application/scim+json",
		Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"DriftSourceFence","active":true}`),
	})
	if err != nil {
		t.Fatal("create the explicitly active source User", err)
	}
	resourceID := directoryFixtureSCIMID(t, created, 201)
	generation := x.start(t)
	delta, err := sso.NewDirectoryUserAdmissionDelta(directoryUserDriftCommandID(t), resourceID, string(created.ETag))
	if err != nil {
		t.Fatal(err)
	}
	request := directoryUserDriftRequest(generation, delta)
	before := captureDirectoryUserDriftState(t, x, generation.ID, resourceID)
	var afterMutation directoryUserDriftState
	reads, changed, invalidTarget := 0, false, false
	var changeErr error
	var changedRevision scim.Version
	trace := directoryUserDriftAttributionTrace{read: func(ctx context.Context, query pgx.TraceQueryStartData) {
		reads++
		if reads != 1 {
			return
		}
		if !reflect.DeepEqual(query.Args, []any{
			string(x.scope.TenantID), string(x.scope.OrganizationID), resourceID, string(x.scope.ProviderID), string(x.scope.ConnectionID),
		}) {
			invalidTarget = true
			return
		}
		assertDirectoryUserDriftUnchanged(t, x, generation.ID, resourceID, before)
		// The original source pool stays outside this tracer, so the public
		// SCIM write cannot reenter the in-progress organization observation.
		response, err := x.native.Execute(ctx, scim.Request{
			Operation: scim.UserPatch, Credential: x.bearer, ResourceID: resourceID, IfMatch: created.ETag,
			ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}`),
		})
		changeErr = err
		changedRevision = response.ETag
		changed = err == nil && response.Status == 200 && response.ETag != "" && response.ETag != created.ETag
		afterMutation = captureDirectoryUserDriftState(t, x, generation.ID, resourceID)
	}}
	pool, err := database.Connect(f.ctx, database.Config{DSN: f.dsn, MaxConns: 2, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database, c.ConnConfig.Tracer = f.database, trace
		return nil
	}})
	if err != nil {
		t.Fatal("connect the separate User-attribution observation pool", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := pool.Close(ctx); err != nil {
			t.Error("close the isolated User drift source-fence pool", err)
		}
	})
	mapper, err := scimorganization.NewDirectoryUserMapper(scimorganization.DirectoryUserMappingConfig{
		TenantID: x.scope.TenantID, OrganizationID: x.scope.OrganizationID, ProviderID: sso.ProviderID(x.scope.ProviderID), ConnectionID: x.scope.ConnectionID,
		MappingVersion: 1, Members: []scimorganization.DirectoryMemberUserMapping{{MemberID: resourceID, UserID: identity.UserID(resourceID)}}, AllowAdmission: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := directoryServicePolicy(func(d authorization.DecisionContext) bool {
		return d.Request.Tenant == authorization.TenantID(x.scope.TenantID) && d.Request.Subject.Kind == authorization.SubjectServiceAccount &&
			d.Request.Subject.ID == directoryTestActor && d.Request.Action == "identity.sso.directory-sync-inspect-user-drift"
	})
	provider := x.provider.config
	inspector, err := ssopg.NewDirectoryUserSyncService(pool, ssopg.DirectoryUserSyncConfig{
		TenantID: x.scope.TenantID, OrganizationID: x.scope.OrganizationID, ConnectionID: x.scope.ConnectionID,
		Clock: provider.Clock, MaximumDuration: provider.MaximumDuration,
		PolicyID: provider.PolicyID, PolicyVersion: provider.PolicyVersion, Coordinator: provider.Coordinator,
	}, ssopg.DirectorySyncUsersConfig{
		Source: x.groups, Mapping: mapper, Authorization: policy, MaximumMembers: 50, MaximumPerUser: 10, AuthorityNamespace: directoryTestAuthority,
		ApplyAuthorization: directoryUserPolicy(func(ctx context.Context, d authorization.DecisionContext, version uint64) (ssopg.ProviderUpdateAuthorizationEvidence, error) {
			decision, err := policy.Decide(ctx, d)
			return ssopg.ProviderUpdateAuthorizationEvidence{Context: d, Decision: decision, ActorAuthorizationVersion: version,
				ValidUntil: d.Request.Environment.Time.Add(5 * time.Second)}, err
		}),
	})
	if err != nil {
		t.Fatal("compose separately authorized User drift inspection on the traced pool", err)
	}

	report, err := inspector.ObserveDrift(f.ctx, request)
	if reads == 0 || invalidTarget || !changed || changeErr != nil {
		t.Fatal("the exact source User did not change between source and organization observations", reads, changeErr)
	}
	if !errors.Is(err, sso.ErrDirectoryReconciliation) || report != (ssopg.DirectoryUserDrift{}) {
		t.Fatal("a User revision changed during observation disclosed a drift report", err)
	}
	current, err := x.native.Execute(f.ctx, scim.Request{Operation: scim.UserGet, Credential: x.bearer, ResourceID: resourceID})
	if err != nil || current.Status != 200 || current.ETag != changedRevision {
		t.Fatal("the public SCIM mutation did not retain its changed revision", err)
	}
	if afterMutation.generation != before.generation || afterMutation.attribution != before.attribution {
		t.Fatal("the source-only fixture mutation changed the generation or local attribution")
	}
	assertDirectoryUserDriftUnchanged(t, x, generation.ID, resourceID, afterMutation)
}
