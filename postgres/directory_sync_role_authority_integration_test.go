//go:build integration

package postgres_test

import (
	"context"
	"encoding/json"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	database "github.com/faustbrian/go-postgres"
	scim "github.com/faustbrian/go-scim"
	scimorganization "github.com/faustbrian/go-scim/organization"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/jackc/pgx/v5"
)

type directoryRoleReadPolicy struct{ directoryGroupPolicy }

func (p directoryRoleReadPolicy) ObserveDirectoryRoleAuthorization(ctx context.Context, d authorization.DecisionContext, version uint64) (ssopg.ProviderUpdateAuthorizationEvidence, error) {
	return p.ObserveDirectoryGroupAuthorization(ctx, d, version)
}

func directoryRoleReadWorker(t *testing.T, x directoryGroupApplyFixture, sync *ssopg.DirectorySyncService) *ssopg.DirectoryGroupRoleSyncService {
	t.Helper()
	mapper, err := scimorganization.NewDirectoryRoleMapper(scimorganization.DirectoryRoleMappingConfig{
		Directory: scimorganization.DirectoryMappingConfig{
			TenantID: x.scope.TenantID, OrganizationID: x.scope.OrganizationID, ProviderID: sso.ProviderID(x.scope.ProviderID), ConnectionID: x.scope.ConnectionID, MappingVersion: 1,
			Groups:  []scimorganization.DirectoryGroupTeamMapping{{GroupID: x.groupID, TeamID: directoryTestTeam}},
			Members: []scimorganization.DirectoryMemberUserMapping{{MemberID: x.userID, UserID: identity.UserID(x.userID)}},
		},
		Roles: []scimorganization.DirectoryGroupRoleMapping{{GroupID: x.groupID, TeamID: directoryTestTeam, RoleID: "reader"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	member := x.workerConfig(t)
	worker, err := sync.WithGroupRoles(ssopg.DirectorySyncGroupRolesConfig{
		Source: x.groups, Mapping: mapper, Authorization: member.Authorization, AuthorityNamespace: member.AuthorityNamespace,
		ApplyAuthorization: directoryRoleReadPolicy{member.ApplyAuthorization.(directoryGroupPolicy)},
	})
	if err != nil {
		t.Fatal("compose live role source reader", err)
	}
	return worker
}

func directoryRoleReadClaim(x directoryGroupApplyFixture) organizationpg.DirectoryTeamRoleSource {
	return organizationpg.DirectoryTeamRoleSource{
		Scope: organizationpg.DirectoryTeamGrantScope{TenantID: x.scope.TenantID, OrganizationID: x.scope.OrganizationID,
			ProviderID: organization.ID(x.scope.ProviderID), ConnectionID: organization.ID(x.scope.ConnectionID),
			GroupID: organization.ID(x.groupID), TeamID: directoryTestTeam, UserID: identity.UserID(x.userID)},
		MemberResourceID: organization.ID(x.userID), RoleID: "reader", ProviderVersion: x.providerVersion, MappingVersion: 1, ConnectionVersion: 1,
	}
}

func TestNativeDirectoryRoleAuthorityUsesCurrentExactSource(t *testing.T) {
	x := newDirectoryGroupApplyFixture(t, organizationpg.DynamicRoleMigrationSource{Version: 687},
		organizationpg.TeamRoleBindingMigrationSource{Version: 688}, organizationpg.DirectoryTeamRoleMigrationSource{Version: 689})
	f := x.provider.f
	worker := directoryRoleReadWorker(t, x, x.sync)
	claim := directoryRoleReadClaim(x)
	assertCurrent := func(want bool) {
		t.Helper()
		got, err := worker.CurrentRoleSources(f.ctx, []organizationpg.DirectoryTeamRoleSource{claim})
		if err != nil || !reflect.DeepEqual(got, []bool{want}) {
			t.Fatal("wrong live exact role source", got, want, err)
		}
	}
	assertCurrent(true)
	mutations := []struct {
		name string
		edit func(*organizationpg.DirectoryTeamRoleSource)
	}{
		{"tenant", func(s *organizationpg.DirectoryTeamRoleSource) { s.Scope.TenantID = "other" }},
		{"organization", func(s *organizationpg.DirectoryTeamRoleSource) { s.Scope.OrganizationID = "other" }},
		{"provider", func(s *organizationpg.DirectoryTeamRoleSource) { s.Scope.ProviderID = "other" }},
		{"connection", func(s *organizationpg.DirectoryTeamRoleSource) { s.Scope.ConnectionID = "other" }},
		{"group", func(s *organizationpg.DirectoryTeamRoleSource) { s.Scope.GroupID = "other" }},
		{"team", func(s *organizationpg.DirectoryTeamRoleSource) { s.Scope.TeamID = "other" }},
		{"user", func(s *organizationpg.DirectoryTeamRoleSource) { s.Scope.UserID = "other" }},
		{"member resource", func(s *organizationpg.DirectoryTeamRoleSource) { s.MemberResourceID = "other" }},
		{"role", func(s *organizationpg.DirectoryTeamRoleSource) { s.RoleID = "other" }},
		{"provider version", func(s *organizationpg.DirectoryTeamRoleSource) { s.ProviderVersion++ }},
		{"mapping version", func(s *organizationpg.DirectoryTeamRoleSource) { s.MappingVersion++ }},
		{"connection version", func(s *organizationpg.DirectoryTeamRoleSource) { s.ConnectionVersion++ }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			wrong := claim
			mutation.edit(&wrong)
			got, err := worker.CurrentRoleSources(f.ctx, []organizationpg.DirectoryTeamRoleSource{wrong, claim, wrong})
			if err != nil || !reflect.DeepEqual(got, []bool{false, true, false}) {
				t.Fatal("changed source field was accepted or positional results changed", got, err)
			}
		})
	}
	for _, claims := range [][]organizationpg.DirectoryTeamRoleSource{nil, make([]organizationpg.DirectoryTeamRoleSource, 129)} {
		if got, err := worker.CurrentRoleSources(f.ctx, claims); err == nil || got != nil {
			t.Fatal("invalid role source batch returned usable results")
		}
	}
	ctx, cancel := context.WithCancel(f.ctx)
	cancel()
	if got, err := worker.CurrentRoleSources(ctx, []organizationpg.DirectoryTeamRoleSource{claim}); err == nil || got != nil {
		t.Fatal("canceled authority returned usable results")
	}

	// Seed only the retained role projection at this read boundary. Its Group,
	// User and provider are genuine native resources, not callback booleans.
	seedDirectoryRolePermissionSource(t, x)
	repository, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	configured, err := repository.WithDirectoryTeamRoles(worker.CurrentRoleSources)
	if err != nil {
		t.Fatal(err)
	}
	permission := organization.Query{Operation: organization.CheckPermission, TenantID: x.scope.TenantID, OrganizationID: x.scope.OrganizationID,
		ActorID: identity.UserID(x.userID), IncludeTeamRoles: true, Limit: 10}
	assertPermission := func(want bool) {
		t.Helper()
		got, err := configured.Read(f.ctx, permission)
		if err != nil || (len(got.DynamicRoles) == 1 && got.DynamicRoles[0].ID == "reader") != want || !want && len(got.DynamicRoles) != 0 {
			t.Fatal("native permission lookup ignored live directory role authority", want, err)
		}
	}
	assertPermission(true)
	user, err := x.native.Execute(f.ctx, scim.Request{Operation: scim.UserGet, Credential: x.bearer, ResourceID: x.userID})
	if err != nil {
		t.Fatal(err)
	}
	setActive := func(version scim.Version, active string) scim.Response {
		t.Helper()
		response, err := x.native.Execute(f.ctx, scim.Request{Operation: scim.UserPatch, Credential: x.bearer, ResourceID: x.userID, IfMatch: version,
			ContentType: "application/scim+json", Body: []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":` + active + `}]}`)})
		if err != nil || response.Status != 200 {
			t.Fatal("set native User activity", response.Status, err)
		}
		return response
	}
	inactive := setActive(user.ETag, "false")
	assertCurrent(false)
	assertPermission(false)
	setActive(inactive.ETag, "true")
	assertPermission(true)
	for _, column := range []string{"metadata_version", "metadata_mapping_version"} {
		if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE sso_providers.providers SET `+column+`=`+column+`+1 WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`,
			string(x.scope.TenantID), string(x.scope.OrganizationID), x.scope.ProviderID); err != nil {
			t.Fatal("change live provider authority", column, err)
		}
		assertCurrent(false)
		assertPermission(false)
		if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE sso_providers.providers SET `+column+`=`+column+`-1 WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`,
			string(x.scope.TenantID), string(x.scope.OrganizationID), x.scope.ProviderID); err != nil {
			t.Fatal("restore isolated live provider authority", column, err)
		}
		assertCurrent(true)
		assertPermission(true)
	}
	var enablementProof []byte
	var enablementGeneration string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT enablement_proof,enablement_credential_generation::text FROM sso_providers.providers
 WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`,
		string(x.scope.TenantID), string(x.scope.OrganizationID), x.scope.ProviderID).Scan(&enablementProof, &enablementGeneration); err != nil {
		t.Fatal("retain original isolated enablement fields", err)
	}
	defer clear(enablementProof)
	// Isolate the enabled predicate without changing the retained metadata
	// version. Both fixture states must satisfy the installed enablement shape.
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE sso_providers.providers SET enabled=false,enablement_proof=NULL,enablement_credential_generation=NULL
 WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`,
		string(x.scope.TenantID), string(x.scope.OrganizationID), x.scope.ProviderID); err != nil {
		t.Fatal(err)
	}
	assertCurrent(false)
	assertPermission(false)
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE sso_providers.providers SET enabled=true,enablement_proof=$4,enablement_credential_generation=$5::numeric
 WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`,
		string(x.scope.TenantID), string(x.scope.OrganizationID), x.scope.ProviderID, enablementProof, enablementGeneration); err != nil {
		t.Fatal(err)
	}
	assertCurrent(true)
	assertPermission(true)
	x.withdrawSourceMember(t)
	assertCurrent(false)
	assertPermission(false)
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE scim.users SET resource=convert_to('{}','UTF8') WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4 AND resource_id=$5`,
		string(x.scope.TenantID), string(x.scope.OrganizationID), x.scope.ProviderID, x.scope.ConnectionID, x.userID); err != nil {
		t.Fatal(err)
	}
	if got, err := worker.CurrentRoleSources(f.ctx, []organizationpg.DirectoryTeamRoleSource{claim, claim}); err == nil || got != nil {
		t.Fatal("ambiguous stored source returned usable authority")
	}
	if got, err := configured.Read(f.ctx, permission); err == nil || len(got.DynamicRoles) != 0 {
		t.Fatal("ambiguous stored source produced usable permission roles")
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE scim.connections SET state='revoked',version=version+1 WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4`,
		string(x.scope.TenantID), string(x.scope.OrganizationID), x.scope.ProviderID, x.scope.ConnectionID); err != nil {
		t.Fatal(err)
	}
	if got, err := worker.CurrentRoleSources(f.ctx, []organizationpg.DirectoryTeamRoleSource{claim}); err == nil || got != nil {
		t.Fatal("unavailable source connection returned usable authority")
	}
}

func seedDirectoryRolePermissionSource(t *testing.T, x directoryGroupApplyFixture) {
	t.Helper()
	f := x.provider.f
	statements, err := json.Marshal([]organization.RoleStatement{{PermissionID: "document-read", ResourceID: "one", Effect: authorization.Allow}})
	if err != nil {
		t.Fatal(err)
	}
	steps := []struct {
		sql  string
		args []any
	}{
		{`UPDATE organization.team_memberships SET state='removed' WHERE tenant_id=$1 AND organization_id=$2 AND team_id=$3 AND user_id=$4`, []any{string(x.scope.TenantID), string(x.scope.OrganizationID), directoryTestTeam, x.userID}},
		{`INSERT INTO organization.custom_roles(tenant_id,organization_id,role_id,name,version,state,statements) VALUES($1,$2,'reader','Reader',1,'active',$3)`, []any{string(x.scope.TenantID), string(x.scope.OrganizationID), string(statements)}},
		{`INSERT INTO organization.team_role_bindings(tenant_id,organization_id,team_id,role_id,version,state) VALUES($1,$2,$3,'reader',1,'active')`, []any{string(x.scope.TenantID), string(x.scope.OrganizationID), directoryTestTeam}},
		{`INSERT INTO organization.directory_team_grants(tenant_id,organization_id,provider_id,connection_id,group_id,team_id,user_id,version,organization_member_version,active)
 SELECT tenant_id,organization_id,$3,$4,$5,$6,user_id,1,version,true FROM organization.memberships WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$7`,
			[]any{string(x.scope.TenantID), string(x.scope.OrganizationID), x.scope.ProviderID, x.scope.ConnectionID, x.groupID, directoryTestTeam, x.userID}},
		{`INSERT INTO organization.directory_team_role_grants(tenant_id,organization_id,user_id,provider_id,connection_id,group_id,team_id,member_resource_id,role_id,grant_version,binding_version,provider_version,mapping_version,connection_version)
 VALUES($1,$2,$3,$4,$5,$6,$7,$3,'reader',1,1,$8::numeric,1,1)`,
			[]any{string(x.scope.TenantID), string(x.scope.OrganizationID), x.userID, x.scope.ProviderID, x.scope.ConnectionID, x.groupID, directoryTestTeam, strconv.FormatUint(x.providerVersion, 10)}},
	}
	for _, step := range steps {
		if _, err := f.pool.Raw().Exec(f.ctx, step.sql, step.args...); err != nil {
			t.Fatal("seed exact retained directory role permission source", err)
		}
	}
}

type directoryRoleReadFenceTrace struct {
	read func(context.Context)
}

func (t directoryRoleReadFenceTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, query pgx.TraceQueryStartData) context.Context {
	if strings.HasPrefix(query.SQL, "SELECT metadata_version::text,COALESCE(metadata_mapping_version,mapping_version)::text,enabled") {
		t.read(ctx)
	}
	return ctx
}

func (directoryRoleReadFenceTrace) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func TestNativeDirectoryRoleAuthorityRefencesProviderAfterSourceRead(t *testing.T) {
	x := newDirectoryGroupApplyFixture(t)
	f := x.provider.f
	reads, changed := 0, false
	var changeErr error
	trace := directoryRoleReadFenceTrace{read: func(ctx context.Context) {
		reads++
		if reads != 2 {
			return
		}
		_, changeErr = f.pool.Raw().Exec(ctx, `UPDATE sso_providers.providers SET enabled=false,enablement_proof=NULL,enablement_credential_generation=NULL
 WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`,
			string(x.scope.TenantID), string(x.scope.OrganizationID), x.scope.ProviderID)
		changed = changeErr == nil
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
			t.Error("close isolated provider-fence pool", err)
		}
	})
	provider, err := ssopg.NewProviderService(pool, x.provider.config, f.auth(directoryTestTenant, "owner"), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	provider, err = withProviderUpdateOwner(t, provider).ForOrganization(string(x.scope.OrganizationID))
	if err != nil {
		t.Fatal(err)
	}
	sync, err := provider.DirectorySync(x.scope.ConnectionID, directoryAdminPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	worker := directoryRoleReadWorker(t, x, sync)
	got, err := worker.CurrentRoleSources(f.ctx, []organizationpg.DirectoryTeamRoleSource{directoryRoleReadClaim(x)})
	if !changed || changeErr != nil || reads != 2 {
		t.Fatal("controlled disable did not occur at the final provider fence", reads, changeErr)
	}
	if err == nil || got != nil {
		t.Fatal("provider disabled after a live edge read returned usable authority", got, err)
	}
}

func TestNativeDirectoryRoleProviderAuthorityQueryScale(t *testing.T) {
	x := newDirectoryGroupApplyFixture(t)
	f := x.provider.f
	_, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO sso_providers.providers(tenant_id,organization_id,provider_id,issuer_digest,configuration_envelope,mapping_version,pending_domains)
 SELECT CASE WHEN n<=9000 THEN tenant_id ELSE 'role-scale-'||(n%100)::text END,organization_id,
 'role-scale-'||n::text,decode(md5(n::text)||md5('role-'||n::text),'hex'),configuration_envelope,mapping_version,pending_domains
 FROM sso_providers.providers CROSS JOIN generate_series(1,10000) n WHERE provider_id=$1`, x.scope.ProviderID)
	if err != nil {
		t.Fatal("populate representative isolated providers", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `ANALYZE sso_providers.providers`); err != nil {
		t.Fatal(err)
	}
	var engine, columns string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT current_setting('server_version'),string_agg(attname||' '||format_type(atttypid,atttypmod),', ' ORDER BY attnum)
 FROM pg_attribute WHERE attrelid='sso_providers.providers'::regclass
 AND attname IN ('tenant_id','organization_id','provider_id','metadata_version','metadata_mapping_version','mapping_version','enabled')`).Scan(&engine, &columns); err != nil {
		t.Fatal("inspect isolated provider engine and actual column types", err)
	}
	t.Logf("isolated PostgreSQL %s; provider columns: %s; synthetic rows are performance-only, not accepted source authority", engine, columns)
	trace := new(providerTrace)
	provider, err := tracedProviderService(t, f, x.provider.config, trace).ForOrganization(string(x.scope.OrganizationID))
	if err != nil {
		t.Fatal(err)
	}
	sync, err := provider.DirectorySync(x.scope.ConnectionID, directoryAdminPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	worker := directoryRoleReadWorker(t, x, sync)
	claim := directoryRoleReadClaim(x)
	for _, size := range []int{1, 128} {
		claims := make([]organizationpg.DirectoryTeamRoleSource, size)
		for i := range claims {
			claims[i] = claim
		}
		var timings []time.Duration
		for range 5 {
			trace.mu.Lock()
			queryStart := len(trace.queries)
			trace.mu.Unlock()
			started := time.Now()
			got, err := worker.CurrentRoleSources(f.ctx, claims)
			timings = append(timings, time.Since(started))
			if err != nil || len(got) != size {
				t.Fatal("loaded live role authority", err)
			}
			for _, current := range got {
				if !current {
					t.Fatal("loaded matching role source was denied")
				}
			}
			trace.mu.Lock()
			providerReads := 0
			for _, query := range trace.queries[queryStart:] {
				if strings.HasPrefix(query.sql, "SELECT metadata_version::text,COALESCE(metadata_mapping_version,mapping_version)::text,enabled") {
					providerReads++
				}
			}
			trace.mu.Unlock()
			if providerReads != 2 {
				t.Fatal("provider lookup must stay bounded to initial and final fences independently of batch size", size, providerReads)
			}
		}
		sort.Slice(timings, func(i, j int) bool { return timings[i] < timings[j] })
		t.Logf("10k isolated providers, 9k same tenant and organization, %d role sources; 5 warm reads median=%s max=%s; no concurrent load", size, timings[2], timings[4])
	}
	trace.mu.Lock()
	queries, traceErr := append([]providerQuery(nil), trace.queries...), trace.err
	trace.mu.Unlock()
	if traceErr != nil {
		t.Fatal(traceErr)
	}
	var captured *providerQuery
	for i := range queries {
		if strings.HasPrefix(queries[i].sql, "SELECT metadata_version::text,COALESCE(metadata_mapping_version,mapping_version)::text,enabled") {
			captured = &queries[i]
			break
		}
	}
	if captured == nil {
		t.Fatal("missing executed provider current-authority SQL")
	}
	prepared, err := f.pool.Raw().Acquire(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	description, err := prepared.Conn().Prepare(f.ctx, "directory_role_provider_plan", captured.sql)
	prepared.Release()
	if err != nil || len(description.ParamOIDs) != 3 {
		t.Fatal("inspect actual provider query binding types", err)
	}
	t.Logf("executed provider query parameter OIDs=%v; Go bindings=%T,%T,%T; exact primary-key lookup, no statement per claimed edge", description.ParamOIDs, captured.args[0], captured.args[1], captured.args[2])
	for _, partition := range []string{"selected provider", "missing provider"} {
		query := *captured
		query.args = append([]any(nil), captured.args...)
		if partition == "missing provider" {
			query.args[2] = "missing-role-source-provider"
		}
		proveDirectoryGenerationPlan(t, f, query, partition, "")
	}
}
