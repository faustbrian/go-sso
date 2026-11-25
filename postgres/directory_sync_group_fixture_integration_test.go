//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	scim "github.com/faustbrian/go-scim"
	scimpostgres "github.com/faustbrian/go-scim/postgres"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

const (
	directoryTestTenant    = "org-test-basic"
	directoryTestActor     = "directory-sync-service"
	directoryTestAuthority = "directory-sync-source"
	directoryTestTeam      = "directory-team"
)

type directoryGroupApplyFixture struct {
	provider        providerEnableFixture
	providerVersion uint64
	sync            *ssopg.DirectorySyncService
	groups          *scimpostgres.GroupsService
	native          *scimpostgres.Service
	scope           scim.Scope
	bearer          authentication.BearerCredential
	groupID, userID string
	groupETag       scim.Version
}

func newDirectoryGroupApplyFixture(t *testing.T, additional ...migrations.Source) directoryGroupApplyFixture {
	t.Helper()
	x := newProviderEnableFixture(t)
	f := x.f
	groupHistory := scimpostgres.GroupsMigrationSource{
		Base:    scimpostgres.UsersMigrationSource{Base: scimpostgres.MigrationSource{Version: 681}, Version: 682},
		Version: 683,
	}
	canonical, err := (kernel.CanonicalRequestMigrationSource{Base: f.history, Version: 680}).Load(f.ctx)
	if err != nil {
		t.Fatal("load canonical SCIM request prerequisites", err)
	}
	prerequisites := []migrations.Source{
		ssopg.ProviderCredentialsMigrationSource{Version: 322}, ssopg.ProviderEnableMigrationSource{Version: 323},
		migrationList(canonical[len(canonical)-1:]), groupHistory,
		organizationpg.TeamMigrationSource{Version: 684}, organizationpg.TeamLifecycleMigrationSource{Version: 685},
		organizationpg.DirectoryTeamGrantMigrationSource{Version: 686},
	}
	installNativeDirectoryGeneration(t, f, append(prerequisites, additional...)...)
	enabled, err := x.service.ProviderEnable(f.ctx, x.request)
	if err != nil || !enabled.Provider.Enabled {
		t.Fatal("enable source provider", err)
	}
	scope := scim.Scope{TenantID: directoryTestTenant, OrganizationID: x.proof.OrganizationID, ProviderID: enabled.Provider.ID, ConnectionID: "scim-source"}
	native, groups, bearer := createDirectorySCIMSource(t, f, scope)
	user, err := native.Execute(f.ctx, scim.Request{
		Operation: scim.UserCreate, Credential: bearer, ContentType: "application/scim+json",
		Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"DirectoryExistingMember","displayName":"Directory member"}`),
	})
	if err != nil {
		t.Fatal("create real SCIM user", err)
	}
	userID := directoryFixtureSCIMID(t, user, 201)
	group, err := groups.Execute(f.ctx, scim.Request{
		Operation: scim.GroupCreate, Credential: bearer, IdempotencyKey: "native-directory-source-group", ContentType: "application/scim+json",
		Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Directory group","members":[{"type":"User","value":"` + userID + `"}]}`),
	})
	if err != nil {
		t.Fatal("create real SCIM group edge", err)
	}
	groupID := directoryFixtureSCIMID(t, group, 201)
	seedDirectoryTeam(t, f, scope, userID)
	sync, err := x.base.DirectorySync(scope.ConnectionID, directoryAdminPolicy{})
	if err != nil {
		t.Fatal("select actual native generation", err)
	}
	return directoryGroupApplyFixture{provider: x, providerVersion: enabled.Provider.Version, sync: sync, groups: groups, native: native, scope: scope,
		bearer: bearer, groupID: groupID, userID: userID, groupETag: group.ETag}
}

func createDirectorySCIMSource(t *testing.T, f *orgFixture, scope scim.Scope) (*scimpostgres.Service, *scimpostgres.GroupsService, authentication.BearerCredential) {
	t.Helper()
	const policyID = "scim-directory-fixture"
	const keyID = "scim-directory-envelope"
	policy := directoryServicePolicy(func(d authorization.DecisionContext) bool {
		return d.Request.Tenant == authorization.TenantID(scope.TenantID) &&
			d.Request.Subject.Kind == authorization.SubjectServiceAccount && d.Request.Subject.ID == directoryTestActor
	})
	query := kernel.CommandQueryPolicy{Authorization: policy, Clock: clock.System{}, PolicyVersion: 1}
	requestKeys, err := kernel.NewRequestKeyConfig(policyID, [32]byte{0xcf}, query)
	if err != nil {
		t.Fatal(err)
	}
	bearer := authentication.NewBearerCredential("isolated-scim-directory-fixture-credential-with-entropy")
	configured, err := scimpostgres.NewConfiguredCredential("directory-credential", bearer, [32]byte{0xd1})
	if err != nil {
		t.Fatal(err)
	}
	schema := identity.AttributeSchema{ID: policyID, Version: 1}
	for _, name := range []string{"scim_user_name", "scim_display_name"} {
		schema.Fields = append(schema.Fields, identity.FieldPolicy{Name: name, Kind: identity.AttributeString, Cardinality: identity.CardinalityScalar,
			Normalization: identity.NormalizeNone, InputPermission: identity.FieldWrite, OutputPermission: identity.FieldRead, WriteAuthorization: identity.FieldWriteSystem,
			Sensitivity: identity.SensitivityPersonal, MigrationVersion: 1})
	}
	fields, err := identity.NewAttributeProcessor(schema, policy, func(_ context.Context, _ identity.NormalizationPolicy, scalar identity.AttributeScalar) (identity.AttributeScalar, error) {
		return scalar, nil
	}, identity.AttributeProcessorConfig{Clock: clock.System{}, MaximumDuration: time.Second, PolicyVersion: 1,
		ValidateCanonicalUserID: func(_ context.Context, id identity.UserID) error {
			_, err := identity.ParseSubjectID(string(id))
			return err
		}, ValidateValue: func(context.Context, identity.FieldPolicy, identity.AttributeValue) error { return nil },
	})
	if err != nil {
		t.Fatal("construct the SCIM field policy", err)
	}
	config := scimpostgres.Config{
		Scope: scope, ConnectionVersion: 1, Credential: configured, CredentialExpiresAt: time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond),
		ActorID: directoryTestActor, PolicyID: policyID, PolicyVersion: 1, ConfigurationID: "scim-directory-fixture-v1", Authorization: policy,
		AuthorityNamespace: directoryTestAuthority, GlobalAuthorityID: f.profile.GlobalAuthorityID, Fields: fields, FieldSchema: schema,
		UserNameField: "scim_user_name", DisplayNameField: "scim_display_name", RequestKeys: requestKeys,
		Coordinator: kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute,
			CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {0xd3}}, QueryPolicy: &query, AdmissionPolicy: &query},
		IntentKey: [32]byte{0xd4}, ActiveEnvelopeKeyID: keyID, Limits: scim.DefaultLimits(), BaseURL: "https://directory.example.test/scim/v2", MaximumDuration: 3 * time.Second,
	}
	_, err = authoritypg.InitializeAuthority(f.ctx, f.pool.Raw(), authoritypg.AuthorityScope{
		TenantID: authorization.TenantID(scope.TenantID), PolicyNamespace: directoryTestAuthority, SubjectID: directoryTestActor,
	}, time.Second)
	if err != nil {
		t.Fatal("install original directory-service authority epoch", err)
	}
	keys, err := keyring.New(map[string][]byte{keyID: bytes.Repeat([]byte{0xd5}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	native, err := scimpostgres.NewService(f.pool, config, keys)
	if err != nil {
		t.Fatal("construct configured SCIM source", err)
	}
	installed, err := native.InitializeConfiguredConnection(f.ctx)
	if err != nil || installed.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("install configured SCIM connection", err)
	}
	groups, err := scimpostgres.NewGroupsService(native, scim.DefaultGroupMembers)
	if err != nil {
		t.Fatal("select SCIM Groups", err)
	}
	return native, groups, bearer
}

func seedDirectoryTeam(t *testing.T, f *orgFixture, scope scim.Scope, user string) {
	t.Helper()
	// Local membership is deliberately separate from the directory grant.
	// Fixture setup does not give SSO a substitute organization writer.
	reader, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	owner, err := reader.ObserveCredentialAuthority(f.ctx, organization.CredentialAuthorityQuery{TenantID: scope.TenantID, OrganizationID: scope.OrganizationID})
	if err != nil {
		t.Fatal("read current organization version", err)
	}
	f.add(t, string(scope.TenantID), user, organization.RoleMember, owner.Version)
	steps := []string{
		"INSERT INTO organization.team_identities(tenant_id,organization_id,team_id) VALUES($1,$2,$3)",
		"INSERT INTO organization.teams(tenant_id,organization_id,team_id,name,version) VALUES($1,$2,$3,'Directory team',1)",
	}
	for _, sql := range steps {
		if _, err := f.pool.Raw().Exec(f.ctx, sql, string(scope.TenantID), string(scope.OrganizationID), directoryTestTeam); err != nil {
			t.Fatal("seed the existing local team", err)
		}
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO organization.team_memberships
 (tenant_id,organization_id,team_id,user_id,state,version,organization_member_version)
 SELECT tenant_id,organization_id,$3,user_id,'active',1,version
 FROM organization.memberships WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$4`,
		string(scope.TenantID), string(scope.OrganizationID), directoryTestTeam, user); err != nil {
		t.Fatal("seed existing local team contribution", err)
	}
}
