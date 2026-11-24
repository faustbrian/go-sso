//go:build integration

package postgres_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/knroy/go-xml/v2/c14n"
	"github.com/knroy/go-xml/v2/xdm"
)

const nativeSAMLRoleClaim = "urn:example:roles:project-reader"
const nativeSAMLRoleID organization.ID = "native-saml-project-reader"

type nativeSAMLRoleJourneyFixture struct {
	callback *nativeSAMLCallbackFixture
	key      *ecdsa.PrivateKey
}

func newNativeSAMLRoleJourneyFixture(t *testing.T) nativeSAMLRoleJourneyFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("generate isolated role assertion signing key", err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal("create installed role assertion certificate", err)
	}
	x := newNativeSAMLCallbackFixtureWithStart(t, newSAMLStartFixtureWithBundle(t, nil, certificate))
	installNativeSAMLRoleJourneyHistory(t, x)
	profile := x.start.profiles[0]
	// The shared role-creation helper reads only this organization selector;
	// the actual start, provider and completion remain exclusively SAML.
	roleFixture := x.start.start
	roleFixture.config.Profiles = []ssopg.StaticOIDCLoginProfile{{OrganizationID: profile.OrganizationID}}
	prepareNativeCallbackRole(t, roleFixture, nativeSAMLRoleID)
	f := x.start.start.enable.f
	// The projection migration intentionally does not backfill installed
	// providers. Populate the exact already-authenticated fixture generation.
	if _, err := f.pool.Raw().Exec(f.ctx, `SELECT organization.project_provider_role_source(
tenant_id,organization_id,provider_id,metadata_version,COALESCE(metadata_mapping_version,mapping_version),enabled)
FROM sso_providers.providers WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`,
		string(x.start.start.config.TenantID), string(profile.OrganizationID), string(profile.ProviderID)); err != nil {
		t.Fatal("project installed SAML provider role source", err)
	}
	x.completion, err = x.completion.WithRoleSync([]ssopg.StaticSAMLRoleMapping{{OrganizationID: profile.OrganizationID,
		ProviderID: profile.ProviderID, MappingVersion: profile.MappingVersion,
		Rules: []ssopg.StaticSAMLRoleRule{{ClaimName: nativeSAMLRoleClaim, RoleID: nativeSAMLRoleID}}}}, time.Second)
	if err != nil {
		t.Fatal("select native signed SAML role synchronization", err)
	}
	return nativeSAMLRoleJourneyFixture{callback: x, key: key}
}

func installNativeSAMLRoleJourneyHistory(t *testing.T, x *nativeSAMLCallbackFixture) {
	t.Helper()
	f := x.start.start.enable.f
	configuration, err := pgx.ParseConfig(f.dsn)
	if err != nil {
		t.Fatal(err)
	}
	configuration.Database = f.database
	db := stdlib.OpenDB(*configuration)
	defer db.Close()
	backend, err := migrationpg.New(db)
	if err != nil {
		t.Fatal(err)
	}
	history := append(migrationList(nil), f.history...)
	// Native SAML start already owns 350..352, which the OIDC-only role
	// fixture uses. Append the same public optional sources after ACS history.
	for _, source := range []migrations.Source{
		organizationpg.DynamicRoleMigrationSource{Version: 381},
		organizationpg.ProviderRoleGrantMigrationSource{Version: 382},
		organizationpg.ProviderRoleSourceProjectionMigrationSource{Version: 383},
		ssopg.ProviderRoleSourceMigrationSource{Version: 384},
	} {
		steps, err := source.Load(f.ctx)
		if err != nil {
			t.Fatal("load public SAML role journey history", err)
		}
		history = append(history, steps...)
	}
	runner, err := migrations.NewRunner(history, backend)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := runner.Up(f.ctx); err != nil {
			t.Fatal("install and replay native SAML role history", err)
		}
	}
	f.history = history
}

func TestNativeSAMLRoleCallbackCommitsGrantSessionAndReplayOnce(t *testing.T) {
	x := newNativeSAMLRoleJourneyFixture(t)
	f := x.callback.start.start.enable.f
	profile := x.callback.start.profiles[0]
	tenant := string(x.callback.start.start.config.TenantID)
	auth := f.auth(tenant, "owner")
	readOrganization := func() organization.View {
		t.Helper()
		view, err := f.service.Get(f.ctx, organization.ReadRequest{Authentication: auth, OrganizationID: profile.OrganizationID,
			CorrelationID: "native-saml-role-permission"})
		if err != nil {
			t.Fatal("observe current SAML role organization", err)
		}
		return view
	}
	reader, err := organizationpg.NewRepositoryWithProviderRoleGrants(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	permissions, err := organization.NewService(f.sessions, reader, fixturePolicy{}, f.configuration.Core)
	if err != nil {
		t.Fatal(err)
	}
	assertPermission := func(want authorization.Outcome) {
		t.Helper()
		got, err := permissions.CheckPermission(f.ctx, organization.PermissionCheckRequest{Authentication: auth,
			OrganizationID: profile.OrganizationID, OrganizationVersion: readOrganization().Organization.Version,
			Action: "project.view", ResourceType: "project", ResourceID: "one", CorrelationID: "native-saml-role-permission"})
		if err != nil || got.Outcome != want {
			t.Fatalf("effective SAML/application role permission=%v, want %v: %v", got.Outcome, want, err)
		}
	}
	assertPermission(authorization.Deny)
	x.callback.request.SAMLResponse = x.signedResponse(t, `<a:Attribute Name="`+nativeSAMLRoleClaim+`"><a:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" xsi:type="xs:boolean">true</a:AttributeValue></a:Attribute>`)
	before := nativeSAMLCallbackSuccessCounts(t, x.callback)
	got, err := x.callback.completion.SigninCallback(f.ctx, x.callback.request)
	if err != nil || got.Completion.Outcome != identity.CommitOutcomeCommitted || got.Issuance.CommitOutcome != identity.CommitOutcomeCommitted ||
		got.Issuance.Replayed || x.callback.calls != 0 {
		t.Fatal("real signed SAML role assertion did not commit through the selected native verifier", err)
	}
	roles, committed := x.grant(t)
	if !slices.Equal(roles, []string{string(nativeSAMLRoleID)}) {
		t.Fatal("signed true did not commit the exact installed custom role")
	}
	assertPermission(authorization.Allow)
	spec, err := got.Issuance.Session.Bindings()
	if err != nil || spec.UserID != "owner" || spec.Authentication.Proof.Method != "sso-saml" ||
		spec.Authentication.CredentialID != "saml-provider-credential" || spec.Audience != "native-saml-app" {
		t.Fatal("SAML role commit did not issue the linked member's actual session", err)
	}
	bearer, err := got.Issuance.Token.Reveal()
	if err != nil || bearer == "" {
		t.Fatal("committed signed SAML role callback withheld its bearer", err)
	}
	csrf, err := got.CSRF.Reveal()
	if err != nil || csrf == "" {
		t.Fatal("committed signed SAML role callback withheld its CSRF", err)
	}
	assertNativeSAMLCallbackCommit(t, x.callback, got, bearer, csrf)
	after := nativeSAMLCallbackSuccessCounts(t, x.callback)
	if after[0] != before[0]+1 || after[1] != before[1]+1 || after[2] != 1 || after[3] != 2 || after[4] != 1 || after[5] != 1 {
		t.Fatalf("signed role callback did not commit one session and its replay pair: before %v after %v", before, after)
	}
	repeated, _ := x.callback.completion.SigninCallback(f.ctx, x.callback.request)
	assertNativeSAMLCallbackWithholdsIssuance(t, repeated)
	_, replayed := x.grant(t)
	if replayed != committed || nativeSAMLCallbackSuccessCounts(t, x.callback) != after || x.callback.calls != 0 {
		t.Fatal("terminal signed SAML retry changed role grants, repeated verification or durable effects")
	}

	// Assign the same role independently through the real application admin.
	// The provider's later false observation must not remove this binding.
	f.seedUser(t, x.callback.start.start.config.TenantID, "second")
	f.add(t, tenant, "second", organization.RoleAdministrator, readOrganization().Organization.Version)
	applyAdminBinding := func(assign bool) {
		t.Helper()
		admin := f.auth(tenant, "second")
		view, err := f.service.GetDynamicRole(f.ctx, organization.DynamicRoleReadRequest{Authentication: admin,
			OrganizationID: profile.OrganizationID, RoleID: nativeSAMLRoleID, TargetUserID: "owner", CorrelationID: "independent-saml-app-role"})
		if err != nil {
			t.Fatal("read independent application role assignment", err)
		}
		request := organization.RoleBindingRequest{Authentication: admin, CommandID: commandID(t), OrganizationID: profile.OrganizationID,
			RoleID: nativeSAMLRoleID, UserID: "owner", OrganizationVersion: view.Organization.Version, RoleVersion: view.DynamicRole.Version,
			OrganizationMemberVersion: view.Target.Version, BindingVersion: view.RoleBinding.Version, CorrelationID: "independent-saml-app-role"}
		var prepared organizationpg.PreparedCommand
		if assign {
			prepared, err = f.service.PrepareAssignDynamicRole(f.ctx, request, "127.0.0.1")
		} else {
			prepared, err = f.service.PrepareRevokeDynamicRole(f.ctx, request, "127.0.0.1")
		}
		if err != nil {
			t.Fatal("prepare independent application role transition", err)
		}
		if changed, err := f.service.Execute(f.ctx, prepared); err != nil || changed.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("commit independent application role transition", err)
		}
	}
	applyAdminBinding(true)

	x.nextAttempt(t, "native-saml-role-missing")
	x.callback.request.SAMLResponse = x.signedResponse(t, "")
	beforeMissing := nativeSAMLCallbackSuccessCounts(t, x.callback)
	missing, err := x.callback.completion.SigninCallback(f.ctx, x.callback.request)
	assertNativeSAMLCallbackWithholdsIssuance(t, missing)
	_, retained := x.grant(t)
	if !errors.Is(err, sso.ErrForbidden) || retained != committed ||
		nativeSAMLCallbackSuccessCounts(t, x.callback) != beforeMissing || x.callback.calls != 0 {
		t.Fatal("signed missing role observation changed the retained grant or issued a session", err)
	}

	x.nextAttempt(t, "native-saml-role-withdrawal")
	x.callback.request.SAMLResponse = x.signedResponse(t, `<a:Attribute Name="`+nativeSAMLRoleClaim+`"><a:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" xsi:type="xs:boolean">false</a:AttributeValue></a:Attribute>`)
	beforeWithdrawal := nativeSAMLCallbackSuccessCounts(t, x.callback)
	withdrawn, err := x.callback.completion.SigninCallback(f.ctx, x.callback.request)
	if err != nil || withdrawn.Completion.Outcome != identity.CommitOutcomeCommitted ||
		withdrawn.Issuance.CommitOutcome != identity.CommitOutcomeCommitted || x.callback.calls != 0 {
		t.Fatal("signed false did not commit provider-role withdrawal and a new native session", err)
	}
	roles, checkpoint := x.grant(t)
	if len(roles) != 0 || checkpoint == committed {
		t.Fatal("signed false retained the old grant or lost its durable withdrawal checkpoint")
	}
	afterWithdrawal := nativeSAMLCallbackSuccessCounts(t, x.callback)
	if afterWithdrawal[0] != beforeWithdrawal[0]+1 || afterWithdrawal[3] != 2 || afterWithdrawal[2] != 1 ||
		afterWithdrawal[4] != 1 || afterWithdrawal[5] != 1 {
		t.Fatal("role withdrawal did not atomically issue one session with its own replay pair")
	}
	assertPermission(authorization.Allow)
	applyAdminBinding(false)
	assertPermission(authorization.Deny)
}

func TestNativeSAMLRoleCallbackInactiveSourceRollsBackSessionAndRetainsGrant(t *testing.T) {
	x := newNativeSAMLRoleJourneyFixture(t)
	f := x.callback.start.start.enable.f
	profile := x.callback.start.profiles[0]
	tenant := string(x.callback.start.start.config.TenantID)
	x.callback.request.SAMLResponse = x.signedResponse(t, `<a:Attribute Name="`+nativeSAMLRoleClaim+`"><a:AttributeValue>true</a:AttributeValue></a:Attribute>`)
	first, err := x.callback.completion.SigninCallback(f.ctx, x.callback.request)
	if err != nil || first.Completion.Outcome != identity.CommitOutcomeCommitted || first.Issuance.CommitOutcome != identity.CommitOutcomeCommitted {
		t.Fatal("establish signed SAML role grant before source retirement", err)
	}
	roles, committed := x.grant(t)
	if !slices.Equal(roles, []string{string(nativeSAMLRoleID)}) {
		t.Fatal("source-retirement fixture did not retain the actual provider grant")
	}
	x.nextAttempt(t, "native-saml-inactive-role-source")
	x.callback.request.SAMLResponse = x.signedResponse(t, `<a:Attribute Name="`+nativeSAMLRoleClaim+`"><a:AttributeValue>false</a:AttributeValue></a:Attribute>`)
	if _, err := f.pool.Raw().Exec(f.ctx, `SELECT organization.project_provider_role_source(
tenant_id,organization_id,provider_id,metadata_version,COALESCE(metadata_mapping_version,mapping_version),false)
FROM sso_providers.providers WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`,
		tenant, string(profile.OrganizationID), string(profile.ProviderID)); err != nil {
		t.Fatal("retire the exact installed provider-role source", err)
	}
	readAuthority := func() string {
		t.Helper()
		var snapshot string
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT json_build_array(o.version::text,m.authorization_version::text,to_jsonb(s))::text
FROM organization.organizations o JOIN organization.memberships m USING(tenant_id,organization_id)
JOIN organization.provider_role_sources s USING(tenant_id,organization_id)
WHERE o.tenant_id=$1 AND o.organization_id=$2 AND m.user_id='owner' AND s.provider_id=$3 AND NOT s.active`,
			tenant, string(profile.OrganizationID), string(profile.ProviderID)).Scan(&snapshot); err != nil {
			t.Fatal("observe retired source and exact organization/member authority", err)
		}
		return snapshot
	}
	authorityBefore := readAuthority()
	before := nativeSAMLCallbackSuccessCounts(t, x.callback)
	// The sequence survives rollback and observes only the exact callback's
	// attempted issuance. It does not cause the refusal: Apply's real inactive
	// provider-role source fence runs after the native session/browser writes.
	nativeCallbackJourneyExec(t, x.callback.start.start, `CREATE SEQUENCE organization_sessions.fixture_saml_role_source_attempts`)
	nativeCallbackJourneyExec(t, x.callback.start.start, `CREATE FUNCTION organization_sessions.observe_saml_role_source_attempt() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.tenant_id::text=TG_ARGV[0] AND encode(NEW.command_id,'hex')=TG_ARGV[1] AND NEW.purpose='identity.sso.saml-acs' THEN
  PERFORM nextval('organization_sessions.fixture_saml_role_source_attempts');
 END IF;
 RETURN NEW;
END $$`)
	var trigger string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT format('CREATE TRIGGER fixture_saml_role_source_attempt BEFORE INSERT ON organization_sessions.session_issuances FOR EACH ROW EXECUTE FUNCTION organization_sessions.observe_saml_role_source_attempt(%L,%L)',$1::text,encode($2::bytea,'hex'))`,
		tenant, x.callback.binary).Scan(&trigger); err != nil {
		t.Fatal("scope issuance observation to the original SAML callback", err)
	}
	nativeCallbackJourneyExec(t, x.callback.start.start, trigger)
	denied, err := x.callback.completion.SigninCallback(f.ctx, x.callback.request)
	assertNativeSAMLCallbackWithholdsIssuance(t, denied)
	var reached bool
	if readErr := f.pool.Raw().QueryRow(f.ctx, `SELECT is_called FROM organization_sessions.fixture_saml_role_source_attempts`).Scan(&reached); readErr != nil || !reached {
		t.Fatal("inactive-source refusal did not reach the native SAML issuance Work", readErr)
	}
	_, retained := x.grant(t)
	if err == nil || denied.Completion.Outcome != identity.CommitOutcomeNotCommitted || denied.Completion.Binding.CommandID == "" ||
		retained != committed || readAuthority() != authorityBefore || nativeSAMLCallbackSuccessCounts(t, x.callback) != before || x.callback.calls != 0 {
		t.Fatal("late inactive-source refusal failed to roll back session/replay writes or changed the retained provider grant", err)
	}
}

func TestNativeSAMLRoleCallbackRejectsSignedStringInsteadOfBoolean(t *testing.T) {
	x := newNativeSAMLRoleJourneyFixture(t)
	f := x.callback.start.start.enable.f
	x.callback.request.SAMLResponse = x.signedResponse(t, `<a:Attribute Name="`+nativeSAMLRoleClaim+`"><a:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" xsi:type="xs:string">true</a:AttributeValue></a:Attribute>`)
	before := nativeSAMLCallbackSuccessCounts(t, x.callback)
	got, err := x.callback.completion.SigninCallback(f.ctx, x.callback.request)
	assertNativeSAMLCallbackWithholdsIssuance(t, got)
	if !errors.Is(err, sso.ErrForbidden) || got.Completion.Outcome == identity.CommitOutcomeCommitted ||
		nativeSAMLCallbackSuccessCounts(t, x.callback) != before || x.callback.calls != 0 {
		t.Fatal("signed string role escaped strict boolean mapping or persisted success effects", err)
	}
	var count int
	profile := x.callback.start.profiles[0]
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM organization.provider_role_grants
WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND user_id='owner'`,
		string(x.callback.start.start.config.TenantID), string(profile.OrganizationID), string(profile.ProviderID)).Scan(&count); err != nil || count != 0 {
		t.Fatal("rejected signed role observation left a durable grant", err)
	}
}

func (x nativeSAMLRoleJourneyFixture) grant(t *testing.T) ([]string, string) {
	t.Helper()
	f := x.callback.start.start.enable.f
	profile := x.callback.start.profiles[0]
	var roles []string
	var snapshot string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT role_ids,to_jsonb(g)::text FROM organization.provider_role_grants g
WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND user_id='owner'`,
		string(x.callback.start.start.config.TenantID), string(profile.OrganizationID), string(profile.ProviderID)).Scan(&roles, &snapshot); err != nil {
		t.Fatal("read exact persisted SAML provider-role grant", err)
	}
	return roles, snapshot
}

func (x nativeSAMLRoleJourneyFixture) nextAttempt(t *testing.T, correlation string) {
	t.Helper()
	start := x.callback.start
	f := start.start.enable.f
	prepared, err := start.start.flowIssuer.Prepare(session.PreAuthPrepareInput{CommandID: commandID(t),
		TenantID: start.start.config.TenantID, CorrelationID: correlation, Remember: start.start.originalFlow.Intent.Remember})
	if err != nil {
		t.Fatal("prepare next original SAML browser flow", err)
	}
	issued, err := start.start.flowIssuer.Issue(f.ctx, prepared)
	if err != nil || issued.CommitOutcome != identity.CommitOutcomeCommitted || issued.Replayed {
		t.Fatal("issue next original SAML browser flow", err)
	}
	flow, err := issued.Flow.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	secret, err := issued.Token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	browser := start.start.browser
	browser.FlowID, browser.FlowCookie = flow.Binding.ID, authentication.NewBearerCredential(secret)
	request := start.request
	request.IdempotencyKey, err = identity.NewIdempotencyKey([]byte(correlation))
	if err != nil {
		t.Fatal(err)
	}
	before := len(start.inputs)
	started, err := start.start.service.SigninStartSAML(f.ctx, request, browser)
	if err != nil || started.Completion.Outcome != identity.CommitOutcomeCommitted || len(start.inputs) != before+1 {
		t.Fatal("commit next original SAML start", err)
	}
	x.callback.started = started
	x.callback.request.RelayState, x.callback.request.Browser = started.RedirectURI.Query().Get("RelayState"), browser
	start.start.browser, start.start.originalFlow = browser, flow.Binding
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT callback_command_id,expires_at FROM sso_providers.login_transactions
WHERE start_command_id=$1`, started.TransactionID).Scan(&x.callback.callback, &x.callback.expires); err != nil {
		t.Fatal("read next original SAML callback correlation", err)
	}
	x.callback.binary, err = base64.RawURLEncoding.DecodeString(x.callback.callback)
	if err != nil {
		t.Fatal(err)
	}
}

// The independent signing fixture follows SAML Core §§2.4.1.2, 2.5.1.2,
// 3.2.2 and Profiles §4.1.4.3. Both signatures cover the exact attributes;
// the SP's released verifier, not this helper, decides their meaning.
func (x nativeSAMLRoleJourneyFixture) signedResponse(t *testing.T, attributes string) string {
	t.Helper()
	attempt := len(x.callback.start.inputs)
	original := x.callback.start.inputs[attempt-1]
	responseID, assertionID := nativeSAMLCallbackResponseID, nativeSAMLCallbackAssertionID
	if attempt > 1 {
		responseID += fmt.Sprintf("-%d", attempt)
		assertionID += fmt.Sprintf("-%d", attempt)
	}
	escape := func(value string) string {
		var out bytes.Buffer
		if err := xml.EscapeText(&out, []byte(value)); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	issued := now.Format(time.RFC3339Nano)
	expires := now.Add(2 * time.Minute).Format(time.RFC3339Nano)
	issuer := `<a:Issuer>` + nativeSAMLCallbackIssuer + `</a:Issuer>`
	assertionOpen := fmt.Sprintf(`<a:Assertion xmlns:a="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" IssueInstant="%s" Version="2.0">`, assertionID, issued)
	subject := `<a:Subject><a:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">` + nativeSAMLCallbackSubject + `</a:NameID>` +
		`<a:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
		fmt.Sprintf(`<a:SubjectConfirmationData InResponseTo="%s" NotOnOrAfter="%s" Recipient="%s"></a:SubjectConfirmationData>`, escape(original.RequestID), expires, escape(original.AssertionConsumerURL)) +
		`</a:SubjectConfirmation></a:Subject>`
	conditions := fmt.Sprintf(`<a:Conditions NotBefore="%s" NotOnOrAfter="%s"><a:AudienceRestriction><a:Audience>%s</a:Audience></a:AudienceRestriction></a:Conditions>`, issued, expires, escape(original.SPEntityID))
	authentication := fmt.Sprintf(`<a:AuthnStatement AuthnInstant="%s" SessionIndex="%s">`, issued, assertionID) +
		`<a:AuthnContext><a:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</a:AuthnContextClassRef></a:AuthnContext></a:AuthnStatement>`
	statement := ""
	if attributes != "" {
		statement = `<a:AttributeStatement>` + attributes + `</a:AttributeStatement>`
	}
	assertionContent := subject + conditions + authentication + statement + `</a:Assertion>`
	assertion := assertionOpen + issuer + x.signXML(t, assertionID, assertionOpen+issuer+assertionContent) + assertionContent
	responseOpen := fmt.Sprintf(`<p:Response xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" Destination="%s" ID="%s" InResponseTo="%s" IssueInstant="%s" Version="2.0">`, escape(original.AssertionConsumerURL), responseID, escape(original.RequestID), issued)
	responseIssuer := `<a:Issuer xmlns:a="urn:oasis:names:tc:SAML:2.0:assertion">` + nativeSAMLCallbackIssuer + `</a:Issuer>`
	content := `<p:Status><p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"></p:StatusCode></p:Status>` + assertion + `</p:Response>`
	response := responseOpen + responseIssuer + x.signXML(t, responseID, responseOpen+responseIssuer+content) + content
	return base64.StdEncoding.EncodeToString([]byte(response))
}

func (x nativeSAMLRoleJourneyFixture) signXML(t *testing.T, id, unsigned string) string {
	t.Helper()
	const namespace = `xmlns:ds="http://www.w3.org/2000/09/xmldsig#"`
	digest := base64.StdEncoding.EncodeToString(nativeSAMLRoleCanonicalDigest(t, unsigned))
	content := `<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod>` +
		`<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"></ds:SignatureMethod>` +
		`<ds:Reference URI="#` + id + `"><ds:Transforms>` +
		`<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform>` +
		`<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms>` +
		`<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod>` +
		`<ds:DigestValue>` + digest + `</ds:DigestValue></ds:Reference>`
	r, s, err := ecdsa.Sign(rand.Reader, x.key, nativeSAMLRoleCanonicalDigest(t, `<ds:SignedInfo `+namespace+`>`+content+`</ds:SignedInfo>`))
	if err != nil {
		t.Fatal("sign exact SAML role fixture node", err)
	}
	// XML Signature 1.1 §6.4.3 requires fixed-width R || S, not ASN.1 DER.
	var signature [64]byte
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return `<ds:Signature ` + namespace + `><ds:SignedInfo>` + content + `</ds:SignedInfo><ds:SignatureValue>` +
		base64.StdEncoding.EncodeToString(signature[:]) + `</ds:SignatureValue></ds:Signature>`
}

func nativeSAMLRoleCanonicalDigest(t *testing.T, source string) []byte {
	t.Helper()
	tree, err := xdm.Parse(strings.NewReader(source), xdm.ParseOptions{MaxBytes: 64 << 10, MaxDepth: 24, MaxNodes: 256})
	if err != nil {
		t.Fatal("parse independent SAML role signing input", err)
	}
	digest, err := c14n.Digest(sha256.New(), tree.Root.FirstChild(), c14n.Options{Algorithm: c14n.Exclusive10})
	if err != nil {
		t.Fatal("canonicalize independent SAML role signing input", err)
	}
	return digest
}
