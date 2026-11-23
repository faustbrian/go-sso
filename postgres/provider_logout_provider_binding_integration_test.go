//go:build integration

package postgres_test

import (
	"errors"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-sso"
	"github.com/faustbrian/go-sso/oidc"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestNativeProviderLogoutStartDeniesInstalledOtherProviderWithOriginalCookie(t *testing.T) {
	trace := new(providerTrace)
	x := newNativeProviderLogoutFixture(t, true, trace)
	ctx := x.journey.start.enable.f.ctx
	originalProfile := x.loginConfig.Profiles[0]
	// The start fixture already registered, credentialed and enabled this
	// distinct issuer before installing the journey's linked provider.
	otherProvider := sso.ProviderID(x.journey.start.enable.request.ProviderID)
	const otherIssuer = "https://enable.example.com"
	if otherProvider == originalProfile.ProviderID {
		t.Fatal("the fixture needs two independently installed providers")
	}
	otherNamespace, err := ssopg.SSOOIDCAccountProviderNamespace(originalProfile.OrganizationID, otherProvider)
	if err != nil {
		t.Fatal(err)
	}
	const otherCredential = "logout-other-provider-credential"
	const otherAccount = "logout-other-provider-account"
	tenant := string(x.session.TenantID)
	start := x.journey.start
	nativeCallbackJourneyExec(t, start, `INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled)
 VALUES($1,'owner',$2,3,'sso',1,true)`, tenant, otherCredential)
	nativeCallbackJourneyExec(t, start, `WITH a AS (SELECT $3::text AS provider,$4::text AS issuer,$5::text AS subject)
 INSERT INTO identity.accounts(tenant_id,user_id,account_id,provider,issuer,subject,subject_key,version,social_link_version,linked)
 SELECT $1,'owner',$2,provider,issuer,subject,
 sha256(convert_to(octet_length(provider)::text||':'||provider||octet_length(issuer)::text||':'||issuer||octet_length(subject)::text||':'||subject,'UTF8')),1,1,true FROM a`,
		tenant, otherAccount, otherNamespace, otherIssuer, "logout-other-provider-subject")
	nativeCallbackJourneyExec(t, start, `INSERT INTO identity.account_credentials(tenant_id,user_id,credential_id,account_id)
 VALUES($1,'owner',$2,$3)`, tenant, otherCredential, otherAccount)

	otherProfile := originalProfile
	otherProfile.ProviderID = otherProvider
	loginConfig := x.loginConfig
	loginConfig.Profiles = []ssopg.StaticOIDCLoginProfile{originalProfile, otherProfile}
	router := nativeProviderLogoutTracedRouter(t, start.enable, trace)
	login, err := ssopg.NewProviderLoginService(router, loginConfig)
	if err != nil {
		t.Fatal("select both installed providers at the same configuration epochs", err)
	}
	logoutConfig := x.logoutConfig
	logoutConfig.Profiles = []ssopg.ProviderLogoutProfile{x.logoutConfig.Profiles[0], {
		OrganizationID: otherProfile.OrganizationID, ProviderID: otherProvider,
		Protocol: oidc.RPLogoutProfileConfig{Issuer: otherIssuer, ClientID: otherProfile.ClientID,
			EndSessionEndpoint: otherIssuer + "/end-session",
			CallbackURI:        loginConfig.Origin + "/sso/oidc/" + string(otherProvider) + "/logout/callback"},
	}}
	service, err := ssopg.NewProviderLogoutService(login, logoutConfig)
	if err != nil {
		t.Fatal("select the second provider's exact native logout callback", err)
	}

	// Public routing is a non-mutating eligibility oracle; an absent,
	// disabled, stale or unproved provider cannot reach the binding case.
	routeRequest, err := sso.NewDomainRouteRequest(x.session.TenantID, otherProfile.Domain, otherProvider)
	if err != nil {
		t.Fatal(err)
	}
	route, err := router.Route(ctx, routeRequest)
	if err != nil || route.Value != string(otherProvider) {
		t.Fatal("the second installed provider must be usable through real admission", err)
	}
	bindings, err := route.Bindings()
	if err != nil || bindings.ProviderVersion != originalProfile.ProviderVersion ||
		bindings.ProviderVersion != x.session.Authentication.ProofVersion ||
		bindings.CredentialGeneration != originalProfile.CredentialGeneration ||
		bindings.Proof.Key.OrganizationID != originalProfile.OrganizationID {
		t.Fatal("the second provider must not be rejected by an earlier provider epoch or organization check", err)
	}

	request := x.request
	request.ProviderID = string(otherProvider)
	before := nativeProviderLogoutStartCounts(t, x)
	providerPosts := x.journey.posts.Load()
	trace.mu.Lock()
	trace.queries = nil
	trace.mu.Unlock()
	denied, err := service.Start(ctx, request, x.browser)
	if _, disclosed := denied.RedirectURI(); !errors.Is(err, sso.ErrForbidden) || disclosed ||
		denied.Outcome() != oidc.OIDCLogoutInvalid || denied.Validate() == nil {
		t.Fatal("the original provider cookie authorized logout through another installed provider", err)
	}
	trace.mu.Lock()
	queries, traceErr := append([]providerQuery(nil), trace.queries...), trace.err
	trace.mu.Unlock()
	if traceErr != nil {
		t.Fatal("observe the provider binding boundary", traceErr)
	}
	reachedBinding := false
	for _, query := range queries {
		if strings.HasPrefix(query.sql, "WITH account AS MATERIALIZED") && len(query.args) == 8 &&
			query.args[2] == string(otherProvider) && query.args[5] == x.session.Authentication.CredentialID &&
			query.args[6] == string(x.session.UserID) && query.args[7] == otherNamespace {
			reachedBinding = true
		}
	}
	if !reachedBinding {
		t.Fatal("the denial did not reach the original credential's installed-provider binding guard")
	}
	if nativeProviderLogoutStartCounts(t, x) != before || x.journey.posts.Load() != providerPosts {
		t.Fatal("the denied provider substitution created state, revoked a session or caused provider effects")
	}
	assertNativeProviderLogoutCookieState(t, x, true)

	accepted, err := service.Start(ctx, x.request, x.browser)
	if err != nil || accepted.Validate() != nil || accepted.Outcome() != oidc.OIDCLogoutRedirect {
		t.Fatal("the denied substitution consumed the original cookie or retry key", err)
	}
	redirect, present := accepted.RedirectURI()
	completion, receiptErr := accepted.Completion()
	if !present || redirect.Host != nativeCallbackJourneyHost || redirect.Path != "/end-session" ||
		redirect.Query().Get("post_logout_redirect_uri") != nativeProviderLogoutCallback(x.journey) ||
		receiptErr != nil || completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("the original cookie lost its own provider logout binding", receiptErr)
	}
	assertNativeProviderLogoutCookieState(t, x, false)
	assertNativeProviderLogoutStartCommit(t, x, completion, redirect.Query().Get("state"), true)
	if x.journey.posts.Load() != providerPosts {
		t.Fatal("native logout unexpectedly contacted the provider")
	}
}
