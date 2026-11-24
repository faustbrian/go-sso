//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestNativeSAMLLogoutStartRevokesExactCookieWithDisabledProvider(t *testing.T) {
	t.Run("acknowledged", func(t *testing.T) { assertNativeSAMLLogoutWithDisabledProvider(t, false) })
	t.Run("lost-acknowledgement", func(t *testing.T) { assertNativeSAMLLogoutWithDisabledProvider(t, true) })
}

func assertNativeSAMLLogoutWithDisabledProvider(t *testing.T, loseAcknowledgement bool) {
	t.Helper()
	x := newNativeSAMLCallbackFixture(t)
	f, loginConfig := x.start.start.enable.f, x.start.start.config
	ctx := f.ctx
	revoke, err := (sessionpg.RevokeOneMigrationSource{Base: sessionpg.RevocationMigrationSource{
		Base: sessionpg.MigrationSource{Schema: loginConfig.Session.Schema, Version: 20}, Version: 370,
	}, Version: 432}).Load(ctx)
	if err != nil || len(revoke) != 3 || revoke[2].Version() != 432 {
		t.Fatal("load the single-session revocation journal after its installed base", err)
	}
	installSAMLIDPStorage(t, f, migrationList(revoke[2:]))
	installSAMLIDPStorage(t, f, sessionpg.SSOSAMLLogoutStartMigrationSource{Schema: loginConfig.Session.Schema,
		Version: 433, ValidationVersion: 434, PreviousConstraint: "session_revocations_purpose_check"})
	issued, err := x.completion.SigninCallback(ctx, x.request)
	if err != nil || issued.Issuance.CommitOutcome != identity.CommitOutcomeCommitted {
		t.Fatal("issue original cookie through real SAML login", err)
	}
	exact, err := issued.Issuance.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	bearer, err := issued.Issuance.Token.Reveal()
	if err != nil || bearer == "" {
		t.Fatal("obtain the acknowledged original cookie", err)
	}
	organizations, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	selection := sessionpg.SSOSAMLSessionAdmission{Profile: sessionpg.IdentifierAdmissionConfig{GlobalAuthorityID: loginConfig.GlobalAuthorityID,
		PolicyNamespace: "users", Audience: exact.Audience, AuthenticationMethod: "sso-saml", CredentialKind: identity.CredentialProvider, CredentialOwner: "sso"},
		Authority: organizations}
	validation := session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: exact.Audience, LookupKeys: []session.DigestKey{x.lookup},
		Clock: clock.System{}, MaximumDuration: time.Second, ClockUncertainty: time.Millisecond}
	reader, err := sessionpg.NewSelectedSessionServiceWithSSOSAML(f.pool, sessionpg.SelectedSessionServiceConfig{
		Repository: loginConfig.Session, Validation: validation}, selection, nil)
	if err != nil {
		t.Fatal(err)
	}
	get := nativeProviderLogoutGetRequest(t, exact.TenantID, bearer)
	if observed, err := reader.Get(ctx, get); err != nil || !observed.Authenticated {
		t.Fatal("original cookie did not authenticate before logout", err)
	}
	policy := kernel.CommandQueryPolicy{Authorization: nativeSAMLLogoutStartPolicy{tenant: exact.TenantID, user: exact.UserID},
		Clock: clock.System{}, PolicyVersion: 1}
	loginConfig.Coordinator.QueryPolicy, loginConfig.Coordinator.AdmissionPolicy = &policy, &policy
	loginConfig.RequestKeys.Policy = policy
	logoutKeys, err := kernel.NewRequestKeyConfig("native-sso-login", [32]byte{0xaa}, policy)
	if err != nil {
		t.Fatal(err)
	}
	login, err := ssopg.NewProviderLoginServiceWithSAML(x.start.router, loginConfig, x.start.profiles, x.start.sign)
	if err != nil {
		t.Fatal(err)
	}
	logoutConfig := ssopg.ProviderSAMLLogoutConfig{Session: validation, Admission: selection,
		CSRFKeys: []session.CSRFKey{x.csrf}, FinalRedirectAllowlist: []string{nativeLogoutFinalRedirect}}
	if _, err := ssopg.NewProviderSAMLLogoutServiceWithRequestKeys(login, logoutConfig, loginConfig.RequestKeys); !errors.Is(err, sso.ErrInvalidInput) {
		t.Fatal("explicitly selecting the canonical login namespace for logout was accepted", err)
	}
	service, err := ssopg.NewProviderSAMLLogoutServiceWithRequestKeys(login, logoutConfig, logoutKeys)
	if err != nil {
		t.Fatal(err)
	}
	key, err := identity.NewIdempotencyKey([]byte("native-saml-original-session-logout"))
	if err != nil {
		t.Fatal(err)
	}
	req := ssopg.ProviderLogoutStartRequest{ProviderID: string(x.request.ProviderID), IdempotencyKey: key, FinalRedirect: nativeLogoutFinalRedirect}
	browser := ssopg.ProviderLogoutBrowser{Session: authentication.NewBearerCredential(bearer), CSRF: issued.CSRF, Origin: loginConfig.Origin}
	foreign := req
	foreign.ProviderID = "other-saml-provider"
	denied, err := service.Start(ctx, foreign, browser)
	if !errors.Is(err, sso.ErrForbidden) || denied.LocalRevocation.Validate() == nil {
		t.Fatal("an unrelated route provider selected this SAML session", err)
	}
	wrongBrowser := browser
	wrongBrowser.CSRF = session.CSRFToken{}
	denied, err = service.Start(ctx, req, wrongBrowser)
	if !errors.Is(err, sso.ErrForbidden) || denied.LocalRevocation.Validate() == nil {
		t.Fatal("invalid CSRF selected a local revocation", err)
	}
	profile := x.start.profiles[0]
	if tag, err := f.pool.Raw().Exec(ctx, `UPDATE sso_providers.providers SET enabled=false,enablement_proof=NULL,enablement_credential_generation=NULL
 WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`, exact.TenantID, profile.OrganizationID, profile.ProviderID); err != nil || tag.RowsAffected() != 1 {
		t.Fatal("disable the installed remote provider after issuance", err)
	}

	firstService := service
	var fault *providerCommitFault
	if loseAcknowledgement {
		pool, controlled := providerLossPool(t, f, `.session_revocations(tenant_id,command_id,purpose`)
		fault = controlled
		borrowed := *f
		borrowed.pool = pool
		enabled := x.start.start.enable
		enabled.f = &borrowed
		router, err := newProviderRouter(t, enabled, 4).WithProtocolRegistry()
		if err != nil {
			t.Fatal(err)
		}
		router, err = router.WithSAMLRouteValidation(func(context.Context, []byte, time.Time) (time.Time, error) {
			t.Error("native local logout attempted remote SAML route validation")
			return time.Time{}, sso.ErrUnavailable
		})
		if err != nil {
			t.Fatal(err)
		}
		faultLogin, err := ssopg.NewProviderLoginServiceWithSAML(router, loginConfig, x.start.profiles, x.start.sign)
		if err != nil {
			t.Fatal("compose the exact-session commit-fault fixture", err)
		}
		firstService, err = ssopg.NewProviderSAMLLogoutServiceWithRequestKeys(faultLogin, logoutConfig, logoutKeys)
		if err != nil {
			t.Fatal("compose the controlled lost-acknowledgement operation", err)
		}
	}
	got, err := firstService.Start(ctx, req, browser)
	if loseAcknowledgement {
		local := got.LocalRevocation
		var unknown identity.UnknownCommitError
		if !fault.seen.Load() || !fault.lost.Load() || !errors.As(err, &unknown) || got.LocalOnly || local.Validate() != nil ||
			local.SessionID != exact.SessionID || local.Version != exact.Version+1 || local.Committed || !local.ReconciliationRequired {
			t.Fatal("lost acknowledgement did not keep the exact local outcome unknown", err)
		}
		if observed, err := reader.Get(ctx, get); err != nil || observed.Authenticated {
			t.Fatal("fixture did not commit the original-session revocation before losing the acknowledgement", err)
		}
		got, err = service.Start(ctx, req, browser)
		if got.Completion.Binding.CommandID != unknown.CommandID {
			t.Fatal("recovery did not settle the exact original command", err)
		}
	}
	l := got.LocalRevocation
	if err != nil || !got.LocalOnly || got.Completion.Outcome != identity.CommitOutcomeCommitted || l.Validate() != nil ||
		l.SessionID != exact.SessionID || l.Version != exact.Version+1 || !l.Committed || l.ReconciliationRequired {
		t.Fatal("disabled provider prevented acknowledgement of the exact local revocation", err)
	}
	if observed, err := reader.Get(ctx, get); err != nil || observed.Authenticated {
		t.Fatal("original SAML cookie still authenticates after local logout", err)
	}
	recovered, err := service.Start(ctx, req, browser)
	if err != nil || recovered.LocalRevocation != l || !recovered.LocalOnly || recovered.Completion.Binding != got.Completion.Binding {
		t.Fatal("same-key recovery did not return the original revocation", err)
	}
	var rows int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM organization_sessions.session_revocations
 WHERE tenant_id=$1 AND session_id=$2 AND purpose=$3 AND after_version=$4::numeric`,
		exact.TenantID, exact.SessionID, got.Completion.Binding.OperationID, strconv.FormatUint(l.Version, 10)).Scan(&rows); err != nil || rows != 1 {
		t.Fatal("the exact session did not retain one original revocation receipt", err)
	}
	req.IdempotencyKey, err = identity.NewIdempotencyKey([]byte("another-saml-session-logout"))
	if err != nil {
		t.Fatal(err)
	}
	denied, err = service.Start(ctx, req, browser)
	if !errors.Is(err, sso.ErrForbidden) || denied.LocalRevocation.Validate() == nil {
		t.Fatal("a revoked cookie initiated another logout key", err)
	}
}

type nativeSAMLLogoutStartPolicy struct {
	tenant identity.TenantID
	user   identity.UserID
}

func (p nativeSAMLLogoutStartPolicy) Decide(_ context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	op := kernel.SSOSAMLLogoutStartOperation().OperationID
	r := c.Request
	ownsResource := r.Resource.Type == "identity.user" && r.Resource.ID == authorization.ResourceID(p.user)
	mayResolveKey := r.Resource.Type == "identity.request-admission" && r.Resource.ID == authorization.ResourceID(op)
	if c.PolicyRevision == 1 && r.Tenant == authorization.TenantID(p.tenant) && r.Subject.Kind == authorization.SubjectUser &&
		r.Subject.ID == authorization.SubjectID(p.user) && r.Action == authorization.Action(op) && (ownsResource || mayResolveKey) {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
	}
	return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, nil
}
