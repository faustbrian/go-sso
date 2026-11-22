//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	"github.com/faustbrian/go-organization"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

type nativeMemberJourneyPolicy struct{}

const nativeLinkMember = identity.UserID("01ARZ3NDEKTSV4RRFFQ69G5FAT")

func (nativeMemberJourneyPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	if c.PolicyRevision == 1 && c.Request.Tenant == authorization.TenantID(discoveryFixtureTenant) &&
		c.Request.Subject.Kind == authorization.SubjectUser && c.Request.Subject.ID == authorization.SubjectID(nativeLinkMember) &&
		(c.Request.Action == "identity.sso.signin-start" || c.Request.Action == "identity.sso.oidc-callback") {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
	}
	return (nativeCallbackJourneyPolicy{}).Decide(ctx, c)
}

func prepareNativeMemberJourneyIdentity(t *testing.T, x providerLoginStartFixture) {
	t.Helper()
	f, tenant, org := x.enable.f, x.config.TenantID, x.config.Profiles[0].OrganizationID
	var revision uint64
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT version::bigint FROM organization.organizations WHERE tenant_id=$1 AND organization_id=$2`, string(tenant), string(org)).Scan(&revision); err != nil {
		t.Fatal("read organization before creating the preexisting member", err)
	}
	f.seedUser(t, tenant, nativeLinkMember)
	f.add(t, string(tenant), string(nativeLinkMember), organization.RoleMember, revision)
	seedNativeCallbackJourneyFactors(t, x, nativeLinkMember)
}

func prepareNativeMemberJourneyStart(t *testing.T, x *providerLoginStartFixture) ssopg.ProviderLinkBrowser {
	t.Helper()
	f, tenant := x.enable.f, x.config.TenantID
	bearer := f.auth(string(tenant), string(nativeLinkMember)).Bearer
	token, err := session.ParseToken(bearer.Token())
	if err != nil {
		t.Fatal("read the preexisting local password cookie", err)
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		t.Fatal(err)
	}
	request := session.GetRequest{TenantID: tenant, Credential: credential}
	got, err := f.sessions.Get(f.ctx, request)
	if err != nil || !got.Authenticated || got.ValidateAt(time.Now().UTC()) != nil {
		t.Fatal("the preexisting password cookie must authenticate through its native primary reader", err)
	}
	spec, err := got.Session.Bindings()
	if err != nil || spec.UserID != nativeLinkMember || spec.Authentication.Proof.Method != "password" {
		t.Fatal("the source cookie does not belong to the existing password-authenticated member", err)
	}
	csrfKey, err := session.NewCSRFKey(1, bytes.Repeat([]byte{0xd1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := session.NewCSRFToken()
	if err != nil {
		t.Fatal(err)
	}
	state, err := csrf.Digest(csrfKey, session.CSRFBinding{TenantID: tenant, SessionID: spec.SessionID, SessionVersion: spec.Version})
	if err != nil {
		t.Fatal(err)
	}
	projection, err := state.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(projection)
	if err != nil {
		t.Fatal(err)
	}
	// Upgrade the canonical fixture's preexisting session to its supported
	// digest-only CSRF projection; no session issuance is attributed to linking.
	nativeCallbackJourneyExec(t, *x, `UPDATE organization_sessions.sessions SET record=jsonb_set(jsonb_set(record,'{Schema}','2'),'{CSRF}',$3::jsonb) WHERE tenant_id=$1 AND session_id=$2`, string(tenant), spec.SessionID, encoded)
	got, err = f.sessions.Get(f.ctx, request)
	if err != nil || !got.Authenticated || got.Session.CSRFState().Check(projection.Binding, csrf, csrfKey) != nil {
		t.Fatal("the primary reader did not retain the source cookie's exact CSRF state", err)
	}
	policy := kernel.CommandQueryPolicy{Authorization: nativeMemberJourneyPolicy{}, Clock: clock.System{}, PolicyVersion: 1}
	x.config.Coordinator.AdmissionPolicy, x.config.Coordinator.QueryPolicy = &policy, &policy
	x.config.RequestKeys, err = kernel.NewRequestKeyConfig("native-sso-login", [32]byte{0xa2}, policy)
	if err != nil {
		t.Fatal(err)
	}
	x.service, err = ssopg.NewProviderLoginServiceWithLink(newProviderRouter(t, x.enable, 4), x.config, ssopg.ProviderLinkConfig{
		ConfigurationID: "native-member-link-v1", Sessions: *f.sessions, Profile: f.profile,
		LookupKeys: []session.DigestKey{f.key}, CSRFKeys: []session.CSRFKey{csrfKey},
	})
	if err != nil {
		t.Fatal("compose explicit linking with the real password session reader", err)
	}
	return ssopg.ProviderLinkBrowser{Session: bearer, CSRF: csrf, Origin: x.browser.Origin, Network: x.browser.Network, Device: x.browser.Device}
}

func nativeMemberJourneyCallback(x nativeCallbackJourneyFixture) ssopg.ProviderLinkCallbackRequest {
	return ssopg.ProviderLinkCallbackRequest{Session: x.linkBrowser.Session, Input: x.request.Input,
		ReceivedRedirectURI: x.request.ReceivedRedirectURI, Origin: x.linkBrowser.Origin, Network: x.linkBrowser.Network, Device: x.linkBrowser.Device}
}

func TestNativeProviderMemberLinkJourneyCommitsExactMemberThenSignsIn(t *testing.T) {
	x := newNativeCallbackJourneyFixture(t, "explicit-member")
	ctx := x.start.enable.f.ctx
	before := nativeJITJourneyCounts(t, x)
	effectsBefore := nativeProviderLoginCounts(t, x.start)
	got, err := x.completion.LinkCallback(ctx, nativeMemberJourneyCallback(x))
	if err != nil || got.Completion.Outcome != identity.CommitOutcomeCommitted || got.RedirectURI != x.start.request.SuccessCallback.String() || x.posts.Load() != 1 {
		t.Fatal("the original password-cookie member did not complete the signed provider link", err)
	}
	want := before
	want.accounts++
	want.credentials++
	want.associations++
	want.tokens++
	if nativeJITJourneyCounts(t, x) != want {
		t.Fatal("explicit linking created a user, membership or session, or omitted its single provider credential/token deposit")
	}
	assertNativeMemberJourneyCommit(t, x, got)
	after := nativeProviderLoginCounts(t, x.start)
	if after.events != effectsBefore.events+1 || after.audits <= effectsBefore.audits || after.transactions != effectsBefore.transactions || after.capabilities != effectsBefore.capabilities {
		t.Fatal("the link did not commit exactly one lifecycle effect under its original transaction/capability")
	}
	replay, err := x.completion.LinkCallback(ctx, nativeMemberJourneyCallback(x))
	if err == nil || replay.RedirectURI != "" || x.posts.Load() != 1 || nativeJITJourneyCounts(t, x) != want || nativeProviderLoginCounts(t, x.start) != after {
		t.Fatal("terminal replay exchanged the provider code or linked the member again", err)
	}
	request := x.newAttempt(t, "native-member-later-signin", nil, time.Time{})
	signedIn, err := x.completion.SigninCallback(ctx, request)
	if err != nil || signedIn.Completion.Outcome != identity.CommitOutcomeCommitted || signedIn.Issuance.CommitOutcome != identity.CommitOutcomeCommitted || signedIn.Issuance.Replayed || x.posts.Load() != 2 {
		t.Fatal("ordinary later provider sign-in did not use the newly committed link", err)
	}
	spec, err := signedIn.Issuance.Session.Bindings()
	if err != nil || spec.UserID != nativeLinkMember || spec.TenantID != x.start.config.TenantID || spec.Authentication.Proof.Method != "sso-oidc" ||
		spec.Authentication.CredentialID != string(got.Completion.Binding.CommandID) {
		t.Fatal("later sign-in did not issue for the exact existing member and newly linked credential", err)
	}
	final := nativeJITJourneyCounts(t, x)
	if final.users != before.users || final.members != before.members || final.accounts != want.accounts || final.credentials != want.credentials ||
		final.sessions != before.sessions+1 || final.families != before.families+1 || final.issuances != before.issuances+1 {
		t.Fatal("later sign-in provisioned another identity/member or failed to issue exactly one native session")
	}
	bearer, err := signedIn.Issuance.Token.Reveal()
	if err != nil {
		t.Fatal("committed later sign-in withheld its native bearer", err)
	}
	reader, _ := nativeCallbackJourneySessionReader(t, x, spec.Audience)
	token, err := session.ParseToken(bearer)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		t.Fatal(err)
	}
	authenticated, err := reader.Get(ctx, session.GetRequest{TenantID: spec.TenantID, Credential: credential})
	if err != nil || !authenticated.Authenticated || authenticated.ValidateAt(time.Now().UTC()) != nil {
		t.Fatal("the later sign-in cookie failed the native current enterprise authority reader", err)
	}
}

func TestNativeProviderMemberLinkJourneyDeniesMissingSourceCookieBeforeExchange(t *testing.T) {
	x := newNativeCallbackJourneyFixture(t, "explicit-member")
	request := nativeMemberJourneyCallback(x)
	request.Session = authentication.BearerCredential{}
	before := nativeJITJourneyCounts(t, x)
	effects := nativeProviderLoginCounts(t, x.start)
	wrongProfile, err := x.completion.SigninCallback(x.start.enable.f.ctx, x.request)
	if !errors.Is(err, sso.ErrForbidden) || wrongProfile.Issuance.Token != (session.Token{}) || x.posts.Load() != 0 {
		t.Fatal("anonymous sign-in accepted authenticated member state", err)
	}
	for range 2 {
		got, err := x.completion.LinkCallback(x.start.enable.f.ctx, request)
		if err == nil || got.Completion.Outcome == identity.CommitOutcomeCommitted || got.RedirectURI != "" || x.posts.Load() != 0 ||
			nativeJITJourneyCounts(t, x) != before || nativeProviderLoginCounts(t, x.start) != effects {
			t.Fatal("missing source cookie or its replay reached provider exchange or committed a link", err)
		}
	}
}

func removeNativeLinkMember(ctx context.Context, x providerLoginStartFixture) error {
	f, tenant, org := x.enable.f, x.config.TenantID, x.config.Profiles[0].OrganizationID
	var revision, membership uint64
	if err := f.pool.Raw().QueryRow(ctx, `SELECT o.version::bigint,m.version::bigint FROM organization.organizations o
JOIN organization.memberships m USING (tenant_id,organization_id) WHERE o.tenant_id=$1 AND o.organization_id=$2 AND m.user_id=$3 AND m.state='active'`,
		string(tenant), string(org), string(nativeLinkMember)).Scan(&revision, &membership); err != nil {
		return err
	}
	command, err := identity.NewCommandID()
	if err != nil {
		return err
	}
	prepared, err := f.service.PrepareRemoveMember(ctx, organization.MemberRequest{Authentication: f.auth(string(tenant), "owner"), CommandID: command,
		OrganizationID: org, UserID: nativeLinkMember, OrganizationVersion: revision, MemberVersion: membership, CorrelationID: "member-withdrawal"}, "127.0.0.1")
	if err != nil {
		return err
	}
	result, err := f.service.Execute(ctx, prepared)
	if err == nil && result.Receipt.Outcome != identity.CommitOutcomeCommitted {
		return errors.New("membership removal did not commit")
	}
	return err
}

func TestNativeProviderMemberLinkJourneyDeniesMembershipRemovedDuringExchange(t *testing.T) {
	x := newNativeCallbackJourneyFixture(t, "explicit-member-removed")
	before := nativeJITJourneyCounts(t, x)
	ctx := x.start.enable.f.ctx
	request := nativeMemberJourneyCallback(x)
	got, err := x.completion.LinkCallback(ctx, request)
	if err == nil || got.RedirectURI != "" || got.Completion.Outcome == identity.CommitOutcomeCommitted || x.posts.Load() != 1 {
		t.Fatal("a member removed during provider exchange was allowed to link", err)
	}
	after := nativeJITJourneyCounts(t, x)
	if after.memberCount != before.memberCount-1 || after.accounts != before.accounts || after.credentials != before.credentials ||
		after.associations != before.associations || after.tokens != before.tokens || after.sessions != before.sessions || after.issuances != before.issuances {
		t.Fatal("late membership removal did not commit, or the denied link left durable effects")
	}
	if _, err := x.completion.LinkCallback(ctx, request); err == nil || x.posts.Load() != 1 {
		t.Fatal("retry after membership removal repeated provider exchange", err)
	}
}

func assertNativeMemberJourneyCommit(t *testing.T, x nativeCallbackJourneyFixture, got ssopg.ProviderLinkCallbackResult) {
	t.Helper()
	callback := string(got.Completion.Binding.CommandID)
	binary, err := base64.RawURLEncoding.DecodeString(callback)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := ssopg.SSOOIDCAccountProviderNamespace(x.start.config.Profiles[0].OrganizationID, x.start.config.Profiles[0].ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	var linked, completed, credential, encrypted, command, erased, temporaryErased, oneUse bool
	var audits, events int
	var ciphertext []byte
	err = x.start.enable.f.pool.Raw().QueryRow(x.start.enable.f.ctx, `SELECT
EXISTS(SELECT 1 FROM identity.accounts WHERE tenant_id=$1 AND user_id=$9 AND account_id=$2 AND provider=$4 AND issuer=$5 AND subject=$6 AND linked AND version=1 AND social_link_version=2),
EXISTS(SELECT 1 FROM identity.credential_references c JOIN identity.account_credentials a USING(tenant_id,user_id,credential_id) WHERE c.tenant_id=$1 AND c.user_id=$9 AND c.credential_id=$2 AND c.kind=3 AND c.owner='sso' AND c.enabled AND c.version=1 AND a.account_id=$2),
l.completed_at IS NOT NULL,l.verifier_envelope IS NULL,
j.state='committed' AND j.result IS NOT NULL,j.preparation_ciphertext IS NULL AND j.preparation_ciphertext_generation IS NULL,
EXISTS(SELECT 1 FROM public.capability_identity_one_use WHERE tenant_id=$1 AND command_id=$2 AND state='finalized' AND uses=1),
v.token_ciphertext,octet_length(v.token_ciphertext)>0 AND v.user_id=$9 AND v.account_id=$2 AND v.account_provider=$4 AND v.account_version=1 AND v.social_link_version=2,
(SELECT count(*) FROM audit.records WHERE tenant_id=$1 AND action='identity.account.link' AND correlation_id=$2 AND outcome=$7),
(SELECT count(*) FROM public.identity_outbox_bindings b JOIN public.outbox_messages m ON m.id=b.effect_id WHERE b.tenant_id=$1 AND b.command_id=$3 AND m.topic='enterprise_provider.account_linked.v1')
FROM sso_providers.login_transactions l
JOIN identity.commands j ON j.tenant_id=l.tenant_id AND j.command_id=$3 AND j.purpose='identity.sso.oidc-callback'
JOIN sso_providers.provider_login_token_sets v ON v.tenant_id=l.tenant_id AND v.callback_command_id=$2
WHERE l.tenant_id=$1 AND l.start_command_id=$8`, string(x.start.config.TenantID), callback, binary, provider,
		nativeCallbackJourneyIssuer, nativeCallbackJourneySubject, int16(audit.OutcomeSucceeded), x.started.TransactionID, string(nativeLinkMember)).
		Scan(&linked, &credential, &completed, &erased, &command, &temporaryErased, &oneUse, &ciphertext, &encrypted, &audits, &events)
	if err != nil || !linked || !credential || !completed || !erased || !command || !temporaryErased || !encrypted || !oneUse || audits != 1 || events != 1 {
		t.Fatal("link, provider credential, encrypted tokens, one-use erasure, audit and lifecycle did not commit together exactly once", err)
	}
	for _, secret := range []string{nativeCallbackJourneyAccessToken, nativeCallbackJourneyRefreshToken, x.idToken, x.linkBrowser.Session.Token()} {
		if bytes.Contains(ciphertext, []byte(secret)) {
			t.Fatal("the link token vault retained plaintext provider/browser custody")
		}
	}
}
