//go:build integration

package postgres_test

import (
	"encoding/base64"
	"errors"
	"strconv"
	"testing"

	identifier "github.com/faustbrian/go-identifier/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

const nativeJITMailbox = "new-enterprise-member@example.com"

// Focused acceptance filter: ^TestNativeProviderLoginJITJourney
// Uses the actual signed TLS exchange and task-owned primary PostgreSQL fixture.
func TestNativeProviderLoginJITJourneyCreatesOrdinaryMemberAndUsableSession(t *testing.T) {
	x := newNativeCallbackJourneyFixture(t, "jit")
	before := nativeJITJourneyCounts(t, x)
	callback, command := nativeJITJourneyCallback(t, x)
	effectsBefore := nativeCallbackJourneyDenialEffects(t, x, callback, command)
	got, err := x.completion.SigninCallback(x.start.enable.f.ctx, x.request)
	if err != nil || got.Completion.Outcome != identity.CommitOutcomeCommitted || got.Issuance.CommitOutcome != identity.CommitOutcomeCommitted || got.Issuance.Replayed || x.posts.Load() != 1 {
		logNativeCallbackJourneyFailure(t, x)
		t.Fatal("opted-in first login did not acknowledge one native JIT issuance", err)
	}
	spec, err := got.Issuance.Session.Bindings()
	if err != nil || spec.UserID == "" || spec.UserID == "owner" || spec.TenantID != x.start.config.TenantID ||
		spec.Authentication.Proof.Method != "sso-oidc" || spec.Authentication.CredentialID == "" || got.RedirectURI != x.start.request.SuccessCallback.String() {
		t.Fatal("first login did not issue the exact prospective enterprise user", err)
	}
	after := nativeJITJourneyCounts(t, x)
	if after.users != before.users+1 || after.identifiers != before.identifiers+1 || after.accounts != before.accounts+1 ||
		after.credentials != before.credentials+1 || after.associations != before.associations+1 || after.members != before.members+1 ||
		after.factors != before.factors+1 || after.policies != before.policies+2 || after.sessions != before.sessions+1 ||
		after.families != before.families+1 || after.issuances != before.issuances+1 || after.tokens != before.tokens+1 ||
		after.organizationVersion != before.organizationVersion+1 || after.memberCount != before.memberCount+1 ||
		after.credentialVersion != before.credentialVersion || after.owners != before.owners {
		t.Fatalf("first login did not atomically create exactly one ordinary-member graph: before=%+v after=%+v", before, after)
	}
	effectsAfter := nativeCallbackJourneyDenialEffects(t, x, callback, command)
	if effectsAfter.sessions != effectsBefore.sessions+1 || effectsAfter.deposits != effectsBefore.deposits+1 ||
		effectsAfter.successAudits != effectsBefore.successAudits+1 || effectsAfter.sessionEvents != effectsBefore.sessionEvents+1 {
		t.Fatal("first login omitted or duplicated its exact callback session, encrypted token, audit or outbox effects")
	}
	assertNativeJITJourneyCreatedGraph(t, x, got)
	bearer, err := got.Issuance.Token.Reveal()
	if err != nil || bearer == "" {
		t.Fatal("committed first login withheld its original session bearer", err)
	}
	csrf, err := got.CSRF.Reveal()
	if err != nil || csrf == "" {
		t.Fatal("committed first login withheld its original session CSRF", err)
	}
	replayed, _ := x.completion.SigninCallback(x.start.enable.f.ctx, x.request)
	assertNativeCallbackRefusalWithholdsIssuance(t, replayed)
	if x.posts.Load() != 1 || nativeJITJourneyCounts(t, x) != after {
		t.Fatal("JIT callback replay exchanged again or repeated a durable graph effect")
	}
	assertNativeCallbackJourneyLocalSessionAndLogout(t, x, got, bearer, csrf)
}

func TestNativeProviderLoginJITJourneyDeniesUnselectedOrUnverifiedMailbox(t *testing.T) {
	for _, mode := range []string{"jit-disabled", "jit-unverified", "jit-wrong-domain", "jit-mailbox-collision", "jit-retired-subject"} {
		t.Run(mode, func(t *testing.T) {
			x := newNativeCallbackJourneyFixture(t, mode)
			tenant := string(x.start.config.TenantID)
			if mode == "jit-mailbox-collision" {
				nativeCallbackJourneyExec(t, x.start, `INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,display_value,verified,is_primary,version,verification_state,verification_version,verified_at,normalization_profile,normalization_version)
VALUES($1,'owner','existing-enterprise-mailbox','email',$2::text,$2::text,true,false,1,2,1,clock_timestamp(),'email-v1',1)`, tenant, nativeJITMailbox)
			}
			if mode == "jit-retired-subject" {
				seedNativeCallbackJourneyRecipient(t, x.start)
				nativeCallbackJourneyExec(t, x.start, `UPDATE identity.accounts SET linked=false WHERE tenant_id=$1 AND account_id='enterprise-linked-account'`, tenant)
			}
			before := nativeJITJourneyCounts(t, x)
			callback, command := nativeJITJourneyCallback(t, x)
			effects := nativeCallbackJourneyDenialEffects(t, x, callback, command)
			got, err := x.completion.SigninCallback(x.start.enable.f.ctx, x.request)
			if !errors.Is(err, sso.ErrForbidden) || got.Completion.Outcome == identity.CommitOutcomeCommitted || x.posts.Load() != 1 {
				t.Fatal("ineligible first login did not give the same refusal after one authenticated provider exchange", err)
			}
			assertNativeCallbackRefusalWithholdsIssuance(t, got)
			if nativeJITJourneyCounts(t, x) != before || nativeCallbackJourneyDenialEffects(t, x, callback, command) != effects {
				t.Fatal("denied first login changed identity, credential, membership, factor, authority, session or token state")
			}
			replayed, _ := x.completion.SigninCallback(x.start.enable.f.ctx, x.request)
			assertNativeCallbackRefusalWithholdsIssuance(t, replayed)
			if replayed.Completion.Outcome == identity.CommitOutcomeCommitted || x.posts.Load() != 1 || nativeJITJourneyCounts(t, x) != before {
				t.Fatal("denied first-login replay exchanged again or created a partial identity graph")
			}
		})
	}
}

func TestNativeProviderLoginJITJourneyDeniesCapacityOrStaleOwner(t *testing.T) {
	for _, mode := range []string{"jit-at-capacity", "jit-stale-owner"} {
		t.Run(mode, func(t *testing.T) {
			x := newNativeCallbackJourneyFixture(t, mode)
			before := nativeJITJourneyCounts(t, x)
			got, err := x.completion.SigninCallback(x.start.enable.f.ctx, x.request)
			if !errors.Is(err, sso.ErrForbidden) || got.Completion.Outcome == identity.CommitOutcomeCommitted || x.posts.Load() != 1 {
				t.Fatal("the callback bypassed current organization capacity or owner authority", err)
			}
			assertNativeCallbackRefusalWithholdsIssuance(t, got)
			if mode == "jit-stale-owner" {
				before.organizationVersion++ // Only the fixture's independent edit persists.
			}
			if nativeJITJourneyCounts(t, x) != before {
				t.Fatal("organization admission denial retained a partial JIT identity or session")
			}
		})
	}
}

func TestNativeProviderLoginJITJourneyCannotProvisionAfterDrain(t *testing.T) {
	x := newNativeCallbackJourneyFixture(t, "jit-provider-draining")
	ctx := x.start.enable.f.ctx
	before := nativeJITJourneyCounts(t, x)
	got, err := x.completion.SigninCallback(ctx, x.request)
	if !errors.Is(err, sso.ErrForbidden) || got.Completion.Outcome == identity.CommitOutcomeCommitted || x.posts.Load() != 1 {
		t.Fatal("a provider drain during a first login did not deny JIT issuance", err)
	}
	assertNativeCallbackRefusalWithholdsIssuance(t, got)
	assertProviderDisableState(t, x.start, false, "4")
	if nativeJITJourneyCounts(t, x) != before {
		t.Fatal("provider drain did not roll back the provisional JIT graph")
	}
	replayed, _ := x.completion.SigninCallback(ctx, x.request)
	assertNativeCallbackRefusalWithholdsIssuance(t, replayed)
	if x.posts.Load() != 1 || nativeJITJourneyCounts(t, x) != before {
		t.Fatal("drained first-login replay repeated the exchange or left effects")
	}
}

func TestNativeProviderLoginJITJourneyLateOutboxFailureRollsBackWholeGraph(t *testing.T) {
	x := newNativeCallbackJourneyFixture(t, "jit-outbox-failure")
	before := nativeJITJourneyCounts(t, x)
	callback, command := nativeJITJourneyCallback(t, x)
	effects := nativeCallbackJourneyDenialEffects(t, x, callback, command)
	// A sequence survives rollback. Its use proves the actual session-created
	// outbox boundary saw the newly created identity/member/session graph.
	nativeCallbackJourneyExec(t, x.start, `CREATE SEQUENCE sso_providers.jit_outbox_failure_attempts`)
	nativeCallbackJourneyExec(t, x.start, `CREATE FUNCTION sso_providers.reject_jit_session_outbox() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.topic='session.created.v1' THEN
  IF NOT EXISTS(SELECT 1 FROM identity.identifiers i
   JOIN identity.users u USING(tenant_id,user_id)
   JOIN organization.memberships m USING(tenant_id,user_id)
   JOIN identity_mfa.factor_authorities f USING(tenant_id,user_id)
   JOIN organization_sessions.sessions s USING(tenant_id,user_id)
   WHERE i.canonical_value='new-enterprise-member@example.com' AND i.verified
   AND u.status='active' AND m.role='member' AND m.state='active'
   AND f.version=1 AND f.active_factors=0 AND s.state='active') THEN
   RAISE EXCEPTION 'fixture did not reach a complete provisional JIT graph';
  END IF;
  PERFORM nextval('sso_providers.jit_outbox_failure_attempts');
  RAISE EXCEPTION 'controlled native JIT late outbox rollback';
 END IF;
 RETURN NEW;
END $$`)
	nativeCallbackJourneyExec(t, x.start, `CREATE TRIGGER reject_jit_session_outbox BEFORE INSERT ON public.outbox_messages
FOR EACH ROW EXECUTE FUNCTION sso_providers.reject_jit_session_outbox()`)
	got, err := x.completion.SigninCallback(x.start.enable.f.ctx, x.request)
	if err == nil || got.Completion.Outcome == identity.CommitOutcomeCommitted || x.posts.Load() != 1 {
		logNativeCallbackJourneyFailure(t, x)
		t.Fatal("late outbox rejection acknowledged a successful first login", err)
	}
	assertNativeCallbackRefusalWithholdsIssuance(t, got)
	var reached bool
	if err := x.start.enable.f.pool.Raw().QueryRow(x.start.enable.f.ctx, `SELECT is_called FROM sso_providers.jit_outbox_failure_attempts`).Scan(&reached); err != nil || !reached {
		t.Fatal("callback failed before the actual late outbox boundary saw its provisional JIT graph", err)
	}
	if nativeJITJourneyCounts(t, x) != before || nativeCallbackJourneyDenialEffects(t, x, callback, command) != effects {
		t.Fatal("late outbox failure retained a user, mailbox, account, credential, factor, membership, authority, session or provider token")
	}
	replayed, _ := x.completion.SigninCallback(x.start.enable.f.ctx, x.request)
	assertNativeCallbackRefusalWithholdsIssuance(t, replayed)
	if x.posts.Load() != 1 || nativeJITJourneyCounts(t, x) != before {
		t.Fatal("failed callback replay repeated exchange or retained partial JIT state")
	}
}

func TestNativeProviderLoginJITJourneyUnknownCommitDoesNotDiscloseOrRepeat(t *testing.T) {
	x := newNativeCallbackJourneyFixture(t, "jit")
	ctx := x.start.enable.f.ctx
	before := nativeJITJourneyCounts(t, x)
	pool, fault := providerLossPool(t, x.start.enable.f, "INSERT INTO sso_providers.provider_login_token_sets")
	copyFixture := *x.start.enable.f
	copyFixture.pool = pool
	enabled := x.start.enable
	enabled.f = &copyFixture
	start, err := ssopg.NewProviderLoginService(newProviderRouter(t, enabled, 4), x.start.config)
	if err != nil {
		t.Fatal("compose the original callback on the faulted local connection", err)
	}
	completion, err := ssopg.NewProviderLoginCompletionServiceWithJIT(start, x.completionConfig, nativeCallbackJourneyJITConfig(t, x.start))
	if err != nil {
		t.Fatal("compose JIT completion on the faulted local connection", err)
	}
	lost, err := completion.SigninCallback(ctx, x.request)
	var unknown identity.UnknownCommitError
	if !fault.seen.Load() || !fault.lost.Load() || !errors.As(err, &unknown) || lost.Completion.Outcome != identity.CommitOutcomeUnknown || x.posts.Load() != 1 {
		logNativeCallbackJourneyFailure(t, x)
		t.Fatal("a genuinely lost database COMMIT acknowledgement did not withhold JIT success", err)
	}
	assertNativeCallbackRefusalWithholdsIssuance(t, lost)
	committed := nativeJITJourneyCounts(t, x)
	if committed.users != before.users+1 || committed.members != before.members+1 || committed.tokens != before.tokens+1 || committed.sessions != before.sessions+1 {
		t.Fatal("lost acknowledgement did not leave exactly one committed JIT graph")
	}
	repeated, err := x.completion.SigninCallback(ctx, x.request)
	assertNativeCallbackRefusalWithholdsIssuance(t, repeated)
	if !errors.Is(err, sso.ErrForbidden) || x.posts.Load() != 1 || nativeJITJourneyCounts(t, x) != committed {
		t.Fatal("callback after lost acknowledgement disclosed credentials or repeated durable work", err)
	}
}

func nativeJITJourneyCallback(t *testing.T, x nativeCallbackJourneyFixture) (string, []byte) {
	t.Helper()
	var callback string
	if err := x.start.enable.f.pool.Raw().QueryRow(x.start.enable.f.ctx, `SELECT callback_command_id FROM sso_providers.login_transactions WHERE start_command_id=$1`, x.started.TransactionID).Scan(&callback); err != nil {
		t.Fatal("read the original native JIT callback correlation", err)
	}
	command, err := base64.RawURLEncoding.DecodeString(callback)
	if err != nil {
		t.Fatal(err)
	}
	return callback, command
}

func nativeCallbackJourneyJITClaims(mode string) map[string]any {
	mailbox, verified := nativeJITMailbox, true
	if mode == "jit-unverified" {
		verified = false
	}
	if mode == "jit-wrong-domain" {
		mailbox = "new-enterprise-member@other.example"
	}
	// Standard claim names deliberately disagree: only the installed mapping
	// supplies provisioning identity, including its verified-email evidence.
	return map[string]any{"work_mail": mailbox, "verified_work_mail": verified, "email": "unselected@other.example", "email_verified": true}
}

func nativeCallbackJourneyJITConfig(t *testing.T, x providerLoginStartFixture) ssopg.ProviderLoginJITConfig {
	t.Helper()
	profile, err := identifier.NewNormalizationProfile(identifier.NormalizationProfileSpec{ID: "email-v1", Version: 1,
		Unicode: identifier.UnicodeNormalizationNFC, CaseFold: true, MaximumBytes: 254})
	if err != nil {
		t.Fatal(err)
	}
	parser, err := email.NewAddressParser(email.AddressPolicy{MaximumBytes: 254, Canonicalization: profile, PreserveDisplay: true})
	if err != nil {
		t.Fatal(err)
	}
	selected := x.config.Profiles[0]
	return ssopg.ProviderLoginJITConfig{Address: parser,
		Directory: kernel.SSOOIDCJITDomainConfig{ComparisonProfile: "canonical-email-v1", CurrentIdentifierKeyVersion: 1, RetainedIdentifierKeys: map[uint32][32]byte{1: {0xd1}}},
		Profiles: []ssopg.StaticOIDCJITPolicy{{OrganizationID: selected.OrganizationID, ProviderID: selected.ProviderID,
			Version: 1, MappingVersion: selected.MappingVersion, MembershipVersion: 1, MaximumMembers: 100, MaximumPerUser: 100}},
	}
}

func installNativeCallbackJourneyJITMigrations(t *testing.T, f *orgFixture) {
	t.Helper()
	retirement := kernel.IdentifierMutationMigrationSource{Base: f.history, Version: 346}
	normalization := kernel.IdentifierNormalizationMigrationSource{Base: retirement, Version: 347}
	subject := kernel.SSOOIDCSubjectAvailabilityMigrationSource{Base: normalization, Version: 348}
	history, err := (mfapg.SSOOIDCJITFactorMigrationSource{Base: subject, Version: 349, ValidationVersion: 350, IndexVersion: 351}).Load(f.ctx)
	if err != nil {
		t.Fatal("load actual identifier, subject and factor JIT prerequisite history", err)
	}
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
	runner, err := migrations.NewRunner(migrationList(history), backend)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := runner.Up(f.ctx); err != nil {
			t.Fatal("install and replay actual native JIT prerequisite migrations", err)
		}
	}
	f.history = append(migrationList(nil), history...)
}

type nativeJITCounts struct {
	users, identifiers, accounts, credentials, associations int
	members, factors, policies, sessions, tokens, owners    int
	families, issuances, memberCount                        int
	organizationVersion, credentialVersion                  uint64
}

func nativeJITJourneyCounts(t *testing.T, x nativeCallbackJourneyFixture) nativeJITCounts {
	t.Helper()
	var counts nativeJITCounts
	var version, credential string
	err := x.start.enable.f.pool.Raw().QueryRow(x.start.enable.f.ctx, `SELECT
(SELECT count(*) FROM identity.users WHERE tenant_id=$1),
(SELECT count(*) FROM identity.identifiers WHERE tenant_id=$1),
(SELECT count(*) FROM identity.accounts WHERE tenant_id=$1),
(SELECT count(*) FROM identity.credential_references WHERE tenant_id=$1),
(SELECT count(*) FROM identity.account_credentials WHERE tenant_id=$1),
(SELECT count(*) FROM organization.memberships WHERE tenant_id=$1),
(SELECT count(*) FROM identity_mfa.factor_authorities WHERE tenant_id=$1),
(SELECT count(*) FROM authorization_subject_authorities WHERE tenant_id=$1),
(SELECT count(*) FROM organization_sessions.sessions WHERE tenant_id=$1),
(SELECT count(*) FROM sso_providers.provider_login_token_sets WHERE tenant_id=$1),
(SELECT count(*) FROM organization_sessions.families WHERE tenant_id=$1),
(SELECT count(*) FROM organization_sessions.session_issuances WHERE tenant_id=$1),owner_count,member_count,version::text,credential_version::text
FROM organization.organizations WHERE tenant_id=$1 AND organization_id=$2`, string(x.start.config.TenantID), string(x.start.config.Profiles[0].OrganizationID)).
		Scan(&counts.users, &counts.identifiers, &counts.accounts, &counts.credentials, &counts.associations, &counts.members,
			&counts.factors, &counts.policies, &counts.sessions, &counts.tokens, &counts.families, &counts.issuances,
			&counts.owners, &counts.memberCount, &version, &credential)
	if err != nil {
		t.Fatal("observe tenant-scoped JIT graph conservation", err)
	}
	counts.organizationVersion, err = strconv.ParseUint(version, 10, 64)
	if err != nil {
		t.Fatal("read exact organization aggregate version", err)
	}
	counts.credentialVersion, err = strconv.ParseUint(credential, 10, 64)
	if err != nil {
		t.Fatal("read exact organization credential epoch", err)
	}
	return counts
}

func assertNativeJITJourneyCreatedGraph(t *testing.T, x nativeCallbackJourneyFixture, issued ssopg.ProviderLoginCallbackResult) {
	t.Helper()
	spec, _ := issued.Issuance.Session.Bindings()
	command, err := base64.RawURLEncoding.DecodeString(string(issued.Completion.Binding.CommandID))
	if err != nil {
		t.Fatal(err)
	}
	provider, err := ssopg.SSOOIDCAccountProviderNamespace(x.start.config.Profiles[0].OrganizationID, x.start.config.Profiles[0].ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	organizationScope, err := organizationpg.OrganizationAuthorityScope(spec.TenantID, x.start.config.Profiles[0].OrganizationID, spec.UserID)
	if err != nil {
		t.Fatal(err)
	}
	var user, identifier, credential, account, member, factor, token, policy bool
	err = x.start.enable.f.pool.Raw().QueryRow(x.start.enable.f.ctx, `SELECT
EXISTS(SELECT 1 FROM identity.users WHERE tenant_id=$1 AND user_id=$2 AND status='active' AND version=1 AND authority_version=1 AND identifier_version=1 AND credential_version=1),
EXISTS(SELECT 1 FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND kind='email' AND canonical_value=$3::text AND display_value=$3::text AND verified AND NOT is_primary AND version=1 AND verification_state=2 AND verification_version=1 AND verified_at IS NOT NULL AND normalization_profile='email-v1' AND normalization_version=1),
EXISTS(SELECT 1 FROM identity.credential_references WHERE tenant_id=$1 AND user_id=$2 AND credential_id=$4 AND kind=3 AND owner='sso' AND version=1 AND enabled AND expires_at IS NULL),
EXISTS(SELECT 1 FROM identity.accounts a JOIN identity.account_credentials c USING(tenant_id,user_id,account_id) WHERE a.tenant_id=$1 AND a.user_id=$2 AND a.provider=$5 AND a.issuer=$6 AND a.subject=$7 AND a.version=1 AND a.social_link_version=1 AND a.linked AND c.credential_id=$4),
EXISTS(SELECT 1 FROM organization.memberships WHERE tenant_id=$1 AND user_id=$2 AND organization_id=$8 AND role='member' AND state='active' AND version=1 AND authorization_version=1),
EXISTS(SELECT 1 FROM identity_mfa.factor_authorities WHERE tenant_id=$1 AND user_id=$2 AND version=1 AND active_factors=0 AND initialized_command_id=$9 AND initialized_purpose IS NULL AND sso_oidc_initialized_purpose='identity.sso.oidc-callback'),
EXISTS(SELECT 1 FROM sso_providers.provider_login_token_sets v JOIN identity.account_credentials c USING(tenant_id,user_id,account_id) WHERE v.tenant_id=$1 AND v.user_id=$2 AND v.callback_command_id=$10 AND c.credential_id=$4 AND octet_length(v.token_ciphertext)>0),
(SELECT count(*) FROM authorization_subject_authorities WHERE tenant_id=$1 AND subject_id=$2 AND policy_namespace IN ('users',$11) AND version=1)=2`,
		string(spec.TenantID), string(spec.UserID), nativeJITMailbox, string(spec.Authentication.CredentialID), provider, nativeCallbackJourneyIssuer,
		nativeCallbackJourneySubject, string(x.start.config.Profiles[0].OrganizationID), command, string(issued.Completion.Binding.CommandID), organizationScope.PolicyNamespace).
		Scan(&user, &identifier, &credential, &account, &member, &factor, &token, &policy)
	if err != nil || !user || !identifier || !credential || !account || !member || !factor || !token || !policy {
		t.Fatalf("JIT graph lacks exact initial authority: user=%t identifier=%t credential=%t account=%t member=%t factor=%t token=%t policy=%t: %v", user, identifier, credential, account, member, factor, token, policy, err)
	}
	if issued.Issuance.Token == (session.Token{}) {
		t.Fatal("committed JIT graph has no commit-gated session custody")
	}
}
