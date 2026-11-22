//go:build integration

package postgres_test

import (
	"errors"
	"testing"
	"time"

	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	"github.com/faustbrian/go-sso"
)

func TestNativeProviderRoleOlderStartCannotReplaceNewerGrant(t *testing.T) {
	x := newNativeCallbackJourneyFixture(t, "role-grant")
	f, profile := x.start.enable.f, x.start.config.Profiles[0]
	tenant := string(x.start.config.TenantID)
	seeded, err := x.completion.SigninCallback(f.ctx, x.request)
	if err != nil || seeded.Completion.Outcome != identity.CommitOutcomeCommitted || seeded.Issuance.CommitOutcome != identity.CommitOutcomeCommitted || x.posts.Load() != 1 {
		t.Fatal("establish the original signed provider grant and native session", err)
	}

	scope, err := organizationpg.OrganizationAuthorityScope(x.start.config.TenantID, profile.OrganizationID, "owner")
	if err != nil {
		t.Fatal(err)
	}
	store, err := authority.NewAuthorityStore(f.pool.Raw(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	type durableState struct {
		grant, organizationVersion, memberVersion, authorizationVersion, roleVersion string
		scopedVersion                                                                uint64
		sessions                                                                     int
	}
	readState := func() durableState {
		t.Helper()
		var got durableState
		err := f.pool.Raw().QueryRow(f.ctx, `SELECT to_jsonb(g)::text,o.version::text,m.version::text,m.authorization_version::text,r.version::text,
(SELECT count(*) FROM organization_sessions.sessions WHERE tenant_id=$1 AND user_id='owner')
FROM organization.provider_role_grants g
JOIN organization.organizations o USING(tenant_id,organization_id)
JOIN organization.memberships m USING(tenant_id,organization_id,user_id)
JOIN organization.custom_roles r ON r.tenant_id=g.tenant_id AND r.organization_id=g.organization_id AND r.role_id='native-enterprise-reader'
WHERE g.tenant_id=$1 AND g.organization_id=$2 AND g.user_id='owner' AND g.provider_id=$3`,
			tenant, string(profile.OrganizationID), string(profile.ProviderID)).Scan(&got.grant, &got.organizationVersion, &got.memberVersion, &got.authorizationVersion, &got.roleVersion, &got.sessions)
		if err != nil {
			t.Fatal("observe the exact durable provider grant, role versions and sessions", err)
		}
		current, err := store.Get(f.ctx, scope)
		if err != nil {
			t.Fatal("observe the actual scoped authorization version", err)
		}
		got.scopedVersion = current.Version
		return got
	}
	before := readState()

	withdraw, retain := false, true
	assertedAt := time.Now().UTC().Truncate(time.Second)
	older := x.newAttempt(t, "native-enterprise-older-withdrawal", &withdraw, assertedAt)
	olderFinished := time.Now().UTC().Truncate(time.Microsecond)
	newer := x.newAttempt(t, "native-enterprise-newer-retained-grant", &retain, assertedAt)
	if older.Browser.FlowID == newer.Browser.FlowID {
		t.Fatal("ordering fixture reused the same native browser flow")
	}
	committed, err := x.completion.SigninCallback(f.ctx, newer)
	if err != nil || committed.Completion.Outcome != identity.CommitOutcomeCommitted || committed.Issuance.CommitOutcome != identity.CommitOutcomeCommitted ||
		committed.Issuance.Token == (session.Token{}) || committed.CSRF == (session.CSRFToken{}) || x.posts.Load() != 2 {
		t.Fatal("commit the newer signed authoritative grant and session first", err)
	}
	afterNewer := readState()
	if afterNewer.sessions != before.sessions+1 || afterNewer.grant == before.grant ||
		afterNewer.organizationVersion != before.organizationVersion || afterNewer.memberVersion != before.memberVersion ||
		afterNewer.authorizationVersion != before.authorizationVersion || afterNewer.roleVersion != before.roleVersion || afterNewer.scopedVersion != before.scopedVersion {
		t.Fatal("retaining the same role did not advance only the provider checkpoint and session count")
	}
	var started, storedAssertion time.Time
	var roleCount int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT flow_started_at,assertion_issued_at,cardinality(role_ids) FROM organization.provider_role_grants
WHERE tenant_id=$1 AND organization_id=$2 AND user_id='owner' AND provider_id=$3`,
		tenant, string(profile.OrganizationID), string(profile.ProviderID)).Scan(&started, &storedAssertion, &roleCount); err != nil || !started.After(olderFinished) || !storedAssertion.Equal(assertedAt) || roleCount != 1 {
		t.Fatal("durable checkpoint did not retain the newer original start and existing provider role", err)
	}

	// Both assertions have the same issuer time and current authority. Only the
	// distinct original login starts order these otherwise valid replacements.
	denied, err := x.completion.SigninCallback(f.ctx, older)
	if !errors.Is(err, sso.ErrConflict) || denied.Completion.Outcome != identity.CommitOutcomeNotCommitted || x.posts.Load() != 3 {
		t.Fatal("older signed callback did not reach exchange and reject replacement as a conflict", err)
	}
	if denied.Issuance.Token != (session.Token{}) || denied.CSRF != (session.CSRFToken{}) {
		t.Fatal("older denied callback disclosed browser credentials")
	}
	if readState() != afterNewer {
		t.Fatal("older callback changed the retained provider grant, role/scope versions or session count")
	}
}
