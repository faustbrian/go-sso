//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestNativeSAMLCallbackCommitsExactLogoutCustodyWithSession(t *testing.T) {
	for _, mode := range []string{"commit", "correlation-denied", "no-session-index"} {
		t.Run(mode, func(t *testing.T) {
			x := newNativeSAMLCallbackFixture(t)
			f := x.start.start.enable.f
			installSAMLIDPStorage(t, f, ssopg.SAMLLogoutSubjectMigrationSource{Version: 432})
			keyReference := x.start.start.config.KeyReference
			custody, err := ssopg.NewSAMLLogoutSubjectCustody(ssopg.SAMLLogoutSubjectCustodyConfig{
				KeyReference: keyReference, CurrentMatchKey: 1, MatchKeys: map[uint32][32]byte{1: {0xa2}},
			})
			if err != nil {
				t.Fatal("select bounded SAML logout subject custody", err)
			}
			cookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_session", SameSite: http.SameSiteLaxMode})
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			index := "original-native-session-index"
			if mode == "no-session-index" {
				index = ""
			}
			completion, err := ssopg.NewProviderSAMLLoginCompletionServiceWithLogoutSubject(x.start.start.service, ssopg.ProviderSAMLLoginCompletionConfig{
				Audience: "native-saml-app", PolicyNamespace: "users", CSRFKey: x.csrf,
				Issuer: session.IssuerConfig{Clock: clock.System{}, MaximumDuration: 3 * time.Second, LookupKey: x.lookup, TokenSize: 32, Cookie: cookie},
			}, func(_ context.Context, input ssopg.SAMLResponseVerificationInput) (ssopg.SAMLVerifiedLoginResponse, error) {
				calls++
				until := input.Now.Add(time.Minute)
				evidence := ssopg.SAMLVerifiedResponse{ResponseID: nativeSAMLCallbackResponseID, AssertionID: nativeSAMLCallbackAssertionID,
					ProviderSubject: nativeSAMLCallbackSubject, SubjectFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
					SessionIndex: index, AssertionExpiresAt: until, ValidUntil: until}
				return ssopg.SAMLVerifiedLoginResponse{Evidence: evidence, LogoutSubject: ssopg.SAMLLogoutSubject{
					ProviderSubject: evidence.ProviderSubject, SubjectFormat: evidence.SubjectFormat, SessionIndex: index,
					NameQualifier: input.IdentityProviderEntityID, SPNameQualifier: input.SPEntityID,
				}}, nil
			})
			if err != nil {
				t.Fatal("select the original signed subject verifier", err)
			}
			completion, err = completion.WithLogoutSubjectCustody(custody)
			if err != nil {
				t.Fatal("compose custody with the native SP callback", err)
			}
			if mode == "correlation-denied" {
				if _, err := f.pool.Raw().Exec(f.ctx, `ALTER TABLE sso_providers.saml_logout_subjects ADD CONSTRAINT fixture_reject_logout_subject CHECK (false)`); err != nil {
					t.Fatal("configure a terminal custody write failure", err)
				}
			}
			got, err := completion.SigninCallback(f.ctx, x.request)
			if mode == "correlation-denied" {
				if err == nil || got.Completion.Outcome == identity.CommitOutcomeCommitted || calls != 1 {
					t.Fatal("failed custody was reported as committed sign-in", err)
				}
				assertNativeSAMLCallbackWithholdsIssuance(t, got)
				var issuance, replay, custodyRows int
				if err := f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT count(*) FROM organization_sessions.session_issuances WHERE command_id=$1),
 (SELECT count(*) FROM sso_providers.saml_replay_members WHERE callback_command_id=$1),
 (SELECT count(*) FROM sso_providers.saml_logout_subjects WHERE issuance_command_id=$1)`, x.binary).Scan(&issuance, &replay, &custodyRows); err != nil || issuance != 0 || replay != 0 || custodyRows != 0 {
					t.Fatal("failed correlation did not roll back the original session and replay", err)
				}
				return
			}
			if err != nil || got.Completion.Outcome != identity.CommitOutcomeCommitted || calls != 1 {
				t.Fatal("complete native SAML session with selected logout custody", err)
			}
			record, err := got.Issuance.Session.Bindings()
			if err != nil {
				t.Fatal(err)
			}
			lifetime, err := got.Issuance.Session.Lifetime(record.LastActivityAt)
			if err != nil {
				t.Fatal(err)
			}
			var user, id, family, provider, purpose string
			var expires time.Time
			var sealed, subjectMatch, indexMatch []byte
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT user_id,session_id,family_id,provider_id,issuance_purpose,expires_at,
 subject_envelope,subject_digest,session_index_digest FROM sso_providers.saml_logout_subjects
 WHERE tenant_id=$1 AND issuance_command_id=$2`, string(record.TenantID), x.binary).Scan(&user, &id, &family, &provider, &purpose, &expires, &sealed, &subjectMatch, &indexMatch); err != nil {
				t.Fatal("read the one committed correlation row", err)
			}
			if user != string(record.UserID) || id != record.SessionID || family != record.FamilyID || provider != string(x.request.ProviderID) || purpose != "identity.sso.saml-acs" || !expires.Equal(lifetime.AbsoluteExpiresAt.Truncate(time.Microsecond)) {
				t.Fatal("correlation did not retain the exact issued session and original expiry")
			}
			if len(sealed) == 0 || len(subjectMatch) != 32 || index != "" && len(indexMatch) != 32 || index == "" && indexMatch != nil || bytes.Contains(sealed, []byte(nativeSAMLCallbackSubject)) {
				t.Fatal("correlation did not retain sealed subject and exact optional index")
			}
			repeated, _ := completion.SigninCallback(f.ctx, x.request)
			assertNativeSAMLCallbackWithholdsIssuance(t, repeated)
			if calls != 1 {
				t.Fatal("replay reverified the assertion while selecting its existing custody")
			}
		})
	}
}
