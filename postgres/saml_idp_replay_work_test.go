package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestSAMLIDPReplayRejectsUnaffiliatedWorkAndRecovery(t *testing.T) {
	claim := samlIDPReplayClaimForTest()
	if err := reserveSAMLIDPReplayInWork(t.Context(), kernel.Work{}, nil, claim); !errors.Is(err, identity.ForbiddenError{}) {
		t.Fatal("unaffiliated Work reached IdP replay mutation", err)
	}
	if exact, err := observeSAMLIDPReplayInRecovery(t.Context(), kernel.RecoveryWork{}, nil, claim); exact || !errors.Is(err, identity.ForbiddenError{}) {
		t.Fatal("unaffiliated recovery Work established an IdP replay vote", exact, err)
	}
	if status, err := verifySAMLIDPReplayAbsentInRecovery(t.Context(), kernel.RecoveryWork{}, nil); status != kernel.RecoveryUnknown || !errors.Is(err, identity.ForbiddenError{}) {
		t.Fatal("unaffiliated recovery Work proved replay absence", status, err)
	}
}

func TestSAMLIDPReplayInsertionBindsOriginalClaimAndExplicitPurpose(t *testing.T) {
	claim := samlIDPReplayClaimForTest()
	called := false
	err := insertSAMLIDPReplayPair(t.Context(), func(_ context.Context, sql string, args ...any) (int64, error) {
		called = true
		if !strings.HasPrefix(sql, "INSERT INTO sso_providers.saml_replay_members") ||
			!strings.Contains(sql, "callback_purpose") || !strings.Contains(sql, "'identity.sso.saml-idp-init'") ||
			!strings.Contains(sql, "ORDER BY m.digest") || strings.Contains(sql, "ON CONFLICT") {
			t.Fatal("IdP reservation did not use one strict purpose-bound, deterministically ordered pair insertion", sql)
		}
		assertSAMLIDPReplayBindings(t, claim, args)
		return 2, nil
	}, claim)
	if err != nil || !called {
		t.Fatal("valid IdP replay pair was not inserted", err)
	}
}

func TestSAMLIDPReplayInsertionRejectsInvalidClaimsBeforeSQL(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*samlReplayClaim)
	}{
		{"tenant", func(c *samlReplayClaim) { c.Tenant = "" }},
		{"organization", func(c *samlReplayClaim) { c.OrganizationID = "" }},
		{"provider", func(c *samlReplayClaim) { c.ProviderID = "" }},
		{"issuer", func(c *samlReplayClaim) { c.IssuerDigest = [32]byte{} }},
		{"response", func(c *samlReplayClaim) { c.ResponseDigest = [32]byte{} }},
		{"assertion", func(c *samlReplayClaim) { c.AssertionDigest = [32]byte{} }},
		{"same member in both roles", func(c *samlReplayClaim) { c.AssertionDigest = c.ResponseDigest }},
		{"fingerprint", func(c *samlReplayClaim) { c.Fingerprint = [32]byte{} }},
		{"command", func(c *samlReplayClaim) { c.CommandID = "invalid" }},
		{"generation", func(c *samlReplayClaim) { c.Generation = 0 }},
		{"retention", func(c *samlReplayClaim) { c.RetainUntil = time.Time{} }},
		{"storage precision", func(c *samlReplayClaim) { c.RetainUntil = c.RetainUntil.Add(time.Nanosecond) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claim := samlIDPReplayClaimForTest()
			tc.change(&claim)
			exec := func(context.Context, string, ...any) (int64, error) {
				t.Fatal("invalid claim reached replay insertion")
				return 0, nil
			}
			if err := insertSAMLIDPReplayPair(t.Context(), exec, claim); !errors.Is(err, identity.InvalidInputError{Field: "saml_replay"}) {
				t.Fatal("invalid IdP replay claim was not rejected", err)
			}
		})
	}
}

func TestSAMLIDPReplayInsertionPreservesFailureAndCancellationSemantics(t *testing.T) {
	claim := samlIDPReplayClaimForTest()
	for _, tc := range []struct {
		name string
		rows int64
		err  error
		want error
	}{
		{"partial pair", 1, nil, identity.UnavailableError{}},
		{"unexpected extra member", 3, nil, identity.UnavailableError{}},
		{"driver failure", 0, errors.New("unavailable storage"), identity.UnavailableError{}},
		{"shared member collision", 0, &pgconn.PgError{Code: "23505", TableName: "saml_replay_members", ConstraintName: "saml_replay_member_scope_pkey"}, identity.ConflictError{}},
		{"command member collision", 0, &pgconn.PgError{Code: "23505", TableName: "saml_replay_members", ConstraintName: "saml_replay_command_member_key"}, identity.ConflictError{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := insertSAMLIDPReplayPair(t.Context(), func(context.Context, string, ...any) (int64, error) {
				return tc.rows, tc.err
			}, claim)
			if !errors.Is(err, tc.want) {
				t.Fatal("IdP replay insertion changed storage failure semantics", err)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := insertSAMLIDPReplayPair(ctx, func(context.Context, string, ...any) (int64, error) {
		t.Fatal("cancelled insertion reached storage")
		return 0, nil
	}, claim); !errors.Is(err, context.Canceled) {
		t.Fatal("IdP replay insertion lost cancellation", err)
	}
	if err := insertSAMLIDPReplayPair(nil, nil, claim); !errors.Is(err, identity.InvalidInputError{Field: "saml_replay"}) {
		t.Fatal("nil insertion context or executor was not rejected", err)
	}
}

func TestSAMLIDPReplayObservationRequiresPurposeAndOriginalFullClaim(t *testing.T) {
	claim := samlIDPReplayClaimForTest()
	for _, exact := range []bool{false, true} {
		called := false
		got, err := observeSAMLIDPReplayPair(t.Context(), func(_ context.Context, sql string, args ...any) (bool, error) {
			called = true
			for _, fragment := range []string{
				"SELECT count(*)=2", "FROM sso_providers.saml_replay_members",
				"callback_purpose='identity.sso.saml-idp-init'",
				"tenant_id=$1", "organization_id=$2", "provider_id=$3", "issuer_digest=$4",
				"callback_command_id=$5", "execution_fingerprint=$6", "execution_generation=$7",
				"retain_until=$8", "member_kind=1 AND member_digest=$9", "member_kind=2 AND member_digest=$10",
			} {
				if !strings.Contains(sql, fragment) {
					t.Fatal("IdP replay recovery omitted an original claim binding", fragment, sql)
				}
			}
			assertSAMLIDPReplayBindings(t, claim, args)
			return exact, nil
		}, claim)
		if err != nil || got != exact || !called {
			t.Fatal("IdP replay recovery changed the exact-pair vote", got, exact, err)
		}
	}
}

func TestSAMLIDPReplayObservationDoesNotTurnFailureIntoCommit(t *testing.T) {
	claim := samlIDPReplayClaimForTest()
	if exact, err := observeSAMLIDPReplayPair(t.Context(), func(context.Context, string, ...any) (bool, error) {
		return true, errors.New("unavailable storage")
	}, claim); exact || !errors.Is(err, identity.UnavailableError{}) {
		t.Fatal("failed IdP replay lookup established commit", exact, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if exact, err := observeSAMLIDPReplayPair(ctx, func(context.Context, string, ...any) (bool, error) {
		t.Fatal("cancelled observation reached storage")
		return true, nil
	}, claim); exact || !errors.Is(err, context.Canceled) {
		t.Fatal("IdP replay observation lost cancellation", exact, err)
	}
	if exact, err := observeSAMLIDPReplayPair(nil, nil, claim); exact || !errors.Is(err, identity.InvalidInputError{Field: "saml_replay"}) {
		t.Fatal("nil observation context or lookup established commit", exact, err)
	}
}

func samlIDPReplayClaimForTest() samlReplayClaim {
	return samlReplayClaim{
		Tenant: "replay-tenant", OrganizationID: "replay-organization", ProviderID: "replay-provider",
		IssuerDigest: sha256.Sum256([]byte("issuer")), ResponseDigest: sha256.Sum256([]byte("response")),
		AssertionDigest: sha256.Sum256([]byte("assertion")), Fingerprint: sha256.Sum256([]byte("execution")),
		CommandID:  identity.CommandID(base64.RawURLEncoding.EncodeToString([]byte("replay-command-1"))),
		Generation: 7, RetainUntil: time.Date(2026, 11, 23, 6, 0, 0, 123000, time.UTC),
	}
}

func assertSAMLIDPReplayBindings(t *testing.T, claim samlReplayClaim, got []any) {
	t.Helper()
	want := []any{string(claim.Tenant), claim.OrganizationID, claim.ProviderID, claim.IssuerDigest[:],
		[]byte("replay-command-1"), claim.Fingerprint[:], "7", claim.RetainUntil,
		claim.ResponseDigest[:], claim.AssertionDigest[:]}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("IdP replay statement did not preserve the complete original ten-argument claim")
	}
}
