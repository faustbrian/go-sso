package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestSAMLIDPPendingArrivalRejectsUnaffiliatedWork(t *testing.T) {
	a := samlIDPPendingArrivalForTest()
	if err := insertSAMLIDPPendingArrival(t.Context(), kernel.Work{}, nil, identity.Command{}, a); err == nil {
		t.Fatal("unaffiliated Work inserted pending custody")
	}
	if status, err := observeSAMLIDPPendingArrival(t.Context(), kernel.RecoveryWork{}, nil, a); status != kernel.RecoveryUnknown || err == nil {
		t.Fatal("unaffiliated recovery established custody evidence", status, err)
	}
}

func TestSAMLIDPPendingArrivalPreservesOriginalSQLBindings(t *testing.T) {
	a := samlIDPPendingArrivalForTest()
	args, err := a.bindings()
	if err != nil {
		t.Fatal(err)
	}
	want := []any{string(a.Binding.TenantID), []byte("arrival-command1"), string(a.Organization), string(a.Provider),
		string(a.Binding.UserID), a.Envelope, int64(a.KeyVersion), a.BrowserDigest[:], a.FormDigest[:], a.IssuedAt, a.ExpiresAt}
	if !reflect.DeepEqual(args, want) {
		t.Fatal("pending custody changed original canonical command, scope, ciphertext, commitments or times")
	}
	called := false
	if err := writeSAMLIDPPendingArrival(t.Context(), func(_ context.Context, _ string, got ...any) (int64, error) {
		called = true
		if !reflect.DeepEqual(got, want) {
			t.Fatal("insertion changed the original pending custody")
		}
		return 1, nil
	}, a); err != nil || !called {
		t.Fatal("valid pending custody was not inserted", err)
	}
}

func TestSAMLIDPPendingArrivalRejectsInvalidCustodyBeforeSQL(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*samlIDPPendingArrival)
	}{
		{"tenant", func(a *samlIDPPendingArrival) { a.Binding.TenantID = "" }},
		{"user", func(a *samlIDPPendingArrival) { a.Binding.UserID = "" }},
		{"anonymous subject", func(a *samlIDPPendingArrival) { a.Binding.AnonymousFlowID = "flow" }},
		{"operation", func(a *samlIDPPendingArrival) { a.Binding.OperationID = "identity.sso.saml-idp-init" }},
		{"schema", func(a *samlIDPPendingArrival) { a.Binding.SchemaVersion = 2 }},
		{"record", func(a *samlIDPPendingArrival) { a.Binding.RecordID = "other-record" }},
		{"command", func(a *samlIDPPendingArrival) { a.Binding.CommandID = "invalid" }},
		{"zero command", func(a *samlIDPPendingArrival) {
			a.Binding.CommandID = identity.CommandID(base64.RawURLEncoding.EncodeToString(make([]byte, 16)))
		}},
		{"organization", func(a *samlIDPPendingArrival) { a.Organization = "" }},
		{"provider", func(a *samlIDPPendingArrival) { a.Provider = "" }},
		{"empty envelope", func(a *samlIDPPendingArrival) { a.Envelope = nil }},
		{"oversized envelope", func(a *samlIDPPendingArrival) { a.Envelope = make([]byte, 65537) }},
		{"key version", func(a *samlIDPPendingArrival) { a.KeyVersion = 0 }},
		{"browser commitment", func(a *samlIDPPendingArrival) { a.BrowserDigest = [32]byte{} }},
		{"form commitment", func(a *samlIDPPendingArrival) { a.FormDigest = [32]byte{} }},
		{"same roles", func(a *samlIDPPendingArrival) { a.FormDigest = a.BrowserDigest }},
		{"zero issue", func(a *samlIDPPendingArrival) { a.IssuedAt = time.Time{} }},
		{"zero expiry", func(a *samlIDPPendingArrival) { a.ExpiresAt = time.Time{} }},
		{"empty lifetime", func(a *samlIDPPendingArrival) { a.ExpiresAt = a.IssuedAt }},
		{"long lifetime", func(a *samlIDPPendingArrival) { a.ExpiresAt = a.IssuedAt.Add(5*time.Minute + time.Microsecond) }},
		{"issue precision", func(a *samlIDPPendingArrival) { a.IssuedAt = a.IssuedAt.Add(time.Nanosecond) }},
		{"expiry precision", func(a *samlIDPPendingArrival) { a.ExpiresAt = a.ExpiresAt.Add(time.Nanosecond) }},
		{"unsupported year", func(a *samlIDPPendingArrival) {
			a.IssuedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
			a.ExpiresAt = a.IssuedAt.Add(time.Minute)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := samlIDPPendingArrivalForTest()
			tc.change(&a)
			if err := writeSAMLIDPPendingArrival(t.Context(), func(context.Context, string, ...any) (int64, error) {
				t.Fatal("invalid custody reached SQL")
				return 1, nil
			}, a); !errors.Is(err, identity.InvalidInputError{Field: "saml_idp_pending_arrival"}) {
				t.Fatal("invalid pending custody was not rejected", err)
			}
		})
	}
}

func TestSAMLIDPPendingArrivalInsertionRequiresOneFreshRow(t *testing.T) {
	for _, tc := range []struct {
		name string
		rows int64
		err  error
		want error
	}{
		{"original validity ended", 0, nil, identity.ForbiddenError{}},
		{"extra row", 2, nil, identity.UnavailableError{}},
		{"storage failure", 0, errors.New("private driver details"), identity.UnavailableError{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := writeSAMLIDPPendingArrival(t.Context(), func(context.Context, string, ...any) (int64, error) { return tc.rows, tc.err }, samlIDPPendingArrivalForTest())
			if !errors.Is(err, tc.want) {
				t.Fatal("insertion changed fresh-row failure semantics", err)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := writeSAMLIDPPendingArrival(ctx, func(context.Context, string, ...any) (int64, error) {
		t.Fatal("cancelled write reached SQL")
		return 1, nil
	}, samlIDPPendingArrivalForTest()); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
	if err := writeSAMLIDPPendingArrival(nil, nil, samlIDPPendingArrivalForTest()); !errors.Is(err, identity.InvalidInputError{Field: "saml_idp_pending_arrival"}) {
		t.Fatal("nil context or executor accepted", err)
	}
}

func TestSAMLIDPPendingArrivalClassifiesExactAndConflictingRows(t *testing.T) {
	a := samlIDPPendingArrivalForTest()
	for _, tc := range []struct {
		name   string
		change func(*samlIDPPendingArrivalRow)
		want   kernel.RecoveryStatus
	}{
		{"original pending", func(*samlIDPPendingArrivalRow) {}, kernel.RecoveryCommitted},
		{"other organization", func(r *samlIDPPendingArrivalRow) { r.Organization = "other" }, kernel.RecoveryUnknown},
		{"other provider", func(r *samlIDPPendingArrivalRow) { r.Provider = "other" }, kernel.RecoveryUnknown},
		{"other user", func(r *samlIDPPendingArrivalRow) { r.User = "other" }, kernel.RecoveryUnknown},
		{"renewed issue", func(r *samlIDPPendingArrivalRow) { r.IssuedAt = r.IssuedAt.Add(time.Microsecond) }, kernel.RecoveryUnknown},
		{"renewed expiry", func(r *samlIDPPendingArrivalRow) { r.ExpiresAt = r.ExpiresAt.Add(time.Microsecond) }, kernel.RecoveryUnknown},
		{"changed ciphertext", func(r *samlIDPPendingArrivalRow) { r.Envelope = []byte("other") }, kernel.RecoveryUnknown},
		{"changed key", func(r *samlIDPPendingArrivalRow) { v := int64(2); r.KeyVersion = &v }, kernel.RecoveryUnknown},
		{"changed browser", func(r *samlIDPPendingArrivalRow) { r.BrowserDigest = bytes.Repeat([]byte{3}, 32) }, kernel.RecoveryUnknown},
		{"swapped form", func(r *samlIDPPendingArrivalRow) { r.FormDigest = a.BrowserDigest[:] }, kernel.RecoveryUnknown},
		{"partial erasure", func(r *samlIDPPendingArrivalRow) { r.Envelope = nil }, kernel.RecoveryUnknown},
		{"completion command without time", func(r *samlIDPPendingArrivalRow) { r.CompletionCommand = []byte("complete-command") }, kernel.RecoveryUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := samlIDPPendingArrivalRowForTest(a)
			tc.change(&r)
			if got := classifySAMLIDPPendingArrivalRow(a, r); got != tc.want {
				t.Fatal("row classification changed custody evidence", got, tc.want)
			}
		})
	}
}

func TestSAMLIDPPendingArrivalRetainsCommitEvidenceAfterTerminalErasure(t *testing.T) {
	a := samlIDPPendingArrivalForTest()
	r := samlIDPPendingArrivalRowForTest(a)
	completed := a.IssuedAt.Add(time.Minute)
	r.CompletedAt, r.CompletionCommand = &completed, []byte("complete-command")
	r.Envelope, r.KeyVersion, r.BrowserDigest, r.FormDigest = nil, nil, nil, nil
	if got := classifySAMLIDPPendingArrivalRow(a, r); got != kernel.RecoveryCommitted {
		t.Fatal("terminal erasure lost immutable original arrival evidence", got)
	}
	for _, change := range []func(*samlIDPPendingArrivalRow){
		func(r *samlIDPPendingArrivalRow) { v := a.ExpiresAt; r.CompletedAt = &v },
		func(r *samlIDPPendingArrivalRow) { v := a.IssuedAt.Add(-time.Microsecond); r.CompletedAt = &v },
		func(r *samlIDPPendingArrivalRow) { r.CompletionCommand = []byte("arrival-command1") },
		func(r *samlIDPPendingArrivalRow) { r.CompletionCommand = make([]byte, 16) },
		func(r *samlIDPPendingArrivalRow) { r.Envelope = []byte("retained-secret") },
		func(r *samlIDPPendingArrivalRow) { r.User = "other-user" },
	} {
		changed := r
		change(&changed)
		if got := classifySAMLIDPPendingArrivalRow(a, changed); got != kernel.RecoveryUnknown {
			t.Fatal("conflicting terminal custody established arrival commit", got)
		}
	}
}

func TestSAMLIDPPendingArrivalOriginOnlyRecoveryHasNoPositiveEvidence(t *testing.T) {
	full := samlIDPPendingArrivalForTest()
	origin := samlIDPPendingArrival{Binding: full.Binding}
	args, originOnly, err := origin.recoveryBindings()
	if err != nil || !originOnly || !reflect.DeepEqual(args, []any{string(full.Binding.TenantID), []byte("arrival-command1")}) {
		t.Fatal("exact origin did not select bounded primary-key-only recovery", originOnly, err)
	}
	if got := classifySAMLIDPPendingArrivalRow(origin, samlIDPPendingArrivalRowForTest(full)); got != kernel.RecoveryUnknown {
		t.Fatal("origin-only recovery established positive custody evidence", got)
	}
	if _, err := origin.bindings(); !errors.Is(err, identity.InvalidInputError{Field: "saml_idp_pending_arrival"}) {
		t.Fatal("origin-only recovery input became insertion custody", err)
	}
	args, originOnly, err = full.recoveryBindings()
	if err != nil || originOnly || !reflect.DeepEqual(args, []any{string(full.Binding.TenantID), []byte("arrival-command1")}) {
		t.Fatal("full recovery did not retain exact expected custody mode", originOnly, err)
	}
}

func TestSAMLIDPPendingArrivalRecoveryRejectsPartiallyContaminatedOrigin(t *testing.T) {
	full := samlIDPPendingArrivalForTest()
	for _, change := range []func(*samlIDPPendingArrival){
		func(a *samlIDPPendingArrival) { a.Organization = full.Organization },
		func(a *samlIDPPendingArrival) { a.Provider = full.Provider },
		func(a *samlIDPPendingArrival) { a.Envelope = []byte{} },
		func(a *samlIDPPendingArrival) { a.Envelope = full.Envelope },
		func(a *samlIDPPendingArrival) { a.KeyVersion = full.KeyVersion },
		func(a *samlIDPPendingArrival) { a.BrowserDigest = full.BrowserDigest },
		func(a *samlIDPPendingArrival) { a.FormDigest = full.FormDigest },
		func(a *samlIDPPendingArrival) { a.IssuedAt = full.IssuedAt },
		func(a *samlIDPPendingArrival) { a.ExpiresAt = full.ExpiresAt },
		func(a *samlIDPPendingArrival) { a.Binding.RecordID = "other" },
	} {
		origin := samlIDPPendingArrival{Binding: full.Binding}
		change(&origin)
		if _, _, err := origin.recoveryBindings(); !errors.Is(err, identity.InvalidInputError{Field: "saml_idp_pending_arrival"}) {
			t.Fatal("partial origin became conclusive recovery input", err)
		}
	}
}

func samlIDPPendingArrivalForTest() samlIDPPendingArrival {
	command := identity.CommandID(base64.RawURLEncoding.EncodeToString([]byte("arrival-command1")))
	issued := time.Date(2026, 11, 23, 12, 0, 0, 123000, time.UTC)
	return samlIDPPendingArrival{
		Binding: identity.CommandBinding{CommandID: command, TenantID: "tenant", UserID: "user", ActorID: "service", ActorKind: authorization.SubjectServiceAccount,
			OperationID: "identity.sso.saml-idp-prepare", PolicyID: "policy", PolicyVersion: 1, SchemaID: "sso-enterprise-saml-idp-prepare-v1", SchemaVersion: 1,
			CorrelationID: "correlation", RecordID: string(command)},
		Organization: "organization", Provider: "provider", Envelope: []byte("encrypted-binding"), KeyVersion: 1,
		BrowserDigest: [32]byte{1}, FormDigest: [32]byte{2}, IssuedAt: issued, ExpiresAt: issued.Add(5 * time.Minute),
	}
}

func samlIDPPendingArrivalRowForTest(a samlIDPPendingArrival) samlIDPPendingArrivalRow {
	version := int64(a.KeyVersion)
	return samlIDPPendingArrivalRow{Organization: string(a.Organization), Provider: string(a.Provider), User: string(a.Binding.UserID),
		Envelope: bytes.Clone(a.Envelope), KeyVersion: &version, BrowserDigest: bytes.Clone(a.BrowserDigest[:]), FormDigest: bytes.Clone(a.FormDigest[:]),
		IssuedAt: a.IssuedAt, ExpiresAt: a.ExpiresAt}
}
