package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestSAMLIDPPendingConfirmationRejectsUnaffiliatedWork(t *testing.T) {
	for _, ctx := range []context.Context{nil, t.Context()} {
		if err := completeSAMLIDPPendingConfirmation(ctx, kernel.Work{}, nil, identity.Command{}, samlIDPPendingArrivalForTest()); err == nil {
			t.Fatal("unaffiliated Work completed pending confirmation")
		}
	}
}

func TestSAMLIDPPendingConfirmationPreservesExactOriginalSQLCustody(t *testing.T) {
	a := samlIDPPendingArrivalForTest()
	b := samlIDPPendingConfirmationBindingForTest(a)
	want := []any{string(a.Binding.TenantID), []byte("arrival-command1"), string(a.Organization), string(a.Provider),
		string(a.Binding.UserID), a.Envelope, int64(a.KeyVersion), a.BrowserDigest[:], a.FormDigest[:], a.IssuedAt, a.ExpiresAt,
		[]byte("complete-command")}
	called := false
	err := writeSAMLIDPPendingConfirmation(t.Context(), func(_ context.Context, statement string, got ...any) (int64, error) {
		called = true
		if statement != completeSAMLIDPPendingConfirmationSQL || !reflect.DeepEqual(got, want) {
			t.Fatal("completion lost the original pending custody or distinct completion command")
		}
		return 1, nil
	}, b, a)
	if err != nil || !called {
		t.Fatal("exact completion was not written", err)
	}
}

func TestSAMLIDPPendingConfirmationRejectsInvalidCustodyBeforeSQL(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*identity.CommandBinding, *samlIDPPendingArrival)
	}{
		{"other tenant", func(b *identity.CommandBinding, _ *samlIDPPendingArrival) { b.TenantID = "other" }},
		{"other linked user", func(b *identity.CommandBinding, _ *samlIDPPendingArrival) { b.UserID = "other" }},
		{"other original arrival", func(b *identity.CommandBinding, _ *samlIDPPendingArrival) { b.RecordID = string(b.CommandID) }},
		{"same completion command", func(b *identity.CommandBinding, a *samlIDPPendingArrival) { b.CommandID = a.Binding.CommandID }},
		{"noncanonical completion", func(b *identity.CommandBinding, _ *samlIDPPendingArrival) { b.CommandID += "=" }},
		{"zero completion", func(b *identity.CommandBinding, _ *samlIDPPendingArrival) {
			b.CommandID = identity.CommandID(base64.RawURLEncoding.EncodeToString(make([]byte, 16)))
		}},
		{"wrong operation", func(b *identity.CommandBinding, _ *samlIDPPendingArrival) { b.OperationID = "identity.sso.saml-acs" }},
		{"wrong schema", func(b *identity.CommandBinding, _ *samlIDPPendingArrival) { b.SchemaID = "sso-enterprise-saml-acs-v1" }},
		{"wrong actor kind", func(b *identity.CommandBinding, _ *samlIDPPendingArrival) { b.ActorKind = authorization.SubjectUser }},
		{"missing original record", func(_ *identity.CommandBinding, a *samlIDPPendingArrival) { a.Binding.RecordID = "" }},
		{"missing envelope", func(_ *identity.CommandBinding, a *samlIDPPendingArrival) { a.Envelope = nil }},
		{"missing key", func(_ *identity.CommandBinding, a *samlIDPPendingArrival) { a.KeyVersion = 0 }},
		{"missing browser commitment", func(_ *identity.CommandBinding, a *samlIDPPendingArrival) { a.BrowserDigest = [32]byte{} }},
		{"same commitments", func(_ *identity.CommandBinding, a *samlIDPPendingArrival) { a.FormDigest = a.BrowserDigest }},
		{"renewed lifetime", func(_ *identity.CommandBinding, a *samlIDPPendingArrival) { a.ExpiresAt = a.ExpiresAt.Add(1) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := samlIDPPendingArrivalForTest()
			b := samlIDPPendingConfirmationBindingForTest(a)
			tc.change(&b, &a)
			err := writeSAMLIDPPendingConfirmation(t.Context(), func(context.Context, string, ...any) (int64, error) {
				t.Fatal("invalid completion custody reached SQL")
				return 1, nil
			}, b, a)
			if err == nil {
				t.Fatal("invalid completion custody was accepted")
			}
		})
	}
}

func TestSAMLIDPPendingConfirmationRequiresExactlyOneFreshPendingRow(t *testing.T) {
	for _, tc := range []struct {
		name string
		rows int64
		err  error
		want error
	}{
		{"no fresh exact pending row", 0, nil, identity.ForbiddenError{}},
		{"impossible row count", 2, nil, identity.UnavailableError{}},
		{"negative row count", -1, nil, identity.UnavailableError{}},
		{"private SQL failure", 0, errors.New("private driver and custody details"), identity.UnavailableError{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := samlIDPPendingArrivalForTest()
			err := writeSAMLIDPPendingConfirmation(t.Context(), func(context.Context, string, ...any) (int64, error) {
				return tc.rows, tc.err
			}, samlIDPPendingConfirmationBindingForTest(a), a)
			if !errors.Is(err, tc.want) || strings.Contains(err.Error(), "private") {
				t.Fatal("completion changed safe fresh-row failure semantics", err)
			}
		})
	}
}

func TestSAMLIDPPendingConfirmationPreservesCancellation(t *testing.T) {
	a := samlIDPPendingArrivalForTest()
	b := samlIDPPendingConfirmationBindingForTest(a)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := writeSAMLIDPPendingConfirmation(ctx, func(context.Context, string, ...any) (int64, error) {
		t.Fatal("cancelled completion reached SQL")
		return 1, nil
	}, b, a); !errors.Is(err, context.Canceled) {
		t.Fatal("pre-write cancellation was lost", err)
	}
	for _, sqlErr := range []error{nil, errors.New("private driver details")} {
		ctx, cancel := context.WithCancel(t.Context())
		err := writeSAMLIDPPendingConfirmation(ctx, func(context.Context, string, ...any) (int64, error) {
			cancel()
			return 1, sqlErr
		}, b, a)
		if !errors.Is(err, context.Canceled) {
			t.Fatal("in-flight cancellation was lost", err)
		}
	}
	if err := writeSAMLIDPPendingConfirmation(nil, nil, b, a); err == nil {
		t.Fatal("nil context and executor were accepted")
	}
}

func samlIDPPendingConfirmationBindingForTest(a samlIDPPendingArrival) identity.CommandBinding {
	b := a.Binding
	b.CommandID = identity.CommandID(base64.RawURLEncoding.EncodeToString([]byte("complete-command")))
	b.OperationID = "identity.sso.saml-idp-init"
	b.SchemaID = "sso-enterprise-saml-idp-init-v1"
	return b
}
