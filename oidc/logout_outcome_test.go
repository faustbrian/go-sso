package oidc_test

import (
	"bytes"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-sso"
	"github.com/faustbrian/go-sso/oidc"
)

func logoutCompletion(t testing.TB, operation string, outcome identity.CommitOutcome) oidc.Completion {
	t.Helper()
	descriptor := identity.FeatureOperation{
		Owner: "sso/oidc", OperationID: operation, SchemaID: "oidc-logout-v1", SchemaVersion: 1,
		RecordRequirement: identity.FeatureRecordRequired,
	}
	completion := identity.CommandResult{
		Binding: identity.CommandBinding{
			CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", TenantID: "tenant", UserID: "user", ActorID: "actor",
			ActorKind: authorization.SubjectUser, OperationID: operation, PolicyID: "policy", PolicyVersion: 1,
			SchemaID: descriptor.SchemaID, SchemaVersion: 1, CorrelationID: "correlation", RecordID: "session",
		},
		Outcome: outcome, Feature: &identity.FeatureReceipt{Operation: descriptor},
	}
	if outcome == identity.CommitOutcomeCommitted {
		completion.AuditEventID = "audit-event"
		completion.Feature.BeforeVersion = 1
		completion.Feature.AfterVersion = 2
	}
	if outcome == identity.CommitOutcomeInProgress {
		completion.RetryAfter = time.Second
	}
	if err := completion.Validate(); err != nil {
		t.Fatal("invalid local command fixture", err)
	}
	return completion
}

func logoutRedirect() url.URL {
	return url.URL{Scheme: "https", Host: "provider.example", Path: "/logout", RawQuery: "state=secret-state&post_logout_redirect_uri=https%3A%2F%2Fclient.example%2Fdone"}
}

func TestLogoutResultsSelectOnlyTheirPermittedPhaseVariants(t *testing.T) {
	for _, outcome := range []oidc.OIDCLogoutOutcome{
		oidc.OIDCLogoutRedirect, oidc.OIDCLogoutLocalOnly, oidc.OIDCLogoutProviderComplete,
		oidc.OIDCLogoutProviderError, oidc.OIDCLogoutTimeout, oidc.OIDCLogoutUnknownReconciliation,
	} {
		t.Run(fmt.Sprint(outcome), func(t *testing.T) {
			var redirect url.URL
			if outcome == oidc.OIDCLogoutRedirect {
				redirect = logoutRedirect()
			}
			startReceipt := logoutCompletion(t, "identity.sso.oidc-logout", identity.CommitOutcomeCommitted)
			start, err := oidc.NewLogoutStartResult(outcome, redirect, startReceipt)
			startAllowed := outcome == oidc.OIDCLogoutRedirect || outcome == oidc.OIDCLogoutLocalOnly || outcome == oidc.OIDCLogoutUnknownReconciliation
			if !startAllowed {
				if !errors.Is(err, sso.ErrInvalidInput) || start != (oidc.LogoutStartResult{}) {
					t.Fatal("start accepted a completion-only variant", err)
				}
			} else {
				if err != nil || start.Validate() != nil || start.Outcome() != outcome {
					t.Fatal("start rejected or changed a permitted variant", err)
				}
				got, present := start.RedirectURI()
				if got != redirect || present != (outcome == oidc.OIDCLogoutRedirect) {
					t.Fatal("start exposed incorrect variant-specific redirect")
				}
				local, err := start.Completion()
				if err != nil || !reflect.DeepEqual(local, startReceipt) {
					t.Fatal("start changed local completion", err)
				}
			}
			completeReceipt := logoutCompletion(t, "identity.sso.oidc-logout-complete", identity.CommitOutcomeCommitted)
			complete, err := oidc.NewLogoutCompleteResult(outcome, redirect, completeReceipt)
			if err != nil || complete.Validate() != nil || complete.Outcome() != outcome {
				t.Fatal("completion rejected or changed a permitted variant", err)
			}
			got, present := complete.RedirectURI()
			if got != redirect || present != (outcome == oidc.OIDCLogoutRedirect) {
				t.Fatal("completion exposed incorrect variant-specific redirect")
			}
			local, err := complete.Completion()
			if err != nil || !reflect.DeepEqual(local, completeReceipt) {
				t.Fatal("completion changed local command receipt", err)
			}
		})
	}
}

func TestLogoutResultsNeverPromoteUnknownLocalRevocation(t *testing.T) {
	for _, localOutcome := range []identity.CommitOutcome{
		identity.CommitOutcomeCommitted, identity.CommitOutcomeUnknown, identity.CommitOutcomeInProgress,
		identity.CommitOutcomeNotCommitted, identity.CommitOutcomeConflict,
	} {
		for _, providerOutcome := range []oidc.OIDCLogoutOutcome{
			oidc.OIDCLogoutRedirect, oidc.OIDCLogoutLocalOnly, oidc.OIDCLogoutProviderComplete,
			oidc.OIDCLogoutProviderError, oidc.OIDCLogoutTimeout, oidc.OIDCLogoutUnknownReconciliation,
		} {
			t.Run(fmt.Sprintf("local-%d-provider-%d", localOutcome, providerOutcome), func(t *testing.T) {
				var redirect url.URL
				if providerOutcome == oidc.OIDCLogoutRedirect {
					redirect = logoutRedirect()
				}
				allowed := localOutcome == identity.CommitOutcomeCommitted || providerOutcome == oidc.OIDCLogoutUnknownReconciliation && (localOutcome == identity.CommitOutcomeUnknown || localOutcome == identity.CommitOutcomeInProgress)
				for _, phase := range []string{"identity.sso.oidc-logout", "identity.sso.oidc-logout-complete"} {
					completion := logoutCompletion(t, phase, localOutcome)
					var err error
					var preserved oidc.Completion
					phaseAllowed := allowed
					if phase == "identity.sso.oidc-logout" {
						phaseAllowed = allowed && (providerOutcome == oidc.OIDCLogoutRedirect || providerOutcome == oidc.OIDCLogoutLocalOnly || providerOutcome == oidc.OIDCLogoutUnknownReconciliation)
						var result oidc.LogoutStartResult
						result, err = oidc.NewLogoutStartResult(providerOutcome, redirect, completion)
						if err == nil {
							preserved, err = result.Completion()
						}
					} else {
						var result oidc.LogoutCompleteResult
						result, err = oidc.NewLogoutCompleteResult(providerOutcome, redirect, completion)
						if err == nil {
							preserved, err = result.Completion()
						}
					}
					if phaseAllowed {
						if err != nil || !reflect.DeepEqual(preserved, completion) {
							t.Fatal("local revocation receipt was changed or discarded", err)
						}
					} else if !errors.Is(err, sso.ErrInvalidInput) {
						t.Fatal("unproved local revocation became a settled provider result", err)
					}
				}
			})
		}
	}
}

func TestLogoutResultsRejectInvalidVariantsReceiptsAndRedirects(t *testing.T) {
	for _, phase := range []string{"identity.sso.oidc-logout", "identity.sso.oidc-logout-complete"} {
		newResult := func(outcome oidc.OIDCLogoutOutcome, redirect url.URL, completion oidc.Completion) error {
			if phase == "identity.sso.oidc-logout" {
				_, err := oidc.NewLogoutStartResult(outcome, redirect, completion)
				return err
			}
			_, err := oidc.NewLogoutCompleteResult(outcome, redirect, completion)
			return err
		}
		completion := logoutCompletion(t, phase, identity.CommitOutcomeCommitted)
		for _, outcome := range []oidc.OIDCLogoutOutcome{oidc.OIDCLogoutInvalid, 7, 255} {
			if err := newResult(outcome, url.URL{}, completion); !errors.Is(err, sso.ErrInvalidInput) {
				t.Fatal("invalid closed variant accepted", err)
			}
		}
		wrongPhase := "identity.sso.oidc-logout"
		if phase == wrongPhase {
			wrongPhase = "identity.sso.oidc-logout-complete"
		}
		for _, invalid := range []oidc.Completion{{}, logoutCompletion(t, wrongPhase, identity.CommitOutcomeCommitted)} {
			if err := newResult(oidc.OIDCLogoutLocalOnly, url.URL{}, invalid); !errors.Is(err, sso.ErrInvalidInput) {
				t.Fatal("zero or cross-phase receipt accepted", err)
			}
		}
		foreignOwner := logoutCompletion(t, phase, identity.CommitOutcomeCommitted)
		foreignOwner.Feature.Operation.Owner = "unrelated"
		if err := newResult(oidc.OIDCLogoutLocalOnly, url.URL{}, foreignOwner); !errors.Is(err, sso.ErrInvalidInput) {
			t.Fatal("unrelated receipt owner accepted", err)
		}
		for _, outcome := range []oidc.OIDCLogoutOutcome{oidc.OIDCLogoutLocalOnly, oidc.OIDCLogoutProviderComplete, oidc.OIDCLogoutProviderError, oidc.OIDCLogoutTimeout, oidc.OIDCLogoutUnknownReconciliation} {
			if err := newResult(outcome, logoutRedirect(), completion); !errors.Is(err, sso.ErrInvalidInput) {
				t.Fatal("nonredirect variant accepted a secret redirect", err)
			}
		}
		invalidRedirects := []url.URL{
			{}, {Scheme: "http", Host: "provider.example"}, {Scheme: "https"},
			{Scheme: "https", Host: "provider.example", User: url.User("credential")},
			{Scheme: "https", Host: "provider.example", Fragment: "state"},
			{Scheme: "https", Host: "provider.example", RawFragment: "hidden"},
			{Scheme: "https", Host: "provider.example", Opaque: "hidden"},
			{Scheme: "https", Host: "provider.example", OmitHost: true},
			{Scheme: "https", Host: "provider.example", Path: "/logout", RawPath: "/other"},
			{Scheme: "https", Host: "provider.example", RawQuery: strings.Repeat("s", 2049)},
		}
		for _, redirect := range invalidRedirects {
			if err := newResult(oidc.OIDCLogoutRedirect, redirect, completion); !errors.Is(err, sso.ErrInvalidInput) {
				t.Fatal("invalid redirect shape accepted", err)
			}
		}
		maximum := url.URL{Scheme: "https", Host: "provider.example", Path: "/" + strings.Repeat("a", 2048-len("https://provider.example/"))}
		if err := newResult(oidc.OIDCLogoutRedirect, maximum, completion); err != nil {
			t.Fatal("exact 2048-byte redirect rejected", err)
		}
		maximum.Path += "a"
		if err := newResult(oidc.OIDCLogoutRedirect, maximum, completion); !errors.Is(err, sso.ErrInvalidInput) {
			t.Fatal("oversized serialized redirect accepted", err)
		}
	}
}

func TestLogoutResultCopiesReceiptsAndRejectsZeroValues(t *testing.T) {
	startReceipt := logoutCompletion(t, "identity.sso.oidc-logout", identity.CommitOutcomeCommitted)
	start, err := oidc.NewLogoutStartResult(oidc.OIDCLogoutLocalOnly, url.URL{}, startReceipt)
	if err != nil {
		t.Fatal(err)
	}
	startReceipt.Feature.AfterVersion = 99
	first, err := start.Completion()
	if err != nil || first.Feature.AfterVersion != 2 {
		t.Fatal("input mutation reached start result", err)
	}
	first.Feature.AfterVersion = 77
	second, err := start.Completion()
	if err != nil || second.Feature.AfterVersion != 2 {
		t.Fatal("projection mutation reached start result", err)
	}
	completeReceipt := logoutCompletion(t, "identity.sso.oidc-logout-complete", identity.CommitOutcomeCommitted)
	complete, err := oidc.NewLogoutCompleteResult(oidc.OIDCLogoutProviderError, url.URL{}, completeReceipt)
	if err != nil {
		t.Fatal(err)
	}
	completeReceipt.Feature.AfterVersion = 99
	first, err = complete.Completion()
	if err != nil || first.Feature.AfterVersion != 2 {
		t.Fatal("provider failure or input mutation changed committed local revocation", err)
	}
	first.Feature.AfterVersion = 77
	second, err = complete.Completion()
	if err != nil || second.Feature.AfterVersion != 2 {
		t.Fatal("projection mutation reached completion result", err)
	}
	if err := (oidc.LogoutStartResult{}).Validate(); !errors.Is(err, sso.ErrInvalidInput) {
		t.Fatal("zero start result valid", err)
	}
	if err := (oidc.LogoutCompleteResult{}).Validate(); !errors.Is(err, sso.ErrInvalidInput) {
		t.Fatal("zero completion result valid", err)
	}
	if value, err := (oidc.LogoutStartResult{}).Completion(); !errors.Is(err, sso.ErrInvalidInput) || !reflect.DeepEqual(value, oidc.Completion{}) {
		t.Fatal("zero start result fabricated local receipt", err)
	}
	if value, err := (oidc.LogoutCompleteResult{}).Completion(); !errors.Is(err, sso.ErrInvalidInput) || !reflect.DeepEqual(value, oidc.Completion{}) {
		t.Fatal("zero completion result fabricated local receipt", err)
	}
}

func TestLogoutResultsRedactImplicitDisclosure(t *testing.T) {
	start, err := oidc.NewLogoutStartResult(oidc.OIDCLogoutRedirect, logoutRedirect(), logoutCompletion(t, "identity.sso.oidc-logout", identity.CommitOutcomeCommitted))
	if err != nil {
		t.Fatal(err)
	}
	complete, err := oidc.NewLogoutCompleteResult(oidc.OIDCLogoutRedirect, logoutRedirect(), logoutCompletion(t, "identity.sso.oidc-logout-complete", identity.CommitOutcomeCommitted))
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{start, &start, complete, &complete} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X"} {
			if got := fmt.Sprintf(format, value); strings.Contains(got, "secret-state") || strings.Contains(got, "provider.example") || strings.Contains(got, "client.example") || !strings.Contains(got, "redacted") {
				t.Fatal("formatted result disclosed redirect or state")
			}
		}
		if data, err := json.Marshal(value); !errors.Is(err, sso.ErrSensitiveSerialization) || len(data) != 0 {
			t.Fatal("result allowed implicit JSON disclosure", err)
		}
		if data, err := value.(encoding.TextMarshaler).MarshalText(); !errors.Is(err, sso.ErrSensitiveSerialization) || len(data) != 0 {
			t.Fatal("result allowed implicit text disclosure", err)
		}
		var logs bytes.Buffer
		slog.New(slog.NewJSONHandler(&logs, nil)).Info("logout", "result", value)
		if got := logs.String(); strings.Contains(got, "secret-state") || strings.Contains(got, "provider.example") || !strings.Contains(got, "redacted") {
			t.Fatal("structured logging disclosed redirect or state")
		}
	}
}
