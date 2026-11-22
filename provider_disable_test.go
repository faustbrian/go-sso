package sso_test

import (
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/faustbrian/go-sso"
)

func disableRequest(t testing.TB, mode sso.ActiveTransactionDispositionMode) sso.ProviderDisableRequest {
	t.Helper()
	disposition, err := sso.NewActiveTransactionDisposition("disable-provider", 7, mode)
	if err != nil {
		t.Fatal(err)
	}
	return sso.ProviderDisableRequest{
		ProviderID: "disable-provider", ExpectedVersion: 7, Reason: "sensitive-disable-reason",
		ActiveTransactionDisposition: disposition,
	}
}

func TestActiveTransactionDispositionPreservesDetachedBinding(t *testing.T) {
	for _, mode := range []sso.ActiveTransactionDispositionMode{sso.ActiveTransactionDrain, sso.ActiveTransactionRevoke} {
		t.Run(string(mode), func(t *testing.T) {
			request := disableRequest(t, mode)
			want := sso.ActiveTransactionDispositionBinding{ProviderID: "disable-provider", ProviderVersion: 7, Mode: mode}
			binding, err := request.ActiveTransactionDisposition.Bindings()
			if err != nil || binding != want {
				t.Fatal("disposition did not preserve exact selected binding", err)
			}
			binding.ProviderID = "changed-provider"
			binding.ProviderVersion++
			binding.Mode = "unknown"
			again, err := request.ActiveTransactionDisposition.Bindings()
			if err != nil || again != want {
				t.Fatal("binding projection mutated disposition", err)
			}
			if err := request.Validate(); err != nil {
				t.Fatal("valid bound disposition rejected", err)
			}
		})
	}
	if binding, err := (sso.ActiveTransactionDisposition{}).Bindings(); !errors.Is(err, sso.ErrInvalidInput) || binding != (sso.ActiveTransactionDispositionBinding{}) {
		t.Fatal("zero disposition projected a selected binding", err)
	}
}

func TestActiveTransactionDispositionRejectsInvalidSelectors(t *testing.T) {
	cases := []struct {
		name     string
		provider sso.ProviderID
		version  uint64
		mode     sso.ActiveTransactionDispositionMode
	}{
		{"missing provider", "", 7, sso.ActiveTransactionDrain},
		{"padded provider", " provider", 7, sso.ActiveTransactionDrain},
		{"oversized provider", sso.ProviderID(strings.Repeat("p", 129)), 7, sso.ActiveTransactionDrain},
		{"non ASCII provider", "pröv", 7, sso.ActiveTransactionDrain},
		{"zero version", "disable-provider", 0, sso.ActiveTransactionDrain},
		{"exhausted version", "disable-provider", math.MaxUint64, sso.ActiveTransactionDrain},
		{"missing mode", "disable-provider", 7, ""},
		{"unknown mode", "disable-provider", 7, "other"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			disposition, err := sso.NewActiveTransactionDisposition(test.provider, test.version, test.mode)
			if !errors.Is(err, sso.ErrInvalidInput) {
				t.Fatal("invalid selector admitted", err)
			}
			if _, err := disposition.Bindings(); !errors.Is(err, sso.ErrInvalidInput) {
				t.Fatal("constructor failure returned a usable disposition", err)
			}
		})
	}
}

func TestProviderDisableRequestRejectsInvalidShapeAndBinding(t *testing.T) {
	cases := map[string]func(*sso.ProviderDisableRequest){
		"missing provider":  func(r *sso.ProviderDisableRequest) { r.ProviderID = "" },
		"wrong provider":    func(r *sso.ProviderDisableRequest) { r.ProviderID = "other-provider" },
		"zero version":      func(r *sso.ProviderDisableRequest) { r.ExpectedVersion = 0 },
		"wrong version":     func(r *sso.ProviderDisableRequest) { r.ExpectedVersion++ },
		"exhausted version": func(r *sso.ProviderDisableRequest) { r.ExpectedVersion = math.MaxUint64 },
		"zero disposition": func(r *sso.ProviderDisableRequest) {
			r.ActiveTransactionDisposition = sso.ActiveTransactionDisposition{}
		},
		"missing reason":         func(r *sso.ProviderDisableRequest) { r.Reason = "" },
		"blank ASCII reason":     func(r *sso.ProviderDisableRequest) { r.Reason = "   " },
		"blank Unicode reason":   func(r *sso.ProviderDisableRequest) { r.Reason = "\u2003\u00a0" },
		"oversized ASCII reason": func(r *sso.ProviderDisableRequest) { r.Reason = strings.Repeat("x", 1025) },
		"oversized UTF-8 reason": func(r *sso.ProviderDisableRequest) { r.Reason = strings.Repeat("é", 513) },
		"invalid UTF-8 reason":   func(r *sso.ProviderDisableRequest) { r.Reason = "sensitive-\xff" },
		"NUL reason":             func(r *sso.ProviderDisableRequest) { r.Reason = "sensitive\x00reason" },
		"newline reason":         func(r *sso.ProviderDisableRequest) { r.Reason = "sensitive\nreason" },
		"DEL reason":             func(r *sso.ProviderDisableRequest) { r.Reason = "sensitive\x7freason" },
		"Unicode control reason": func(r *sso.ProviderDisableRequest) { r.Reason = "sensitive\u0085reason" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			request := disableRequest(t, sso.ActiveTransactionDrain)
			mutate(&request)
			if err := request.Validate(); !errors.Is(err, sso.ErrInvalidInput) || err.Error() != sso.ErrInvalidInput.Error() {
				t.Fatal("invalid request did not return only the redacted category")
			}
		})
	}
}

func TestProviderDisableReasonAcceptsExactByteBounds(t *testing.T) {
	for _, reason := range []string{"x", "é", "  maintenance  ", strings.Repeat("x", 1024), strings.Repeat("é", 512)} {
		request := disableRequest(t, sso.ActiveTransactionRevoke)
		request.Reason = reason
		if err := request.Validate(); err != nil {
			t.Fatal("valid bounded reason rejected", err)
		}
		if request.Reason != reason {
			t.Fatal("validation changed original reason")
		}
	}
}

func TestProviderDisableValuesRedactImplicitDisclosure(t *testing.T) {
	request := disableRequest(t, sso.ActiveTransactionDrain)
	for _, value := range []any{request, request.ActiveTransactionDisposition} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
			got := fmt.Sprintf(format, value)
			if !strings.Contains(got, "redacted") || strings.Contains(got, "disable-provider") || strings.Contains(got, "sensitive-disable-reason") {
				t.Fatal("implicit formatting disclosed request or disposition")
			}
		}
		if _, err := json.Marshal(value); !errors.Is(err, sso.ErrSensitiveSerialization) {
			t.Fatal("implicit JSON serialization admitted", err)
		}
		marshaler, ok := value.(encoding.TextMarshaler)
		if !ok {
			t.Fatal("missing text serialization denial")
		}
		if _, err := marshaler.MarshalText(); !errors.Is(err, sso.ErrSensitiveSerialization) {
			t.Fatal("implicit text serialization admitted", err)
		}
	}
}

func FuzzProviderDisableReason(f *testing.F) {
	for _, reason := range []string{"maintenance", "", " ", "\xff", "stop\nnow", strings.Repeat("é", 512), strings.Repeat("x", 1025)} {
		f.Add(reason)
	}
	f.Fuzz(func(t *testing.T, reason string) {
		request := disableRequest(t, sso.ActiveTransactionDrain)
		request.Reason = reason
		wantValid := len(reason) > 0 && len(reason) <= 1024 && utf8.ValidString(reason) && strings.TrimSpace(reason) != ""
		for _, char := range reason {
			if unicode.IsControl(char) {
				wantValid = false
			}
		}
		err := request.Validate()
		if (err == nil) != wantValid {
			t.Fatal("reason validation disagreed with bounded UTF-8 control-free shape")
		}
		if err != nil && err != sso.ErrInvalidInput {
			t.Fatal("invalid reason exposed non-category diagnostics")
		}
	})
}
