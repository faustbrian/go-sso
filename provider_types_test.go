package sso_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/faustbrian/go-sso"
)

func TestAttributeMappingRetainsVersionedFlatClaimNames(t *testing.T) {
	spec := sso.AttributeMappingSpec{Version: 1, SubjectClaim: "sub", EmailClaim: "email", VerifiedEmailClaim: "email_verified", DisplayNameClaim: "https://claims.example.com/display"}
	mapping, err := sso.NewAttributeMapping(spec)
	if err != nil {
		t.Fatal("valid flat mapping", err)
	}
	got, err := mapping.Spec()
	if err != nil || got != spec {
		t.Fatal("mapping names or version changed", err)
	}
	got.SubjectClaim = "changed"
	unchanged, err := mapping.Spec()
	if err != nil || unchanged != spec {
		t.Fatal("projection mutated original mapping", err)
	}
	if _, err := (sso.AttributeMapping{}).Spec(); !errors.Is(err, sso.ErrInvalidInput) {
		t.Fatal("zero mapping admitted", err)
	}
	if _, err := json.Marshal(mapping); !errors.Is(err, sso.ErrSensitiveSerialization) {
		t.Fatal("implicit configuration export allowed", err)
	}
}

func TestAttributeMappingRejectsMissingOrUnboundedClaimPolicy(t *testing.T) {
	for _, spec := range []sso.AttributeMappingSpec{
		{SubjectClaim: "sub"},
		{Version: 1},
		{Version: 1, SubjectClaim: "sub", EmailClaim: "unbounded" + strings.Repeat("a", 128)},
		{Version: 1, SubjectClaim: "sub", VerifiedEmailClaim: "email\x00verified"},
		{Version: 1, SubjectClaim: "sub", DisplayNameClaim: "display name"},
	} {
		if _, err := sso.NewAttributeMapping(spec); !errors.Is(err, sso.ErrInvalidInput) {
			t.Fatal("invalid claim mapping admitted", err)
		}
	}
}

func FuzzAttributeMapping(f *testing.F) {
	f.Add(uint64(1), "sub", "email")
	f.Add(uint64(0), "sub", "")
	f.Add(uint64(1), "nested.path", "claim\x00name")
	f.Fuzz(func(t *testing.T, version uint64, subject, email string) {
		spec := sso.AttributeMappingSpec{Version: version, SubjectClaim: subject, EmailClaim: email}
		mapping, err := sso.NewAttributeMapping(spec)
		if err != nil {
			if !errors.Is(err, sso.ErrInvalidInput) {
				t.Fatal("non-redacted mapping error")
			}
			return
		}
		got, err := mapping.Spec()
		if err != nil || got != spec {
			t.Fatal("accepted flat mapping changed")
		}
	})
}
