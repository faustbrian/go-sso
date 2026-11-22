package oidc

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/faustbrian/go-sso"
)

func TestMergeClaimNamesPreservesMappedPrefixAndAdditionalOrder(t *testing.T) {
	mapped := []string{"email", "email_verified", "name"}
	additional := []string{"tenant_id", "email", "Role", "role", "name", "team.id-1"}
	want := []string{"email", "email_verified", "name", "tenant_id", "Role", "role", "team.id-1"}
	got, err := mergeClaimNames(mapped, additional)
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("ordered claim union = %v, %v; want %v", got, err, want)
	}
}

func TestMergeClaimNamesDetachesBothInputsAndOutput(t *testing.T) {
	for _, additional := range [][]string{nil, {"tenant_id"}} {
		t.Run(fmt.Sprintf("additional_%d", len(additional)), func(t *testing.T) {
			mapped := make([]string, 1, 8)
			mapped[0] = "email"
			additional = slices.Clone(additional)
			got, err := mergeClaimNames(mapped, additional)
			if err != nil {
				t.Fatal(err)
			}
			mapped[0] = "changed_mapped"
			if len(additional) != 0 {
				additional[0] = "changed_additional"
			}
			want := []string{"email"}
			if len(additional) != 0 {
				want = append(want, "tenant_id")
			}
			if !slices.Equal(got, want) {
				t.Fatalf("caller mutation changed selected claims: %v", got)
			}
			got[0] = "changed_output"
			if mapped[0] != "changed_mapped" {
				t.Fatal("selected claims still alias the mapped input")
			}
			if len(additional) != 0 {
				got[1] = "changed_output_additional"
				if additional[0] != "changed_additional" {
					t.Fatal("selected claims still alias the additional input")
				}
			}
		})
	}
}

func TestMergeClaimNamesRejectsRepeatsWithinEitherInput(t *testing.T) {
	for _, tc := range []struct {
		name       string
		mapped     []string
		additional []string
	}{
		{name: "mapped repeat", mapped: []string{"email", "email"}},
		{name: "additional repeat", mapped: []string{"email"}, additional: []string{"role", "role"}},
		{name: "repeated mapped overlap", mapped: []string{"email"}, additional: []string{"email", "email"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := mergeClaimNames(tc.mapped, tc.additional); got != nil || !errors.Is(err, sso.ErrInvalidInput) {
				t.Fatalf("repeated names produced %v, %v", got, err)
			}
		})
	}
}

func TestMergeClaimNamesValidatesExactClaimNames(t *testing.T) {
	invalid := []string{
		"", " email", "email ", "email\n", "email/role", "0role", "-role", ".role", "rôle", strings.Repeat("a", 129),
		"sub", "iss", "aud", "azp", "iat", "exp", "nbf", "auth_time", "nonce", "at_hash", "c_hash", "access_token", "refresh_token", "id_token",
	}
	for _, name := range invalid {
		t.Run(fmt.Sprintf("%q", name), func(t *testing.T) {
			for _, mapped := range []bool{false, true} {
				first, additional := []string{"email"}, []string{name}
				if mapped {
					first, additional = []string{name}, nil
				}
				if got, err := mergeClaimNames(first, additional); got != nil || !errors.Is(err, sso.ErrInvalidInput) {
					t.Fatalf("invalid name %q (mapped %t) produced %v, %v", name, mapped, got, err)
				}
			}
		})
	}
	valid := []string{"_role", "Role", "role", "role1", "team.id-1", strings.Repeat("a", 128)}
	if got, err := mergeClaimNames(nil, valid); err != nil || !slices.Equal(got, valid) {
		t.Fatalf("exact valid names changed: %v, %v", got, err)
	}
}

func TestMergeClaimNamesBoundsUniqueProjection(t *testing.T) {
	names := make([]string, 129)
	for i := range names {
		names[i] = fmt.Sprintf("claim_%d", i)
	}
	for _, tc := range []struct {
		name       string
		mapped     []string
		additional []string
		valid      bool
	}{
		{name: "empty", valid: true},
		{name: "128 mapped", mapped: names[:128], valid: true},
		{name: "128 additional", additional: names[:128], valid: true},
		{name: "128 unique with overlaps", mapped: names[:3], additional: names[:128], valid: true},
		{name: "129 mapped", mapped: names},
		{name: "129 additional", additional: names},
		{name: "129 merged", mapped: names[:3], additional: names[3:]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := mergeClaimNames(tc.mapped, tc.additional)
			if !tc.valid {
				if got != nil || !errors.Is(err, sso.ErrInvalidInput) {
					t.Fatalf("oversized selection produced %v, %v", got, err)
				}
				return
			}
			want := names[:128]
			if len(tc.mapped) == 0 && len(tc.additional) == 0 {
				want = nil
			}
			if err != nil || !slices.Equal(got, want) {
				t.Fatalf("bounded selection = %v, %v; want %v", got, err, want)
			}
		})
	}
}
