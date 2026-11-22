package postgres

import (
	"errors"
	"testing"

	identifier "github.com/faustbrian/go-identifier/v2"
	"github.com/faustbrian/go-identity/email"
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-sso"
)

func TestProviderLoginJITMailboxUsesAuthenticatedMappingAndExactDomain(t *testing.T) {
	profile, err := identifier.NewNormalizationProfile(identifier.NormalizationProfileSpec{
		ID: "email-v1", Version: 1, Unicode: identifier.UnicodeNormalizationNFC, CaseFold: true, MaximumBytes: 254,
	})
	if err != nil {
		t.Fatal(err)
	}
	parser, err := email.NewAddressParser(email.AddressPolicy{MaximumBytes: 254, Canonicalization: profile})
	if err != nil {
		t.Fatal(err)
	}
	mapped := sso.AttributeMappingSpec{Version: 7, SubjectClaim: "sub", EmailClaim: "work_mail", VerifiedEmailClaim: "verified_work_mail"}
	names := []string{"work_mail", "verified_work_mail", "email", "email_verified"}
	for _, tc := range []struct {
		name    string
		mail    any
		proof   any
		change  func(*sso.AttributeMappingSpec)
		allowed bool
	}{
		{name: "verified exact domain", mail: "New@ENTERPRISE.example", proof: true, allowed: true},
		{name: "foreign domain", mail: "New@elsewhere.example", proof: true},
		{name: "subdomain not routed", mail: "New@branch.enterprise.example", proof: true},
		{name: "suffix not routed", mail: "New@otherenterprise.example", proof: true},
		{name: "display syntax", mail: "Name <New@enterprise.example>", proof: true},
		{name: "unverified", mail: "New@enterprise.example", proof: false},
		{name: "string is not verification", mail: "New@enterprise.example", proof: "true"},
		{name: "not present", mail: "New@enterprise.example"},
		{name: "stale mapping", mail: "New@enterprise.example", proof: true, change: func(m *sso.AttributeMappingSpec) { m.Version-- }},
		{name: "unselected subject mapping", mail: "New@enterprise.example", proof: true, change: func(m *sso.AttributeMappingSpec) { m.SubjectClaim = "preferred_username" }},
		{name: "unprojected email", mail: "New@enterprise.example", proof: true, change: func(m *sso.AttributeMappingSpec) { m.EmailClaim = "unprojected" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The standard claims are deliberately populated; no unmapped claim
			// can substitute for the selected claims in the installed profile.
			values := map[string]any{"work_mail": tc.mail, "email": "fallback@enterprise.example", "email_verified": true}
			if tc.proof != nil {
				values["verified_work_mail"] = tc.proof
			}
			claims := verifiedRoleMappingClaims(t, values, names)
			mapping := mapped
			if tc.change != nil {
				tc.change(&mapping)
			}
			got, err := selectProviderLoginJITMailbox(parser, mapping, 7, "enterprise.example", claims)
			if !tc.allowed {
				if !errors.Is(err, sso.ErrForbidden) || got != (email.Address{}) {
					t.Fatal("unapproved mailbox was selected")
				}
				return
			}
			if err != nil || got.Canonical().Record().Value != "new@enterprise.example" {
				t.Fatal("authenticated mapped mailbox lost the configured directory comparison", err)
			}
			if _, err := selectProviderLoginJITMailbox(parser, mapping, 7, "enterprise.example", append(claims, findClaim(t, claims, "work_mail"))); !errors.Is(err, sso.ErrForbidden) {
				t.Fatal("duplicate mapped mailbox observation admitted")
			}
		})
	}
}

func findClaim(t *testing.T, claims []oauth.VerifiedOIDCClaim, name string) oauth.VerifiedOIDCClaim {
	t.Helper()
	for _, claim := range claims {
		if claim.Name() == name {
			return claim
		}
	}
	t.Fatal("test fixture omitted an authenticated projection")
	return oauth.VerifiedOIDCClaim{}
}
