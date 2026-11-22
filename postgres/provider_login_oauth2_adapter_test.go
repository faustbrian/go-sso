package postgres

import (
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/session"
	"github.com/faustbrian/go-sso"
)

func TestOAuth2ProtocolEvidenceRequiresOriginalAuthority(t *testing.T) {
	now := time.Date(2026, 11, 22, 23, 0, 0, 0, time.UTC)
	remember, err := session.NewRememberPolicy(session.RememberPolicySpec{
		Choice: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 20 * time.Minute,
		RefreshAfter: time.Minute, FreshFor: 15 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := sso.NewLoginTransaction(sso.LoginTransaction{
		TenantID: "test-tenant", ID: "AQEBAQEBAQEBAQEBAQEBAQ", ProviderID: "test-provider", OrganizationID: "test-org", Protocol: "oauth2",
		Callback: url.URL{Scheme: "https", Host: "app.example.com", Path: "/oauth/callback"}, ExpiresAt: now.Add(time.Minute), ProviderVersion: 9,
		MappingVersion: 4, RememberPolicy: remember, CommandID: "AgICAgICAgICAgICAgICAg",
	}, 3)
	if err != nil {
		t.Fatal(err)
	}
	issuer := "https://provider.example.com"
	provenance := sso.AttributeProvenance{ProviderID: "test-provider", ProviderProfileVersion: 9, Issuer: issuer, Source: sso.AttributeSourceOAuthIdentityEndpoint}
	attribute, err := sso.NewVerifiedAttribute(sso.VerifiedAttributeSpec{Name: "email", Presence: sso.AttributeAbsent, Provenance: provenance})
	if err != nil {
		t.Fatal(err)
	}
	cutoff := now.Add(15 * time.Second)
	valid := OAuth2ProtocolEvidence{Transaction: tx, ExpiresAt: cutoff, Assertion: sso.ProtocolAssertion{
		ProviderID: "test-provider", OrganizationID: "test-org", ProviderSubject: "stable-subject", ProviderProfileVersion: 9, MappingVersion: 4,
		Attributes: []sso.VerifiedAttribute{attribute},
	}}
	if err := validateOAuth2ProtocolEvidence(tx, issuer, now, cutoff, valid); err != nil {
		t.Fatal("original scope denied", err)
	}
	for _, tc := range []struct {
		name   string
		change func(*OAuth2ProtocolEvidence)
	}{
		{"other tenant", func(e *OAuth2ProtocolEvidence) { e.Transaction.TenantID = "other-tenant" }},
		{"other organization", func(e *OAuth2ProtocolEvidence) { e.Assertion.OrganizationID = "other-org" }},
		{"other provider revision", func(e *OAuth2ProtocolEvidence) { e.Assertion.ProviderProfileVersion++ }},
		{"other mapping", func(e *OAuth2ProtocolEvidence) { e.Assertion.MappingVersion++ }},
		{"extended expiry", func(e *OAuth2ProtocolEvidence) { e.ExpiresAt = cutoff.Add(time.Nanosecond) }},
		{"expired", func(e *OAuth2ProtocolEvidence) { e.ExpiresAt = now }},
		{"OIDC evidence", func(e *OAuth2ProtocolEvidence) {
			changed := provenance
			changed.Source = sso.AttributeSourceOIDCIDToken
			attribute, err := sso.NewVerifiedAttribute(sso.VerifiedAttributeSpec{Name: "email", Presence: sso.AttributeAbsent, Provenance: changed})
			if err != nil {
				t.Fatal(err)
			}
			e.Assertion.Attributes = []sso.VerifiedAttribute{attribute}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := valid
			tc.change(&changed)
			if err := validateOAuth2ProtocolEvidence(tx, issuer, now, cutoff, changed); !errors.Is(err, sso.ErrForbidden) {
				t.Fatal("different evidence authorized preparation", err)
			}
		})
	}
}
