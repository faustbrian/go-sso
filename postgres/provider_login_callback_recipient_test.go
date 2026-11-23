package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/faustbrian/go-identity/oauth"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	"github.com/faustbrian/go-sso"
)

func TestSSOOIDCAccountProviderNamespaceSeparatesOrganizationAndProvider(t *testing.T) {
	const stable = "sso.oidc.v1.a5ddd7d533845ebaed94a0a26b4be750d698cf296ceee1b7fbd6f4170cdc2410"
	if got, err := SSOOIDCAccountProviderNamespace("org-a", "provider-a"); err != nil || got != stable {
		t.Fatal("existing linked-account namespace changed", err)
	}
	seen := make(map[string]bool)
	for _, tuple := range [][2]string{{"org-a", "provider-a"}, {"org-b", "provider-a"}, {"org-a", "provider-b"}, {"ab", "c"}, {"a", "bc"}, {"a:b", "c"}, {"a", "b:c"}} {
		got, err := SSOOIDCAccountProviderNamespace(organization.ID(tuple[0]), sso.ProviderID(tuple[1]))
		if err != nil || got == "" || seen[got] {
			t.Fatal("distinct organization/provider tuples did not retain distinct provider namespaces", err)
		}
		again, err := SSOOIDCAccountProviderNamespace(organization.ID(tuple[0]), sso.ProviderID(tuple[1]))
		if err != nil || got != again {
			t.Fatal("provider namespace was not stable", err)
		}
		if err := (kernel.ProviderSigninAccountQuery{TenantID: "tenant", Provider: got, Issuer: "https://issuer.example", Subject: "opaque-subject"}).Validate(); err != nil {
			t.Fatal("namespace cannot be used by the identity-owned account query", err)
		}
		seen[got] = true
	}
	if got, err := SSOOIDCAccountProviderNamespace(organization.ID(strings.Repeat("o", 128)), sso.ProviderID(strings.Repeat("p", 128))); err != nil || len(got) > 128 {
		t.Fatal("maximum supported source identifiers do not fit identity's provider bound", err)
	}
}

func TestSSOOIDCAccountProviderNamespaceRejectsMalformedSourceIdentifiers(t *testing.T) {
	for _, bad := range []string{"", "bad id", "bad\nvalue", strings.Repeat("x", 129), "é"} {
		if got, err := SSOOIDCAccountProviderNamespace(organization.ID(bad), "provider"); !errors.Is(err, sso.ErrInvalidInput) || got != "" {
			t.Fatal("malformed organization received an account namespace", err)
		}
		if got, err := SSOOIDCAccountProviderNamespace("organization", sso.ProviderID(bad)); !errors.Is(err, sso.ErrInvalidInput) || got != "" {
			t.Fatal("malformed provider received an account namespace", err)
		}
	}
}

func TestSSOSAMLAccountProviderNamespaceDoesNotAliasEnterpriseOAuth(t *testing.T) {
	oidc, _ := SSOOIDCAccountProviderNamespace("org-a", "provider-a")
	oauth, _ := SSOOAuth2AccountProviderNamespace("org-a", "provider-a")
	saml, err := SSOSAMLAccountProviderNamespace("org-a", "provider-a")
	if err != nil || saml == oidc || saml == oauth || !strings.HasPrefix(saml, "sso.saml.v1.") || len(saml) != len("sso.saml.v1.")+64 {
		t.Fatal("SAML did not receive its distinct stable account namespace", err)
	}
	if got, err := SSOSAMLAccountProviderNamespace("org-a", "provider-a"); err != nil || got != saml {
		t.Fatal("SAML provider namespace was not stable", err)
	}
	if got, err := SSOSAMLAccountProviderNamespace("org-b", "provider-a"); err != nil || got == saml {
		t.Fatal("SAML account namespace lost its organization binding", err)
	}
	if got, err := SSOSAMLAccountProviderNamespace("org-a", "foreign provider"); !errors.Is(err, sso.ErrInvalidInput) || got != "" {
		t.Fatal("invalid provider received a SAML namespace", err)
	}
}

func TestProviderLoginCallbackRecipientRejectsMissingOriginalAuthority(t *testing.T) {
	for _, service := range []*ProviderLoginService{nil, {}, {router: &ProviderRouter{}}} {
		got, err := service.resolveProviderLoginCallbackRecipient(context.Background(), providerLoginStartInput{}, oauth.ProviderIdentity{}, "policy")
		if !errors.Is(err, sso.ErrForbidden) || got != (providerLoginCallbackRecipient{}) {
			t.Fatal("missing original native authority yielded recipient evidence", err)
		}
	}
}
