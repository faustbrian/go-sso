package sso_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-sso"
)

func oauthRegistration(t testing.TB) sso.ProviderRegisterOauthRequest {
	t.Helper()
	parse := func(raw string) url.URL {
		t.Helper()
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return *u
	}
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	key, err := identity.NewIdempotencyKey([]byte("enterprise-oauth-registration"))
	if err != nil {
		t.Fatal(err)
	}
	mapping, err := sso.NewAttributeMapping(sso.AttributeMappingSpec{
		Version: 2, SubjectClaim: "stable_id", EmailClaim: "email", VerifiedEmailClaim: "verified",
	})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := sso.NewIdentityProofPolicy(sso.IdentityProofPolicySpec{
		Version: 4, Issuer: "https://login.example/Case.Exact", SubjectKind: sso.OAuthSubjectString,
		EmailVerification: sso.OAuthEmailBooleanClaim,
	})
	if err != nil {
		t.Fatal(err)
	}
	return sso.ProviderRegisterOauthRequest{
		CommandID: command, OrganizationID: "Enterprise-01", AuthorizationEndpoint: parse("https://login.example/authorize"),
		TokenEndpoint: parse("https://login.example/exchange"), IdentityEndpoint: parse("https://directory.example/self"),
		RevocationEndpoint: parse("https://login.example/revoke"), IdentityProofPolicy: policy, Mapping: mapping,
		Domains: []string{"example.com"}, IdempotencyKey: key,
	}
}

func TestEnterpriseOAuthRegistrationIntentBindsExplicitIdentityProof(t *testing.T) {
	r := oauthRegistration(t)
	if err := r.Validate(); err != nil {
		t.Fatal("explicit HTTPS identity proof profile was rejected", err)
	}
	got, err := r.IdentityProofPolicy.Spec()
	if err != nil || got.Issuer != "https://login.example/Case.Exact" || got.Version != 4 ||
		got.SubjectKind != sso.OAuthSubjectString || got.EmailVerification != sso.OAuthEmailBooleanClaim {
		t.Fatal("configuration lost exact issuer, policy version or claim authority")
	}
	r.RevocationEndpoint = url.URL{}
	if err := r.Validate(); err != nil {
		t.Fatal("optional revocation endpoint was made a registration prerequisite", err)
	}
}

func TestEnterpriseOAuthRegistrationDeniesUnsafeOrAmbiguousIntent(t *testing.T) {
	cases := map[string]func(*sso.ProviderRegisterOauthRequest){
		"no identity endpoint":       func(r *sso.ProviderRegisterOauthRequest) { r.IdentityEndpoint = url.URL{} },
		"token endpoint as identity": func(r *sso.ProviderRegisterOauthRequest) { r.IdentityEndpoint = r.TokenEndpoint },
		"authorization endpoint as identity": func(r *sso.ProviderRegisterOauthRequest) {
			r.IdentityEndpoint = r.AuthorizationEndpoint
		},
		"identity plaintext": func(r *sso.ProviderRegisterOauthRequest) { r.IdentityEndpoint.Scheme = "http" },
		"identity URL userinfo": func(r *sso.ProviderRegisterOauthRequest) {
			r.IdentityEndpoint.User = url.User("fixture-config-user")
		},
		"token query data":      func(r *sso.ProviderRegisterOauthRequest) { r.TokenEndpoint.RawQuery = "profile=one" },
		"identity fragment":     func(r *sso.ProviderRegisterOauthRequest) { r.IdentityEndpoint.Fragment = "fragment" },
		"inconsistent raw path": func(r *sso.ProviderRegisterOauthRequest) { r.IdentityEndpoint.RawPath = "/different" },
		"oversized endpoint": func(r *sso.ProviderRegisterOauthRequest) {
			r.TokenEndpoint.Path = "/" + strings.Repeat("t", 2048)
		},
		"explicit empty query": func(r *sso.ProviderRegisterOauthRequest) { r.AuthorizationEndpoint.ForceQuery = true },
		"noncanonical domain":  func(r *sso.ProviderRegisterOauthRequest) { r.Domains = []string{"Example.COM"} },
		"duplicate domain":     func(r *sso.ProviderRegisterOauthRequest) { r.Domains = []string{"example.com", "example.com"} },
		"missing owner":        func(r *sso.ProviderRegisterOauthRequest) { r.OrganizationID = "" },
		"missing command":      func(r *sso.ProviderRegisterOauthRequest) { r.CommandID = "" },
		"missing idempotency":  func(r *sso.ProviderRegisterOauthRequest) { r.IdempotencyKey = identity.IdempotencyKey{} },
		"missing proof policy": func(r *sso.ProviderRegisterOauthRequest) { r.IdentityProofPolicy = sso.IdentityProofPolicy{} },
		"no verified mail claim": func(r *sso.ProviderRegisterOauthRequest) {
			r.Mapping, _ = sso.NewAttributeMapping(sso.AttributeMappingSpec{Version: 2, SubjectClaim: "uid", EmailClaim: "mail"})
		},
		"verification aliases mail": func(r *sso.ProviderRegisterOauthRequest) {
			r.Mapping, _ = sso.NewAttributeMapping(sso.AttributeMappingSpec{
				Version: 2, SubjectClaim: "uid", EmailClaim: "mail", VerifiedEmailClaim: "mail",
			})
		},
		"no verification borrows a claim": func(r *sso.ProviderRegisterOauthRequest) {
			spec, _ := r.IdentityProofPolicy.Spec()
			spec.EmailVerification = sso.OAuthEmailUnverified
			r.IdentityProofPolicy, _ = sso.NewIdentityProofPolicy(spec)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := oauthRegistration(t)
			mutate(&r)
			if err := r.Validate(); err != sso.ErrInvalidInput {
				t.Fatal("expected redacted invalid registration intent", err)
			}
		})
	}
}

func TestEnterpriseOAuthProofPolicyDoesNotInferTrust(t *testing.T) {
	r := oauthRegistration(t)
	original, _ := r.IdentityProofPolicy.Spec()
	invalidSpecs := []sso.IdentityProofPolicySpec{
		{Version: 1, Issuer: "https://issuer.example?profile=other", SubjectKind: original.SubjectKind, EmailVerification: original.EmailVerification},
		{Version: 1, Issuer: original.Issuer, SubjectKind: 0, EmailVerification: original.EmailVerification},
		{Version: 1, Issuer: original.Issuer, SubjectKind: original.SubjectKind, EmailVerification: 0},
		{Version: 0, Issuer: original.Issuer, SubjectKind: original.SubjectKind, EmailVerification: original.EmailVerification},
	}
	for _, invalid := range invalidSpecs {
		policy, err := sso.NewIdentityProofPolicy(invalid)
		if err != sso.ErrInvalidInput || policy != (sso.IdentityProofPolicy{}) {
			t.Fatal("constructor invented trust for invalid policy")
		}
	}
	original.SubjectKind = sso.OAuthSubjectPositiveInteger
	original.EmailVerification = sso.OAuthEmailUnverified
	unverified, err := sso.NewIdentityProofPolicy(original)
	if err != nil {
		t.Fatal("explicit nonverified profile rejected", err)
	}
	r.IdentityProofPolicy = unverified
	r.Mapping, _ = sso.NewAttributeMapping(sso.AttributeMappingSpec{Version: 2, SubjectClaim: "uid", EmailClaim: "email"})
	if err := r.Validate(); err != nil {
		t.Fatal("unverified-only mapping was rejected", err)
	}
	old, _ := oauthRegistration(t).IdentityProofPolicy.Spec()
	if old.SubjectKind != sso.OAuthSubjectString || old.EmailVerification != sso.OAuthEmailBooleanClaim {
		t.Fatal("projection unexpectedly changed another trust policy")
	}
}

func TestEnterpriseOAuthRegistrationRedactsProviderConfiguration(t *testing.T) {
	r := oauthRegistration(t)
	for _, value := range []any{r, r.IdentityProofPolicy} {
		for _, format := range []string{"%+v", "%#v", "%q"} {
			if got := fmt.Sprintf(format, value); !strings.Contains(got, "redacted") || strings.Contains(got, "example") {
				t.Fatal("implicit formatting disclosed provider configuration")
			}
		}
		if _, err := json.Marshal(value); !errors.Is(err, sso.ErrSensitiveSerialization) {
			t.Fatal("implicit serialization was not rejected", err)
		}
		loggable, ok := value.(slog.LogValuer)
		if !ok || !strings.Contains(loggable.LogValue().String(), "redacted") {
			t.Fatal("missing structured-log redaction")
		}
	}
}

func FuzzEnterpriseOAuthIdentityEndpointIntent(f *testing.F) {
	for _, value := range []string{"https://api.example/self", "https://api.example/space%20bound", "http://api.example/self",
		"https://username@api.example", "https://api.example/self?claim=a", "https://api.example/self#other"} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > 4096 {
			return
		}
		parsed, err := url.Parse(value)
		if err != nil {
			return
		}
		r := oauthRegistration(t)
		r.IdentityEndpoint = *parsed
		if err := r.Validate(); err == nil {
			switch {
			case parsed.Scheme != "https", parsed.Hostname() == "", parsed.User != nil, parsed.Opaque != "",
				parsed.RawQuery != "", parsed.Fragment != "", parsed.ForceQuery, len(parsed.String()) > 2048,
				*parsed == r.TokenEndpoint, *parsed == r.AuthorizationEndpoint:
				t.Fatal("validation admitted an ambiguous or unsafe identity endpoint")
			}
		}
	})
}
