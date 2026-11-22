package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"testing"
	"time"

	organization "github.com/faustbrian/go-organization"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
)

func providerOAuth2CallbackMaterialFixture(t *testing.T) (providerLoginPayloadConfig, providerLoginCallbackLookup, providerLoginStartInput, providerLoginCallbackAuthority) {
	t.Helper()
	payload, found, _, _ := providerOAuth2CallbackCustodyFixture(t, providerProtocolOAuth2)
	input := found.Binding.Metadata.Input
	original := providerLoginStartInput{
		Command: providerLoginStoredCommand(input.Command), Intent: input.InputFingerprint,
		ProviderID: sso.ProviderID(input.ProviderID), ProviderVersion: input.ProviderVersion, Generation: input.CredentialGeneration,
		MappingVersion: input.MappingVersion, Issuer: input.Issuer, AuthorizationEndpoint: input.Issuer + "/authorize", ClientID: input.ClientID,
		ProtocolRedirectURI: input.RedirectURI, BrowserOrigin: input.BrowserOrigin, SuccessCallback: input.SuccessCallback, ErrorCallback: input.ErrorCallback,
		Remember: input.Remember, Issued: input.IssuedAt, Expires: input.ExpiresAt, Protocol: providerProtocolOAuth2,
		Proof: organization.DomainProofKey{TenantID: input.Command.TenantID, OrganizationID: organization.ID(input.OrganizationID), Domain: "enterprise.example", ExpiresAt: input.ExpiresAt},
	}
	now := found.ObservedAt
	authority := providerLoginCallbackAuthority{deadline: now.Add(20 * time.Second), organization: organization.CredentialAuthorityObservation{
		TenantID: input.Command.TenantID, OrganizationID: organization.ID(input.OrganizationID), Version: 1, CredentialVersion: 1,
		ReadStartedAt: now, VerifiedAt: now, ValidUntil: now.Add(20 * time.Second),
	}}
	return payload, found, original, authority
}

func TestProviderOAuth2CallbackMaterialRequiresExactPendingOAuthScope(t *testing.T) {
	_, found, original, authority := providerOAuth2CallbackMaterialFixture(t)
	if !validProviderOAuth2CallbackMaterialInput(found, original, authority, found.ObservedAt) {
		t.Fatal("original pending OAuth callback material scope was denied")
	}
	for name, change := range map[string]func(*providerLoginCallbackLookup, *providerLoginStartInput, *providerLoginCallbackAuthority, *time.Time){
		"OIDC row": func(f *providerLoginCallbackLookup, _ *providerLoginStartInput, _ *providerLoginCallbackAuthority, _ *time.Time) {
			f.Row.Protocol = ""
		},
		"OIDC origin": func(_ *providerLoginCallbackLookup, i *providerLoginStartInput, _ *providerLoginCallbackAuthority, _ *time.Time) {
			i.Protocol = ""
		},
		"unknown protocol": func(f *providerLoginCallbackLookup, i *providerLoginStartInput, _ *providerLoginCallbackAuthority, _ *time.Time) {
			f.Row.Protocol, f.Binding.Metadata.Input.Protocol, i.Protocol = "unknown", "unknown", "unknown"
		},
		"explicit link": func(f *providerLoginCallbackLookup, i *providerLoginStartInput, _ *providerLoginCallbackAuthority, _ *time.Time) {
			i.Link = &providerLoginMemberIntent{}
			f.Binding.Metadata.Input.Link = i.Link
		},
		"completed": func(f *providerLoginCallbackLookup, _ *providerLoginStartInput, _ *providerLoginCallbackAuthority, now *time.Time) {
			f.CompletedAt = now
		},
		"generation": func(f *providerLoginCallbackLookup, _ *providerLoginStartInput, _ *providerLoginCallbackAuthority, _ *time.Time) {
			f.Row.CredentialGeneration++
		},
		"original issuer": func(_ *providerLoginCallbackLookup, i *providerLoginStartInput, _ *providerLoginCallbackAuthority, _ *time.Time) {
			i.Issuer += "/other"
		},
		"foreign organization": func(_ *providerLoginCallbackLookup, _ *providerLoginStartInput, a *providerLoginCallbackAuthority, _ *time.Time) {
			a.organization.OrganizationID = "other"
		},
		"renewed deadline": func(_ *providerLoginCallbackLookup, _ *providerLoginStartInput, a *providerLoginCallbackAuthority, _ *time.Time) {
			a.deadline = a.deadline.Add(time.Second)
		},
		"expired": func(_ *providerLoginCallbackLookup, _ *providerLoginStartInput, a *providerLoginCallbackAuthority, now *time.Time) {
			*now = a.deadline
		},
	} {
		t.Run(name, func(t *testing.T) {
			f, i, a, now := found, original, authority, found.ObservedAt
			change(&f, &i, &a, &now)
			if validProviderOAuth2CallbackMaterialInput(f, i, a, now) {
				t.Fatal("substituted or expired callback scope admitted OAuth material")
			}
		})
	}
}

func TestProviderOAuth2CallbackMaterialAuthenticatesCurrentOriginalConfiguration(t *testing.T) {
	payload, _, original, _ := providerOAuth2CallbackMaterialFixture(t)
	configuration := providerOAuthConfiguration{
		AuthorizationEndpoint: original.AuthorizationEndpoint, TokenEndpoint: original.Issuer + "/token", IdentityEndpoint: original.Issuer + "/identity",
		Proof:   sso.IdentityProofPolicySpec{Version: 1, Issuer: original.Issuer, SubjectKind: sso.OAuthSubjectString, EmailVerification: sso.OAuthEmailUnverified},
		Mapping: sso.AttributeMappingSpec{Version: original.MappingVersion, SubjectClaim: "stable_id"}, Domains: []string{original.Proof.Domain},
	}
	version := strconv.FormatUint(original.ProviderVersion, 10)
	seal := func(stored providerOAuthConfiguration, changeAAD func(map[string]string), noncanonical bool) []byte {
		t.Helper()
		plain, err := json.Marshal(stored)
		if err != nil {
			t.Fatal(err)
		}
		if noncanonical {
			plain = append(plain, '\n')
		}
		defer clear(plain)
		values := map[string]string{"owner": "sso/provider", "tenant": string(original.Proof.TenantID), "organization": string(original.Proof.OrganizationID), "provider": string(original.ProviderID), "protocol": providerProtocolOAuth2, "purpose": "static-configuration", "version": version}
		if changeAAD != nil {
			changeAAD(values)
		}
		aad, err := envelope.NewContext(values)
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := payload.Envelope.Encrypt(t.Context(), envelope.EncryptRequest{Plaintext: plain, KeyReference: payload.KeyReference, Context: aad})
		if err != nil {
			t.Fatal(err)
		}
		wire, err := sealed.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	wire := seal(configuration, nil, false)
	defer clear(wire)
	got, err := openProviderOAuth2CallbackConfiguration(t.Context(), payload.Envelope, original, version, wire)
	if err != nil || !reflect.DeepEqual(got, configuration) {
		t.Fatal("authenticated OAuth configuration was not retained exactly", err)
	}
	for name, change := range map[string]func(*providerOAuthConfiguration){
		"issuer":            func(c *providerOAuthConfiguration) { c.Proof.Issuer += "/other" },
		"authorization":     func(c *providerOAuthConfiguration) { c.AuthorizationEndpoint += "/other" },
		"mapping version":   func(c *providerOAuthConfiguration) { c.Mapping.Version++ },
		"mapping contract":  func(c *providerOAuthConfiguration) { c.Mapping.SubjectClaim = "" },
		"domain":            func(c *providerOAuthConfiguration) { c.Domains = []string{"other.example"} },
		"extra domain":      func(c *providerOAuthConfiguration) { c.Domains = []string{original.Proof.Domain, "other.example"} },
		"identity endpoint": func(c *providerOAuthConfiguration) { c.IdentityEndpoint = c.TokenEndpoint },
		"identity policy":   func(c *providerOAuthConfiguration) { c.Proof.SubjectKind = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := configuration
			change(&changed)
			wire := seal(changed, nil, false)
			defer clear(wire)
			if _, err := openProviderOAuth2CallbackConfiguration(t.Context(), payload.Envelope, original, version, wire); err == nil {
				t.Fatal("authenticated but substituted OAuth configuration was admitted")
			}
		})
	}
	for _, field := range []string{"tenant", "organization", "provider", "protocol", "version"} {
		t.Run("AAD "+field, func(t *testing.T) {
			wire := seal(configuration, func(values map[string]string) { values[field] = "other" }, false)
			defer clear(wire)
			if _, err := openProviderOAuth2CallbackConfiguration(t.Context(), payload.Envelope, original, version, wire); err == nil {
				t.Fatal("configuration authenticated across a foreign envelope scope")
			}
		})
	}
	noncanonical := seal(configuration, nil, true)
	defer clear(noncanonical)
	for name, attempt := range map[string]struct {
		version string
		wire    []byte
	}{
		"successor drain":      {strconv.FormatUint(original.ProviderVersion+1, 10), wire},
		"noncanonical version": {"0" + version, wire},
		"noncanonical JSON":    {version, noncanonical},
		"malformed ciphertext": {version, []byte("invalid")},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := openProviderOAuth2CallbackConfiguration(t.Context(), payload.Envelope, original, attempt.version, attempt.wire); err == nil {
				t.Fatal("non-current or unauthenticated configuration was admitted")
			}
		})
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := openProviderOAuth2CallbackConfiguration(cancelled, payload.Envelope, original, version, wire); !errors.Is(err, context.Canceled) {
		t.Fatal("configuration lost cancellation", err)
	}
}

func TestProviderOAuth2CallbackMaterialValidatesInstalledCredentialWithoutDecrypting(t *testing.T) {
	payload, found, original, _ := providerOAuth2CallbackMaterialFixture(t)
	installed := original.ProviderVersion
	binding := sso.CredentialReferenceContext{TenantID: string(original.Proof.TenantID), OrganizationID: string(original.Proof.OrganizationID), ProviderID: string(original.ProviderID),
		Protocol: providerProtocolOAuth2, Purpose: "client-secret", Audience: "identity.sso.provider.credentials-rotate", Generation: original.Generation,
		ProviderVersion: installed - 1, EnvelopeKeyID: payload.KeyReference, IssuedAt: found.ObservedAt.Add(-time.Hour), ExpiresAt: found.ObservedAt.Add(-time.Minute)}
	aad, err := binding.EncryptionContext()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := payload.Envelope.Encrypt(t.Context(), envelope.EncryptRequest{Plaintext: []byte("synthetic-client-credential"), KeyReference: payload.KeyReference, Context: aad})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := sealed.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(wire)
	contextWire, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(contextWire)
	if err := validateProviderOAuth2CallbackCredential(original, installed, wire, contextWire); err != nil {
		t.Fatal("exact installed OAuth ciphertext was rejected", err)
	}
	for name, change := range map[string]func(*sso.CredentialReferenceContext){
		"OIDC":             func(c *sso.CredentialReferenceContext) { c.Protocol = providerProtocolOIDC },
		"unknown protocol": func(c *sso.CredentialReferenceContext) { c.Protocol = "unknown" },
		"tenant":           func(c *sso.CredentialReferenceContext) { c.TenantID = "other" },
		"organization":     func(c *sso.CredentialReferenceContext) { c.OrganizationID = "other" },
		"provider":         func(c *sso.CredentialReferenceContext) { c.ProviderID = "other" },
		"generation":       func(c *sso.CredentialReferenceContext) { c.Generation++ },
		"version":          func(c *sso.CredentialReferenceContext) { c.ProviderVersion++ },
		"purpose":          func(c *sso.CredentialReferenceContext) { c.Purpose = "other" },
		"key":              func(c *sso.CredentialReferenceContext) { c.EnvelopeKeyID = "other" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := binding
			change(&changed)
			encoded, err := json.Marshal(changed)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(encoded)
			if err := validateProviderOAuth2CallbackCredential(original, installed, wire, encoded); err == nil {
				t.Fatal("foreign installed credential context was admitted")
			}
		})
	}
	if err := validateProviderOAuth2CallbackCredential(original, installed+1, wire, contextWire); err == nil {
		t.Fatal("future installation was admitted")
	}
	if err := validateProviderOAuth2CallbackCredential(original, 1, wire, contextWire); err == nil {
		t.Fatal("uninstalled credential was admitted")
	}
	if err := validateProviderOAuth2CallbackCredential(original, installed, wire, append(append([]byte{}, contextWire...), '\n')); err == nil {
		t.Fatal("noncanonical credential context was admitted")
	}
	if err := validateProviderOAuth2CallbackCredential(original, installed, []byte("invalid"), contextWire); err == nil {
		t.Fatal("malformed credential envelope was admitted")
	}
}
