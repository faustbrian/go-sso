package postgres

import (
	"encoding/json"
	"strconv"
	"testing"
	"time"

	organization "github.com/faustbrian/go-organization"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
)

func TestProviderLoginCallbackMaterialCannotRenewOrSubstituteOriginalStart(t *testing.T) {
	_, input, now, _ := providerLoginPayloadFixture(t)
	original := providerLoginStartInput{
		Command: providerLoginStoredCommand(input.Command), Intent: input.InputFingerprint,
		ProviderID: sso.ProviderID(input.ProviderID), ProviderVersion: input.ProviderVersion, Generation: input.CredentialGeneration,
		MappingVersion: input.MappingVersion, Issuer: input.Issuer, AuthorizationEndpoint: input.Issuer + "/authorize", ClientID: input.ClientID,
		ProtocolRedirectURI: input.RedirectURI, BrowserOrigin: input.BrowserOrigin, SuccessCallback: input.SuccessCallback, ErrorCallback: input.ErrorCallback,
		Remember: input.Remember, Issued: input.IssuedAt, Expires: input.ExpiresAt,
		Proof: organization.DomainProofKey{TenantID: input.Command.TenantID, OrganizationID: organization.ID(input.OrganizationID), Domain: "enterprise.example", ExpiresAt: input.ExpiresAt},
	}
	found := providerLoginCallbackLookup{Row: input.rowIdentity(), ObservedAt: *now, Binding: providerLoginStoredBinding{Metadata: providerLoginBindingMetadata{Input: input}}}
	authority := providerLoginCallbackAuthority{deadline: now.Add(20 * time.Second), organization: organization.CredentialAuthorityObservation{
		TenantID: input.Command.TenantID, OrganizationID: organization.ID(input.OrganizationID), Version: 1, CredentialVersion: 1,
		ReadStartedAt: *now, VerifiedAt: *now, ValidUntil: now.Add(20 * time.Second),
	}}
	if !validProviderLoginCallbackMaterialInput(found, original, authority, *now) {
		t.Fatal("exact original start and current authority were denied")
	}
	for name, change := range map[string]func(*providerLoginCallbackLookup, *providerLoginStartInput, *providerLoginCallbackAuthority, *time.Time){
		"terminal": func(f *providerLoginCallbackLookup, _ *providerLoginStartInput, _ *providerLoginCallbackAuthority, _ *time.Time) {
			f.CompletedAt = now
		},
		"row substituted": func(f *providerLoginCallbackLookup, _ *providerLoginStartInput, _ *providerLoginCallbackAuthority, _ *time.Time) {
			f.Row.CredentialGeneration++
		},
		"start substituted": func(_ *providerLoginCallbackLookup, i *providerLoginStartInput, _ *providerLoginCallbackAuthority, _ *time.Time) {
			i.Intent[0] ^= 1
		},
		"issuer substituted": func(_ *providerLoginCallbackLookup, i *providerLoginStartInput, _ *providerLoginCallbackAuthority, _ *time.Time) {
			i.Issuer += "/other"
		},
		"foreign proof": func(_ *providerLoginCallbackLookup, i *providerLoginStartInput, _ *providerLoginCallbackAuthority, _ *time.Time) {
			i.Proof.TenantID = "other"
		},
		"foreign owner": func(_ *providerLoginCallbackLookup, _ *providerLoginStartInput, a *providerLoginCallbackAuthority, _ *time.Time) {
			a.organization.OrganizationID = "other"
		},
		"renewed deadline": func(_ *providerLoginCallbackLookup, _ *providerLoginStartInput, a *providerLoginCallbackAuthority, _ *time.Time) {
			a.deadline = now.Add(21 * time.Second)
		},
		"expired deadline": func(_ *providerLoginCallbackLookup, _ *providerLoginStartInput, a *providerLoginCallbackAuthority, clock *time.Time) {
			*clock = a.deadline
		},
		"proof expires first": func(_ *providerLoginCallbackLookup, i *providerLoginStartInput, _ *providerLoginCallbackAuthority, _ *time.Time) {
			i.Proof.ExpiresAt = now.Add(time.Second)
		},
		"observation from future": func(f *providerLoginCallbackLookup, _ *providerLoginStartInput, _ *providerLoginCallbackAuthority, clock *time.Time) {
			f.ObservedAt = clock.Add(time.Second)
		},
	} {
		t.Run(name, func(t *testing.T) {
			f, i, a, clock := found, original, authority, *now
			change(&f, &i, &a, &clock)
			if validProviderLoginCallbackMaterialInput(f, i, a, clock) {
				t.Fatal("substituted start or renewed authority admitted callback exchange material")
			}
		})
	}
}

func TestProviderLoginCallbackMaterialAuthenticatesOriginalConfigurationAtStoredVersion(t *testing.T) {
	payload, input, _, _ := providerLoginPayloadFixture(t)
	original := providerLoginStartInput{
		ProviderID: sso.ProviderID(input.ProviderID), ProviderVersion: input.ProviderVersion,
		MappingVersion: input.MappingVersion, Issuer: input.Issuer, AuthorizationEndpoint: input.Issuer + "/authorize",
		Proof: organization.DomainProofKey{TenantID: input.Command.TenantID, OrganizationID: organization.ID(input.OrganizationID), Domain: "enterprise.example"},
	}
	configuration := providerConfiguration{
		Metadata: sso.OIDCStaticMetadataSpec{Issuer: input.Issuer, AuthorizationEndpoint: original.AuthorizationEndpoint, TokenEndpoint: input.Issuer + "/token", JWKSURI: input.Issuer + "/keys"},
		Mapping:  sso.AttributeMappingSpec{Version: input.MappingVersion, SubjectClaim: "sub"}, Domains: []string{original.Proof.Domain},
	}
	seal := func(stored providerConfiguration, version uint64, noncanonical bool) []byte {
		t.Helper()
		plain, err := json.Marshal(stored)
		if err != nil {
			t.Fatal(err)
		}
		if noncanonical {
			plain = append(plain, '\n')
		}
		defer clear(plain)
		aad, err := envelope.NewContext(map[string]string{"owner": "sso/provider", "tenant": string(original.Proof.TenantID), "organization": string(original.Proof.OrganizationID), "provider": string(original.ProviderID), "protocol": "oidc", "purpose": "static-configuration", "version": strconv.FormatUint(version, 10)})
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
	for _, storedVersion := range []uint64{original.ProviderVersion, original.ProviderVersion + 1} {
		wire := seal(configuration, storedVersion, false)
		got, err := openProviderLoginCallbackConfiguration(t.Context(), payload.Envelope, original, strconv.FormatUint(storedVersion, 10), wire)
		clear(wire)
		if err != nil || got != configuration.Metadata {
			t.Fatal("exact current or immediate-drain metadata was not authenticated at its stored envelope version", err)
		}
	}
	for name, change := range map[string]func(*providerConfiguration){
		"issuer substitution":        func(c *providerConfiguration) { c.Metadata.Issuer = "https://other.example" },
		"authorization substitution": func(c *providerConfiguration) { c.Metadata.AuthorizationEndpoint += "/other" },
		"mapping substitution":       func(c *providerConfiguration) { c.Mapping.Version++ },
		"invalid mapping":            func(c *providerConfiguration) { c.Mapping.SubjectClaim = "" },
		"domain substitution":        func(c *providerConfiguration) { c.Domains = []string{"other.example"} },
		"invalid metadata":           func(c *providerConfiguration) { c.Metadata.TokenEndpoint = "http://enterprise.example/token" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := configuration
			change(&changed)
			wire := seal(changed, original.ProviderVersion, false)
			defer clear(wire)
			if _, err := openProviderLoginCallbackConfiguration(t.Context(), payload.Envelope, original, strconv.FormatUint(original.ProviderVersion, 10), wire); err == nil {
				t.Fatal("authenticated but substituted callback configuration was admitted")
			}
		})
	}
	for name, attempt := range map[string]struct {
		version string
		wire    []byte
	}{
		"successor AAD required":     {strconv.FormatUint(original.ProviderVersion, 10), seal(configuration, original.ProviderVersion+1, false)},
		"canonical storage required": {strconv.FormatUint(original.ProviderVersion, 10), seal(configuration, original.ProviderVersion, true)},
		"ciphertext required":        {strconv.FormatUint(original.ProviderVersion, 10), []byte("invalid")},
	} {
		t.Run(name, func(t *testing.T) {
			defer clear(attempt.wire)
			if _, err := openProviderLoginCallbackConfiguration(t.Context(), payload.Envelope, original, attempt.version, attempt.wire); err == nil {
				t.Fatal("unauthenticated or noncanonical callback configuration was admitted")
			}
		})
	}
}
