package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	organization "github.com/faustbrian/go-organization"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
)

func samlLoginProfileConfiguration() StaticSAMLLoginProfile {
	return StaticSAMLLoginProfile{
		ProviderID: "_exact-Provider", OrganizationID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Domain: "example.com",
		TrustedOrigin: "https://identity.example:8443", ProviderVersion: 3, CredentialGeneration: 1, MappingVersion: 2,
	}
}

func samlLoginProfileStoredConfiguration() providerSAMLConfiguration {
	return providerSAMLConfiguration{
		IdP: sso.SAMLConfigurationSpec{EntityID: "HTTPS://idp.example/Enterprise%2fExact?realm=one",
			RedirectEndpoint:    "https://idp.example/saml/redirect?realm=exact%2Fvalue&realm=another",
			SigningCertificates: [][]byte{[]byte("bounded-pinned-certificate")}},
		Origin: "https://identity.example:8443", Mapping: sso.AttributeMappingSpec{Version: 2, SubjectClaim: "name_id"},
		Domains: []string{"example.com"},
	}
}

func TestNativeSAMLLoginProfileRequiresExactDeploymentAndCanonicalProviderPath(t *testing.T) {
	configured := samlLoginProfileConfiguration()
	if got, err := normalizeStaticSAMLLoginProfile(configured); err != nil || got != configured {
		t.Fatal("selected exact SAML deployment changed", err)
	}
	for name, change := range map[string]func(*StaticSAMLLoginProfile){
		"provider":           func(p *StaticSAMLLoginProfile) { p.ProviderID = "" },
		"provider path":      func(p *StaticSAMLLoginProfile) { p.ProviderID = "other/provider" },
		"provider escaping":  func(p *StaticSAMLLoginProfile) { p.ProviderID = "other%2Fprovider" },
		"provider traversal": func(p *StaticSAMLLoginProfile) { p.ProviderID = ".." },
		"organization":       func(p *StaticSAMLLoginProfile) { p.OrganizationID = "" },
		"domain":             func(p *StaticSAMLLoginProfile) { p.Domain = "EXAMPLE.com" },
		"version":            func(p *StaticSAMLLoginProfile) { p.ProviderVersion = 0 },
		"generation":         func(p *StaticSAMLLoginProfile) { p.CredentialGeneration = 0 },
		"mapping":            func(p *StaticSAMLLoginProfile) { p.MappingVersion = 0 },
		"insecure origin":    func(p *StaticSAMLLoginProfile) { p.TrustedOrigin = "http://identity.example" },
		"origin case":        func(p *StaticSAMLLoginProfile) { p.TrustedOrigin = "https://IDENTITY.example" },
		"origin path":        func(p *StaticSAMLLoginProfile) { p.TrustedOrigin += "/portal" },
		"origin query":       func(p *StaticSAMLLoginProfile) { p.TrustedOrigin += "?tenant=other" },
		"origin fragment":    func(p *StaticSAMLLoginProfile) { p.TrustedOrigin += "#fragment" },
		"origin userinfo":    func(p *StaticSAMLLoginProfile) { p.TrustedOrigin = "https://user@identity.example" },
		"origin bound":       func(p *StaticSAMLLoginProfile) { p.TrustedOrigin = "https://" + strings.Repeat("x", 513) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := configured
			change(&changed)
			if got, err := normalizeStaticSAMLLoginProfile(changed); !errors.Is(err, sso.ErrInvalidInput) || got != (StaticSAMLLoginProfile{}) {
				t.Fatal("invalid SAML deployment selected a profile", err)
			}
		})
	}
}

func TestNativeSAMLLoginProfilePreservesExactInstalledIdentityAndDetachedConfiguration(t *testing.T) {
	configured, stored := samlLoginProfileConfiguration(), samlLoginProfileStoredConfiguration()
	plain, err := json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	issuer := sha256.Sum256([]byte(stored.IdP.EntityID))
	profile, err := decodeProviderSAMLLoginProfile(plain, issuer[:], configured)
	if err != nil || profile.configured != configured || !reflect.DeepEqual(profile.configuration, stored.IdP) ||
		!reflect.DeepEqual(profile.mapping, stored.Mapping) || profile.acsURL != configured.TrustedOrigin+"/saml2/_exact-Provider/acs" ||
		profile.spEntityID != configured.TrustedOrigin+"/saml2/_exact-Provider/metadata" {
		t.Fatal("installed exact IdP, mapping or SP identity changed", err)
	}
	clear(plain)
	stored.IdP.SigningCertificates[0][0] ^= 0xff
	stored.Domains[0] = "other.example"
	if !bytes.Equal(profile.configuration.SigningCertificates[0], []byte("bounded-pinned-certificate")) || profile.configured.Domain != "example.com" {
		t.Fatal("installed projection aliases decrypted or caller storage")
	}
}

func TestNativeSAMLLoginProfileRejectsInvalidOrMismatchedAuthenticatedConfiguration(t *testing.T) {
	configured := samlLoginProfileConfiguration()
	for name, change := range map[string]func(*providerSAMLConfiguration){
		"origin":             func(p *providerSAMLConfiguration) { p.Origin = "https://other.example" },
		"domain":             func(p *providerSAMLConfiguration) { p.Domains[0] = "other.example" },
		"domain count":       func(p *providerSAMLConfiguration) { p.Domains = append(p.Domains, "another.example") },
		"mapping version":    func(p *providerSAMLConfiguration) { p.Mapping.Version++ },
		"invalid mapping":    func(p *providerSAMLConfiguration) { p.Mapping.SubjectClaim = "" },
		"entity":             func(p *providerSAMLConfiguration) { p.IdP.EntityID = "http://idp.example" },
		"insecure redirect":  func(p *providerSAMLConfiguration) { p.IdP.RedirectEndpoint = "http://idp.example/sso" },
		"redirect injection": func(p *providerSAMLConfiguration) { p.IdP.RedirectEndpoint += "&%53AMLRequest=foreign" },
		"missing pins":       func(p *providerSAMLConfiguration) { p.IdP.SigningCertificates = nil },
		"duplicate pins": func(p *providerSAMLConfiguration) {
			p.IdP.SigningCertificates = append(p.IdP.SigningCertificates, bytes.Clone(p.IdP.SigningCertificates[0]))
		},
	} {
		t.Run(name, func(t *testing.T) {
			stored := samlLoginProfileStoredConfiguration()
			change(&stored)
			plain, err := json.Marshal(stored)
			if err != nil {
				t.Fatal(err)
			}
			issuer := sha256.Sum256([]byte(stored.IdP.EntityID))
			if got, err := decodeProviderSAMLLoginProfile(plain, issuer[:], configured); err == nil || got.spEntityID != "" || got.configuration.EntityID != "" {
				t.Fatal("invalid authenticated configuration produced a usable profile", err)
			}
		})
	}
	stored := samlLoginProfileStoredConfiguration()
	plain, err := json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	issuer := sha256.Sum256([]byte(stored.IdP.EntityID))
	wrongIssuer := sha256.Sum256([]byte(strings.ToLower(stored.IdP.EntityID)))
	for _, digest := range [][]byte{nil, issuer[:31], wrongIssuer[:]} {
		if got, err := decodeProviderSAMLLoginProfile(plain, digest, configured); !errors.Is(err, sso.ErrUnavailable) || got.configuration.EntityID != "" {
			t.Fatal("different exact issuer digest selected installed SAML identity", err)
		}
	}
	for _, wire := range [][]byte{nil, []byte("{"), append([]byte(" "), plain...), append(append(bytes.Clone(plain[:len(plain)-1]), []byte(",\"unknown\":true")...), '}'), bytes.Repeat([]byte("x"), providerConfigurationMaximumBytes+1)} {
		if got, err := decodeProviderSAMLLoginProfile(wire, issuer[:], configured); !errors.Is(err, sso.ErrUnavailable) || got.configuration.EntityID != "" {
			t.Fatal("noncanonical or unbounded installed SAML configuration accepted", err)
		}
	}
}

type samlLoginProfileClock struct{ at time.Time }

func (c samlLoginProfileClock) Now() time.Time { return c.at }

func TestNativeSAMLLoginProfileRejectsForeignOrStaleRouteBeforeRegistryRead(t *testing.T) {
	configured := samlLoginProfileConfiguration()
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	proof := organization.DomainProofKey{TenantID: "tenant-saml-profile", OrganizationID: configured.OrganizationID,
		ClaimID: "claim-profile", Domain: configured.Domain, ClaimVersion: 1, ProofVersion: 1,
		Method: organization.DomainDNS, ObservedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}
	binding := sso.DomainRouteBinding{ProviderID: configured.ProviderID, ProviderVersion: configured.ProviderVersion,
		CredentialGeneration: configured.CredentialGeneration, PolicyVersion: 1,
		Proof: sso.DomainProofCheckpoint{Key: proof, ProofVersion: 1}, ObservedAt: now, ValidUntil: now.Add(20 * time.Second)}
	// An inert pool makes these cases fail if denial is postponed until SQL.
	router := &ProviderRouter{pool: &database.Pool{}, protocolRegistry: true,
		config:            ProviderRouterConfig{Clock: samlLoginProfileClock{now}, Envelope: &envelope.Service{}},
		samlRouteValidate: func(context.Context, []byte, time.Time) (time.Time, error) { return now.Add(time.Minute), nil }}
	for name, constructor := range map[string]func(sso.DomainRouteBinding) (sso.DomainRoute, error){"OIDC": sso.NewDomainRoute, "OAuth2": sso.NewOAuth2DomainRoute} {
		t.Run(name, func(t *testing.T) {
			route, err := constructor(binding)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := router.readProviderSAMLLoginProfile(context.Background(), route, configured); !errors.Is(err, sso.ErrForbidden) || got.configuration.EntityID != "" {
				t.Fatal("foreign protocol evidence reached SAML registry read", err)
			}
		})
	}
	for name, change := range map[string]func(*sso.DomainRouteBinding){
		"provider":           func(b *sso.DomainRouteBinding) { b.ProviderID = "other-provider" },
		"organization":       func(b *sso.DomainRouteBinding) { b.Proof.Key.OrganizationID = "other-organization" },
		"domain":             func(b *sso.DomainRouteBinding) { b.Proof.Key.Domain = "other.example.com" },
		"version":            func(b *sso.DomainRouteBinding) { b.ProviderVersion++ },
		"generation":         func(b *sso.DomainRouteBinding) { b.CredentialGeneration++ },
		"future observation": func(b *sso.DomainRouteBinding) { b.ObservedAt = now.Add(time.Second) },
		"exclusive expiry":   func(b *sso.DomainRouteBinding) { b.ObservedAt, b.ValidUntil = now.Add(-time.Second), now },
	} {
		t.Run(name, func(t *testing.T) {
			changed := binding
			change(&changed)
			route, err := sso.NewSAMLDomainRoute(changed)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := router.readProviderSAMLLoginProfile(context.Background(), route, configured); !errors.Is(err, sso.ErrForbidden) || got.configuration.EntityID != "" {
				t.Fatal("mismatched or expired SAML evidence reached registry read", err)
			}
		})
	}
	route, err := sso.NewSAMLDomainRoute(binding)
	if err != nil {
		t.Fatal(err)
	}
	for _, disable := range []func(*ProviderRouter){func(r *ProviderRouter) { r.protocolRegistry = false }, func(r *ProviderRouter) { r.samlRouteValidate = nil }} {
		unselected := *router
		disable(&unselected)
		if got, err := unselected.readProviderSAMLLoginProfile(context.Background(), route, configured); !errors.Is(err, sso.ErrForbidden) || got.configuration.EntityID != "" {
			t.Fatal("unselected SAML route validation reached registry read", err)
		}
	}
}
