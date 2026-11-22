package sso_test

import (
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	"github.com/faustbrian/go-sso"
)

func enableCredentialBinding() sso.CredentialCheckpointBinding {
	observed := time.Date(2026, time.November, 22, 10, 0, 0, 123456000, time.UTC)
	return sso.CredentialCheckpointBinding{
		TenantID: "enable-tenant", OrganizationID: "enable-organization", ProviderID: "enable-provider",
		ProviderVersion: 7, Generation: 3, ObservedAt: observed, ExpiresAt: observed.Add(20 * time.Second),
	}
}

func enableRequest(t *testing.T) sso.ProviderEnableRequest {
	t.Helper()
	binding := enableCredentialBinding()
	credential, err := sso.NewCredentialCheckpoint(binding)
	if err != nil {
		t.Fatal(err)
	}
	key, err := identity.NewIdempotencyKey([]byte("enable-key"))
	if err != nil {
		t.Fatal(err)
	}
	return sso.ProviderEnableRequest{
		ProviderID: binding.ProviderID, ExpectedVersion: binding.ProviderVersion, CredentialCheckpoint: credential, IdempotencyKey: key,
		DomainProofCheckpoint: sso.DomainProofCheckpoint{
			ProofVersion: 1,
			Key: organization.DomainProofKey{
				TenantID: binding.TenantID, OrganizationID: binding.OrganizationID, ClaimID: "enable-claim",
				Domain: "enable.example.com", ClaimVersion: 2, ProofVersion: 1, Method: organization.DomainDNS,
				ObservedAt: binding.ObservedAt.Add(-time.Minute), ExpiresAt: binding.ObservedAt.Add(time.Hour),
			},
		},
	}
}

func TestCredentialCheckpointPreservesDetachedBinding(t *testing.T) {
	original := enableCredentialBinding()
	checkpoint, err := sso.NewCredentialCheckpoint(original)
	if err != nil {
		t.Fatal(err)
	}
	original.ProviderID = "changed-owner"
	projected, err := checkpoint.Bindings()
	if err != nil || projected != enableCredentialBinding() {
		t.Fatal("checkpoint did not preserve its original exact binding", err)
	}
	projected.Generation++
	again, err := checkpoint.Bindings()
	if err != nil || again != enableCredentialBinding() {
		t.Fatal("projected binding mutated checkpoint custody", err)
	}
	if _, err := (sso.CredentialCheckpoint{}).Bindings(); !errors.Is(err, sso.ErrInvalidInput) {
		t.Fatal("zero checkpoint projected a usable binding", err)
	}
}

func TestCredentialCheckpointRejectsMalformedBindings(t *testing.T) {
	cases := map[string]func(*sso.CredentialCheckpointBinding){
		"missing tenant":            func(b *sso.CredentialCheckpointBinding) { b.TenantID = "" },
		"missing organization":      func(b *sso.CredentialCheckpointBinding) { b.OrganizationID = "" },
		"missing provider":          func(b *sso.CredentialCheckpointBinding) { b.ProviderID = "" },
		"noncanonical owner":        func(b *sso.CredentialCheckpointBinding) { b.TenantID = " padded" },
		"oversized provider":        func(b *sso.CredentialCheckpointBinding) { b.ProviderID = strings.Repeat("p", 129) },
		"zero version":              func(b *sso.CredentialCheckpointBinding) { b.ProviderVersion = 0 },
		"terminal provider version": func(b *sso.CredentialCheckpointBinding) { b.ProviderVersion = math.MaxUint64 },
		"zero generation":           func(b *sso.CredentialCheckpointBinding) { b.Generation = 0 },
		"zero observation":          func(b *sso.CredentialCheckpointBinding) { b.ObservedAt = time.Time{} },
		"zero expiry":               func(b *sso.CredentialCheckpointBinding) { b.ExpiresAt = time.Time{} },
		"zero interval":             func(b *sso.CredentialCheckpointBinding) { b.ExpiresAt = b.ObservedAt },
		"negative interval":         func(b *sso.CredentialCheckpointBinding) { b.ExpiresAt = b.ObservedAt.Add(-time.Microsecond) },
		"over twenty seconds": func(b *sso.CredentialCheckpointBinding) {
			b.ExpiresAt = b.ObservedAt.Add(20*time.Second + time.Microsecond)
		},
		"non UTC observation": func(b *sso.CredentialCheckpointBinding) {
			b.ObservedAt = b.ObservedAt.In(time.FixedZone("other", 3600))
		},
		"non UTC expiry":             func(b *sso.CredentialCheckpointBinding) { b.ExpiresAt = b.ExpiresAt.In(time.FixedZone("other", 3600)) },
		"submicrosecond observation": func(b *sso.CredentialCheckpointBinding) { b.ObservedAt = b.ObservedAt.Add(time.Nanosecond) },
		"submicrosecond expiry":      func(b *sso.CredentialCheckpointBinding) { b.ExpiresAt = b.ExpiresAt.Add(-time.Nanosecond) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			binding := enableCredentialBinding()
			mutate(&binding)
			checkpoint, err := sso.NewCredentialCheckpoint(binding)
			if !errors.Is(err, sso.ErrInvalidInput) || checkpoint != (sso.CredentialCheckpoint{}) {
				t.Fatal("malformed binding admitted or failure returned custody", err)
			}
		})
	}
	for _, lifetime := range []time.Duration{time.Microsecond, 20 * time.Second} {
		binding := enableCredentialBinding()
		binding.ExpiresAt = binding.ObservedAt.Add(lifetime)
		if _, err := sso.NewCredentialCheckpoint(binding); err != nil {
			t.Fatal("valid bounded interval rejected", err)
		}
	}
}

func TestOAuth2CredentialCheckpointRetainsProtocolAndOriginalLifetime(t *testing.T) {
	binding := enableCredentialBinding()
	oauth, err := sso.NewOAuth2CredentialCheckpoint(binding)
	if err != nil || oauth.Protocol() != "oauth2" {
		t.Fatal("OAuth credential checkpoint did not preserve its protocol", err)
	}
	read, err := oauth.Bindings()
	if err != nil || read != binding {
		t.Fatal("OAuth credential checkpoint changed immutable metadata", err)
	}
	oidc, err := sso.NewCredentialCheckpoint(binding)
	if err != nil || oidc.Protocol() != "oidc" || oauth == oidc {
		t.Fatal("existing OIDC checkpoint became interchangeable with OAuth", err)
	}
	request := enableRequest(t)
	request.CredentialCheckpoint = oauth
	if err = request.Validate(); err != nil {
		t.Fatal("OAuth checkpoint failed exact enablement shape", err)
	}
	binding.ExpiresAt = binding.ExpiresAt.Add(time.Microsecond)
	if _, err = sso.NewOAuth2CredentialCheckpoint(binding); !errors.Is(err, sso.ErrInvalidInput) {
		t.Fatal("OAuth checkpoint accepted evidence beyond twenty seconds", err)
	}
	if (sso.CredentialCheckpoint{}).Protocol() != "" {
		t.Fatal("an unselected checkpoint defaulted to a protocol")
	}
}

func TestProviderEnableRequestValidatesShapeWithoutGrantingAuthority(t *testing.T) {
	for _, method := range []organization.DomainMethod{organization.DomainDNS, organization.DomainHTTPS} {
		request := enableRequest(t)
		request.DomainProofCheckpoint.Key.Method = method
		if err := request.Validate(); err != nil {
			t.Fatal("exact supported metadata rejected", err)
		}
	}
	// Deliberately historical inputs remain structurally valid. Only native current
	// owner reads and its clock can establish readiness, not this pure validation.
	request := enableRequest(t)
	if err := request.Validate(); err != nil {
		t.Fatal("shape validation inferred current authority or renewed a lifetime", err)
	}
}

func TestProviderEnableRequestRejectsMismatchAndMalformedProof(t *testing.T) {
	cases := map[string]func(*sso.ProviderEnableRequest){
		"empty provider":             func(r *sso.ProviderEnableRequest) { r.ProviderID = "" },
		"different provider":         func(r *sso.ProviderEnableRequest) { r.ProviderID = "other-provider" },
		"zero provider version":      func(r *sso.ProviderEnableRequest) { r.ExpectedVersion = 0 },
		"wrapping provider version":  func(r *sso.ProviderEnableRequest) { r.ExpectedVersion = math.MaxUint64 },
		"different provider version": func(r *sso.ProviderEnableRequest) { r.ExpectedVersion++ },
		"missing credential":         func(r *sso.ProviderEnableRequest) { r.CredentialCheckpoint = sso.CredentialCheckpoint{} },
		"missing key":                func(r *sso.ProviderEnableRequest) { r.IdempotencyKey = identity.IdempotencyKey{} },
		"zero proof":                 func(r *sso.ProviderEnableRequest) { r.DomainProofCheckpoint = sso.DomainProofCheckpoint{} },
		"different tenant":           func(r *sso.ProviderEnableRequest) { r.DomainProofCheckpoint.Key.TenantID = "other-tenant" },
		"different organization":     func(r *sso.ProviderEnableRequest) { r.DomainProofCheckpoint.Key.OrganizationID = "other-organization" },
		"missing claim":              func(r *sso.ProviderEnableRequest) { r.DomainProofCheckpoint.Key.ClaimID = "" },
		"zero claim version":         func(r *sso.ProviderEnableRequest) { r.DomainProofCheckpoint.Key.ClaimVersion = 0 },
		"zero proof version":         func(r *sso.ProviderEnableRequest) { r.DomainProofCheckpoint.ProofVersion = 0 },
		"different proof version":    func(r *sso.ProviderEnableRequest) { r.DomainProofCheckpoint.ProofVersion++ },
		"noncanonical domain":        func(r *sso.ProviderEnableRequest) { r.DomainProofCheckpoint.Key.Domain = "Enable.Example.com" },
		"URL instead of domain":      func(r *sso.ProviderEnableRequest) { r.DomainProofCheckpoint.Key.Domain = "https://enable.example.com" },
		"unsupported method":         func(r *sso.ProviderEnableRequest) { r.DomainProofCheckpoint.Key.Method = "other-method" },
		"revoked proof":              func(r *sso.ProviderEnableRequest) { r.DomainProofCheckpoint.Key.Revoked = true },
		"zero proof observation":     func(r *sso.ProviderEnableRequest) { r.DomainProofCheckpoint.Key.ObservedAt = time.Time{} },
		"zero proof expiry":          func(r *sso.ProviderEnableRequest) { r.DomainProofCheckpoint.Key.ExpiresAt = time.Time{} },
		"inverted proof interval": func(r *sso.ProviderEnableRequest) {
			r.DomainProofCheckpoint.Key.ExpiresAt = r.DomainProofCheckpoint.Key.ObservedAt
		},
		"nonmicrosecond proof": func(r *sso.ProviderEnableRequest) {
			r.DomainProofCheckpoint.Key.ObservedAt = r.DomainProofCheckpoint.Key.ObservedAt.Add(time.Nanosecond)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			request := enableRequest(t)
			mutate(&request)
			if err := request.Validate(); !errors.Is(err, sso.ErrInvalidInput) {
				t.Fatal("malformed or inconsistent request admitted", err)
			}
		})
	}
}

func TestProviderEnableValuesRedactImplicitDisclosure(t *testing.T) {
	request := enableRequest(t)
	for _, value := range []any{request, request.DomainProofCheckpoint, request.CredentialCheckpoint} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
			got := fmt.Sprintf(format, value)
			if !strings.Contains(got, "redacted") || strings.Contains(got, "enable-") || strings.Contains(got, "example.com") {
				t.Fatal("implicit formatting disclosed checkpoint or request")
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

func FuzzProviderEnableShape(f *testing.F) {
	f.Add("enable-provider", "enable.example.com", "dns-txt")
	f.Add("", "https://enable.example.com", "https")
	f.Add("enable-provider", "Enable.Example.com", "other")
	f.Fuzz(func(t *testing.T, provider, domain, method string) {
		request := enableRequest(t)
		request.ProviderID = provider
		request.DomainProofCheckpoint.Key.Domain = domain
		request.DomainProofCheckpoint.Key.Method = organization.DomainMethod(method)
		err := request.Validate()
		canonical, domainErr := organization.CanonicalDomain(domain)
		wantValid := provider == "enable-provider" && domainErr == nil && canonical == domain &&
			(method == string(organization.DomainDNS) || method == string(organization.DomainHTTPS))
		if (err == nil) != wantValid {
			t.Fatal("shape result disagreed with exact owner and canonical supported domain profile")
		}
		if err != nil && !errors.Is(err, sso.ErrInvalidInput) {
			t.Fatal("shape validation exposed an unbounded error")
		}
	})
}
