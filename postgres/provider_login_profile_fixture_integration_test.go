//go:build integration

package postgres_test

import (
	"encoding/json"
	"errors"
	"testing"

	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestNativeLoginProfileSelectsExactEnabledConfigurationAndRejectsStaleScope(t *testing.T) {
	x := newProviderEnableFixture(t)
	provider := enableRouteFixture(t, x, false)
	router := newProviderRouter(t, x, 4)
	request, err := sso.NewDomainRouteRequest(x.proof.TenantID, x.proof.Domain, provider)
	if err != nil {
		t.Fatal(err)
	}
	route, err := router.Route(x.f.ctx, request)
	if err != nil {
		t.Fatal("select authenticated provider route", err)
	}
	configured := ssopg.StaticOIDCLoginProfile{ProviderID: provider, OrganizationID: x.proof.OrganizationID, Domain: x.proof.Domain, ClientID: "enterprise-client", ProtocolRedirectURI: "https://app.example.com/sso/callback", ProviderVersion: 3, CredentialGeneration: 1, MappingVersion: 1, Scopes: []string{"openid", "email"}}
	t.Logf("profile read string bindings: %#v", []any{string(x.proof.TenantID), string(x.proof.OrganizationID), string(provider), "3", "1", "1"})
	got, err := ssopg.ReadProviderLoginProfileRedirectForTest(x.f.ctx, router, route, configured)
	if err != nil || got.Host != "enable.example.com" || got.Path != "/authorize" || got.Query().Get("client_id") != configured.ClientID {
		t.Fatal("exact selected enabled configuration was not usable", err)
	}
	foreignBinding, _ := route.Bindings()
	foreignBinding.Proof.Key.TenantID = "org-test-scope"
	foreignRoute, err := sso.NewDomainRoute(foreignBinding)
	if err != nil {
		t.Fatal("construct cross-tenant negative fixture", err)
	}
	if got, err := ssopg.ReadProviderLoginProfileRedirectForTest(x.f.ctx, router, foreignRoute, configured); !errors.Is(err, sso.ErrForbidden) || got.String() != "" {
		t.Fatal("foreign tenant reused selected provider configuration", err)
	}
	for name, change := range map[string]func(*ssopg.StaticOIDCLoginProfile){
		"provider":              func(p *ssopg.StaticOIDCLoginProfile) { p.ProviderID = "different-provider" },
		"organization":          func(p *ssopg.StaticOIDCLoginProfile) { p.OrganizationID = "01ARZ3NDEKTSV4RRFFQ69G5FAW" },
		"domain":                func(p *ssopg.StaticOIDCLoginProfile) { p.Domain = "other.example.com" },
		"provider version":      func(p *ssopg.StaticOIDCLoginProfile) { p.ProviderVersion++ },
		"credential generation": func(p *ssopg.StaticOIDCLoginProfile) { p.CredentialGeneration++ },
		"mapping version":       func(p *ssopg.StaticOIDCLoginProfile) { p.MappingVersion++ },
	} {
		t.Run(name, func(t *testing.T) {
			other := configured
			change(&other)
			if got, err := ssopg.ReadProviderLoginProfileRedirectForTest(x.f.ctx, router, route, other); !errors.Is(err, sso.ErrForbidden) || got.String() != "" {
				t.Fatal("stale or cross-scope deployment received redirect", err)
			}
		})
	}
	var enabledProof, configuration []byte
	scope := []any{string(x.proof.TenantID), string(x.proof.OrganizationID), string(provider)}
	const where = ` WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`
	if err := x.f.pool.Raw().QueryRow(x.f.ctx, `SELECT enablement_proof,metadata_configuration_envelope FROM sso_providers.providers`+where, scope...).Scan(&enabledProof, &configuration); err != nil {
		t.Fatal("capture original fixture envelopes", err)
	}
	if _, err := x.f.pool.Raw().Exec(x.f.ctx, `UPDATE sso_providers.credentials SET generation=2`+where, scope...); err != nil {
		t.Fatal("fixture unactivated successor credential", err)
	}
	if got, err := ssopg.ReadProviderLoginProfileRedirectForTest(x.f.ctx, router, route, configured); !errors.Is(err, sso.ErrForbidden) || got.String() != "" {
		t.Fatal("enabled profile accepted a different installed credential generation", err)
	}
	if _, err := x.f.pool.Raw().Exec(x.f.ctx, `UPDATE sso_providers.credentials SET generation=1`+where, scope...); err != nil {
		t.Fatal("restore exact installed credential", err)
	}
	aad, err := envelope.NewContext(map[string]string{"owner": "sso/provider", "tenant": string(x.proof.TenantID), "organization": string(x.proof.OrganizationID), "provider": string(provider), "protocol": "oidc", "purpose": "static-configuration", "version": "3"})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := envelope.ParseEnvelope(configuration)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := x.config.Envelope.Decrypt(x.f.ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	defer clear(plain)
	if err != nil {
		t.Fatal("open exact fixture configuration", err)
	}
	type configurationProjection struct {
		Metadata sso.OIDCStaticMetadataSpec
		Mapping  sso.AttributeMappingSpec
		Domains  []string
	}
	for name, mutate := range map[string]func(*configurationProjection){
		"authenticated wrong domain":    func(p *configurationProjection) { p.Domains[0] = "other.example.com" },
		"authenticated wrong mapping":   func(p *configurationProjection) { p.Mapping.Version++ },
		"invalid mapping":               func(p *configurationProjection) { p.Mapping.SubjectClaim = "" },
		"different issuer":              func(p *configurationProjection) { p.Metadata.Issuer = "https://different.example.com" },
		"invalid static metadata":       func(p *configurationProjection) { p.Metadata.TokenEndpoint = "http://enable.example.com/token" },
		"authorization query collision": func(p *configurationProjection) { p.Metadata.AuthorizationEndpoint += "?response_type=token" },
	} {
		t.Run(name, func(t *testing.T) {
			var projected configurationProjection
			if json.Unmarshal(plain, &projected) != nil {
				t.Fatal("decode baseline fixture configuration")
			}
			mutate(&projected)
			changed, err := json.Marshal(projected)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(changed)
			sealed, err := x.config.Envelope.Encrypt(x.f.ctx, envelope.EncryptRequest{Plaintext: changed, KeyReference: x.config.KeyReference, Context: aad})
			if err != nil {
				t.Fatal("seal mismatched fixture configuration", err)
			}
			wire, err := sealed.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			args := append(append([]any{}, scope...), wire)
			if _, err := x.f.pool.Raw().Exec(x.f.ctx, `UPDATE sso_providers.providers SET metadata_configuration_envelope=$4`+where, args...); err != nil {
				t.Fatal("fixture authenticated configuration mismatch", err)
			}
			if got, err := ssopg.ReadProviderLoginProfileRedirectForTest(x.f.ctx, router, route, configured); err == nil || got.String() != "" {
				t.Fatal("authenticated but mismatched configuration produced redirect")
			}
		})
	}
	for _, mutation := range []string{
		`UPDATE sso_providers.providers SET enabled=false,enablement_proof=NULL,enablement_credential_generation=NULL`,
		`UPDATE sso_providers.providers SET metadata_version=4`,
		`UPDATE sso_providers.providers SET metadata_mapping_version=2`,
		`UPDATE sso_providers.providers SET enablement_credential_generation=2`,
		`UPDATE sso_providers.providers SET metadata_configuration_envelope=configuration_envelope`,
		`UPDATE sso_providers.providers SET metadata_configuration_envelope=decode('00','hex')`,
	} {
		resetArgs := append(append([]any{}, scope...), enabledProof, configuration)
		if _, err := x.f.pool.Raw().Exec(x.f.ctx, `UPDATE sso_providers.providers SET enabled=true,metadata_version=3,metadata_mapping_version=1,enablement_proof=$4,enablement_credential_generation=1,metadata_configuration_envelope=$5`+where, resetArgs...); err != nil {
			t.Fatal("reset isolated original provider snapshot", err)
		}
		if _, err := x.f.pool.Raw().Exec(x.f.ctx, mutation+where, scope...); err != nil {
			t.Fatal("fixture successor provider state", err)
		}
		if got, err := ssopg.ReadProviderLoginProfileRedirectForTest(x.f.ctx, router, route, configured); err == nil || got.String() != "" {
			t.Fatal("retired, mismatched or unauthenticated provider snapshot received redirect")
		}
	}
}
