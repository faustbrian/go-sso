package postgres

import (
	"errors"
	"testing"
	"time"

	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	"github.com/faustbrian/go-sso"
)

func TestSAMLRoleSyncRefusesMappingsOutsideOriginalProfile(t *testing.T) {
	const provider sso.ProviderID = "saml-provider"
	service := &ProviderSAMLLoginCompletionService{effect: &sessionpg.SSOSAMLSigninEffect{}, start: &ProviderLoginService{
		saml: &providerSAMLStart{profiles: map[sso.ProviderID]StaticSAMLLoginProfile{
			provider: {ProviderID: provider, OrganizationID: "org", MappingVersion: 3},
		}},
	}}
	mapping := StaticSAMLRoleMapping{ProviderID: provider, OrganizationID: "org", MappingVersion: 3,
		Rules: []StaticSAMLRoleRule{{ClaimName: "entitled", RoleID: "project-reader"}}}
	if selected, err := service.WithRoleSync([]StaticSAMLRoleMapping{mapping}, 0); err != nil || selected == service {
		t.Fatal("exact installed policy did not select a separate service", err)
	}
	for name, change := range map[string]func(*StaticSAMLRoleMapping){
		"provider":     func(m *StaticSAMLRoleMapping) { m.ProviderID = "other" },
		"organization": func(m *StaticSAMLRoleMapping) { m.OrganizationID = "other" },
		"version":      func(m *StaticSAMLRoleMapping) { m.MappingVersion++ },
	} {
		t.Run(name, func(t *testing.T) {
			foreign := mapping
			change(&foreign)
			if got, err := service.WithRoleSync([]StaticSAMLRoleMapping{foreign}, 0); got != nil || !errors.Is(err, sso.ErrInvalidInput) {
				t.Fatal("a role policy outside the installed SAML profile was accepted", err)
			}
		})
	}
	if got, err := service.WithRoleSync([]StaticSAMLRoleMapping{mapping, mapping}, 0); got != nil || !errors.Is(err, sso.ErrInvalidInput) {
		t.Fatal("duplicate policy was accepted", err)
	}
	if got, err := service.WithRoleSync([]StaticSAMLRoleMapping{mapping}, -time.Second); got != nil || !errors.Is(err, sso.ErrInvalidInput) {
		t.Fatal("invalid signed-time skew was accepted", err)
	}
}
