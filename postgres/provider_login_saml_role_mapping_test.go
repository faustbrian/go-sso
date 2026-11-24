package postgres

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	organization "github.com/faustbrian/go-organization"
	"github.com/faustbrian/go-sso"
)

const samlRoleMappingIssuer = "urn:example:IdP:Enterprise"

func samlRoleMappingConfig() StaticSAMLRoleMapping {
	return StaticSAMLRoleMapping{OrganizationID: "organization-a", ProviderID: "Provider_A", MappingVersion: 7,
		Rules: []StaticSAMLRoleRule{{ClaimName: "urn:example:roles:z", RoleID: "custom-z"},
			{ClaimName: "https://claims.example/roles/a", RoleID: "custom-a"}}}
}

func samlRoleAttribute(t *testing.T, name string, value any, mutate ...func(*sso.VerifiedAttributeSpec)) sso.VerifiedAttribute {
	t.Helper()
	spec := sso.VerifiedAttributeSpec{Name: name, Presence: sso.AttributeValue,
		Provenance: sso.AttributeProvenance{ProviderID: "Provider_A", ProviderProfileVersion: 3,
			Issuer: samlRoleMappingIssuer, Source: sso.AttributeSourceSAMLAssertion}}
	switch value := value.(type) {
	case bool:
		spec.BooleanValue = &value
	case string:
		spec.StringValue = &value
	case sso.AttributePresence:
		spec.Presence = value
	default:
		t.Fatal("unsupported role observation fixture")
	}
	for _, change := range mutate {
		change(&spec)
	}
	attribute, err := sso.NewVerifiedAttribute(spec)
	if err != nil {
		t.Fatal("invalid role observation fixture", err)
	}
	return attribute
}

func samlRoleAssertion(t *testing.T, a, z any) sso.ProtocolAssertion {
	t.Helper()
	return sso.ProtocolAssertion{ProviderID: "Provider_A", OrganizationID: "organization-a", ProviderSubject: "stable-subject",
		ProviderProfileVersion: 3, MappingVersion: 7, Attributes: []sso.VerifiedAttribute{
			samlRoleAttribute(t, "name_id", "stable-subject"),
			samlRoleAttribute(t, "https://claims.example/roles/a", a),
			samlRoleAttribute(t, "urn:example:roles:z", z),
		}}
}

func TestProviderLoginSAMLRoleMappingRejectsInvalidConfiguration(t *testing.T) {
	for name, mutate := range map[string]func(*StaticSAMLRoleMapping){
		"missing organization": func(c *StaticSAMLRoleMapping) { c.OrganizationID = "" },
		"missing provider":     func(c *StaticSAMLRoleMapping) { c.ProviderID = "" },
		"zero version":         func(c *StaticSAMLRoleMapping) { c.MappingVersion = 0 },
		"organization spaces":  func(c *StaticSAMLRoleMapping) { c.OrganizationID = "organization a" },
		"organization Unicode": func(c *StaticSAMLRoleMapping) { c.OrganizationID = "organization-é" },
		"organization bound": func(c *StaticSAMLRoleMapping) {
			c.OrganizationID = organization.ID(strings.Repeat("o", 129))
		},
		"provider controls": func(c *StaticSAMLRoleMapping) { c.ProviderID = "Provider\nA" },
		"provider bound": func(c *StaticSAMLRoleMapping) {
			c.ProviderID = sso.ProviderID(strings.Repeat("p", 129))
		},
		"no rules":        func(c *StaticSAMLRoleMapping) { c.Rules = nil },
		"too many rules":  func(c *StaticSAMLRoleMapping) { c.Rules = make([]StaticSAMLRoleRule, 101) },
		"duplicate claim": func(c *StaticSAMLRoleMapping) { c.Rules[1].ClaimName = c.Rules[0].ClaimName },
		"duplicate role":  func(c *StaticSAMLRoleMapping) { c.Rules[1].RoleID = c.Rules[0].RoleID },
		"missing role":    func(c *StaticSAMLRoleMapping) { c.Rules[0].RoleID = "" },
		"role space":      func(c *StaticSAMLRoleMapping) { c.Rules[0].RoleID = "custom role" },
		"role control":    func(c *StaticSAMLRoleMapping) { c.Rules[0].RoleID = "custom\x7frole" },
		"role UTF8":       func(c *StaticSAMLRoleMapping) { c.Rules[0].RoleID = organization.ID([]byte{0xff}) },
		"role bound": func(c *StaticSAMLRoleMapping) {
			c.Rules[0].RoleID = organization.ID(strings.Repeat("r", 129))
		},
	} {
		t.Run(name, func(t *testing.T) {
			config := samlRoleMappingConfig()
			mutate(&config)
			mapping, err := newProviderLoginSAMLRoleMapping(config)
			if !errors.Is(err, sso.ErrInvalidInput) || mapping.digest != ([32]byte{}) {
				t.Fatal("invalid configuration returned usable policy", err)
			}
		})
	}
	for _, name := range []string{"", "name_id", "nonce", "at_hash", "c_hash", "access_token", "refresh_token", "id_token",
		"role name", "role\nname", "role\x7fname", "é", string([]byte{0xff}), strings.Repeat("r", 129)} {
		t.Run("claim "+name, func(t *testing.T) {
			config := samlRoleMappingConfig()
			config.Rules[0].ClaimName = name
			if _, err := newProviderLoginSAMLRoleMapping(config); !errors.Is(err, sso.ErrInvalidInput) {
				t.Fatal("invalid or secret claim name accepted", err)
			}
		})
	}
	for _, role := range []organization.Role{organization.RoleOwner, organization.RoleAdministrator, organization.RoleMember} {
		t.Run("static role "+string(role), func(t *testing.T) {
			config := samlRoleMappingConfig()
			config.Rules[0].RoleID = organization.ID(role)
			if _, err := newProviderLoginSAMLRoleMapping(config); !errors.Is(err, sso.ErrInvalidInput) {
				t.Fatal("static membership role accepted", err)
			}
		})
	}
}

func TestProviderLoginSAMLRoleMappingAcceptsExactBoundsAndFlatNames(t *testing.T) {
	config := StaticSAMLRoleMapping{OrganizationID: organization.ID(strings.Repeat("o", 128)),
		ProviderID: sso.ProviderID(strings.Repeat("p", 128)), MappingVersion: ^uint64(0), Rules: make([]StaticSAMLRoleRule, 100)}
	assertion := sso.ProtocolAssertion{OrganizationID: config.OrganizationID, ProviderID: config.ProviderID,
		ProviderProfileVersion: ^uint64(0), MappingVersion: config.MappingVersion, ProviderSubject: "stable-subject"}
	for i := range config.Rules {
		name := fmt.Sprintf("urn:example:roles/%03d", i)
		config.Rules[i] = StaticSAMLRoleRule{ClaimName: name, RoleID: organization.ID(fmt.Sprintf("custom-%03d", i))}
	}
	config.Rules[0] = StaticSAMLRoleRule{ClaimName: "!" + strings.Repeat("r", 126) + "~", RoleID: organization.ID(strings.Repeat("r", 128))}
	config.Rules[1].RoleID = "custom-é"
	for _, rule := range config.Rules {
		assertion.Attributes = append(assertion.Attributes, samlRoleAttribute(t, rule.ClaimName, true, func(s *sso.VerifiedAttributeSpec) {
			s.Provenance.ProviderID, s.Provenance.ProviderProfileVersion = config.ProviderID, assertion.ProviderProfileVersion
		}))
	}
	mapping, err := newProviderLoginSAMLRoleMapping(config)
	if err != nil {
		t.Fatal("exact policy bounds rejected", err)
	}
	got, err := mapping.desiredRoles(assertion, samlRoleMappingIssuer, assertion.ProviderProfileVersion)
	if err != nil || len(got) != 100 || !slices.IsSorted(got) || !slices.Contains(got, organization.ID("custom-é")) ||
		!slices.Contains(got, config.Rules[0].RoleID) {
		t.Fatal("exact role bounds lost configured grants", err)
	}
}

func TestProviderLoginSAMLRoleMappingConsumesOnlyExactBooleanObservations(t *testing.T) {
	mapping, err := newProviderLoginSAMLRoleMapping(samlRoleMappingConfig())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		a, z any
		want []organization.ID
	}{
		{"both true", true, true, []organization.ID{"custom-a", "custom-z"}},
		{"withdraw a", false, true, []organization.ID{"custom-z"}},
		{"withdraw z", true, false, []organization.ID{"custom-a"}},
		{"explicit empty", false, false, []organization.ID{}},
		{"absent", true, sso.AttributeAbsent, nil},
		{"null", true, sso.AttributeNull, nil},
		{"string true", true, "true", nil},
		{"role ID string", true, "owner", nil},
		{"false and malformed", false, "false", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertion := samlRoleAssertion(t, tc.a, tc.z)
			got, err := mapping.desiredRoles(assertion, samlRoleMappingIssuer, 3)
			if tc.want == nil {
				if !errors.Is(err, sso.ErrForbidden) || got != nil {
					t.Fatal("ambiguous assertion returned a partial grant mutation", err)
				}
				return
			}
			if err != nil || got == nil || !slices.Equal(got, tc.want) {
				t.Fatal("wrong explicit desired roles", err)
			}
		})
	}
}

func TestProviderLoginSAMLRoleMappingRejectsStaleForeignAndMixedAssertions(t *testing.T) {
	mapping, err := newProviderLoginSAMLRoleMapping(samlRoleMappingConfig())
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*sso.ProtocolAssertion){
		"wrong organization": func(a *sso.ProtocolAssertion) { a.OrganizationID = "organization-b" },
		"wrong provider":     func(a *sso.ProtocolAssertion) { a.ProviderID = "Provider_B" },
		"stale profile":      func(a *sso.ProtocolAssertion) { a.ProviderProfileVersion = 2 },
		"stale mapping":      func(a *sso.ProtocolAssertion) { a.MappingVersion = 6 },
		"invalid subject":    func(a *sso.ProtocolAssertion) { a.ProviderSubject = "" },
		"no attributes":      func(a *sso.ProtocolAssertion) { a.Attributes = nil },
		"missing rule":       func(a *sso.ProtocolAssertion) { a.Attributes = a.Attributes[:2] },
		"duplicate rule": func(a *sso.ProtocolAssertion) {
			a.Attributes = append(a.Attributes, a.Attributes[1])
		},
		"duplicate metadata": func(a *sso.ProtocolAssertion) {
			a.Attributes = append(a.Attributes, a.Attributes[0])
		},
		"invalid attribute": func(a *sso.ProtocolAssertion) { a.Attributes = append(a.Attributes, sso.VerifiedAttribute{}) },
		"attribute bound":   func(a *sso.ProtocolAssertion) { a.Attributes = make([]sso.VerifiedAttribute, 257) },
		"case mismatch": func(a *sso.ProtocolAssertion) {
			a.Attributes[1] = samlRoleAttribute(t, "https://claims.example/roles/A", true)
		},
		"mixed issuer": func(a *sso.ProtocolAssertion) {
			a.Attributes[2] = samlRoleAttribute(t, "urn:example:roles:z", true, func(s *sso.VerifiedAttributeSpec) {
				s.Provenance.Issuer = "urn:example:IdP:Foreign"
			})
		},
		"mixed source": func(a *sso.ProtocolAssertion) {
			a.Attributes[2] = samlRoleAttribute(t, "urn:example:roles:z", true, func(s *sso.VerifiedAttributeSpec) {
				s.Provenance.Source, s.Provenance.Issuer = sso.AttributeSourceOIDCIDToken, "https://idp.example"
			})
		},
		"mixed profile": func(a *sso.ProtocolAssertion) {
			a.Attributes[2] = samlRoleAttribute(t, "urn:example:roles:z", true, func(s *sso.VerifiedAttributeSpec) {
				s.Provenance.ProviderProfileVersion = 2
			})
		},
		"mixed provider": func(a *sso.ProtocolAssertion) {
			a.Attributes[2] = samlRoleAttribute(t, "urn:example:roles:z", true, func(s *sso.VerifiedAttributeSpec) {
				s.Provenance.ProviderID = "Provider_B"
			})
		},
	} {
		t.Run(name, func(t *testing.T) {
			assertion := samlRoleAssertion(t, true, true)
			mutate(&assertion)
			if got, err := mapping.desiredRoles(assertion, samlRoleMappingIssuer, 3); !errors.Is(err, sso.ErrForbidden) || got != nil {
				t.Fatal("invalid assertion returned a grant mutation", err)
			}
		})
	}
	for _, expected := range []struct {
		issuer  string
		version uint64
	}{{"", 3}, {samlRoleMappingIssuer, 0}, {samlRoleMappingIssuer, 4}, {"urn:example:idp:enterprise", 3}} {
		if got, err := mapping.desiredRoles(samlRoleAssertion(t, true, true), expected.issuer, expected.version); !errors.Is(err, sso.ErrForbidden) || got != nil {
			t.Fatal("different installed issuer or profile returned a grant mutation", err)
		}
	}
	for _, source := range []sso.AttributeSource{sso.AttributeSourceOIDCIDToken, sso.AttributeSourceOAuthIdentityEndpoint} {
		t.Run("foreign protocol "+string(source), func(t *testing.T) {
			assertion := samlRoleAssertion(t, true, true)
			for i, attribute := range assertion.Attributes {
				spec, err := attribute.Spec()
				if err != nil {
					t.Fatal(err)
				}
				spec.Provenance.Source, spec.Provenance.Issuer = source, "https://idp.example"
				spec.Verified, spec.Authoritative = true, true
				assertion.Attributes[i], err = sso.NewVerifiedAttribute(spec)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := assertion.Validate(); err != nil {
				t.Fatal("valid foreign-protocol assertion fixture rejected", err)
			}
			if got, err := mapping.desiredRoles(assertion, "https://idp.example", 3); !errors.Is(err, sso.ErrForbidden) || got != nil {
				t.Fatal("foreign protocol assessments substituted for SAML evidence", err)
			}
		})
	}
	if got, err := (providerLoginSAMLRoleMapping{}).desiredRoles(samlRoleAssertion(t, true, true), samlRoleMappingIssuer, 3); !errors.Is(err, sso.ErrForbidden) || got != nil {
		t.Fatal("zero policy returned a grant mutation", err)
	}
}

func TestProviderLoginSAMLRoleMappingIgnoresUnselectedMetadataWithoutInferringTrust(t *testing.T) {
	mapping, err := newProviderLoginSAMLRoleMapping(samlRoleMappingConfig())
	if err != nil {
		t.Fatal(err)
	}
	assertion := samlRoleAssertion(t, false, true)
	for _, attribute := range []sso.VerifiedAttribute{
		samlRoleAttribute(t, "email", "member@example.test"),
		samlRoleAttribute(t, "email_verified", true),
		samlRoleAttribute(t, "display_name", "Example Member"),
		samlRoleAttribute(t, "owner", true, func(s *sso.VerifiedAttributeSpec) { s.Verified, s.Authoritative = true, true }),
		samlRoleAttribute(t, "unknown", sso.AttributeNull),
	} {
		assertion.Attributes = append(assertion.Attributes, attribute)
	}
	got, err := mapping.desiredRoles(assertion, samlRoleMappingIssuer, 3)
	if err != nil || !slices.Equal(got, []organization.ID{"custom-z"}) {
		t.Fatal("unselected identity claims changed explicit role policy", err)
	}
}

func TestProviderLoginSAMLRoleMappingSnapshotsAndBindsExactPolicy(t *testing.T) {
	config := samlRoleMappingConfig()
	mapping, err := newProviderLoginSAMLRoleMapping(config)
	if err != nil {
		t.Fatal(err)
	}
	config.Rules[0] = StaticSAMLRoleRule{ClaimName: "other", RoleID: "foreign"}
	got, err := mapping.desiredRoles(samlRoleAssertion(t, true, true), samlRoleMappingIssuer, 3)
	if err != nil || !slices.Equal(got, []organization.ID{"custom-a", "custom-z"}) {
		t.Fatal("startup mutation changed selected roles", err)
	}
	got[0] = "foreign"
	fresh, err := mapping.desiredRoles(samlRoleAssertion(t, true, true), samlRoleMappingIssuer, 3)
	if err != nil || !slices.Equal(fresh, []organization.ID{"custom-a", "custom-z"}) {
		t.Fatal("returned roles were not detached", err)
	}
	canonical := samlRoleMappingConfig()
	slices.Reverse(canonical.Rules)
	same, err := newProviderLoginSAMLRoleMapping(canonical)
	if err != nil || mapping.digest == ([32]byte{}) || same.digest != mapping.digest ||
		!slices.Equal(mapping.claimNames, []string{"https://claims.example/roles/a", "urn:example:roles:z"}) {
		t.Fatal("equivalent policy order changed mapping identity", err)
	}
	for _, mutate := range []func(*StaticSAMLRoleMapping){
		func(c *StaticSAMLRoleMapping) { c.OrganizationID = "organization-b" },
		func(c *StaticSAMLRoleMapping) { c.ProviderID = "Provider_B" },
		func(c *StaticSAMLRoleMapping) { c.MappingVersion++ },
		func(c *StaticSAMLRoleMapping) { c.Rules[0].RoleID = "custom-other" },
		func(c *StaticSAMLRoleMapping) { c.Rules[0].ClaimName = "other" },
	} {
		config := samlRoleMappingConfig()
		mutate(&config)
		changed, err := newProviderLoginSAMLRoleMapping(config)
		if err != nil || changed.digest == mapping.digest {
			t.Fatal("different scoped mapping reused policy identity", err)
		}
	}
	oidcConfig := roleMappingConfig()
	oidc, err := newProviderLoginRoleMapping(oidcConfig, []string{"role_a", "role_z"})
	if err != nil {
		t.Fatal(err)
	}
	saml, err := newProviderLoginSAMLRoleMapping(StaticSAMLRoleMapping{OrganizationID: oidcConfig.OrganizationID,
		ProviderID: oidcConfig.ProviderID, MappingVersion: oidcConfig.MappingVersion,
		Rules: []StaticSAMLRoleRule{{ClaimName: "role_a", RoleID: "custom-a"}, {ClaimName: "role_z", RoleID: "custom-z"}}})
	if err != nil || saml.digest == oidc.digest {
		t.Fatal("SAML policy reused the OIDC identity domain", err)
	}
}
