package saml

import (
	"slices"
	"strings"
	"unicode/utf8"

	organization "github.com/faustbrian/go-organization"
	"github.com/faustbrian/go-sso"
	"github.com/knroy/go-xml/v2/xdm"
)

const (
	samlNameIDClaim        = "name_id"
	samlXMLSchemaNS        = "http://www.w3.org/2001/XMLSchema"
	samlXMLSchemaInstance  = "http://www.w3.org/2001/XMLSchema-instance"
	maximumSAMLScalarBytes = 512 // sso.VerifiedAttributeSpec scalar string limit.
)

type postAssertionMapping struct {
	organizationID organization.ID
	mappingVersion uint64
	provenance     sso.AttributeProvenance
	claims         []samlScalarClaim
}

type samlScalarClaim struct {
	name    string
	boolean bool
}

// WithAssertionMapping returns a copy of the verifier that projects an exact
// installed SAML mapping. The caller must source provider and mapping from the
// same approved signing profile, not XML or request parameters. This does not
// check current provider/domain authority, reserve IDs or assign privileges.
// No mapping is inferred for the unchanged original verifier.
func (p POSTResponseProfile) WithAssertionMapping(provider sso.Provider, mapping sso.AttributeMapping) (POSTResponseProfile, error) {
	spec, err := mapping.Spec()
	if err != nil || len(p.signing) == 0 || !provider.Enabled || provider.Protocol != "saml" ||
		!validSAMLMappingScope(provider) || provider.Version == 0 || spec.Version != provider.MappingVersion ||
		spec.SubjectClaim != samlNameIDClaim || (spec.VerifiedEmailClaim != "" && spec.EmailClaim == "") {
		return POSTResponseProfile{}, ErrInvalidInput
	}
	selected := make([]samlScalarClaim, 0, 3)
	for _, claim := range [...]samlScalarClaim{{name: spec.EmailClaim}, {name: spec.VerifiedEmailClaim, boolean: true}, {name: spec.DisplayNameClaim}} {
		if claim.name == "" {
			continue
		}
		if claim.name == samlNameIDClaim || slices.ContainsFunc(selected, func(other samlScalarClaim) bool { return other.name == claim.name }) {
			return POSTResponseProfile{}, ErrInvalidInput
		}
		selected = append(selected, claim)
	}
	p.mapping = &postAssertionMapping{
		organizationID: organization.ID(provider.OrganizationID), mappingVersion: spec.Version, claims: selected,
		provenance: sso.AttributeProvenance{ProviderID: sso.ProviderID(provider.ID), ProviderProfileVersion: provider.Version,
			Issuer: p.idp, Source: sso.AttributeSourceSAMLAssertion},
	}
	return p, nil
}

func validSAMLMappingScope(provider sso.Provider) bool {
	// Match ProtocolAssertion's separate opaque provider and organization ID
	// grammars. A route-derived IdP profile additionally checks its exact ID.
	if len(provider.ID) == 0 || len(provider.ID) > 128 || len(provider.OrganizationID) == 0 ||
		len(provider.OrganizationID) > 128 || !utf8.ValidString(provider.OrganizationID) {
		return false
	}
	for i := range len(provider.ID) {
		if provider.ID[i] < '!' || provider.ID[i] > '~' {
			return false
		}
	}
	return !strings.ContainsFunc(provider.OrganizationID, func(r rune) bool { return r <= ' ' || r == 127 })
}

// WithAssertionMapping selects the installed mapping for the same provider as
// the unsolicited ACS. Projection never replaces browser confirmation.
func (p IDPInitiatedPOSTResponseProfile) WithAssertionMapping(provider sso.Provider, mapping sso.AttributeMapping) (IDPInitiatedPOSTResponseProfile, error) {
	if provider.ID != p.providerID {
		return IDPInitiatedPOSTResponseProfile{}, ErrInvalidInput
	}
	verifier, err := p.verifier.WithAssertionMapping(provider, mapping)
	if err != nil {
		return IDPInitiatedPOSTResponseProfile{}, err
	}
	p.verifier = verifier
	return p, nil
}

// ProtocolAssertion returns detached observations for the opt-in mapping. It
// contains signed NameID provenance followed by each selected claim in mapping
// order, including absent and null values. The XML supplies no Verified or
// Authoritative assessment. Unselected, denied and zero results return
// ErrInvalidInput and no assertion; reserve the replay pair separately.
func (v VerifiedPOSTResponse) ProtocolAssertion() (sso.ProtocolAssertion, error) {
	return v.verified.protocolAssertion()
}

// ProtocolAssertion returns the detached mapped observations from an accepted
// unsolicited response. It does not establish browser, replay or login authority.
func (v VerifiedIDPInitiatedPOSTResponse) ProtocolAssertion() (sso.ProtocolAssertion, error) {
	return v.verified.protocolAssertion()
}

func (v verifiedPOSTResponseData) protocolAssertion() (sso.ProtocolAssertion, error) {
	if v.assertion == nil {
		return sso.ProtocolAssertion{}, ErrInvalidInput
	}
	assertion := *v.assertion
	assertion.Attributes = slices.Clone(assertion.Attributes)
	return assertion, nil
}

func (m postAssertionMapping) project(subject string, statements []*xdm.Node) (sso.ProtocolAssertion, error) {
	// SAML Core §§2.3.3, 2.7.3: the stable subject comes only from the
	// verified NameID. Include it as an observation so its exact issuer
	// remains available even for a subject-only mapping.
	nameID, err := sso.NewVerifiedAttribute(sso.VerifiedAttributeSpec{
		Name: samlNameIDClaim, Presence: sso.AttributeValue, StringValue: &subject, Provenance: m.provenance,
	})
	if err != nil {
		return sso.ProtocolAssertion{}, ErrInvalidInput
	}
	attributes := make([]sso.VerifiedAttribute, 1, 1+len(m.claims))
	attributes[0] = nameID
	if len(m.claims) != 0 {
		attributes, err = m.appendSelected(attributes, statements)
		if err != nil {
			return sso.ProtocolAssertion{}, err
		}
	}
	assertion, err := sso.NewProtocolAssertion(sso.ProtocolAssertion{
		ProviderID: m.provenance.ProviderID, OrganizationID: m.organizationID, ProviderSubject: subject, Attributes: attributes,
		ProviderProfileVersion: m.provenance.ProviderProfileVersion, MappingVersion: m.mappingVersion,
	})
	if err != nil {
		return sso.ProtocolAssertion{}, ErrInvalidInput
	}
	return assertion, nil
}

func (m postAssertionMapping) appendSelected(out []sso.VerifiedAttribute, statements []*xdm.Node) ([]sso.VerifiedAttribute, error) {
	var matches [3]*xdm.Node
	for _, statement := range statements {
		children, ok := samlElementChildren(statement, maximumSAMLXMLNodes)
		if !ok || len(children) == 0 || statement.NumAttrs() != 0 {
			return nil, ErrInvalidInput
		}
		for _, child := range children {
			// An EncryptedAttribute could hide a selected name. This profile
			// cannot decrypt it and must not present it as an absent claim.
			if !samlElement(child, samlAssertionNS, "Attribute") {
				return nil, ErrInvalidInput
			}
			name := samlAttr(child, "Name")
			if name == "" {
				return nil, ErrInvalidInput
			}
			for i, claim := range m.claims {
				if name != claim.name {
					continue
				}
				if matches[i] != nil {
					return nil, ErrInvalidInput
				}
				matches[i] = child
				break
			}
		}
	}
	for i, claim := range m.claims {
		spec := sso.VerifiedAttributeSpec{Name: claim.name, Presence: sso.AttributeAbsent, Provenance: m.provenance}
		if matches[i] != nil && !readSAMLAttribute(matches[i], claim, &spec) {
			return nil, ErrInvalidInput
		}
		attribute, err := sso.NewVerifiedAttribute(spec)
		if err != nil {
			return nil, ErrInvalidInput
		}
		out = append(out, attribute)
	}
	return out, nil
}

func readSAMLAttribute(attribute *xdm.Node, claim samlScalarClaim, spec *sso.VerifiedAttributeSpec) bool {
	for i := range attribute.NumAttrs() {
		attr := attribute.AttrAt(i)
		if attr.Name().URI != "" {
			return false
		}
		switch attr.Name().Local {
		case "Name", "FriendlyName":
		case "NameFormat":
			switch attr.Value() {
			case "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified",
				"urn:oasis:names:tc:SAML:2.0:attrname-format:uri", "urn:oasis:names:tc:SAML:2.0:attrname-format:basic":
			default:
				return false
			}
		default:
			return false
		}
	}
	children, ok := samlElementChildren(attribute, 1)
	if !ok || len(children) != 1 || !samlElement(children[0], samlAssertionNS, "AttributeValue") {
		return false
	}
	return readSAMLScalar(children[0], claim, spec)
}

func readSAMLScalar(value *xdm.Node, claim samlScalarClaim, spec *sso.VerifiedAttributeSpec) bool {
	isNil := false
	for i := range value.NumAttrs() {
		attr := value.AttrAt(i)
		if attr.Name().URI != samlXMLSchemaInstance {
			return false
		}
		switch attr.Name().Local {
		case "nil":
			var ok bool
			isNil, ok = samlSchemaBoolean(attr.Value())
			if !ok {
				return false
			}
		case "type":
			if !samlMatchesScalarType(value, attr.Value(), claim) {
				return false
			}
		default:
			return false
		}
	}
	var text strings.Builder
	for child := range value.Children() {
		switch child.Kind() {
		case xdm.KindText:
			if len(child.Value()) > maximumSAMLScalarBytes-text.Len() {
				return false
			}
			text.WriteString(child.Value())
		case xdm.KindComment:
			// Exclusive canonicalization excludes comments. Their presence
			// must not change the authenticated sequence of scalar text.
		default:
			return false
		}
	}
	if isNil {
		spec.Presence = sso.AttributeNull
		return text.Len() == 0
	}
	spec.Presence = sso.AttributeValue
	if claim.boolean {
		parsed, ok := samlSchemaBoolean(text.String())
		spec.BooleanValue = &parsed
		return ok
	}
	raw := text.String()
	spec.StringValue = &raw
	return true
}

func samlMatchesScalarType(value *xdm.Node, raw string, claim samlScalarClaim) bool {
	want := "string"
	if claim.boolean {
		want = "boolean"
	}
	prefix, local, qualified := strings.Cut(raw, ":")
	if !qualified {
		local, prefix = prefix, ""
	}
	if local != want || (qualified && !xdm.IsNCName(prefix)) {
		return false
	}
	// OASIS Core §2.7.3.1.1 permits an explicit XML Schema type. Its
	// QName's namespace binding may be omitted by exclusive canonicalization
	// (W3C Exclusive C14N §1.3). It can check, but never choose, the locally
	// selected decoder, trust, or value.
	namespace, bound := value.LookupPrefix(prefix)
	return bound && namespace == samlXMLSchemaNS
}

func samlSchemaBoolean(raw string) (bool, bool) {
	switch raw {
	case "true", "1":
		return true, true
	case "false", "0":
		return false, true
	default:
		return false, false
	}
}
