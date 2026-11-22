package oidc

import (
	"slices"

	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-sso"
)

func selectedClaims(mapping sso.AttributeMappingSpec) ([]string, error) {
	if mapping.SubjectClaim != "sub" || mapping.VerifiedEmailClaim != "" && mapping.EmailClaim == "" {
		return nil, sso.ErrInvalidInput
	}
	// Do not let one observation satisfy both sides of the verified-email
	// decision, or turn a protocol binding into an application claim.
	names := make([]string, 0, 3)
	for _, name := range [...]string{mapping.EmailClaim, mapping.VerifiedEmailClaim, mapping.DisplayNameClaim} {
		if name == "" {
			continue
		}
		if slices.Contains(names, name) || !validClaimName(name) {
			return nil, sso.ErrInvalidInput
		}
		names = append(names, name)
	}
	return names, nil
}

func validClaimName(name string) bool {
	switch name {
	case "sub", "iss", "aud", "azp", "iat", "exp", "nbf", "auth_time", "nonce", "at_hash", "c_hash", "access_token", "refresh_token", "id_token":
		return false
	}
	// Match the bounded wire projection grammar before exposing a redirect for
	// a profile that could never complete.
	if len(name) == 0 || len(name) > 128 {
		return false
	}
	for i := range len(name) {
		c := name[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c == '_' {
			continue
		}
		if i == 0 || !(c >= '0' && c <= '9' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

func (s *Service) projectAssertion(exchange oauth.ExchangeResult) (sso.ProtocolAssertion, error) {
	id, tx := exchange.Identity, s.cfg.Transaction
	if id.ProviderID() != s.cfg.Profile.ID || id.Issuer() != s.cfg.Profile.Issuer {
		return sso.ProtocolAssertion{}, sso.ErrInvalidInput
	}
	claims := exchange.VerifiedOIDCClaims()
	if len(claims) != len(s.claims) {
		return sso.ProtocolAssertion{}, sso.ErrInvalidInput
	}
	provenance := sso.AttributeProvenance{
		ProviderID: sso.ProviderID(tx.ProviderID), ProviderProfileVersion: tx.ProviderVersion,
		Issuer: id.Issuer(), Source: sso.AttributeSourceOIDCIDToken,
	}
	verifiedEmail := false
	for _, claim := range claims {
		if claim.Name() == s.mapping.VerifiedEmailClaim {
			verifiedEmail, _ = claim.BoolValue()
		}
	}
	attributes := make([]sso.VerifiedAttribute, len(claims))
	for i, claim := range claims {
		if claim.Name() != s.claims[i] {
			return sso.ProtocolAssertion{}, sso.ErrInvalidInput
		}
		spec := sso.VerifiedAttributeSpec{Name: claim.Name(), Provenance: provenance}
		switch claim.Kind() {
		case oauth.OIDCClaimAbsent:
			spec.Presence = sso.AttributeAbsent
		case oauth.OIDCClaimNull:
			spec.Presence = sso.AttributeNull
		case oauth.OIDCClaimString:
			value, _ := claim.StringValue()
			spec.Presence, spec.StringValue = sso.AttributeValue, &value
			if claim.Name() == s.mapping.EmailClaim && verifiedEmail && value != "" {
				spec.Verified, spec.Authoritative = true, true
			}
		case oauth.OIDCClaimBool:
			value, _ := claim.BoolValue()
			spec.Presence, spec.BooleanValue = sso.AttributeValue, &value
		default:
			return sso.ProtocolAssertion{}, sso.ErrInvalidInput
		}
		attribute, err := sso.NewVerifiedAttribute(spec)
		if err != nil {
			return sso.ProtocolAssertion{}, err
		}
		attributes[i] = attribute
	}
	return sso.NewProtocolAssertion(sso.ProtocolAssertion{
		ProviderID: sso.ProviderID(tx.ProviderID), OrganizationID: tx.OrganizationID, ProviderSubject: id.Subject(),
		ProviderProfileVersion: tx.ProviderVersion, MappingVersion: tx.MappingVersion, Attributes: attributes,
	})
}
