package oauth2

import (
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-sso"
)

func projectAssertion(exchange oauth.ExchangeResult, transaction sso.LoginTransaction, mapping sso.AttributeMappingSpec, proof sso.IdentityProofPolicySpec) (sso.ProtocolAssertion, error) {
	if transaction.Protocol != "oauth2" || mapping.Version != transaction.MappingVersion ||
		exchange.Identity.Subject() == "" || exchange.Identity.Issuer() != proof.Issuer {
		return sso.ProtocolAssertion{}, sso.ErrInvalidInput
	}

	names := selectedClaims(mapping)
	claims := exchange.ObservedOAuth2Claims()
	if len(claims) != len(names) {
		return sso.ProtocolAssertion{}, sso.ErrInvalidInput
	}
	provenance := sso.AttributeProvenance{
		ProviderID:             sso.ProviderID(transaction.ProviderID),
		ProviderProfileVersion: transaction.ProviderVersion,
		Issuer:                 exchange.Identity.Issuer(),
		Source:                 sso.AttributeSourceOAuthIdentityEndpoint,
	}
	attributes := make([]sso.VerifiedAttributeSpec, len(claims))
	verifiedEmail := false
	for index, claim := range claims {
		if claim.Name() != names[index] {
			return sso.ProtocolAssertion{}, sso.ErrInvalidInput
		}
		attribute := sso.VerifiedAttributeSpec{Name: claim.Name(), Provenance: provenance}
		switch claim.Kind() {
		case oauth.OAuth2ClaimAbsent:
			attribute.Presence = sso.AttributeAbsent
		case oauth.OAuth2ClaimNull:
			attribute.Presence = sso.AttributeNull
		case oauth.OAuth2ClaimString:
			value, _ := claim.StringValue()
			attribute.Presence, attribute.StringValue = sso.AttributeValue, &value
		case oauth.OAuth2ClaimBool:
			value, _ := claim.BoolValue()
			attribute.Presence, attribute.BooleanValue = sso.AttributeValue, &value
			if claim.Name() == mapping.VerifiedEmailClaim && proof.EmailVerification == sso.OAuthEmailBooleanClaim {
				verifiedEmail = value
			}
		default:
			return sso.ProtocolAssertion{}, sso.ErrInvalidInput
		}
		attributes[index] = attribute
	}

	assertion := sso.ProtocolAssertion{
		ProviderID:             sso.ProviderID(transaction.ProviderID),
		OrganizationID:         transaction.OrganizationID,
		ProviderSubject:        exchange.Identity.Subject(),
		ProviderProfileVersion: transaction.ProviderVersion,
		MappingVersion:         transaction.MappingVersion,
		Attributes:             make([]sso.VerifiedAttribute, len(attributes)),
	}
	for index, attribute := range attributes {
		if attribute.Name == mapping.EmailClaim && verifiedEmail && attribute.StringValue != nil && *attribute.StringValue != "" {
			attribute.Verified, attribute.Authoritative = true, true
		}
		var err error
		assertion.Attributes[index], err = sso.NewVerifiedAttribute(attribute)
		if err != nil {
			return sso.ProtocolAssertion{}, sso.ErrInvalidInput
		}
	}
	return sso.NewProtocolAssertion(assertion)
}

func selectedClaims(mapping sso.AttributeMappingSpec) []string {
	// The wire owner already validates and projects the stable subject. Selecting
	// it as a scalar observation would reject its supported integer encoding.
	names := make([]string, 0, 3)
	for _, name := range [...]string{mapping.EmailClaim, mapping.VerifiedEmailClaim, mapping.DisplayNameClaim} {
		if name == "" {
			continue
		}
		duplicate := false
		for _, selected := range names {
			if selected == name {
				duplicate = true
				break
			}
		}
		if !duplicate {
			names = append(names, name)
		}
	}
	return names
}
