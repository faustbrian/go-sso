package saml

import (
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/knroy/go-xml/v2/xdm"
)

func (p POSTResponseProfile) responseAssertion(response *xdm.Node, binding postResponseBinding) *xdm.Node {
	// OASIS Core §3.2.2: bind the successful response to the exact configured
	// consumer and the selected request mode. Neither profile permits extensions
	// or additional assertions here.
	if !binding.matchesRequest(response, 4) || samlAttr(response, "Version") != "2.0" || samlAttr(response, "Destination") != p.acs {
		return nil
	}
	children, ok := samlElementChildren(response, 4)
	if !ok || len(children) != 4 || !samlElement(children[0], samlAssertionNS, "Issuer") ||
		!samlElement(children[1], xmlSignatureNamespace, "Signature") ||
		!samlElement(children[2], samlProtocolNS, "Status") || !successfulSAMLStatus(children[2]) ||
		!samlElement(children[3], samlAssertionNS, "Assertion") {
		return nil
	}
	return children[3]
}

func successfulSAMLStatus(status *xdm.Node) bool {
	children, ok := samlElementChildren(status, 1)
	if !ok || status.NumAttrs() != 0 || len(children) != 1 || !samlElement(children[0], samlProtocolNS, "StatusCode") {
		return false
	}
	code := children[0]
	_, empty := samlElementChildren(code, 0)
	return empty && code.NumAttrs() == 1 && samlAttr(code, "Value") == samlStatusSuccess
}

func (p POSTResponseProfile) bindAssertion(assertion *xdm.Node, binding postResponseBinding) (verifiedPOSTResponseData, bool) {
	localCutoff, ok := p.issueCutoff(assertion, binding)
	if assertion.NumAttrs() != 3 || samlAttr(assertion, "Version") != "2.0" || !ok {
		return verifiedPOSTResponseData{}, false
	}
	parts, ok := samlElementChildren(assertion, maximumSAMLXMLNodes)
	if !ok || len(parts) < 5 || !samlElement(parts[0], samlAssertionNS, "Issuer") ||
		!samlElement(parts[1], xmlSignatureNamespace, "Signature") || !samlElement(parts[2], samlAssertionNS, "Subject") ||
		!samlElement(parts[3], samlAssertionNS, "Conditions") || !samlElement(parts[4], samlAssertionNS, "AuthnStatement") {
		return verifiedPOSTResponseData{}, false
	}
	// Unselected AttributeStatements confer no privilege. They remain signed,
	// but are not mapped by the existing-linked-NameID profile.
	for _, part := range parts[5:] {
		if !samlElement(part, samlAssertionNS, "AttributeStatement") {
			return verifiedPOSTResponseData{}, false
		}
	}
	assertionExpiry, ok := p.bindConditions(parts[3], binding.now)
	if !ok {
		return verifiedPOSTResponseData{}, false
	}
	subject, confirmationExpiry, ok := p.bindSubject(parts[2], binding)
	if !ok {
		return verifiedPOSTResponseData{}, false
	}
	remoteSessionIndex, remoteExpiry, ok := p.bindAuthnStatement(parts[4], binding.now)
	if !ok {
		return verifiedPOSTResponseData{}, false
	}
	validUntil := earlierSAMLTime(localCutoff, assertionExpiry.Add(p.skew))
	validUntil = earlierSAMLTime(validUntil, confirmationExpiry.Add(p.skew))
	if !remoteExpiry.IsZero() {
		validUntil = earlierSAMLTime(validUntil, remoteExpiry.Add(p.skew))
	}
	if !binding.now.Before(validUntil) {
		return verifiedPOSTResponseData{}, false
	}
	return verifiedPOSTResponseData{
		evidence: POSTResponseEvidence{
			AssertionID: samlAttr(assertion, "ID"), ProviderSubject: subject.value, SubjectFormat: subject.format,
			SessionIndex: remoteSessionIndex, AssertionExpiresAt: assertionExpiry, ValidUntil: validUntil,
		},
		nameQualifier: subject.nameQualifier, spNameQualifier: subject.spNameQualifier,
	}, true
}

func (p POSTResponseProfile) bindConditions(n *xdm.Node, now time.Time) (time.Time, bool) {
	// Exact selected audience, with one explicit restriction (Core §2.5.1.4).
	begin, beforeOK := parseSAMLTime(samlAttr(n, "NotBefore"))
	expires, afterOK := parseSAMLTime(samlAttr(n, "NotOnOrAfter"))
	if n.NumAttrs() != 2 || !beforeOK || !afterOK || !begin.Before(expires) ||
		now.Add(p.skew).Before(begin) || !now.Before(expires.Add(p.skew)) {
		return time.Time{}, false
	}
	children, ok := samlElementChildren(n, 1)
	if !ok || len(children) != 1 || !samlElement(children[0], samlAssertionNS, "AudienceRestriction") || children[0].NumAttrs() != 0 {
		return time.Time{}, false
	}
	audiences, ok := samlElementChildren(children[0], 1)
	if !ok || len(audiences) != 1 || !samlElement(audiences[0], samlAssertionNS, "Audience") || audiences[0].NumAttrs() != 0 {
		return time.Time{}, false
	}
	value, ok := samlSimpleText(audiences[0], maximumEndpointBytes)
	return expires, ok && value == p.sp
}

type samlNameID struct{ value, format, nameQualifier, spNameQualifier string }

func (p POSTResponseProfile) bindSubject(n *xdm.Node, binding postResponseBinding) (samlNameID, time.Time, bool) {
	children, ok := samlElementChildren(n, 2)
	if !ok || len(children) != 2 || n.NumAttrs() != 0 || !samlElement(children[0], samlAssertionNS, "NameID") ||
		!samlElement(children[1], samlAssertionNS, "SubjectConfirmation") {
		return samlNameID{}, time.Time{}, false
	}
	name := children[0]
	subject := samlNameID{format: samlAttr(name, "Format")}
	if subject.format != samlPersistentNameID && subject.format != samlEmailNameID {
		return samlNameID{}, time.Time{}, false
	}
	for i := range name.NumAttrs() {
		attribute := name.AttrAt(i)
		qname := attribute.Name()
		if qname.URI != "" {
			return samlNameID{}, time.Time{}, false
		}
		switch qname.Local {
		case "Format":
		case "NameQualifier":
			if attribute.Value() != p.idp {
				return samlNameID{}, time.Time{}, false
			}
			subject.nameQualifier = attribute.Value()
		case "SPNameQualifier":
			if attribute.Value() != p.sp {
				return samlNameID{}, time.Time{}, false
			}
			subject.spNameQualifier = attribute.Value()
		default:
			return samlNameID{}, time.Time{}, false
		}
	}
	subject.value, ok = samlSimpleText(name, 512) // SSO ProtocolAssertion subject limit.
	if !ok || strings.TrimSpace(subject.value) == "" {
		return samlNameID{}, time.Time{}, false
	}
	confirmation := children[1]
	if confirmation.NumAttrs() != 1 || samlAttr(confirmation, "Method") != samlBearerConfirmation {
		return samlNameID{}, time.Time{}, false
	}
	data, ok := samlElementChildren(confirmation, 1)
	if !ok || len(data) != 1 || !samlElement(data[0], samlAssertionNS, "SubjectConfirmationData") {
		return samlNameID{}, time.Time{}, false
	}
	// OASIS Profiles §§4.1.4.2, 4.1.5: bind the bearer confirmation to the
	// recipient, expiry and selected request mode. Do not ignore extra fields.
	if !binding.matchesRequest(data[0], 2) || samlAttr(data[0], "Recipient") != p.acs {
		return samlNameID{}, time.Time{}, false
	}
	_, empty := samlElementChildren(data[0], 0)
	expiry, ok := parseSAMLTime(samlAttr(data[0], "NotOnOrAfter"))
	if !empty || !ok || !binding.now.Before(expiry.Add(p.skew)) {
		return samlNameID{}, time.Time{}, false
	}
	return subject, expiry, true
}

func (p POSTResponseProfile) bindAuthnStatement(n *xdm.Node, now time.Time) (string, time.Time, bool) {
	// An IdP may reuse an existing login; AuthnInstant need not follow the
	// original AuthnRequest. It must not be in the future beyond selected skew.
	instant, ok := parseSAMLTime(samlAttr(n, "AuthnInstant"))
	if !ok || instant.After(now.Add(p.skew)) {
		return "", time.Time{}, false
	}
	var sessionIndex string
	var expiry time.Time
	for i := range n.NumAttrs() {
		attr := n.AttrAt(i)
		name, value := attr.Name(), attr.Value()
		if name.URI != "" {
			return "", time.Time{}, false
		}
		switch name.Local {
		case "AuthnInstant":
		case "SessionIndex":
			if value == "" || len(value) > maximumEndpointBytes || !utf8.ValidString(value) || strings.ContainsFunc(value, unicode.IsControl) {
				return "", time.Time{}, false
			}
			sessionIndex = value
		case "SessionNotOnOrAfter":
			expiry, ok = parseSAMLTime(value)
			if !ok || !expiry.After(instant) || !now.Before(expiry.Add(p.skew)) {
				return "", time.Time{}, false
			}
		default:
			return "", time.Time{}, false
		}
	}
	children, ok := samlElementChildren(n, 1)
	if !ok || len(children) != 1 || !samlElement(children[0], samlAssertionNS, "AuthnContext") || children[0].NumAttrs() != 0 {
		return "", time.Time{}, false
	}
	refs, ok := samlElementChildren(children[0], 1)
	if !ok || len(refs) != 1 || !samlElement(refs[0], samlAssertionNS, "AuthnContextClassRef") || refs[0].NumAttrs() != 0 {
		return "", time.Time{}, false
	}
	_, ok = samlSimpleText(refs[0], maximumEndpointBytes)
	return sessionIndex, expiry, ok
}

func (b postResponseBinding) matchesRequest(n *xdm.Node, otherAttrs int) bool {
	request := n.Attr("", "InResponseTo")
	if b.maximumUnsolicitedAge != 0 {
		// Profiles §4.1.5: an empty attribute is not absence. The exact
		// attribute count additionally excludes namespace-qualified aliases.
		return request == nil && n.NumAttrs() == otherAttrs
	}
	return request != nil && request.Value() == b.requestID && n.NumAttrs() == otherAttrs+1
}

func (p POSTResponseProfile) issueCutoff(n *xdm.Node, binding postResponseBinding) (time.Time, bool) {
	instant, ok := parseSAMLTime(samlAttr(n, "IssueInstant"))
	if !ok || instant.After(binding.now.Add(p.skew)) {
		return time.Time{}, false
	}
	if binding.maximumUnsolicitedAge == 0 {
		return binding.expiresAt, !instant.Before(binding.issuedAt.Add(-p.skew))
	}
	cutoff := instant.Add(binding.maximumUnsolicitedAge)
	if !binding.expiresAt.IsZero() {
		cutoff = earlierSAMLTime(cutoff, binding.expiresAt)
	}
	return cutoff, binding.now.Before(cutoff)
}

func parseSAMLTime(source string) (time.Time, bool) {
	// Core §1.3.3 requires expressed UTC times. Validate the lexical bound
	// before parsing and retain the actual signed timestamp.
	if len(source) > 64 || !strings.HasSuffix(source, "Z") {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, source)
	return t, err == nil && validSAMLTime(t)
}

func earlierSAMLTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
