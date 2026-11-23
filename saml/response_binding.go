package saml

import (
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/knroy/go-xml/v2/xdm"
)

func (p POSTResponseProfile) responseAssertion(response *xdm.Node, input POSTResponseInput) *xdm.Node {
	// OASIS Core §3.2.2: the successful, selected SP response is bound to the
	// original request and exact configured consumer. Extensions or additional
	// assertions do not enter this profile.
	if response.NumAttrs() != 5 || samlAttr(response, "Version") != "2.0" ||
		samlAttr(response, "Destination") != p.acs || samlAttr(response, "InResponseTo") != input.RequestID ||
		!p.validIssueInstant(response, input) {
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

func (p POSTResponseProfile) bindAssertion(assertion *xdm.Node, input POSTResponseInput) (POSTResponseEvidence, bool) {
	if assertion.NumAttrs() != 3 || samlAttr(assertion, "Version") != "2.0" || !p.validIssueInstant(assertion, input) {
		return POSTResponseEvidence{}, false
	}
	parts, ok := samlElementChildren(assertion, maximumSAMLXMLNodes)
	if !ok || len(parts) < 5 || !samlElement(parts[0], samlAssertionNS, "Issuer") ||
		!samlElement(parts[1], xmlSignatureNamespace, "Signature") || !samlElement(parts[2], samlAssertionNS, "Subject") ||
		!samlElement(parts[3], samlAssertionNS, "Conditions") || !samlElement(parts[4], samlAssertionNS, "AuthnStatement") {
		return POSTResponseEvidence{}, false
	}
	// Unselected AttributeStatements confer no privilege. They remain signed,
	// but are not mapped by the existing-linked-NameID profile.
	for _, part := range parts[5:] {
		if !samlElement(part, samlAssertionNS, "AttributeStatement") {
			return POSTResponseEvidence{}, false
		}
	}
	assertionExpiry, ok := p.bindConditions(parts[3], input.Now)
	if !ok {
		return POSTResponseEvidence{}, false
	}
	subject, format, confirmationExpiry, ok := p.bindSubject(parts[2], input)
	if !ok {
		return POSTResponseEvidence{}, false
	}
	remoteSessionIndex, remoteExpiry, ok := p.bindAuthnStatement(parts[4], input.Now)
	if !ok {
		return POSTResponseEvidence{}, false
	}
	validUntil := earlierSAMLTime(input.ExpiresAt, assertionExpiry.Add(p.skew))
	validUntil = earlierSAMLTime(validUntil, confirmationExpiry.Add(p.skew))
	if !remoteExpiry.IsZero() {
		validUntil = earlierSAMLTime(validUntil, remoteExpiry.Add(p.skew))
	}
	if !input.Now.Before(validUntil) {
		return POSTResponseEvidence{}, false
	}
	return POSTResponseEvidence{
		AssertionID: samlAttr(assertion, "ID"), ProviderSubject: subject, SubjectFormat: format,
		SessionIndex: remoteSessionIndex, AssertionExpiresAt: assertionExpiry, ValidUntil: validUntil,
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

func (p POSTResponseProfile) bindSubject(n *xdm.Node, input POSTResponseInput) (string, string, time.Time, bool) {
	children, ok := samlElementChildren(n, 2)
	if !ok || len(children) != 2 || n.NumAttrs() != 0 || !samlElement(children[0], samlAssertionNS, "NameID") ||
		!samlElement(children[1], samlAssertionNS, "SubjectConfirmation") {
		return "", "", time.Time{}, false
	}
	name := children[0]
	format := samlAttr(name, "Format")
	if format != samlPersistentNameID && format != samlEmailNameID {
		return "", "", time.Time{}, false
	}
	for i := range name.NumAttrs() {
		attribute := name.AttrAt(i)
		qname := attribute.Name()
		if qname.URI != "" {
			return "", "", time.Time{}, false
		}
		switch qname.Local {
		case "Format":
		case "NameQualifier":
			if attribute.Value() != p.idp {
				return "", "", time.Time{}, false
			}
		case "SPNameQualifier":
			if attribute.Value() != p.sp {
				return "", "", time.Time{}, false
			}
		default:
			return "", "", time.Time{}, false
		}
	}
	subject, ok := samlSimpleText(name, 512) // SSO ProtocolAssertion subject limit.
	if !ok || strings.TrimSpace(subject) == "" {
		return "", "", time.Time{}, false
	}
	confirmation := children[1]
	if confirmation.NumAttrs() != 1 || samlAttr(confirmation, "Method") != samlBearerConfirmation {
		return "", "", time.Time{}, false
	}
	data, ok := samlElementChildren(confirmation, 1)
	if !ok || len(data) != 1 || !samlElement(data[0], samlAssertionNS, "SubjectConfirmationData") {
		return "", "", time.Time{}, false
	}
	// OASIS Profiles §4.1.4.2: bearer confirmation is recipient-, expiry- and
	// request-bound. Unselected NotBefore/Address must not be silently ignored.
	if data[0].NumAttrs() != 3 || samlAttr(data[0], "Recipient") != p.acs || samlAttr(data[0], "InResponseTo") != input.RequestID {
		return "", "", time.Time{}, false
	}
	_, empty := samlElementChildren(data[0], 0)
	expiry, ok := parseSAMLTime(samlAttr(data[0], "NotOnOrAfter"))
	return subject, format, expiry, empty && ok && input.Now.Before(expiry.Add(p.skew))
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

func (p POSTResponseProfile) validIssueInstant(n *xdm.Node, input POSTResponseInput) bool {
	instant, ok := parseSAMLTime(samlAttr(n, "IssueInstant"))
	return ok && !instant.Before(input.IssuedAt.Add(-p.skew)) && !instant.After(input.Now.Add(p.skew))
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
