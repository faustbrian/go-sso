package saml

import (
	"context"
	"crypto/sha256"
	"strings"
	"time"

	"github.com/knroy/go-xml/v2/xdm"
)

const (
	samlMetadataNamespace      = "urn:oasis:names:tc:SAML:2.0:metadata"
	samlIDPHTTPRedirectBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
)

// IDPMetadata contains detached explicit registration inputs from one approved
// metadata document. SigningCertificates owns its DER slices; callers may
// change the result without changing the document or another import. This is
// not provider authority, an activation result, or evidence of certificate
// trust chains or current certificate validity. Its zero value is invalid.
type IDPMetadata struct {
	EntityID, RedirectEndpoint string
	SigningCertificates        [][]byte
}

// ImportIDPMetadata imports one bounded UTF-8 Metadata 2.0 EntityDescriptor.
// approvedSHA256 must be a nonzero digest obtained and approved separately;
// computing the digest from untrusted input does not establish its authority.
// Both the exact raw bytes and expectedEntityID must match before any fields
// are returned. The single direct SAML 2.0 IDPSSODescriptor must contain exactly
// one HTTP-Redirect SSO endpoint and 1..5 distinct usable signing certificates.
// Only signing or unspecified-use KeyDescriptors with X509Data contribute keys;
// other roles, bindings and encryption keys cannot supply fallback values.
//
// Entity and selected-role validUntil deadlines, when present, are exclusive
// against the explicit nonzero now. No cache, signature trust, URL retrieval,
// activation, or wall-clock certificate-validity decision is supplied. The
// existing registration validator checks the resulting fields and certificate
// profile. A refresh still requires separate endpoint/key approval by its owner.
//
// Inputs are borrowed synchronously, never modified or retained, and must not
// be changed concurrently. Independent calls share no mutable state. Failure
// returns a zero result and ErrInvalidInput, or the actual context error on
// cancellation; errors never contain document or configuration data.
func ImportIDPMetadata(ctx context.Context, document []byte, expectedEntityID string, approvedSHA256 [32]byte, now time.Time) (IDPMetadata, error) {
	if ctx == nil {
		return IDPMetadata{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return IDPMetadata{}, err
	}
	if len(document) == 0 || len(document) > maximumSAMLXMLBytes || approvedSHA256 == [32]byte{} ||
		!samlIdPEntityID(expectedEntityID) || !validSAMLTime(now) {
		return IDPMetadata{}, ErrInvalidInput
	}
	if sha256.Sum256(document) != approvedSHA256 {
		return IDPMetadata{}, ErrInvalidInput
	}
	root, err := parseSAMLDocument(ctx, document)
	if err != nil {
		return IDPMetadata{}, err
	}
	if !samlElement(root, samlMetadataNamespace, "EntityDescriptor") || samlAttr(root, "entityID") != expectedEntityID || !freshIDPMetadata(root, now) {
		return IDPMetadata{}, ErrInvalidInput
	}
	for node := range root.Descendants() {
		if err := ctx.Err(); err != nil {
			return IDPMetadata{}, err
		}
		if samlElement(node, samlMetadataNamespace, "EntityDescriptor") {
			return IDPMetadata{}, ErrInvalidInput
		}
	}

	role := selectedIDPMetadataRole(root)
	if role == nil || !freshIDPMetadata(role, now) {
		return IDPMetadata{}, ErrInvalidInput
	}
	result, err := importIDPMetadataRole(ctx, role)
	if err != nil {
		return IDPMetadata{}, err
	}
	result.EntityID = strings.Clone(expectedEntityID)
	if err := ValidateRegistration(ctx, result.EntityID, result.RedirectEndpoint, result.SigningCertificates); err != nil {
		return IDPMetadata{}, err
	}
	return result, nil
}

// Metadata 2.0 §§2.3.2 and 2.4.1.1 permit an explicit exclusive expiry at
// either level. cacheDuration is not a substitute for an absolute deadline or
// an authorization to cache/activate this detached registration projection.
func freshIDPMetadata(node *xdm.Node, now time.Time) bool {
	attribute := node.Attr("", "validUntil")
	if attribute == nil {
		return true
	}
	deadline, ok := parseSAMLTime(attribute.Value())
	return ok && now.Before(deadline)
}

func selectedIDPMetadataRole(root *xdm.Node) *xdm.Node {
	children, ok := samlElementChildren(root, maximumSAMLXMLNodes)
	if !ok {
		return nil
	}
	var selected *xdm.Node
	for _, child := range children {
		if !samlElement(child, samlMetadataNamespace, "IDPSSODescriptor") || !supportsSAML2Metadata(child) {
			continue
		}
		if selected != nil {
			return nil
		}
		selected = child
	}
	return selected
}

func supportsSAML2Metadata(role *xdm.Node) bool {
	// protocolSupportEnumeration is an XML-whitespace-separated anyURI list
	// (Metadata 2.0 §2.4.1.1), not a substring or Unicode-whitespace match.
	protocols := strings.FieldsFunc(samlAttr(role, "protocolSupportEnumeration"), func(character rune) bool {
		return character == ' ' || character == '\t' || character == '\r' || character == '\n'
	})
	for _, protocol := range protocols {
		if protocol == samlProtocolNS {
			return true
		}
	}
	return false
}

func importIDPMetadataRole(ctx context.Context, role *xdm.Node) (IDPMetadata, error) {
	children, ok := samlElementChildren(role, maximumSAMLXMLNodes)
	if !ok {
		return IDPMetadata{}, ErrInvalidInput
	}
	var result IDPMetadata
	redirectCount := 0
	for _, child := range children {
		if err := ctx.Err(); err != nil {
			return IDPMetadata{}, err
		}
		switch {
		case samlElement(child, samlMetadataNamespace, "SingleSignOnService"):
			if samlAttr(child, "Binding") != samlIDPHTTPRedirectBinding {
				continue
			}
			redirectCount++
			parts, valid := samlElementChildren(child, 0)
			if redirectCount != 1 || !valid || len(parts) != 0 {
				return IDPMetadata{}, ErrInvalidInput
			}
			result.RedirectEndpoint = strings.Clone(samlAttr(child, "Location"))
		case samlElement(child, samlMetadataNamespace, "KeyDescriptor"):
			use := samlAttr(child, "use")
			if use == "encryption" {
				continue
			}
			if use != "signing" && child.Attr("", "use") != nil {
				return IDPMetadata{}, ErrInvalidInput
			}
			certificates, err := importIDPMetadataKey(child, maximumMetadataCertificates-len(result.SigningCertificates))
			if err != nil {
				return IDPMetadata{}, err
			}
			result.SigningCertificates = append(result.SigningCertificates, certificates...)
		}
	}
	if redirectCount != 1 {
		return IDPMetadata{}, ErrInvalidInput
	}
	return result, nil
}

func importIDPMetadataKey(descriptor *xdm.Node, remaining int) ([][]byte, error) {
	// Metadata 2.0 §2.4.1.3 and XML Signature 1.1 §4.5.4: this selected
	// profile imports only explicit X.509 DER, never KeyValue/RetrievalMethod
	// or alternate material as a fallback for a missing or unusable pin.
	parts := signatureParts(descriptor, "KeyInfo")
	if parts == nil {
		return nil, ErrInvalidInput
	}
	parts = signatureParts(parts[0], "X509Data")
	if parts == nil {
		return nil, ErrInvalidInput
	}
	certificates, ok := samlElementChildren(parts[0], remaining)
	if !ok || len(certificates) == 0 {
		return nil, ErrInvalidInput
	}
	result := make([][]byte, 0, len(certificates))
	for _, certificate := range certificates {
		if !samlElement(certificate, xmlSignatureNamespace, "X509Certificate") || certificate.NumAttrs() != 0 {
			return nil, ErrInvalidInput
		}
		der, ok := decodeSignatureValue(certificate, maximumCertificateBytes)
		if !ok {
			return nil, ErrInvalidInput
		}
		result = append(result, der)
	}
	return result, nil
}
