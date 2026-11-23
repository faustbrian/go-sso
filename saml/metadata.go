package saml

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
)

const (
	// Reference saml.certificates_per_metadata_entity and saml.certificate_bytes
	// bound the approved active/rollover set before certificate parsing.
	maximumMetadataCertificates = 5
	maximumCertificateBytes     = 64 * 1024
)

// SPMetadataConfig contains already-approved SP identity, the SP-initiated
// HTTP-POST ACS, and 1..5 active/rollover public X.509 certificates in DER form.
// EntityID is an exact absolute HTTPS identifier of up to 1024 bytes. The ACS
// is an exact canonical HTTPS route of up to 2048 bytes, with no query. Neither
// admits a fragment or userinfo. Certificates must be distinct, at most 64 KiB
// each, and contain RSA keys compatible with the outbound RSA-PSS profile
// (at least 2048 bits).
// No private key, trust-chain validation or provider activation is performed.
type SPMetadataConfig struct {
	EntityID             string
	AssertionConsumerURL string
	SigningCertificates  [][]byte
}

// ExportSPMetadata produces unsigned Metadata 2.0 XML for the first signed
// SP-initiated profile: signed AuthnRequests, signed assertions, signing-only
// certificates, and one default index-0 HTTP-POST ACS. It advertises neither
// Single Logout nor IdP-initiated login. Invalid configuration returns nil and
// ErrInvalidInput without exposing input. The result owns its bytes; inputs
// are never modified or retained, and callers must not mutate them concurrently.
// Approval, signing-key ownership and metadata publication remain with callers.
func ExportSPMetadata(config SPMetadataConfig) ([]byte, error) {
	if !samlSPEntityID(config.EntityID) {
		return nil, ErrInvalidInput
	}
	if !samlAssertionConsumerURL(config.AssertionConsumerURL) {
		return nil, ErrInvalidInput
	}
	if len(config.SigningCertificates) < 1 || len(config.SigningCertificates) > maximumMetadataCertificates {
		return nil, ErrInvalidInput
	}

	seenCertificates := make(map[string]struct{}, len(config.SigningCertificates))
	for _, der := range config.SigningCertificates {
		if len(der) < 1 || len(der) > maximumCertificateBytes {
			return nil, ErrInvalidInput
		}
		identity := string(der)
		if _, duplicate := seenCertificates[identity]; duplicate {
			return nil, ErrInvalidInput
		}
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, ErrInvalidInput
		}
		publicKey, isRSA := certificate.PublicKey.(*rsa.PublicKey)
		if !isRSA || publicKey.N.BitLen() < 2048 {
			return nil, ErrInvalidInput
		}
		seenCertificates[identity] = struct{}{}
	}

	keys := make([]spMetadataKeyDescriptor, len(config.SigningCertificates))
	for i, der := range config.SigningCertificates {
		keys[i] = spMetadataKeyDescriptor{
			Use: "signing",
			KeyInfo: spMetadataKeyInfo{
				X509Data: spMetadataX509Data{Certificate: base64.StdEncoding.EncodeToString(der)},
			},
		}
	}
	document := spMetadataEntityDescriptor{
		EntityID: config.EntityID,
		SP: spMetadataSPDescriptor{
			Protocol:             "urn:oasis:names:tc:SAML:2.0:protocol",
			AuthnRequestsSigned:  true,
			WantAssertionsSigned: true,
			Keys:                 keys,
			Consumer: spMetadataConsumer{
				Binding: httpPostBinding, Location: config.AssertionConsumerURL, Index: 0, Default: true,
			},
		},
	}
	encoded, err := xml.Marshal(document)
	if err != nil {
		return nil, ErrInvalidInput
	}
	return encoded, nil
}

// OASIS Metadata 2.0 §§2.3.2, 2.4.1.1 and 2.4.4 prescribe the namespaces,
// attributes and child ordering; certificate material uses XML Signature KeyInfo.
type spMetadataEntityDescriptor struct {
	XMLName  xml.Name               `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	EntityID string                 `xml:"entityID,attr"`
	SP       spMetadataSPDescriptor `xml:"urn:oasis:names:tc:SAML:2.0:metadata SPSSODescriptor"`
}

type spMetadataSPDescriptor struct {
	Protocol             string                    `xml:"protocolSupportEnumeration,attr"`
	AuthnRequestsSigned  bool                      `xml:"AuthnRequestsSigned,attr"`
	WantAssertionsSigned bool                      `xml:"WantAssertionsSigned,attr"`
	Keys                 []spMetadataKeyDescriptor `xml:"urn:oasis:names:tc:SAML:2.0:metadata KeyDescriptor"`
	Consumer             spMetadataConsumer        `xml:"urn:oasis:names:tc:SAML:2.0:metadata AssertionConsumerService"`
}

type spMetadataKeyDescriptor struct {
	Use     string            `xml:"use,attr"`
	KeyInfo spMetadataKeyInfo `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
}

type spMetadataKeyInfo struct {
	X509Data spMetadataX509Data `xml:"http://www.w3.org/2000/09/xmldsig# X509Data"`
}

type spMetadataX509Data struct {
	Certificate string `xml:"http://www.w3.org/2000/09/xmldsig# X509Certificate"`
}

type spMetadataConsumer struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
	Index    uint16 `xml:"index,attr"`
	Default  bool   `xml:"isDefault,attr"`
}
