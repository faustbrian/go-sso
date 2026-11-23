package saml

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"strconv"
	"strings"
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

// SPMetadataEndpoints explicitly selects optional SP metadata endpoints. The
// zero value advertises neither optional route. IDPInitiatedACS adds the
// non-default index-1 HTTP-POST /idp-init ACS; SingleLogout adds one HTTP-POST
// /slo endpoint. Both are derived from the same canonical origin and provider
// as the configured /acs route; neither accepts an externally supplied URL.
// These selections advertise metadata only, not route or provider activation.
type SPMetadataEndpoints struct {
	IDPInitiatedACS bool
	SingleLogout    bool
}

// ExportSPMetadata produces unsigned Metadata 2.0 XML for the first signed
// SP-initiated profile: signed AuthnRequests, signed assertions, signing-only
// certificates, and one default index-0 HTTP-POST ACS. It advertises neither
// Single Logout nor IdP-initiated login. Invalid configuration returns nil and
// ErrInvalidInput without exposing input. The result owns its bytes; inputs
// are never modified or retained, and callers must not mutate them concurrently.
// Approval, signing-key ownership and metadata publication remain with callers.
func ExportSPMetadata(config SPMetadataConfig) ([]byte, error) {
	return exportSPMetadata(config, "", "")
}

// ExportSPMetadataWithIDPInitiatedACS explicitly advertises a separate,
// non-default index-1 HTTP-POST ACS for IdP-initiated login while preserving
// the default index-0 SP-initiated ACS. AssertionConsumerURL must be the exact
// HTTPS /saml2/{provider}/acs route with a canonical 1..128-byte provider path
// segment. The additional URL is derived from that same origin and provider
// as /saml2/{provider}/idp-init; no second caller-supplied URL is accepted.
// Entity and certificate validation, ownership, concurrency and error semantics
// are the same as ExportSPMetadata. No Single Logout endpoint is advertised.
// This only exports unsigned metadata; provider approval, unsolicited-login
// policy, route exposure, signing-key ownership and publication remain with callers.
func ExportSPMetadataWithIDPInitiatedACS(config SPMetadataConfig) ([]byte, error) {
	return ExportSPMetadataWithEndpoints(config, SPMetadataEndpoints{IDPInitiatedACS: true})
}

// ExportSPMetadataWithEndpoints exports the same unsigned SP metadata as
// ExportSPMetadata plus only the explicitly selected optional endpoints. With
// zero options it preserves ExportSPMetadata's exact bytes and route policy;
// IDPInitiatedACS alone preserves ExportSPMetadataWithIDPInitiatedACS's bytes.
//
// Selecting either option requires AssertionConsumerURL to be the exact
// canonical HTTPS /saml2/{provider}/acs route with a 1..128-byte provider segment.
// The derived URLs are /saml2/{provider}/idp-init and /saml2/{provider}/slo on
// that same exact origin. Every selected URL must be at most 2048 bytes.
// SingleLogout advertises HTTP-POST only, never HTTP-Redirect; its element
// follows all signing keys and precedes the ACS endpoints in schema order.
//
// Entity/certificate validation, owned output bytes, borrowed inputs,
// concurrency and redacted errors are the same as ExportSPMetadata. This
// performs no I/O, trust-chain validation, route mounting, provider admission,
// session mutation or runtime activation. Publication remains with the caller.
func ExportSPMetadataWithEndpoints(config SPMetadataConfig, endpoints SPMetadataEndpoints) ([]byte, error) {
	if !endpoints.IDPInitiatedACS && !endpoints.SingleLogout {
		return exportSPMetadata(config, "", "")
	}
	prefix, ok := spMetadataProviderPrefix(config.AssertionConsumerURL)
	if !ok {
		return nil, ErrInvalidInput
	}
	var idpInitiatedURL, singleLogoutURL string
	if endpoints.IDPInitiatedACS {
		idpInitiatedURL = prefix + "/idp-init"
		if !samlAssertionConsumerURL(idpInitiatedURL) {
			return nil, ErrInvalidInput
		}
	}
	if endpoints.SingleLogout {
		singleLogoutURL = prefix + "/slo"
		if !samlAssertionConsumerURL(singleLogoutURL) {
			return nil, ErrInvalidInput
		}
	}
	return exportSPMetadata(config, idpInitiatedURL, singleLogoutURL)
}

func spMetadataProviderPrefix(assertionConsumerURL string) (string, bool) {
	consumer, ok := samlHTTPSURL(assertionConsumerURL, maximumEndpointBytes, false)
	if !ok || strings.Contains(consumer.EscapedPath(), "%") || strings.HasSuffix(consumer.Host, ":") {
		return "", false
	}
	provider, selected := strings.CutPrefix(consumer.Path, "/saml2/")
	if !selected {
		return "", false
	}
	provider, selected = strings.CutSuffix(provider, "/acs")
	if !selected || !validIDPInitiatedProviderSegment(provider) {
		return "", false
	}
	// Match NewIDPInitiatedPOSTResponseProfile's origin so advertised metadata
	// cannot select a destination rejected by the unsolicited-response verifier.
	if port := consumer.Port(); port != "" {
		value, err := strconv.ParseUint(port, 10, 16)
		if err != nil || value == 0 || strconv.FormatUint(value, 10) != port {
			return "", false
		}
	}
	return "https://" + consumer.Host + "/saml2/" + provider, true
}

func exportSPMetadata(config SPMetadataConfig, idpInitiatedURL, singleLogoutURL string) ([]byte, error) {
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
	consumers := []spMetadataConsumer{{
		Binding: httpPostBinding, Location: config.AssertionConsumerURL, Index: 0, Default: true,
	}}
	if idpInitiatedURL != "" {
		consumers = append(consumers, spMetadataConsumer{
			Binding: httpPostBinding, Location: idpInitiatedURL, Index: 1, Default: false,
		})
	}
	document := spMetadataEntityDescriptor{
		EntityID: config.EntityID,
		SP: spMetadataSPDescriptor{
			Protocol:             "urn:oasis:names:tc:SAML:2.0:protocol",
			AuthnRequestsSigned:  true,
			WantAssertionsSigned: true,
			Keys:                 keys,
			Consumers:            consumers,
		},
	}
	if singleLogoutURL != "" {
		document.SP.SingleLogout = &spMetadataEndpoint{Binding: httpPostBinding, Location: singleLogoutURL}
	}
	encoded, err := xml.Marshal(document)
	if err != nil {
		return nil, ErrInvalidInput
	}
	return encoded, nil
}

// OASIS Metadata 2.0 §§2.3.2, 2.4.1.1, 2.4.2 and 2.4.4 prescribe the namespaces,
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
	SingleLogout         *spMetadataEndpoint       `xml:"urn:oasis:names:tc:SAML:2.0:metadata SingleLogoutService,omitempty"`
	Consumers            []spMetadataConsumer      `xml:"urn:oasis:names:tc:SAML:2.0:metadata AssertionConsumerService"`
}

type spMetadataEndpoint struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
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
