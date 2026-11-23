package saml_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-sso/saml"
)

const metadataNamespace = "urn:oasis:names:tc:SAML:2.0:metadata"
const signatureNamespace = "http://www.w3.org/2000/09/xmldsig#"

// OASIS Metadata 2.0 §§2.2.1–2.2.3, 2.3.2, 2.4.1, 2.4.1.1, 2.4.4.
func TestExportSPMetadataPublishesExactSignedSPProfile(t *testing.T) {
	key := metadataRSAKey(t, 2048)
	certificates := make([][]byte, 5)
	for i := range certificates {
		certificates[i] = metadataCertificate(t, key, &key.PublicKey, int64(i+1))
	}
	for _, certificateCount := range []int{1, 5} {
		config := saml.SPMetadataConfig{
			EntityID:             "HTTPS://identity.example/saml2/SP%2fexact?realm=one&service=saml",
			AssertionConsumerURL: "https://identity.example/saml2/acme/acs",
			SigningCertificates:  certificates[:certificateCount],
		}
		encoded, err := saml.ExportSPMetadata(config)
		if err != nil {
			t.Fatal(err)
		}
		var document metadataElement
		if err := xml.Unmarshal(encoded, &document); err != nil {
			t.Fatal(err)
		}
		assertMetadataElement(t, document, metadataNamespace, "EntityDescriptor", map[string]string{"entityID": config.EntityID}, 1)
		descriptor := document.Children[0]
		assertMetadataElement(t, descriptor, metadataNamespace, "SPSSODescriptor", map[string]string{
			"protocolSupportEnumeration": "urn:oasis:names:tc:SAML:2.0:protocol",
			"AuthnRequestsSigned":        "true",
			"WantAssertionsSigned":       "true",
		}, certificateCount+1)
		for i, expectedDER := range config.SigningCertificates {
			keyDescriptor := descriptor.Children[i]
			assertMetadataElement(t, keyDescriptor, metadataNamespace, "KeyDescriptor", map[string]string{"use": "signing"}, 1)
			keyInfo := keyDescriptor.Children[0]
			assertMetadataElement(t, keyInfo, signatureNamespace, "KeyInfo", nil, 1)
			certificateData := keyInfo.Children[0]
			assertMetadataElement(t, certificateData, signatureNamespace, "X509Data", nil, 1)
			certificate := certificateData.Children[0]
			assertMetadataElement(t, certificate, signatureNamespace, "X509Certificate", nil, 0)
			actualDER, err := base64.StdEncoding.Strict().DecodeString(certificate.Text)
			if err != nil || !bytes.Equal(actualDER, expectedDER) {
				t.Fatal("published certificate does not preserve the approved DER bytes")
			}
			if _, err := x509.ParseCertificate(actualDER); err != nil {
				t.Fatal("published certificate is not consumable X.509 DER")
			}
		}
		assertMetadataElement(t, descriptor.Children[certificateCount], metadataNamespace, "AssertionConsumerService", map[string]string{
			"Binding":   "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
			"Location":  config.AssertionConsumerURL,
			"index":     "0",
			"isDefault": "true",
		}, 0)
	}
}

// OASIS Metadata 2.0 §§2.2.1–2.2.3 and the reference entity/URI bounds.
func TestExportSPMetadataValidatesExactHTTPSConfiguration(t *testing.T) {
	key := metadataRSAKey(t, 2048)
	certificate := metadataCertificate(t, key, &key.PublicKey, 1)
	base := saml.SPMetadataConfig{
		EntityID: "https://identity.example/sp", AssertionConsumerURL: "https://identity.example/saml2/acme/acs",
		SigningCertificates: [][]byte{certificate},
	}
	for _, field := range []string{"entity", "acs"} {
		limit := 1024
		if field == "acs" {
			limit = 2048
		}
		invalidURLs := []string{
			"", "http://identity.example/acs", "https:///acs", "https://user:secret@identity.example/acs",
			"https://identity.example/acs#fragment", "https://identity.example/acs?x=%zz",
			"https://identity.example/\\acs", "https://identity.example/%zz", " https://identity.example/acs",
			"https://identity.example/acs\n", "https://identity.example/" + strings.Repeat("a", limit+1-len("https://identity.example/")),
		}
		if field == "acs" {
			invalidURLs = append(invalidURLs, "https://identity.example/acs?", "https://identity.example/acs?x=y",
				"https://identity.example/saml2/provider%2Facme/acs", "https://identity.example/saml2/provider%20acme/acs")
		}
		for _, invalid := range invalidURLs {
			config := base
			if field == "entity" {
				config.EntityID = invalid
			} else {
				config.AssertionConsumerURL = invalid
			}
			encoded, err := saml.ExportSPMetadata(config)
			if !errors.Is(err, saml.ErrInvalidInput) || encoded != nil {
				t.Errorf("%s configuration accepted or returned usable metadata", field)
			}
			if err != nil && strings.Contains(err.Error(), "user:secret") {
				t.Fatal("invalid configuration leaked credential material")
			}
		}
	}
	for _, root := range []string{"https://identity.example", "https://identity.example/"} {
		config := base
		config.AssertionConsumerURL = root
		encoded, err := saml.ExportSPMetadata(config)
		if !errors.Is(err, saml.ErrInvalidInput) || encoded != nil {
			t.Fatal("accepted an ACS without a registered path")
		}
	}
	config := base
	config.EntityID = "https://identity.example/" + strings.Repeat("e", 1024-len("https://identity.example/"))
	config.AssertionConsumerURL = "https://identity.example/" + strings.Repeat("a", 2048-len("https://identity.example/"))
	if _, err := saml.ExportSPMetadata(config); err != nil {
		t.Fatal("rejected valid URLs at the configured byte limits")
	}
}

// OASIS Metadata 2.0 §2.4.1.1 and the reference RSA-PSS/certificate bounds.
func TestExportSPMetadataRejectsInvalidSigningCertificateSets(t *testing.T) {
	key := metadataRSAKey(t, 2048)
	certificate := metadataCertificate(t, key, &key.PublicKey, 1)
	weakKey := metadataRSAKey(t, 1024)
	weakCertificate := metadataCertificate(t, weakKey, &weakKey.PublicKey, 2)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecCertificate := metadataCertificate(t, key, &ecKey.PublicKey, 3)
	tooMany := make([][]byte, 6)
	for i := range tooMany {
		tooMany[i] = metadataCertificate(t, key, &key.PublicKey, int64(i+10))
	}
	oversized := metadataSizedCertificate(t, key, 64*1024+1)
	for _, tc := range []struct {
		name         string
		certificates [][]byte
	}{
		{"absent", nil},
		{"too many distinct certificates", tooMany},
		{"empty certificate", [][]byte{nil}},
		{"malformed DER", [][]byte{[]byte("not a certificate")}},
		{"truncated DER", [][]byte{certificate[:len(certificate)-1]}},
		{"trailing DER", [][]byte{append(bytes.Clone(certificate), 0)}},
		{"oversized valid DER", [][]byte{oversized}},
		{"PEM instead of DER", [][]byte{pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate})}},
		{"private key instead of certificate", [][]byte{x509.MarshalPKCS1PrivateKey(key)}},
		{"duplicate certificate", [][]byte{certificate, bytes.Clone(certificate)}},
		{"nonadjacent duplicate certificate", [][]byte{certificate, tooMany[0], bytes.Clone(certificate)}},
		{"undersized RSA", [][]byte{weakCertificate}},
		{"ECDSA cannot sign mandatory PSS requests", [][]byte{ecCertificate}},
		{"malformed rollover certificate", [][]byte{certificate, []byte("not a certificate")}},
		{"undersized rollover RSA", [][]byte{certificate, weakCertificate}},
		{"unsupported rollover key", [][]byte{certificate, ecCertificate}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := saml.ExportSPMetadata(saml.SPMetadataConfig{
				EntityID: "https://identity.example/sp", AssertionConsumerURL: "https://identity.example/saml2/acme/acs",
				SigningCertificates: tc.certificates,
			})
			if !errors.Is(err, saml.ErrInvalidInput) || encoded != nil {
				t.Fatal("invalid certificate set accepted or returned usable metadata")
			}
		})
	}
	if _, err := saml.ExportSPMetadata(saml.SPMetadataConfig{
		EntityID: "https://identity.example/sp", AssertionConsumerURL: "https://identity.example/saml2/acme/acs",
		SigningCertificates: [][]byte{metadataSizedCertificate(t, key, 64*1024)},
	}); err != nil {
		t.Fatal("rejected a valid certificate at the DER byte limit")
	}
}

type metadataElement struct {
	XMLName  xml.Name
	Attrs    []xml.Attr        `xml:",any,attr"`
	Children []metadataElement `xml:",any"`
	Text     string            `xml:",chardata"`
}

func assertMetadataElement(t *testing.T, element metadataElement, namespace, name string, expectedAttrs map[string]string, children int) {
	t.Helper()
	if element.XMLName != (xml.Name{Space: namespace, Local: name}) || len(element.Children) != children {
		t.Fatalf("unexpected metadata element %v with %d children", element.XMLName, len(element.Children))
	}
	attrs := make(map[string]string)
	for _, attr := range element.Attrs {
		if attr.Name.Local == "xmlns" || attr.Name.Space == "xmlns" {
			continue
		}
		if attr.Name.Space != "" {
			t.Fatalf("unexpected namespaced attribute on %s", name)
		}
		if _, duplicate := attrs[attr.Name.Local]; duplicate {
			t.Fatalf("duplicate attribute on %s", name)
		}
		attrs[attr.Name.Local] = attr.Value
	}
	if len(attrs) != len(expectedAttrs) {
		t.Fatalf("unexpected %s attributes: %v", name, attrs)
	}
	for key, expected := range expectedAttrs {
		if attrs[key] != expected {
			t.Fatalf("%s %s = %q, want %q", name, key, attrs[key], expected)
		}
	}
}

func metadataRSAKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func metadataCertificate(t *testing.T, signer *rsa.PrivateKey, publicKey any, serial int64) []byte {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "SP metadata test"},
		NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func metadataSizedCertificate(t *testing.T, signer *rsa.PrivateKey, size int) []byte {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(100), Subject: pkix.Name{CommonName: "SP metadata byte limit"},
		NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: make([]byte, size)}},
	}
	for range 4 {
		der, err := x509.CreateCertificate(rand.Reader, template, template, &signer.PublicKey, signer)
		if err != nil {
			t.Fatal(err)
		}
		if len(der) == size {
			if _, err := x509.ParseCertificate(der); err != nil {
				t.Fatal("byte-limit fixture is not valid DER")
			}
			return der
		}
		paddingSize := len(template.ExtraExtensions[0].Value) + size - len(der)
		template.ExtraExtensions[0].Value = make([]byte, paddingSize)
	}
	t.Fatal("could not construct exact certificate byte-limit fixture")
	return nil
}
