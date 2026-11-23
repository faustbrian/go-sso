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

func TestExportSPMetadataWithIDPInitiatedACSPreservesDefaultAndAddsDerivedDestination(t *testing.T) {
	key := metadataRSAKey(t, 2048)
	certificate := metadataCertificate(t, key, &key.PublicKey, 1)
	for _, tc := range []struct {
		origin, provider string
	}{
		{"https://identity.example", "acme"},
		{"https://Identity.Example:9443", "Tenant_0123.-"},
		{"https://[2001:db8::1]:9443", strings.Repeat("p", 128)},
	} {
		t.Run(tc.provider, func(t *testing.T) {
			originalCertificate := bytes.Clone(certificate)
			config := saml.SPMetadataConfig{
				EntityID:             "HTTPS://identity.example/SP%2fexact?realm=one&service=saml",
				AssertionConsumerURL: tc.origin + "/saml2/" + tc.provider + "/acs",
				SigningCertificates:  [][]byte{certificate},
			}
			defaultXML, err := saml.ExportSPMetadata(config)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := saml.ExportSPMetadataWithIDPInitiatedACS(config)
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
				"AuthnRequestsSigned":        "true", "WantAssertionsSigned": "true",
			}, 3)
			assertMetadataElement(t, descriptor.Children[1], metadataNamespace, "AssertionConsumerService", map[string]string{
				"Binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", "Location": config.AssertionConsumerURL,
				"index": "0", "isDefault": "true",
			}, 0)
			idpURL := tc.origin + "/saml2/" + tc.provider + "/idp-init"
			assertMetadataElement(t, descriptor.Children[2], metadataNamespace, "AssertionConsumerService", map[string]string{
				"Binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", "Location": idpURL,
				"index": "1", "isDefault": "false",
			}, 0)
			additionalConsumer := `<AssertionConsumerService xmlns="` + metadataNamespace + `" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="` + idpURL + `" index="1" isDefault="false"></AssertionConsumerService>`
			withoutOptIn := strings.Replace(string(encoded), additionalConsumer, "", 1)
			if withoutOptIn != string(defaultXML) {
				t.Fatal("opt-in changed existing metadata bytes beyond the additional non-default ACS")
			}
			if !bytes.Equal(config.SigningCertificates[0], originalCertificate) {
				t.Fatal("metadata export mutated caller certificate bytes")
			}
		})
	}
}

func TestExportSPMetadataWithIDPInitiatedACSRejectsNoncanonicalSelectedRoute(t *testing.T) {
	key := metadataRSAKey(t, 2048)
	certificate := metadataCertificate(t, key, &key.PublicKey, 1)
	for _, destination := range []string{
		"", "http://identity.example/saml2/acme/acs", "HTTPS://identity.example/saml2/acme/acs",
		"https://identity.example:/saml2/acme/acs", "https://identity.example:0/saml2/acme/acs",
		"https://identity.example:65536/saml2/acme/acs", "https://identity.example:09443/saml2/acme/acs",
		"https://user:secret@identity.example/saml2/acme/acs", "https://identity.example/saml2/acme/acs?",
		"https://identity.example/saml2/acme/acs?provider=other", "https://identity.example/saml2/acme/acs#fragment",
		"https://identity.example/acs", "https://identity.example/prefix/saml2/acme/acs",
		"https://identity.example/saml2/acme/ACS", "https://identity.example/saml2/acme/acs/",
		"https://identity.example/saml2/acme/idp-init", "https://identity.example/saml2/acme/slo",
		"https://identity.example/saml2//acs", "https://identity.example/saml2/./acs",
		"https://identity.example/saml2/../acs", "https://identity.example/saml2/one/two/acs",
		"https://identity.example/saml2/%61cme/acs", "https://identity.example/saml2/acme%2fother/acs",
		"https://identity.example/saml2/acme%252fother/acs", "https://identity.example/saml2/{provider}/acs",
		"https://identity.example/saml2/acme\\other/acs", "https://identity.example/saml2/é/acs",
		"https://identity.example/saml2/" + strings.Repeat("p", 129) + "/acs",
	} {
		config := saml.SPMetadataConfig{
			EntityID: "https://identity.example/sp", AssertionConsumerURL: destination,
			SigningCertificates: [][]byte{certificate},
		}
		encoded, err := saml.ExportSPMetadataWithIDPInitiatedACS(config)
		if !errors.Is(err, saml.ErrInvalidInput) || encoded != nil {
			t.Errorf("noncanonical selected ACS accepted: %q", destination)
		}
		if err != nil && strings.Contains(err.Error(), "user:secret") {
			t.Fatal("invalid configuration leaked credential material")
		}
	}
}

func TestExportSPMetadataWithIDPInitiatedACSBoundsDerivedDestination(t *testing.T) {
	key := metadataRSAKey(t, 2048)
	certificate := metadataCertificate(t, key, &key.PublicKey, 1)
	for _, length := range []int{2048, 2049} {
		origin := "https://" + strings.Repeat("a", length-len("https:///saml2/acme/idp-init"))
		encoded, err := saml.ExportSPMetadataWithIDPInitiatedACS(saml.SPMetadataConfig{
			EntityID: "https://identity.example/sp", AssertionConsumerURL: origin + "/saml2/acme/acs",
			SigningCertificates: [][]byte{certificate},
		})
		if length == 2048 && (err != nil || len(encoded) == 0) {
			t.Fatal("rejected the derived destination at its exact byte limit", err)
		}
		if length > 2048 && (!errors.Is(err, saml.ErrInvalidInput) || encoded != nil) {
			t.Fatal("accepted an oversized derived destination")
		}
	}
}

func TestExportSPMetadataWithIDPInitiatedACSRetainsConfigurationValidation(t *testing.T) {
	key := metadataRSAKey(t, 2048)
	certificate := metadataCertificate(t, key, &key.PublicKey, 1)
	base := saml.SPMetadataConfig{
		EntityID: "https://identity.example/sp", AssertionConsumerURL: "https://identity.example/saml2/acme/acs",
		SigningCertificates: [][]byte{certificate},
	}
	for _, tc := range []struct {
		name   string
		change func(*saml.SPMetadataConfig)
	}{
		{"invalid entity", func(c *saml.SPMetadataConfig) { c.EntityID = "http://identity.example/sp" }},
		{"absent certificates", func(c *saml.SPMetadataConfig) { c.SigningCertificates = nil }},
		{"duplicate certificates", func(c *saml.SPMetadataConfig) { c.SigningCertificates = [][]byte{certificate, certificate} }},
		{"malformed certificate", func(c *saml.SPMetadataConfig) { c.SigningCertificates = [][]byte{[]byte("invalid DER")} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := base
			tc.change(&config)
			encoded, err := saml.ExportSPMetadataWithIDPInitiatedACS(config)
			if !errors.Is(err, saml.ErrInvalidInput) || encoded != nil {
				t.Fatal("invalid metadata configuration accepted or returned usable bytes")
			}
		})
	}
}

// OASIS Metadata §§2.2.2, 2.4.1, 2.4.2 and 2.4.4: inherited signing
// keys precede SingleLogoutService, which precedes the indexed ACS endpoints.
// The selected directional profile advertises POST only; exporting this
// document does not assert that any application route or runtime is enabled.
func TestExportSPMetadataWithEndpointsSelectsOnlyExactOptionalRoutes(t *testing.T) {
	key := metadataRSAKey(t, 2048)
	certificates := [][]byte{
		metadataCertificate(t, key, &key.PublicKey, 1),
		metadataCertificate(t, key, &key.PublicKey, 2),
	}
	for _, route := range []struct{ origin, provider string }{
		{"https://identity.example", "acme"},
		{"https://Identity.Example:9443", "Tenant_0123.-"},
		{"https://[2001:db8::1]:9443", strings.Repeat("p", 128)},
	} {
		for _, selection := range metadataEndpointSelections() {
			t.Run(route.provider+"/"+selection.name, func(t *testing.T) {
				config := saml.SPMetadataConfig{
					EntityID:             "HTTPS://identity.example/SP%2fexact?realm=one&service=saml",
					AssertionConsumerURL: route.origin + "/saml2/" + route.provider + "/acs",
					SigningCertificates:  certificates,
				}
				encoded, err := saml.ExportSPMetadataWithEndpoints(config, selection.endpoints)
				if err != nil {
					t.Fatal(err)
				}
				var document metadataElement
				if err := xml.Unmarshal(encoded, &document); err != nil {
					t.Fatal(err)
				}
				assertMetadataElement(t, document, metadataNamespace, "EntityDescriptor", map[string]string{"entityID": config.EntityID}, 1)
				descriptor := document.Children[0]
				childCount := len(certificates) + 1
				if selection.endpoints.SingleLogout {
					childCount++
				}
				if selection.endpoints.IDPInitiatedACS {
					childCount++
				}
				assertMetadataElement(t, descriptor, metadataNamespace, "SPSSODescriptor", map[string]string{
					"protocolSupportEnumeration": "urn:oasis:names:tc:SAML:2.0:protocol",
					"AuthnRequestsSigned":        "true", "WantAssertionsSigned": "true",
				}, childCount)
				for i, certificate := range certificates {
					keyDescriptor := descriptor.Children[i]
					assertMetadataElement(t, keyDescriptor, metadataNamespace, "KeyDescriptor", map[string]string{"use": "signing"}, 1)
					actual, err := base64.StdEncoding.Strict().DecodeString(keyDescriptor.Children[0].Children[0].Children[0].Text)
					if err != nil || !bytes.Equal(actual, certificate) {
						t.Fatal("selected endpoints changed the approved certificate bytes")
					}
				}
				consumerIndex := len(certificates)
				withoutSLO := encoded
				if selection.endpoints.SingleLogout {
					location := route.origin + "/saml2/" + route.provider + "/slo"
					assertMetadataElement(t, descriptor.Children[consumerIndex], metadataNamespace, "SingleLogoutService", map[string]string{
						"Binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", "Location": location,
					}, 0)
					consumerIndex++
					additionalEndpoint := `<SingleLogoutService xmlns="` + metadataNamespace + `" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="` + location + `"></SingleLogoutService>`
					withoutSLO = []byte(strings.Replace(string(encoded), additionalEndpoint, "", 1))
				}
				assertMetadataElement(t, descriptor.Children[consumerIndex], metadataNamespace, "AssertionConsumerService", map[string]string{
					"Binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", "Location": config.AssertionConsumerURL,
					"index": "0", "isDefault": "true",
				}, 0)
				var previous []byte
				if selection.endpoints.IDPInitiatedACS {
					assertMetadataElement(t, descriptor.Children[consumerIndex+1], metadataNamespace, "AssertionConsumerService", map[string]string{
						"Binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", "Location": route.origin + "/saml2/" + route.provider + "/idp-init",
						"index": "1", "isDefault": "false",
					}, 0)
					previous, err = saml.ExportSPMetadataWithIDPInitiatedACS(config)
				} else {
					previous, err = saml.ExportSPMetadata(config)
				}
				if err != nil || !bytes.Equal(previous, withoutSLO) {
					t.Fatal("options changed previous exporter bytes beyond the selected SLO element")
				}
			})
		}
	}
}

func TestExportSPMetadataWithEndpointsRetainsLegacyZeroOptionsRoutePolicy(t *testing.T) {
	key := metadataRSAKey(t, 2048)
	config := saml.SPMetadataConfig{
		EntityID: "https://identity.example/sp", AssertionConsumerURL: "https://identity.example/custom/registered-acs",
		SigningCertificates: [][]byte{metadataCertificate(t, key, &key.PublicKey, 1)},
	}
	previous, err := saml.ExportSPMetadata(config)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := saml.ExportSPMetadataWithEndpoints(config, saml.SPMetadataEndpoints{})
	if err != nil || !bytes.Equal(previous, encoded) {
		t.Fatal("zero options changed the legacy registered ACS policy or bytes")
	}
	for _, selection := range metadataEndpointSelections()[1:] {
		encoded, err := saml.ExportSPMetadataWithEndpoints(config, selection.endpoints)
		if !errors.Is(err, saml.ErrInvalidInput) || encoded != nil {
			t.Fatal("selected routes were derived from a noncanonical provider ACS")
		}
	}
}

func TestExportSPMetadataWithEndpointsPreservesPublishedExporterBytes(t *testing.T) {
	key := metadataRSAKey(t, 2048)
	certificate := metadataCertificate(t, key, &key.PublicKey, 1)
	config := saml.SPMetadataConfig{
		EntityID: "https://identity.example/sp", AssertionConsumerURL: "https://identity.example/saml2/acme/acs",
		SigningCertificates: [][]byte{certificate},
	}
	// Freeze the published e13921246a08 exporter layout, independently of the
	// legacy functions now delegating to the new options implementation. Only
	// the ephemeral certificate's public DER payload varies between runs.
	const prefix = `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://identity.example/sp"><SPSSODescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" AuthnRequestsSigned="true" WantAssertionsSigned="true"><KeyDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Certificate xmlns="http://www.w3.org/2000/09/xmldsig#">`
	const keyEndAndDefaultACS = `</X509Certificate></X509Data></KeyInfo></KeyDescriptor><AssertionConsumerService xmlns="urn:oasis:names:tc:SAML:2.0:metadata" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://identity.example/saml2/acme/acs" index="0" isDefault="true"></AssertionConsumerService>`
	const additionalACS = `<AssertionConsumerService xmlns="urn:oasis:names:tc:SAML:2.0:metadata" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://identity.example/saml2/acme/idp-init" index="1" isDefault="false"></AssertionConsumerService>`
	const suffix = `</SPSSODescriptor></EntityDescriptor>`
	for _, idpInitiated := range []bool{false, true} {
		want := prefix + base64.StdEncoding.EncodeToString(certificate) + keyEndAndDefaultACS
		if idpInitiated {
			want += additionalACS
		}
		want += suffix
		encoded, err := saml.ExportSPMetadataWithEndpoints(config, saml.SPMetadataEndpoints{IDPInitiatedACS: idpInitiated})
		if err != nil || string(encoded) != want {
			t.Fatal("new options changed the published exporter wire bytes")
		}
	}
}

func TestExportSPMetadataWithEndpointsRejectsNoncanonicalOrAliasedRoutes(t *testing.T) {
	key := metadataRSAKey(t, 2048)
	certificate := metadataCertificate(t, key, &key.PublicKey, 1)
	for _, destination := range []string{
		"", "http://identity.example/saml2/acme/acs", "HTTPS://identity.example/saml2/acme/acs",
		"https://identity.example:/saml2/acme/acs", "https://identity.example:0/saml2/acme/acs",
		"https://identity.example:65536/saml2/acme/acs", "https://identity.example:09443/saml2/acme/acs",
		"https://user:secret@identity.example/saml2/acme/acs", "https://identity.example/saml2/acme/acs?",
		"https://identity.example/saml2/acme/acs?provider=other", "https://identity.example/saml2/acme/acs#fragment",
		"https://identity.example/acs", "https://identity.example/prefix/saml2/acme/acs",
		"https://identity.example/saml2/acme/ACS", "https://identity.example/saml2/acme/acs/",
		"https://identity.example/saml2/acme/idp-init", "https://identity.example/saml2/acme/slo",
		"https://identity.example/saml2//acs", "https://identity.example/saml2/./acs",
		"https://identity.example/saml2/../acs", "https://identity.example/saml2/one/two/acs",
		"https://identity.example/saml2/%61cme/acs", "https://identity.example/saml2/acme%2fother/acs",
		"https://identity.example/saml2/acme%252fother/acs", "https://identity.example/saml2/{provider}/acs",
		"https://identity.example/saml2/acme\\other/acs", "https://identity.example/saml2/é/acs",
		"https://identity.example/saml2/" + strings.Repeat("p", 129) + "/acs",
	} {
		for _, selection := range metadataEndpointSelections()[1:] {
			config := saml.SPMetadataConfig{
				EntityID: "https://identity.example/sp", AssertionConsumerURL: destination,
				SigningCertificates: [][]byte{certificate},
			}
			encoded, err := saml.ExportSPMetadataWithEndpoints(config, selection.endpoints)
			if !errors.Is(err, saml.ErrInvalidInput) || encoded != nil {
				t.Fatal("selected endpoint accepted a noncanonical or aliased route")
			}
		}
	}
}

func TestExportSPMetadataWithEndpointsBoundsOnlySelectedDestinations(t *testing.T) {
	key := metadataRSAKey(t, 2048)
	certificate := metadataCertificate(t, key, &key.PublicKey, 1)
	for _, tc := range []struct {
		name      string
		acsBytes  int
		endpoints saml.SPMetadataEndpoints
		accepted  bool
	}{
		{name: "SLO exactly at limit without unrelated ACS", acsBytes: 2048, endpoints: saml.SPMetadataEndpoints{SingleLogout: true}, accepted: true},
		{name: "SLO above limit", acsBytes: 2049, endpoints: saml.SPMetadataEndpoints{SingleLogout: true}},
		{name: "both exactly at longest derived route limit", acsBytes: 2043, endpoints: saml.SPMetadataEndpoints{SingleLogout: true, IDPInitiatedACS: true}, accepted: true},
		{name: "both reject oversized optional ACS", acsBytes: 2044, endpoints: saml.SPMetadataEndpoints{SingleLogout: true, IDPInitiatedACS: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			origin := "https://" + strings.Repeat("a", tc.acsBytes-len("https:///saml2/acme/acs"))
			config := saml.SPMetadataConfig{
				EntityID: "https://identity.example/sp", AssertionConsumerURL: origin + "/saml2/acme/acs",
				SigningCertificates: [][]byte{certificate},
			}
			encoded, err := saml.ExportSPMetadataWithEndpoints(config, tc.endpoints)
			if tc.accepted {
				if err != nil || len(encoded) == 0 {
					t.Fatal("selected route at its limit was rejected")
				}
			} else if !errors.Is(err, saml.ErrInvalidInput) || encoded != nil {
				t.Fatal("oversized selected route was accepted")
			}
		})
	}
}

func TestExportSPMetadataWithEndpointsRetainsConfigurationValidation(t *testing.T) {
	key := metadataRSAKey(t, 2048)
	certificate := metadataCertificate(t, key, &key.PublicKey, 1)
	weak := metadataRSAKey(t, 1024)
	weakCertificate := metadataCertificate(t, key, &weak.PublicKey, 2)
	base := saml.SPMetadataConfig{
		EntityID: "https://identity.example/sp", AssertionConsumerURL: "https://identity.example/saml2/acme/acs",
		SigningCertificates: [][]byte{certificate},
	}
	for _, tc := range []struct {
		name string
		edit func(*saml.SPMetadataConfig)
	}{
		{name: "invalid entity", edit: func(c *saml.SPMetadataConfig) { c.EntityID = "http://identity.example/sp" }},
		{name: "absent certificates", edit: func(c *saml.SPMetadataConfig) { c.SigningCertificates = nil }},
		{name: "duplicate certificates", edit: func(c *saml.SPMetadataConfig) {
			c.SigningCertificates = [][]byte{certificate, bytes.Clone(certificate)}
		}},
		{name: "malformed certificate", edit: func(c *saml.SPMetadataConfig) { c.SigningCertificates = [][]byte{[]byte("invalid DER")} }},
		{name: "weak certificate", edit: func(c *saml.SPMetadataConfig) { c.SigningCertificates = [][]byte{weakCertificate} }},
	} {
		for _, selection := range metadataEndpointSelections() {
			t.Run(tc.name+"/"+selection.name, func(t *testing.T) {
				config := base
				tc.edit(&config)
				encoded, err := saml.ExportSPMetadataWithEndpoints(config, selection.endpoints)
				if !errors.Is(err, saml.ErrInvalidInput) || encoded != nil {
					t.Fatal("endpoint options bypassed existing configuration admission")
				}
			})
		}
	}
}

func metadataEndpointSelections() []struct {
	name      string
	endpoints saml.SPMetadataEndpoints
} {
	return []struct {
		name      string
		endpoints saml.SPMetadataEndpoints
	}{
		{name: "default"},
		{name: "IdP ACS only", endpoints: saml.SPMetadataEndpoints{IDPInitiatedACS: true}},
		{name: "SLO only", endpoints: saml.SPMetadataEndpoints{SingleLogout: true}},
		{name: "both", endpoints: saml.SPMetadataEndpoints{IDPInitiatedACS: true, SingleLogout: true}},
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
