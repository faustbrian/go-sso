package saml_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-sso/saml"
)

const importedIDPEntity = "HTTPS://idp.example/Entity%2fexact?realm=one&service=saml"
const importedIDPRedirect = "https://idp.example/sso?realm=one&service=saml"

// Metadata 2.0 §§2.3.2, 2.4.1.1, 2.4.1.3, 2.4.2 and 2.4.3; Bindings §3.4.1.
func TestImportIDPMetadataReturnsExactDetachedRegistrationFields(t *testing.T) {
	key := metadataRSAKey(t, 2048)
	certificates := make([][]byte, 5)
	for i := range certificates {
		certificates[i] = metadataCertificate(t, key, &key.PublicKey, int64(i+1))
	}
	for _, count := range []int{1, 5} {
		t.Run(string(rune('0'+count))+" signing certificates", func(t *testing.T) {
			document := []byte(importedMetadataXML(importedMetadataRole(importedMetadataKeys(certificates[:count]), importedMetadataRedirect())))
			before := bytes.Clone(document)
			approved := sha256.Sum256(document)
			result, err := saml.ImportIDPMetadata(t.Context(), document, importedIDPEntity, approved, importedMetadataNow())
			if err != nil {
				t.Fatal("approved exact metadata was rejected", err)
			}
			if result.EntityID != importedIDPEntity || result.RedirectEndpoint != importedIDPRedirect || len(result.SigningCertificates) != count {
				t.Fatal("import did not preserve the selected registration fields")
			}
			for i := range result.SigningCertificates {
				if !bytes.Equal(result.SigningCertificates[i], certificates[i]) {
					t.Fatal("import changed approved signing DER")
				}
			}
			if !bytes.Equal(document, before) {
				t.Fatal("import mutated its borrowed document")
			}
			result.SigningCertificates[0][0] ^= 1
			again, err := saml.ImportIDPMetadata(t.Context(), document, importedIDPEntity, approved, importedMetadataNow())
			if err != nil || !bytes.Equal(again.SigningCertificates[0], certificates[0]) {
				t.Fatal("returned certificate aliases another import or borrowed input", err)
			}
			clear(document)
			if !bytes.Equal(again.SigningCertificates[0], certificates[0]) || again.EntityID != importedIDPEntity || again.RedirectEndpoint != importedIDPRedirect {
				t.Fatal("returned fields retained the borrowed document")
			}
		})
	}
}

// Metadata 2.0 §3.1.1 and the reference's independently approved digest policy.
func TestImportIDPMetadataRequiresExactApprovedBytesAndEntity(t *testing.T) {
	key := metadataRSAKey(t, 2048)
	certificate := metadataCertificate(t, key, &key.PublicKey, 1)
	document := []byte(importedMetadataXML(importedMetadataRole(importedMetadataKeys([][]byte{certificate}), importedMetadataRedirect())))
	approved := sha256.Sum256(document)
	for _, tc := range []struct {
		name, entity string
		document     []byte
		digest       [32]byte
	}{
		{"missing approval", importedIDPEntity, document, [32]byte{}},
		{"different approval", importedIDPEntity, document, sha256.Sum256([]byte("separately-approved-other-document"))},
		{"different bytes same XML", importedIDPEntity, append(bytes.Clone(document), '\n'), approved},
		{"different entity case", strings.Replace(importedIDPEntity, "HTTPS", "https", 1), document, approved},
		{"different entity escaping", strings.Replace(importedIDPEntity, "%2f", "%2F", 1), document, approved},
		{"missing expected entity", "", document, approved},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertImportedMetadataDenied(t, t.Context(), tc.document, tc.entity, tc.digest, importedMetadataNow(), saml.ErrInvalidInput)
		})
	}
}

// Metadata 2.0 §§2.3.2, 2.4.1.1, 2.4.1.3, 2.4.2 and 2.4.3.
func TestImportIDPMetadataSelectsOnlyTheIntendedRoleBindingAndKeys(t *testing.T) {
	key := metadataRSAKey(t, 2048)
	certificate := metadataCertificate(t, key, &key.PublicKey, 1)
	keys := importedMetadataKeys([][]byte{certificate})
	redirect := importedMetadataRedirect()
	role := importedMetadataRole(keys, redirect)
	post := `<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://ignored.example/post"/>`
	encryption := strings.Replace(keys, `use="signing"`, `use="encryption"`, 1)
	otherRole := strings.Replace(role, `IDPSSODescriptor`, `SPSSODescriptor`, 2)
	otherProtocol := strings.Replace(role, `urn:oasis:names:tc:SAML:2.0:protocol`, `urn:oasis:names:tc:SAML:1.1:protocol`, 1)
	for name, selected := range map[string]string{
		"mixed bindings keys and roles": otherRole + otherProtocol + importedMetadataRole(encryption+keys, post+redirect),
		"unspecified key use":           importedMetadataRole(strings.Replace(keys, ` use="signing"`, "", 1), redirect),
		"protocol URI list":             strings.Replace(role, `protocolSupportEnumeration="`, `protocolSupportEnumeration="urn:example:other `, 1),
		"alternate namespace prefixes":  strings.ReplaceAll(strings.ReplaceAll(role, "md:", "m:"), "ds:", "d:"),
	} {
		t.Run(name, func(t *testing.T) {
			document := importedMetadataXML(selected)
			if name == "alternate namespace prefixes" {
				document = strings.ReplaceAll(strings.ReplaceAll(document, "xmlns:md=", "xmlns:m="), "xmlns:ds=", "xmlns:d=")
				document = strings.ReplaceAll(document, "md:EntityDescriptor", "m:EntityDescriptor")
			}
			result, err := saml.ImportIDPMetadata(t.Context(), []byte(document), importedIDPEntity, sha256.Sum256([]byte(document)), importedMetadataNow())
			if err != nil || result.EntityID != importedIDPEntity || result.RedirectEndpoint != importedIDPRedirect || len(result.SigningCertificates) != 1 || !bytes.Equal(result.SigningCertificates[0], certificate) {
				t.Fatal("import did not isolate the selected registration profile", err)
			}
		})
	}
	for name, body := range map[string]string{
		"no IdP role":                  otherRole,
		"no SAML2 IdP role":            otherProtocol,
		"two selected IdP roles":       role + role,
		"no Redirect binding":          importedMetadataRole(keys, post),
		"duplicate Redirect endpoint":  importedMetadataRole(keys, redirect+redirect),
		"other role endpoint fallback": importedMetadataRole(keys, post) + otherRole,
		"other role key fallback":      importedMetadataRole("", redirect) + otherRole,
		"only encryption key":          importedMetadataRole(encryption, redirect),
		"foreign IdP role":             strings.ReplaceAll(role, "md:IDPSSODescriptor", "ds:IDPSSODescriptor"),
		"foreign endpoint":             importedMetadataRole(keys, strings.ReplaceAll(redirect, "md:SingleSignOnService", "ds:SingleSignOnService")),
		"nested role fallback":         `<md:Extensions>` + role + `</md:Extensions>`,
		"invalid selected endpoint":    importedMetadataRole(keys, strings.Replace(redirect, "https://idp.example/sso", "http://idp.example/sso", 1)),
		"reserved binding query":       importedMetadataRole(keys, strings.Replace(redirect, "realm=one", "SAMLRequest=private-value", 1)),
	} {
		t.Run(name, func(t *testing.T) {
			assertImportedXMLDenied(t, importedMetadataXML(body))
		})
	}
}

// Metadata 2.0 §§2.4.1.3 and 3.1.1; XML Signature 1.1 §4.5.4.
func TestImportIDPMetadataRejectsMissingAmbiguousAndUnusableSigningMaterial(t *testing.T) {
	key := metadataRSAKey(t, 2048)
	certificate := metadataCertificate(t, key, &key.PublicKey, 1)
	keys := importedMetadataKeys([][]byte{certificate})
	certificates := make([][]byte, 6)
	for i := range certificates {
		certificates[i] = metadataCertificate(t, key, &key.PublicKey, int64(i+1))
	}
	for name, selected := range map[string]string{
		"no keys":                  "",
		"duplicate DER":            keys + keys,
		"six selected certs":       importedMetadataKeys(certificates),
		"invalid DER":              importedMetadataKeys([][]byte{[]byte("private-certificate-marker")}),
		"oversized DER":            importedMetadataKeys([][]byte{bytes.Repeat([]byte{1}, 64*1024+1)}),
		"empty certificate":        importedMetadataKeys([][]byte{nil}),
		"invalid base64":           strings.Replace(keys, base64.StdEncoding.EncodeToString(certificate), "private-invalid-base64", 1),
		"foreign certificate":      strings.ReplaceAll(keys, "ds:X509Certificate", "md:X509Certificate"),
		"two KeyInfo elements":     strings.Replace(keys, "</md:KeyDescriptor>", `<ds:KeyInfo/></md:KeyDescriptor>`, 1),
		"two X509Data elements":    strings.Replace(keys, "</ds:KeyInfo>", `<ds:X509Data/></ds:KeyInfo>`, 1),
		"only key value":           `<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:KeyValue/></ds:KeyInfo></md:KeyDescriptor>`,
		"unsupported selected use": strings.Replace(keys, `use="signing"`, `use="private-use-marker"`, 1),
		"malformed rollover":       keys + importedMetadataKeys([][]byte{[]byte("private-rollover-marker")}),
	} {
		t.Run(name, func(t *testing.T) {
			assertImportedXMLDenied(t, importedMetadataXML(importedMetadataRole(selected, importedMetadataRedirect())))
		})
	}
}

// Metadata 2.0 §2.4.1.3: absence permits both uses; a present use must be an enum.
func TestImportIDPMetadataRejectsExplicitEmptyKeyUse(t *testing.T) {
	key := metadataRSAKey(t, 2048)
	certificate := metadataCertificate(t, key, &key.PublicKey, 1)
	keys := strings.Replace(importedMetadataKeys([][]byte{certificate}), `use="signing"`, `use=""`, 1)
	assertImportedXMLDenied(t, importedMetadataXML(importedMetadataRole(keys, importedMetadataRedirect())))
}

// Metadata 2.0 §§2.3.2 and 2.4.1.1; Core §1.3.3 UTC lexical policy.
func TestImportIDPMetadataHonorsExclusiveEntityAndSelectedRoleDeadlines(t *testing.T) {
	key := metadataRSAKey(t, 2048)
	certificate := metadataCertificate(t, key, &key.PublicKey, 1)
	role := importedMetadataRole(importedMetadataKeys([][]byte{certificate}), importedMetadataRedirect())
	for _, element := range []string{"EntityDescriptor", "IDPSSODescriptor"} {
		for _, deadline := range []string{"2026-11-23T12:00:00.000000001Z", "2026-11-23T12:00:00Z", "2026-11-23T11:59:59Z", "", "private-deadline-marker", "2026-11-23T13:00:00+01:00"} {
			t.Run(element+" deadline "+deadline, func(t *testing.T) {
				document := []byte(strings.Replace(importedMetadataXML(role), "<md:"+element+" ", "<md:"+element+` validUntil="`+deadline+`" `, 1))
				result, err := saml.ImportIDPMetadata(t.Context(), document, importedIDPEntity, sha256.Sum256(document), importedMetadataNow())
				if deadline == "2026-11-23T12:00:00.000000001Z" {
					if err != nil || result.EntityID != importedIDPEntity {
						t.Fatal("fresh explicit metadata deadline rejected", err)
					}
				} else if err != saml.ErrInvalidInput || result.EntityID != "" || result.RedirectEndpoint != "" || result.SigningCertificates != nil {
					t.Fatal("invalid or exclusive metadata deadline returned fields", err)
				}
			})
		}
	}
	for name, now := range map[string]time.Time{"zero clock": {}, "out of range clock": time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)} {
		t.Run(name, func(t *testing.T) {
			document := []byte(importedMetadataXML(role))
			assertImportedMetadataDenied(t, t.Context(), document, importedIDPEntity, sha256.Sum256(document), now, saml.ErrInvalidInput)
		})
	}
}

// Metadata 2.0 §2.3.2 and the shared bounded UTF-8 XML processing profile.
func TestImportIDPMetadataRejectsAmbiguousOrProhibitedDocuments(t *testing.T) {
	key := metadataRSAKey(t, 2048)
	certificate := metadataCertificate(t, key, &key.PublicKey, 1)
	document := importedMetadataXML(importedMetadataRole(importedMetadataKeys([][]byte{certificate}), importedMetadataRedirect()))
	for name, source := range map[string]string{
		"empty":                  "",
		"aggregate root":         `<md:EntitiesDescriptor xmlns:md="` + metadataNamespace + `">` + document + `</md:EntitiesDescriptor>`,
		"multiple documents":     document + document,
		"nested entity":          strings.Replace(document, "</md:EntityDescriptor>", `<md:Extensions>`+document+`</md:Extensions></md:EntityDescriptor>`, 1),
		"wrong root namespace":   strings.Replace(document, metadataNamespace, "urn:example:foreign", 1),
		"duplicate entity field": strings.Replace(document, "<md:EntityDescriptor ", `<md:EntityDescriptor entityID="urn:example:other" `, 1),
		"DTD":                    `<!DOCTYPE md:EntityDescriptor>` + document,
		"XInclude":               strings.Replace(document, "</md:EntityDescriptor>", `<i:include xmlns:i="http://www.w3.org/2001/XInclude" href="https://not-fetched.example/metadata"/></md:EntityDescriptor>`, 1),
		"non UTF8 declaration":   `<?xml version="1.0" encoding="ISO-8859-1"?>` + document,
		"invalid UTF8":           document + string([]byte{0xff}),
		"document byte limit":    document + strings.Repeat(" ", 1<<20),
		"depth limit":            strings.Replace(document, "</md:EntityDescriptor>", strings.Repeat("<nested>", 65)+strings.Repeat("</nested>", 65)+"</md:EntityDescriptor>", 1),
	} {
		t.Run(name, func(t *testing.T) {
			assertImportedXMLDenied(t, source)
		})
	}
}

func TestImportIDPMetadataPreservesActualContextCancellation(t *testing.T) {
	key := metadataRSAKey(t, 2048)
	certificate := metadataCertificate(t, key, &key.PublicKey, 1)
	document := []byte(importedMetadataXML(importedMetadataRole(importedMetadataKeys([][]byte{certificate}), importedMetadataRedirect())))
	approved := sha256.Sum256(document)
	assertImportedMetadataDenied(t, nil, document, importedIDPEntity, approved, importedMetadataNow(), saml.ErrInvalidInput)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	assertImportedMetadataDenied(t, ctx, document, importedIDPEntity, approved, importedMetadataNow(), context.Canceled)
	ctx, cancel = context.WithCancel(t.Context())
	defer cancel()
	during := &importedMetadataCancelContext{Context: ctx, cancel: cancel, remaining: 12}
	assertImportedMetadataDenied(t, during, document, importedIDPEntity, approved, importedMetadataNow(), context.Canceled)
	if ctx.Err() != context.Canceled {
		t.Fatal("test did not trigger actual cancellation during import")
	}
}

func FuzzImportIDPMetadata(f *testing.F) {
	f.Add([]byte(importedMetadataXML(importedMetadataRole(importedMetadataKeys([][]byte{{1, 2, 3}}), importedMetadataRedirect()))))
	f.Add([]byte(importedMetadataXML(importedMetadataRole("", importedMetadataRedirect()))))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, document []byte) {
		if len(document) > 1<<20 {
			return
		}
		// Synthetic approval exercises the parser after the digest gate.
		digest := sha256.Sum256(document)
		result, err := saml.ImportIDPMetadata(t.Context(), document, importedIDPEntity, digest, importedMetadataNow())
		if err != nil {
			if !errors.Is(err, saml.ErrInvalidInput) || result.EntityID != "" || result.RedirectEndpoint != "" || result.SigningCertificates != nil {
				t.Fatal("rejected metadata returned partial configuration", err)
			}
			return
		}
		if result.EntityID != importedIDPEntity || saml.ValidateRegistration(t.Context(), result.EntityID, result.RedirectEndpoint, result.SigningCertificates) != nil {
			t.Fatal("import returned unbound or unusable registration fields")
		}
		digest[0] ^= 1
		assertImportedMetadataDenied(t, t.Context(), document, importedIDPEntity, digest, importedMetadataNow(), saml.ErrInvalidInput)
	})
}

type importedMetadataCancelContext struct {
	context.Context
	cancel    context.CancelFunc
	remaining int
}

func (c *importedMetadataCancelContext) Err() error {
	c.remaining--
	if c.remaining == 0 {
		c.cancel()
	}
	return c.Context.Err()
}

func importedMetadataNow() time.Time {
	return time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
}

func importedMetadataXML(body string) string {
	return `<md:EntityDescriptor xmlns:md="` + metadataNamespace + `" xmlns:ds="` + signatureNamespace + `" entityID="HTTPS://idp.example/Entity%2fexact?realm=one&amp;service=saml">` + body + `</md:EntityDescriptor>`
}

func importedMetadataRole(keys, endpoints string) string {
	return `<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` + keys + endpoints + `</md:IDPSSODescriptor>`
}

func importedMetadataRedirect() string {
	return `<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example/sso?realm=one&amp;service=saml"/>`
}

func importedMetadataKeys(certificates [][]byte) string {
	var result strings.Builder
	for _, certificate := range certificates {
		result.WriteString(`<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>`)
		result.WriteString(base64.StdEncoding.EncodeToString(certificate))
		result.WriteString(`</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`)
	}
	return result.String()
}

func assertImportedXMLDenied(t *testing.T, source string) {
	t.Helper()
	document := []byte(source)
	assertImportedMetadataDenied(t, t.Context(), document, importedIDPEntity, sha256.Sum256(document), importedMetadataNow(), saml.ErrInvalidInput)
}

func assertImportedMetadataDenied(t *testing.T, ctx context.Context, document []byte, entity string, approved [32]byte, now time.Time, expected error) {
	t.Helper()
	result, err := saml.ImportIDPMetadata(ctx, document, entity, approved, now)
	if !errors.Is(err, expected) || err.Error() != expected.Error() {
		t.Fatal("denied metadata did not return the stable redacted error", err)
	}
	if result.EntityID != "" || result.RedirectEndpoint != "" || result.SigningCertificates != nil {
		t.Fatal("denied metadata returned partial registration fields")
	}
}
