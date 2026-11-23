package saml_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/faustbrian/go-sso/saml"
)

// OASIS Metadata §§2.2.2, 2.4.2 and Profiles §4.4.3.1: choose one
// independently approved endpoint per applicable binding and distinguish
// locations for requests from those for responses.
func TestImportIDPMetadataWithSingleLogoutSelectsDirectionalEndpoints(t *testing.T) {
	const redirect = `<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example/logout?realm=one&amp;source=golib" ResponseLocation="https://idp.example/not-the-request-target"/>`
	const post = `<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example/post" ResponseLocation="https://callback.idp.example/post-result"/>`
	const soap = `<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://unselected.example/soap"/>`
	key := metadataRSAKey(t, 2048)
	certificate := metadataCertificate(t, key, &key.PublicKey, 1)
	keys := importedMetadataKeys([][]byte{certificate})
	document := func(endpointXML string) []byte {
		return []byte(importedMetadataXML(importedMetadataRole(keys, endpointXML+importedMetadataRedirect())))
	}
	approvedHosts := []string{"IDP.EXAMPLE", "callback.idp.example"}
	full := document(soap + redirect + post)
	result, err := saml.ImportIDPMetadataWithSingleLogout(t.Context(), full, importedIDPEntity, sha256.Sum256(full), importedMetadataNow(), approvedHosts)
	if err != nil || result.Login.EntityID != importedIDPEntity || result.Login.RedirectEndpoint != importedIDPRedirect ||
		len(result.Login.SigningCertificates) != 1 || !bytes.Equal(result.Login.SigningCertificates[0], certificate) ||
		result.RedirectRequestURL != "https://idp.example/logout?realm=one&source=golib" || result.POSTResponseURL != "https://callback.idp.example/post-result" {
		t.Fatal("did not return the approved Redirect request and POST response endpoints", err)
	}
	noResponse := document(redirect + strings.Replace(post, ` ResponseLocation="https://callback.idp.example/post-result"`, "", 1))
	result, err = saml.ImportIDPMetadataWithSingleLogout(t.Context(), noResponse, importedIDPEntity, sha256.Sum256(noResponse), importedMetadataNow(), []string{"idp.example"})
	if err != nil || result.POSTResponseURL != "https://idp.example/post" {
		t.Fatal("POST Location did not serve as the response destination when ResponseLocation is absent", err)
	}

	for name, changed := range map[string][]byte{
		"no selected Redirect": document(soap + post),
		"no selected POST":     document(redirect + soap),
		"ambiguous Redirect":   document(redirect + redirect + post),
		"ambiguous POST":       document(redirect + post + post),
		"foreign POST response host": document(redirect + strings.Replace(post,
			"https://callback.idp.example/post-result", "https://callback.idp.example.unapproved.test/post-result", 1)),
		"foreign POST location even with approved response location": document(redirect + strings.Replace(post,
			"https://idp.example/post", "https://unapproved.test/post", 1)),
		"foreign Redirect response location": document(post + strings.Replace(redirect,
			"https://idp.example/not-the-request-target", "https://unapproved.test/not-the-request-target", 1)),
		"POST response uses HTTP": document(redirect + strings.Replace(post, "https://callback", "http://callback", 1)),
		"empty ResponseLocation":  document(redirect + strings.Replace(post, "https://callback.idp.example/post-result", "", 1)),
		"SAML query field":        document(strings.Replace(redirect, "realm=one", "RelayState=not-an-approved-fixed-field", 1) + post),
	} {
		t.Run(name, func(t *testing.T) {
			result, err := saml.ImportIDPMetadataWithSingleLogout(t.Context(), changed, importedIDPEntity, sha256.Sum256(changed), importedMetadataNow(), approvedHosts)
			if !errors.Is(err, saml.ErrInvalidInput) || result.Login.EntityID != "" || result.RedirectRequestURL != "" || result.POSTResponseURL != "" {
				t.Fatal("invalid or ambiguous endpoints yielded a partial trusted projection", err)
			}
		})
	}
	for _, hosts := range [][]string{nil, {"*.example"}, {"idp.example", "IDP.EXAMPLE", "callback.idp.example"},
		{"https://idp.example", "callback.idp.example"}, {"idp.example", "callback.idp.example", "numeric.42"},
		{"idp.example", "callback.idp.example", "hexadecimal.0xabc"}} {
		if _, err := saml.ImportIDPMetadataWithSingleLogout(t.Context(), full, importedIDPEntity, sha256.Sum256(full), importedMetadataNow(), hosts); !errors.Is(err, saml.ErrInvalidInput) {
			t.Fatal("malformed approval set was accepted", err)
		}
	}
	changed := append(bytes.Clone(full), '\n')
	if _, err := saml.ImportIDPMetadataWithSingleLogout(t.Context(), changed, importedIDPEntity, sha256.Sum256(full), importedMetadataNow(), approvedHosts); !errors.Is(err, saml.ErrInvalidInput) {
		t.Fatal("changed bytes reused approval of the original document", err)
	}
	legacy, err := saml.ImportIDPMetadata(t.Context(), full, importedIDPEntity, sha256.Sum256(full), importedMetadataNow())
	if err != nil || legacy.RedirectEndpoint != importedIDPRedirect {
		t.Fatal("the existing login-only importer no longer accepts its selected profile", err)
	}
}
