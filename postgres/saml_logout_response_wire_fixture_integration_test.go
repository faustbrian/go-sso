//go:build integration

package postgres_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-sso/saml"
)

// As in saml/logout_post_test.go, the canonical bytes are independent of the
// production parser. XML Signature 1.1 §§3.1–3.2 selects an enveloped signature
// and exclusive canonicalization; the pinned RSA-PSS profile uses SHA-256 salt.
func nativeSAMLLogoutResponseWire(t *testing.T, signer *rsa.PrivateKey, issuer, destination, responseID, inResponseTo string, issued time.Time, status saml.LogoutPOSTStatus) string {
	t.Helper()
	attribute := strings.NewReplacer("&", "&amp;", "<", "&lt;", `"`, "&quot;", "\t", "&#x9;", "\n", "&#xA;", "\r", "&#xD;")
	text := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\r", "&#xD;")
	open := `<p:LogoutResponse xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" Destination="` + attribute.Replace(destination) +
		`" ID="` + attribute.Replace(responseID) + `" InResponseTo="` + attribute.Replace(inResponseTo) +
		`" IssueInstant="` + issued.UTC().Format(time.RFC3339Nano) + `" Version="2.0">`
	issuerXML := `<a:Issuer xmlns:a="urn:oasis:names:tc:SAML:2.0:assertion">` + text.Replace(issuer) + `</a:Issuer>`
	subcodeXML := ""
	if status.Subcode != "" {
		subcodeXML = `<p:StatusCode Value="` + attribute.Replace(string(status.Subcode)) + `"></p:StatusCode>`
	}
	statusXML := `<p:Status><p:StatusCode Value="` + attribute.Replace(string(status.Code)) + `">` + subcodeXML + `</p:StatusCode></p:Status>`
	const closeXML = `</p:LogoutResponse>`
	targetDigest := sha256.Sum256([]byte(open + issuerXML + statusXML + closeXML))

	const signatureNamespace = `xmlns:ds="http://www.w3.org/2000/09/xmldsig#"`
	signedInfoContents := `<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod>` +
		`<ds:SignatureMethod Algorithm="` + saml.SignatureAlgorithmRSAPSSSHA256 + `"></ds:SignatureMethod>` +
		`<ds:Reference URI="#` + attribute.Replace(responseID) + `"><ds:Transforms>` +
		`<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform>` +
		`<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms>` +
		`<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod>` +
		`<ds:DigestValue>` + base64.StdEncoding.EncodeToString(targetDigest[:]) + `</ds:DigestValue></ds:Reference>`
	signedInfoDigest := sha256.Sum256([]byte(`<ds:SignedInfo ` + signatureNamespace + `>` + signedInfoContents + `</ds:SignedInfo>`))
	signature, err := rsa.SignPSS(rand.Reader, signer, crypto.SHA256, signedInfoDigest[:], &rsa.PSSOptions{SaltLength: sha256.Size})
	if err != nil {
		t.Fatal("sign fixture LogoutResponse", err)
	}
	signatureXML := `<ds:Signature ` + signatureNamespace + `><ds:SignedInfo>` + signedInfoContents +
		`</ds:SignedInfo><ds:SignatureValue>` + base64.StdEncoding.EncodeToString(signature) + `</ds:SignatureValue></ds:Signature>`
	return base64.StdEncoding.EncodeToString([]byte(open + issuerXML + signatureXML + statusXML + closeXML))
}
