package saml

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/knroy/go-xml/v2/xdm"
)

// XML Signature 1.1 §§3.1–3.2 and OASIS Profiles §4.1.4.3. The fixture's
// canonical bytes come from a fixed literal, not the verifier's serializer.
func TestSAMLExactNodeSignature(t *testing.T) {
	privateRSA, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privateEC, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, cfg := range []struct {
		name, algorithm string
		key             crypto.Signer
	}{
		{"rsa-pss", "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1", privateRSA},
		{"p256", "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", privateEC},
	} {
		t.Run(cfg.name, func(t *testing.T) {
			document := signedXMLFixture(t, cfg.algorithm, cfg.key)
			node := parseSignatureFixture(t, document)
			if index, err := verifySAMLSignature(t.Context(), node, []crypto.PublicKey{cfg.key.Public()}); err != nil || index != 0 {
				t.Fatalf("configured signing key rejected: %v", err)
			}
			if _, err := verifySAMLSignature(t.Context(), node, nil); !errors.Is(err, ErrInvalidSignature) {
				t.Fatalf("accepted a signature without a pinned key: %v", err)
			}
			other := privateEC.Public()
			if cfg.name == "p256" {
				other = privateRSA.Public()
			}
			if _, err := verifySAMLSignature(t.Context(), node, []crypto.PublicKey{other}); !errors.Is(err, ErrInvalidSignature) {
				t.Fatalf("accepted an unrelated signing key: %v", err)
			}
			for _, tc := range []struct{ name, original, adjusted string }{
				{"target changed", "urn:example:approved-idp", "urn:example:other-idp"},
				{"different reference", `URI="#_response"`, `URI="#_different"`},
				{"unsupported canonicalizer", `Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"`, `Algorithm="urn:example:unsupported"`},
			} {
				t.Run(tc.name, func(t *testing.T) {
					changed := parseSignatureFixture(t, strings.Replace(document, tc.original, tc.adjusted, 1))
					if _, err := verifySAMLSignature(t.Context(), changed, []crypto.PublicKey{cfg.key.Public()}); !errors.Is(err, ErrInvalidSignature) {
						t.Fatalf("accepted changed signature evidence: %v", err)
					}
				})
			}
		})
	}
}

func signedXMLFixture(t *testing.T, algorithm string, private crypto.Signer) string {
	t.Helper()
	const nodeOpen = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_response">`
	const issuer = `<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:example:approved-idp</saml:Issuer>`
	const nodeClose = `</samlp:Response>`
	return nodeOpen + issuer + fixtureSignature(t, "_response", algorithm, private, nodeOpen+issuer+nodeClose) + nodeClose
}

func fixtureSignature(t *testing.T, id, algorithm string, private crypto.Signer, canonicalTarget string) string {
	t.Helper()
	const ns = `xmlns:ds="http://www.w3.org/2000/09/xmldsig#"`
	refHash := sha256.Sum256([]byte(canonicalTarget))
	signedInfoContents := fmt.Sprintf(`<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="%s"></ds:SignatureMethod><ds:Reference URI="#%s"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod><ds:DigestValue>%s</ds:DigestValue></ds:Reference>`, algorithm, id, base64.StdEncoding.EncodeToString(refHash[:]))
	infoHash := sha256.Sum256([]byte(`<ds:SignedInfo ` + ns + `>` + signedInfoContents + `</ds:SignedInfo>`))
	var signature []byte
	switch private := private.(type) {
	case *rsa.PrivateKey:
		var err error
		signature, err = rsa.SignPSS(rand.Reader, private, crypto.SHA256, infoHash[:], &rsa.PSSOptions{SaltLength: sha256.Size})
		if err != nil {
			t.Fatal(err)
		}
	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, private, infoHash[:])
		if err != nil {
			t.Fatal(err)
		}
		signature = make([]byte, 64)
		r.FillBytes(signature[:32])
		s.FillBytes(signature[32:])
	default:
		t.Fatal("wrong fixture signer")
	}
	return `<ds:Signature ` + ns + `><ds:SignedInfo>` + signedInfoContents +
		`</ds:SignedInfo><ds:SignatureValue>` + base64.StdEncoding.EncodeToString(signature) + `</ds:SignatureValue></ds:Signature>`
}

func parseSignatureFixture(t *testing.T, source string) *xdm.Node {
	t.Helper()
	doc, err := xdm.Parse(strings.NewReader(source), xdm.ParseOptions{MaxBytes: 8192, MaxDepth: 20, MaxNodes: 128})
	if err != nil {
		t.Fatal(err)
	}
	return doc.Root.FirstChild()
}
