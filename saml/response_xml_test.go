package saml

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func FuzzSAMLDocument(f *testing.F) {
	f.Add([]byte(`<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" ID="_response"/>`))
	f.Add([]byte(`<empty/>`))
	f.Add([]byte(`<Response unclosed="value>`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		root, err := parseSAMLDocument(t.Context(), raw)
		if err != nil && root != nil || err == nil && root == nil {
			t.Fatal("parser violated the detached success/denial boundary")
		}
		if len(raw) > maximumSAMLXMLBytes && root != nil {
			t.Fatal("parser exceeded the raw document budget")
		}
	})
}

func TestParseSAMLDocumentReturnsTheOriginalDocumentElement(t *testing.T) {
	document := []byte(`<?xml version="1.0"?><!--before--><p:Response xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" ID="response"><p:Status>accepted &amp; retained<![CDATA[ exactly]]></p:Status></p:Response><!--after-->`)
	root, err := parseSAMLDocument(context.Background(), document)
	if err != nil || root == nil {
		t.Fatalf("parseSAMLDocument() = %v, %v; want document element", root, err)
	}
	if root.Name().Local != "Response" || root.Name().URI != "urn:oasis:names:tc:SAML:2.0:protocol" {
		t.Fatalf("document element = %v; want protocol Response", root.Name())
	}
	if root.Attr("", "ID").Value() != "response" || root.StringValue() != "accepted & retained exactly" {
		t.Fatal("document element did not preserve attributes and text")
	}
	if root.Parent() == nil || root.FirstChild().Parent() != root {
		t.Fatal("returned element must belong to the single materialized document tree")
	}
}

func TestParseSAMLDocumentRejectsInvalidAndProhibitedXML(t *testing.T) {
	for name, document := range map[string]string{
		"empty":                    "",
		"no element":               "<!--only a comment-->",
		"two document elements":    "<r/><s/>",
		"trailing data":            "<r/>not XML",
		"mismatched elements":      "<r><s></r>",
		"unknown entity":           "<r>&unknown;</r>",
		"duplicate attribute":      `<r a="1" a="2"/>`,
		"unquoted assignment":      `<r a=unfinished=assignment/>`,
		"duplicate expanded name":  `<r xmlns:a="urn:one" xmlns:b="urn:one" a:x="1" b:x="2"/>`,
		"unbound namespace prefix": "<p:r/>",
		"doctype":                  "<!DOCTYPE r><r/>",
		"declaration":              "<!ELEMENT r EMPTY><r/>",
		"xinclude":                 `<r xmlns:i="http://www.w3.org/2001/XInclude"><i:include href="not-fetched.xml"/></r>`,
		"alternate encoding":       `<?xml version="1.0" encoding="ISO-8859-1"?><r/>`,
	} {
		t.Run(name, func(t *testing.T) {
			assertSAMLXMLDenied(t, []byte(document), ErrInvalidInput)
		})
	}
}

func TestParseSAMLDocumentEnforcesRawByteBoundary(t *testing.T) {
	const limit = 1 << 20
	for _, extra := range []int{0, 1} {
		document := []byte("<r>" + strings.Repeat("a", limit-len("<r></r>")+extra) + "</r>")
		if extra == 0 {
			assertSAMLXMLAccepted(t, document)
		} else {
			assertSAMLXMLDenied(t, document, ErrInvalidInput)
		}
	}
}

func TestParseSAMLDocumentEnforcesDepthBoundary(t *testing.T) {
	assertSAMLXMLAccepted(t, []byte(strings.Repeat("<r>", 64)+strings.Repeat("</r>", 64)))
	assertSAMLXMLDenied(t, []byte(strings.Repeat("<r>", 65)+strings.Repeat("</r>", 65)), ErrInvalidInput)
}

func TestParseSAMLDocumentEnforcesNodeBoundary(t *testing.T) {
	assertSAMLXMLAccepted(t, []byte("<r>"+strings.Repeat("<s/>", 9999)+"</r>"))
	assertSAMLXMLDenied(t, []byte("<r>"+strings.Repeat("<s/>", 10000)+"</r>"), ErrInvalidInput)
	// Comments, PIs, attributes and namespace declarations consume the same
	// node budget as elements in the pinned XDM parser.
	for name, countedNode := range map[string]string{
		"comment":         "<!--c-->",
		"pi":              "<?example c?>",
		"text":            "text",
		"whitespace text": " ",
		"attribute":       `<s a="v"/>`,
		"namespace":       `<s xmlns:p="urn:example"/>`,
	} {
		t.Run(name, func(t *testing.T) {
			remaining := 9998
			if name == "attribute" || name == "namespace" {
				remaining--
			}
			document := "<r>" + strings.Repeat("<s/>", remaining) + countedNode + "</r>"
			assertSAMLXMLAccepted(t, []byte(document))
			assertSAMLXMLDenied(t, []byte(strings.Replace(document, "</r>", "<s/></r>", 1)), ErrInvalidInput)
		})
	}
}

func TestParseSAMLDocumentEnforcesAttributeBoundaries(t *testing.T) {
	attributes := func(count int) string {
		var result strings.Builder
		for i := 0; i < count; i++ {
			fmt.Fprintf(&result, ` a%d = 'value=retained'`, i)
		}
		return result.String()
	}
	assertSAMLXMLAccepted(t, []byte("<r"+attributes(128)+"/>"))
	assertSAMLXMLDenied(t, []byte("<r"+attributes(129)+"/>"), ErrInvalidInput)
	children := strings.Repeat("<s"+attributes(128)+"/>", 16)
	assertSAMLXMLAccepted(t, []byte("<r>"+children+"</r>"))
	assertSAMLXMLDenied(t, []byte("<r>"+children+`<s one="over"/></r>`), ErrInvalidInput)
	assertSAMLXMLAccepted(t, []byte(`<r xmlns:p="urn:example"`+attributes(128)+"/>"))
}

func TestParseSAMLDocumentEnforcesNamespaceDeclarationBoundary(t *testing.T) {
	var document strings.Builder
	document.WriteString("<r>")
	for i := 0; i < 256; i++ {
		fmt.Fprintf(&document, `<s xmlns:p="urn:example:%d"/>`, i)
	}
	assertSAMLXMLAccepted(t, []byte(document.String()+"</r>"))
	assertSAMLXMLDenied(t, []byte(document.String()+`<s xmlns:p="urn:one-over"/></r>`), ErrInvalidInput)
}

func TestParseSAMLDocumentPreservesCancellationErrors(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	deadline, stop := context.WithDeadline(context.Background(), time.Unix(0, 0))
	defer stop()
	for _, ctx := range []context.Context{canceled, deadline} {
		root, err := parseSAMLDocument(ctx, []byte("<r/>"))
		if root != nil || err != ctx.Err() {
			t.Fatalf("parseSAMLDocument() = %v, %v; want nil, %v", root, err, ctx.Err())
		}
	}
	assertSAMLXMLDenied(t, []byte("<r/>"), ErrInvalidInput, nil)
}

func assertSAMLXMLAccepted(t *testing.T, document []byte) {
	t.Helper()
	root, err := parseSAMLDocument(context.Background(), document)
	if err != nil || root == nil {
		t.Fatalf("parseSAMLDocument() = %v, %v; want document element", root, err)
	}
}

func assertSAMLXMLDenied(t *testing.T, document []byte, expected error, contexts ...context.Context) {
	t.Helper()
	ctx := context.Background()
	if len(contexts) != 0 {
		ctx = contexts[0]
	}
	root, err := parseSAMLDocument(ctx, document)
	if root != nil || err != expected {
		t.Fatalf("parseSAMLDocument() = %v, %v; want nil, exact redacted error %v", root, err, expected)
	}
}
