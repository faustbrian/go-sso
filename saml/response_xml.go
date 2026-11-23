package saml

import (
	"bytes"
	"context"
	"encoding/xml"
	"io"
	"strings"

	"github.com/knroy/go-xml/v2/xdm"
)

const (
	// REFERENCE_CONFIGURATION.md saml.* fixes the defensive callback profile.
	maximumSAMLXMLBytes             = 1 << 20
	maximumSAMLXMLDepth             = 64
	maximumSAMLXMLNodes             = 10000
	maximumSAMLXMLAttributes        = 2048
	maximumSAMLXMLAttributesPerNode = 128
	maximumSAMLXMLNamespaces        = 256
	maximumSAMLXMLTextBytes         = 1 << 20
	xincludeNamespace               = "http://www.w3.org/2001/XInclude"
)

// parseSAMLDocument constructs one tree, whose original element is also the
// signature/semantic gate's input. It supplies neither trust nor SAML claims.
func parseSAMLDocument(ctx context.Context, document []byte) (*xdm.Node, error) {
	if ctx == nil {
		return nil, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(document) == 0 || len(document) > maximumSAMLXMLBytes {
		return nil, ErrInvalidInput
	}
	if err := guardSAMLXMLAttributes(ctx, document); err != nil {
		return nil, err
	}
	if err := preflightSAMLXML(ctx, document); err != nil {
		return nil, err
	}

	// DTDs and custom resolution remain disabled; XInclude is never invoked.
	tree, err := xdm.Parse(&samlXMLReader{ctx: ctx, source: bytes.NewReader(document)}, xdm.ParseOptions{
		MaxBytes: maximumSAMLXMLBytes,
		MaxDepth: maximumSAMLXMLDepth,
		MaxNodes: maximumSAMLXMLNodes,
	})
	if contextErr := ctx.Err(); contextErr != nil {
		return nil, contextErr
	}
	if err != nil {
		return nil, ErrInvalidInput
	}
	for child := tree.Root.FirstChild(); child != nil; child = child.NextSibling() {
		if child.Kind() == xdm.KindElement {
			return child, nil
		}
	}
	return nil, ErrInvalidInput
}

// encoding/xml allocates the whole attribute token before returning it. This
// allocation-free lexical guard bounds that token first, without attempting to
// validate XML. The standard decoder and XDM remain the XML grammar authorities.
func guardSAMLXMLAttributes(ctx context.Context, document []byte) error {
	totalAttributes, namespaces := 0, 0
	for offset := 0; offset < len(document); {
		if err := ctx.Err(); err != nil {
			return err
		}
		start := bytes.IndexByte(document[offset:], '<')
		if start < 0 {
			return nil
		}
		offset += start
		var terminator []byte
		switch {
		case bytes.HasPrefix(document[offset:], []byte("<!--")):
			terminator = []byte("-->")
		case bytes.HasPrefix(document[offset:], []byte("<![CDATA[")):
			terminator = []byte("]]>")
		case bytes.HasPrefix(document[offset:], []byte("<?")):
			terminator = []byte("?>")
		case bytes.HasPrefix(document[offset:], []byte("<!")):
			return ErrInvalidInput
		}
		if terminator != nil {
			end := bytes.Index(document[offset+2:], terminator)
			if end < 0 {
				return ErrInvalidInput
			}
			offset += 2 + end + len(terminator)
			continue
		}

		attributes := 0
		var quote byte
		end := offset + 1
		for ; end < len(document); end++ {
			if end&4095 == 0 {
				if err := ctx.Err(); err != nil {
					return err
				}
			}
			current := document[end]
			if quote != 0 {
				if current == quote {
					quote = 0
				}
				continue
			}
			if current == '\'' || current == '"' {
				quote = current
				continue
			}
			if current == '>' {
				break
			}
			if current != '=' {
				continue
			}
			nameEnd := end
			for nameEnd > offset && samlXMLSpace(document[nameEnd-1]) {
				nameEnd--
			}
			nameStart := nameEnd
			for nameStart > offset && !samlXMLSpace(document[nameStart-1]) && document[nameStart-1] != '<' {
				// These delimiters cannot belong to an attribute name. Reject
				// rather than rescan an earlier assignment on malformed input.
				previous := document[nameStart-1]
				if previous == '=' || previous == '\'' || previous == '"' {
					return ErrInvalidInput
				}
				nameStart--
			}
			name := document[nameStart:nameEnd]
			if bytes.Equal(name, []byte("xmlns")) || bytes.HasPrefix(name, []byte("xmlns:")) {
				namespaces++
			} else {
				attributes++
				totalAttributes++
			}
			if attributes > maximumSAMLXMLAttributesPerNode || totalAttributes > maximumSAMLXMLAttributes || namespaces > maximumSAMLXMLNamespaces {
				return ErrInvalidInput
			}
		}
		if end == len(document) {
			return ErrInvalidInput
		}
		offset = end + 1
	}
	return nil
}

func preflightSAMLXML(ctx context.Context, document []byte) error {
	// The selected callback profile supports UTF-8 only. A UTF-8 BOM is not
	// character data; the XDM parser removes the same prefix from its source.
	document = bytes.TrimPrefix(document, []byte{0xef, 0xbb, 0xbf})
	decoder := xml.NewDecoder(&samlXMLReader{ctx: ctx, source: bytes.NewReader(document)})
	depth, roots, nodes, textBytes := 0, 0, 0, 0
	inText := false
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		token, err := decoder.Token()
		if err == io.EOF {
			if depth != 0 || roots != 1 {
				return ErrInvalidInput
			}
			return nil
		}
		if err != nil {
			if contextErr := ctx.Err(); contextErr != nil {
				return contextErr
			}
			return ErrInvalidInput
		}
		switch value := token.(type) {
		case xml.StartElement:
			if depth == 0 {
				roots++
			}
			depth++
			nodes += 1 + len(value.Attr)
			inText = false
			if depth > maximumSAMLXMLDepth || roots > 1 || value.Name.Space == xincludeNamespace {
				return ErrInvalidInput
			}
		case xml.EndElement:
			depth--
			inText = false
		case xml.CharData:
			textBytes += len(value)
			if textBytes > maximumSAMLXMLTextBytes {
				return ErrInvalidInput
			}
			if depth == 0 {
				if len(bytes.TrimSpace(value)) != 0 {
					return ErrInvalidInput
				}
			} else if len(value) != 0 && !inText {
				nodes++
				inText = true
			}
		case xml.Comment:
			nodes++
			inText = false
		case xml.ProcInst:
			if !strings.EqualFold(value.Target, "xml") {
				nodes++
			}
			inText = false
		case xml.Directive:
			return ErrInvalidInput
		}
		if nodes > maximumSAMLXMLNodes {
			return ErrInvalidInput
		}
	}
}

func samlXMLSpace(character byte) bool {
	return character == ' ' || character == '\t' || character == '\r' || character == '\n'
}

type samlXMLReader struct {
	ctx    context.Context
	source *bytes.Reader
}

func (reader *samlXMLReader) Read(destination []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.source.Read(destination)
}
