package saml

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"

	"github.com/knroy/go-xml/v2/c14n"
	"github.com/knroy/go-xml/v2/xdm"
)

const (
	xmlSignatureNamespace    = "http://www.w3.org/2000/09/xmldsig#"
	xmlDigestSHA256          = "http://www.w3.org/2001/04/xmlenc#sha256"
	xmlEnvelopedTransform    = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
	xmlSignatureECDSAP256    = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
	p256XMLSignatureBytes    = 64 // XML Signature 1.1 §6.4.3: fixed-length R || S.
	maximumPinnedSigningKeys = 5  // Reference saml.certificates_per_metadata_entity.
)

// ErrInvalidSignature reports that a required SAML signature does not validate
// against the selected signing keys and profile. It contains no input details.
var ErrInvalidSignature = errors.New("saml: invalid signature")

type samlSignature struct {
	node, signedInfo, value *xdm.Node
	algorithm               string
	claimedDigest           []byte
}

// The caller supplies the exact Response or Assertion from the authoritative
// bounded parse with unique IDs already checked. Verification never reselects
// a referenced node from XML, uses a key from KeyInfo, or reparses a subtree.
func verifySAMLSignature(ctx context.Context, target *xdm.Node, pinned []crypto.PublicKey) (int, error) {
	if ctx == nil || len(pinned) == 0 || len(pinned) > maximumPinnedSigningKeys {
		return -1, ErrInvalidSignature
	}
	if err := ctx.Err(); err != nil {
		return -1, err
	}
	signature, ok := readSAMLSignature(target)
	if !ok {
		return -1, ErrInvalidSignature
	}
	var maximumBytes int
	for _, key := range pinned {
		maximumBytes = max(maximumBytes, samlSignatureKeyBytes(signature.algorithm, key))
	}
	if maximumBytes == 0 {
		return -1, ErrInvalidSignature
	}
	value, ok := decodeSignatureValue(signature.value, maximumBytes)
	if !ok {
		return -1, ErrInvalidSignature
	}

	// XML Signature 1.1 §6.6.4 excludes this enveloped Signature only. In
	// particular, authenticating the Response still covers the Assertion's
	// own signature and all the other signed Response descendants.
	exclusive := c14n.Options{Algorithm: c14n.Exclusive10}
	filtered := c14n.ExcludeSubtree(target, signature.node)
	digest, err := c14n.DigestNodeSet(sha256.New(), filtered, exclusive)
	if err != nil || subtle.ConstantTimeCompare(signature.claimedDigest, digest) != 1 {
		return -1, ErrInvalidSignature
	}
	signedDigest, err := c14n.Digest(sha256.New(), signature.signedInfo, exclusive)
	if err != nil {
		return -1, ErrInvalidSignature
	}
	for index, key := range pinned {
		if err := ctx.Err(); err != nil {
			return -1, err
		}
		if len(value) == samlSignatureKeyBytes(signature.algorithm, key) && verifySAMLSigningKey(key, signedDigest, value) {
			if err := ctx.Err(); err != nil {
				return -1, err
			}
			return index, nil
		}
	}
	return -1, ErrInvalidSignature
}

func readSAMLSignature(target *xdm.Node) (samlSignature, bool) {
	if target == nil || target.Kind() != xdm.KindElement {
		return samlSignature{}, false
	}
	id := target.Attr("", "ID")
	if id == nil || len(id.Value()) > maximumEndpointBytes || !xdm.IsNCName(id.Value()) {
		return samlSignature{}, false
	}
	signature := samlSingleChild(target, xmlSignatureNamespace, "Signature")
	if !optionalSignatureID(signature) {
		return samlSignature{}, false
	}
	sigParts, ok := samlElementChildren(signature, 3)
	if !ok || len(sigParts) < 2 || !samlElement(sigParts[0], xmlSignatureNamespace, "SignedInfo") ||
		!samlElement(sigParts[1], xmlSignatureNamespace, "SignatureValue") ||
		(len(sigParts) == 3 && !samlElement(sigParts[2], xmlSignatureNamespace, "KeyInfo")) ||
		!optionalSignatureID(sigParts[0]) || !optionalSignatureID(sigParts[1]) {
		return samlSignature{}, false
	}
	info := signatureParts(sigParts[0], "CanonicalizationMethod", "SignatureMethod", "Reference")
	if info == nil || !samlMethod(info[0], string(c14n.Exclusive10)) {
		return samlSignature{}, false
	}
	algorithm := info[1].Attr("", "Algorithm")
	if algorithm == nil || !samlMethod(info[1], algorithm.Value()) {
		return samlSignature{}, false
	}
	switch algorithm.Value() {
	case SignatureAlgorithmRSAPSSSHA256, xmlSignatureECDSAP256:
	default:
		return samlSignature{}, false
	}
	reference := info[2]
	uri := reference.Attr("", "URI")
	if uri == nil || uri.Value() != "#"+id.Value() || reference.NumAttrs() != 1 {
		return samlSignature{}, false
	}
	parts := signatureParts(reference, "Transforms", "DigestMethod", "DigestValue")
	if parts == nil || parts[0].NumAttrs() != 0 || !samlMethod(parts[1], xmlDigestSHA256) || parts[2].NumAttrs() != 0 {
		return samlSignature{}, false
	}
	transforms := signatureParts(parts[0], "Transform", "Transform")
	if transforms == nil || !samlMethod(transforms[0], xmlEnvelopedTransform) || !samlMethod(transforms[1], string(c14n.Exclusive10)) {
		return samlSignature{}, false
	}
	digest, ok := decodeSignatureValue(parts[2], sha256.Size)
	if !ok || len(digest) != sha256.Size {
		return samlSignature{}, false
	}
	return samlSignature{signature, sigParts[0], sigParts[1], algorithm.Value(), digest}, true
}

func samlMethod(n *xdm.Node, algorithm string) bool {
	attr := n.Attr("", "Algorithm")
	if n.NumAttrs() != 1 || attr == nil || attr.Value() != algorithm {
		return false
	}
	_, ok := samlElementChildren(n, 0)
	return ok
}

func optionalSignatureID(n *xdm.Node) bool {
	if n == nil {
		return false
	}
	if n.NumAttrs() == 0 {
		return true
	}
	id := n.Attr("", "Id")
	return n.NumAttrs() == 1 && id != nil && len(id.Value()) <= maximumEndpointBytes && xdm.IsNCName(id.Value())
}

func signatureParts(parent *xdm.Node, names ...string) []*xdm.Node {
	children, ok := samlElementChildren(parent, len(names))
	if !ok || len(children) != len(names) {
		return nil
	}
	for i, name := range names {
		if !samlElement(children[i], xmlSignatureNamespace, name) {
			return nil
		}
	}
	return children
}

func samlElementChildren(parent *xdm.Node, maximum int) ([]*xdm.Node, bool) {
	var children []*xdm.Node
	for child := range parent.Children() {
		switch child.Kind() {
		case xdm.KindElement:
			if len(children) == maximum {
				return nil, false
			}
			children = append(children, child)
		case xdm.KindText:
			if strings.Trim(child.Value(), " \t\r\n") != "" {
				return nil, false
			}
		case xdm.KindComment:
			// This profile uses exclusive canonicalization without comments.
		default:
			return nil, false
		}
	}
	return children, true
}

func samlElement(n *xdm.Node, namespace, name string) bool {
	return n != nil && n.Kind() == xdm.KindElement && n.Name().URI == namespace && n.Name().Local == name
}

func samlSingleChild(parent *xdm.Node, namespace, name string) *xdm.Node {
	var match *xdm.Node
	for child := range parent.Children() {
		if !samlElement(child, namespace, name) {
			continue
		}
		if match != nil {
			return nil
		}
		match = child
	}
	return match
}

func decodeSignatureValue(n *xdm.Node, maximumDecoded int) ([]byte, bool) {
	maximumEncoded := base64.StdEncoding.EncodedLen(maximumDecoded)
	encoded := make([]byte, 0, maximumEncoded)
	for child := range n.Children() {
		if child.Kind() != xdm.KindText {
			return nil, false
		}
		raw := child.Value()
		for i := range len(raw) {
			b := raw[i]
			switch b {
			case ' ', '\t', '\r', '\n':
				continue
			}
			if len(encoded) == maximumEncoded {
				return nil, false
			}
			encoded = append(encoded, b)
		}
	}
	if len(encoded) == 0 {
		return nil, false
	}
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))
	size, err := base64.StdEncoding.Strict().Decode(decoded, encoded)
	if err != nil || size > maximumDecoded {
		return nil, false
	}
	return decoded[:size], true
}

func samlSignatureKeyBytes(algorithm string, public crypto.PublicKey) int {
	switch key := public.(type) {
	case *rsa.PublicKey:
		if algorithm == SignatureAlgorithmRSAPSSSHA256 && key != nil && key.N != nil && key.N.Sign() > 0 &&
			key.N.BitLen() >= 2048 && key.Size() <= maximumCertificateBytes && key.E >= 3 && key.E%2 != 0 {
			return key.Size()
		}
	case *ecdsa.PublicKey:
		if algorithm == xmlSignatureECDSAP256 && key != nil && key.Curve == elliptic.P256() && key.X != nil && key.Y != nil && key.Curve.IsOnCurve(key.X, key.Y) {
			return p256XMLSignatureBytes
		}
	}
	return 0
}

func verifySAMLSigningKey(public crypto.PublicKey, digest, value []byte) bool {
	switch key := public.(type) {
	case *rsa.PublicKey:
		options := &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: sha256.Size}
		return rsa.VerifyPSS(key, crypto.SHA256, digest, value, options) == nil
	case *ecdsa.PublicKey:
		r := new(big.Int).SetBytes(value[:p256XMLSignatureBytes/2])
		s := new(big.Int).SetBytes(value[p256XMLSignatureBytes/2:])
		return ecdsa.Verify(key, digest, r, s)
	default:
		return false
	}
}
