package saml

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	httpclient "github.com/faustbrian/go-http-client/v2"
)

const fetchTestEntity = "urn:example:metadata:approved"

func TestFetchIDPMetadataThroughOwnedTLS(t *testing.T) {
	metadata := testFetchDocument(t)
	digest := sha256.Sum256(metadata)
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Error("unexpected credentials or method")
		}
		w.Header().Set("Content-Type", "application/samlmetadata+xml; charset=utf-8")
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "/ok", http.StatusFound)
		case "/oversized":
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			_, _ = io.WriteString(w, strings.Repeat("x", maximumSAMLXMLBytes+1))
		case "/encoded":
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = w.Write(metadata)
		case "/wrong-type":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write(metadata)
		default:
			_, _ = w.Write(metadata)
		}
	}))
	t.Cleanup(server.Close)
	trusted, err := httpclient.NewTLSPolicy(httpclient.TLSOptions{RootCertificatesPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(server.URL)
	port, _ := strconv.ParseUint(u.Port(), 10, 16)
	// The test policy is deliberately different from production address admission.
	// The same owned HTTP client, redirect controls and import path still run.
	egress, err := httpclient.NewEgressPolicy(httpclient.EgressOptions{AllowedOrigins: []string{server.URL}, AllowedPorts: []uint16{uint16(port)}, AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	client, err := newMetadataFetchClient(egress, trusted)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	result, err := fetchMetadataWithClient(t.Context(), client, server.URL+"/ok", fetchTestEntity, digest)
	if err != nil || result.EntityID != fetchTestEntity || result.RedirectEndpoint != "https://idp.example/sso" || len(result.SigningCertificates) != 1 {
		t.Fatal("HTTPS response did not reach verified import", err)
	}
	badDigest := digest
	badDigest[0] ^= 1
	for _, tc := range []struct {
		path   string
		digest [32]byte
		want   error
	}{{"/redirect", digest, ErrMetadataUnavailable}, {"/oversized", digest, ErrMetadataUnavailable}, {"/encoded", digest, ErrMetadataUnavailable}, {"/wrong-type", digest, ErrMetadataUnavailable}, {"/ok", badDigest, ErrInvalidInput}} {
		before := calls.Load()
		out, err := fetchMetadataWithClient(t.Context(), client, server.URL+tc.path, fetchTestEntity, tc.digest)
		if !errors.Is(err, tc.want) || out.EntityID != "" || out.SigningCertificates != nil || calls.Load() != before+1 {
			t.Fatalf("%s: expected exactly one request and no imported result: %v", tc.path, err)
		}
	}
	wrongTrust, err := newMetadataFetchClient(egress, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer wrongTrust.Close()
	if _, err := fetchMetadataWithClient(t.Context(), wrongTrust, server.URL+"/ok", fetchTestEntity, digest); !errors.Is(err, ErrMetadataUnavailable) {
		t.Fatal("untrusted TLS was not denied", err)
	}
}

func TestFetchIDPMetadataDeniesUnapprovedInputAndNonPublicAnswers(t *testing.T) {
	digest := sha256.Sum256([]byte("approved fixture bytes"))
	for _, source := range []string{"http://idp.example/metadata", "https://127.0.0.1/metadata", "https://idp.example/metadata#section", "https://user@idp.example/metadata"} {
		out, err := FetchIDPMetadata(t.Context(), source, fetchTestEntity, digest)
		if !errors.Is(err, ErrInvalidInput) || out.EntityID != "" {
			t.Fatalf("invalid source was admitted: %v", err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := FetchIDPMetadata(ctx, "https://idp.example/metadata", fetchTestEntity, digest); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation not preserved", err)
	}
	u, _ := url.Parse("https://idp.example/metadata")
	resolver := httpclient.EgressResolverFunc(func(_ context.Context, _, _ string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("100.64.1.1")}, nil
	})
	egress, err := metadataFetchEgress(*u, resolver)
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"127.0.0.1", "10.0.0.1", "100.64.1.1", "169.254.169.254", "::1", "64:ff9b::7f00:1", "2002:7f00:1::1"} {
		if err := egress.ValidateIP(net.ParseIP(address)); !errors.Is(err, httpclient.ErrEgressDenied) {
			t.Fatalf("non-public address not denied: %s", address)
		}
	}
	client, err := newMetadataFetchClient(egress, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	r, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, u.String(), nil)
	if _, err := client.Do(r); !errors.Is(err, httpclient.ErrEgressDenied) {
		t.Fatal("mixed DNS answer did not fail before dial", err)
	}
}

func FuzzApprovedMetadataSource(f *testing.F) {
	for _, seed := range []string{"https://idp.example/metadata?version=selected", "https://127.0.0.1/metadata", "https://idp.example/metadata#other"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		target, ok := approvedMetadataSource(raw)
		if !ok {
			return
		}
		if target.Scheme != "https" || target.User != nil || target.String() != raw || net.ParseIP(target.Hostname()) != nil || target.Fragment != "" {
			t.Fatal("metadata source escaped its exact HTTPS authority")
		}
	})
}

func testFetchDocument(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(`<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="` + fetchTestEntity + `"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>` + base64.StdEncoding.EncodeToString(der) + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>`)
}
