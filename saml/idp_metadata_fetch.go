package saml

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	httpclient "github.com/faustbrian/go-http-client/v2"
)

const metadataFetchTimeout = 5 * time.Second

// ErrMetadataUnavailable reports a failed or unacceptable HTTPS metadata
// response. It never carries a destination, response body or transport error.
var ErrMetadataUnavailable = errors.New("saml: metadata unavailable")

// FetchIDPMetadata retrieves the approved exact HTTPS URL and imports the
// original bytes only when their SHA-256 digest and entity both match separate
// configuration approval. Call it outside the sign-in request path. It uses
// system TLS trust, public-address-only direct egress, no redirects or cookies,
// and a five-second total budget (a caller deadline may shorten it). A fresh
// call is required after a response failure; there is no cache or fallback.
// URLs must use a DNS host. IP literals and internal addresses are unsupported.
// The response must be uncompressed XML, at most one MiB. The document expiry
// is checked after retrieval. This neither writes provider state nor grants
// authority to activate or replace an existing provider.
//
// Invalid input or unapproved document bytes return ErrInvalidInput; HTTPS
// and response failures return ErrMetadataUnavailable. Cancellation or deadline
// returns the context error. All failures return a zero metadata result.
func FetchIDPMetadata(ctx context.Context, sourceURL, expectedEntityID string, approvedSHA256 [32]byte) (IDPMetadata, error) {
	if ctx == nil {
		return IDPMetadata{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return IDPMetadata{}, err
	}
	target, valid := approvedMetadataSource(sourceURL)
	if !valid || !samlIdPEntityID(expectedEntityID) || approvedSHA256 == [32]byte{} {
		return IDPMetadata{}, ErrInvalidInput
	}
	egress, err := metadataFetchEgress(target, nil)
	if err != nil || egress.ValidateURL(&target) != nil {
		return IDPMetadata{}, ErrInvalidInput
	}
	client, err := newMetadataFetchClient(egress, nil)
	if err != nil {
		return IDPMetadata{}, ErrMetadataUnavailable
	}
	defer client.Close()
	return fetchMetadataWithClient(ctx, client, sourceURL, expectedEntityID, approvedSHA256)
}

func approvedMetadataSource(raw string) (url.URL, bool) {
	target, valid := samlHTTPSURL(raw, maximumEndpointBytes, true)
	host := target.Hostname()
	if !valid || strings.Contains(raw, "#") || !strings.Contains(host, ".") || strings.HasSuffix(host, ".") ||
		strings.HasSuffix(target.Host, ":") || net.ParseIP(host) != nil {
		return url.URL{}, false
	}
	return target, true
}

func metadataFetchEgress(target url.URL, resolver httpclient.EgressResolver) (*httpclient.EgressPolicy, error) {
	port := uint64(443)
	if value := target.Port(); value != "" {
		var err error
		if port, err = strconv.ParseUint(value, 10, 16); err != nil || port == 0 {
			return nil, ErrInvalidInput
		}
	}
	return httpclient.NewEgressPolicy(httpclient.EgressOptions{
		AllowedHosts:   []string{target.Hostname()},
		AllowedOrigins: []string{"https://" + target.Host},
		AllowedPorts:   []uint16{uint16(port)},
		Resolver:       resolver,
		// Supplement the client's blocked local/metadata classes with IANA
		// special-use IPv4 ranges and IPv6 transition/special-use ranges. In
		// particular, IPv6 translation must not stand in for a local IPv4 dial.
		AllowedCIDRs: []string{"0.0.0.0/0", "2000::/3"},
		DeniedCIDRs: []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24",
			"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4",
			"2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20"},
	})
}

func newMetadataFetchClient(egress *httpclient.EgressPolicy, tlsPolicy *httpclient.TLSPolicy) (*httpclient.Client, error) {
	client, err := httpclient.New(httpclient.Config{Egress: egress, TLS: tlsPolicy, Timeout: metadataFetchTimeout, ProxyMode: httpclient.ProxyDisabled})
	if err != nil {
		return nil, err
	}
	client.HTTPClient().CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return client, nil
}

func fetchMetadataWithClient(ctx context.Context, client *httpclient.Client, sourceURL, entityID string, digest [32]byte) (IDPMetadata, error) {
	ctx, cancel := context.WithTimeout(ctx, metadataFetchTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, sourceURL, nil)
	if err != nil {
		return IDPMetadata{}, ErrInvalidInput
	}
	request.Header.Set("Accept", "application/samlmetadata+xml, application/xml, text/xml")
	response, err := client.Do(request)
	if err != nil {
		return IDPMetadata{}, metadataFetchFailure(ctx)
	}
	if response.StatusCode != http.StatusOK || response.ContentLength > maximumSAMLXMLBytes ||
		len(response.Header.Values("Content-Encoding")) != 0 || len(response.Header.Values("Content-Type")) != 1 {
		_ = response.Body.Close()
		return IDPMetadata{}, metadataFetchFailure(ctx)
	}
	document, err := httpclient.DecodeResponse(response, httpclient.DecodeOptions{
		MaximumBodyBytes:   maximumSAMLXMLBytes,
		ExpectedMediaTypes: []string{"application/samlmetadata+xml", "application/xml", "text/xml"},
	}, io.ReadAll)
	if err != nil {
		return IDPMetadata{}, metadataFetchFailure(ctx)
	}
	return ImportIDPMetadata(ctx, document, entityID, digest, time.Now())
}

func metadataFetchFailure(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrMetadataUnavailable
}
