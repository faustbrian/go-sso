package domainverification

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"time"

	sso "github.com/faustbrian/go-sso"
)

// HTTPSFetcherConfig is trusted startup network policy, never request input.
// Nil Resolver/DialContext/RootCAs use the standard resolver, bounded dialer and
// system trust roots. Custom network seams must retain normal resolver/dialer
// semantics and cancellation; they cannot replace TLS verification. RootCAs is
// cloned at construction. All borrowed functions must support concurrent calls.
// Timeout is 1ms..30s. Fixed limits are 16 addresses, one TCP connection, 4096
// response-header bytes and 128 body bytes. Ambient proxies are never consulted.
type HTTPSFetcherConfig struct {
	Timeout     time.Duration
	Resolver    *net.Resolver
	DialContext func(context.Context, string, string) (net.Conn, error)
	RootCAs     *x509.CertPool
}

// HTTPSFetcher owns one bounded verified-TLS operation per call, no background
// workers or cached results. It resolves the exact canonical FQDN once, rejects
// every answer if any target is nonpublic, and pins the vetted first IP at 443.
// Each connection is closed before returning; no retry or redirect is followed.
type HTTPSFetcher struct {
	timeout  time.Duration
	resolver *net.Resolver
	dial     func(context.Context, string, string) (net.Conn, error)
	roots    *x509.CertPool
}

func (HTTPSFetcher) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("domainverification.HTTPSFetcher(redacted)"))
}
func (HTTPSFetcherConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("domainverification.HTTPSFetcherConfig(redacted)"))
}

func NewHTTPSFetcher(c HTTPSFetcherConfig) (*HTTPSFetcher, error) {
	if c.Timeout < time.Millisecond || c.Timeout > 30*time.Second {
		return nil, ErrInvalidInput
	}
	resolver := c.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	dial := c.DialContext
	if dial == nil {
		dial = (&net.Dialer{Timeout: c.Timeout, KeepAlive: -1}).DialContext
	}
	var roots *x509.CertPool
	if c.RootCAs != nil {
		roots = c.RootCAs.Clone()
	}
	return &HTTPSFetcher{timeout: c.Timeout, resolver: resolver, dial: dial, roots: roots}, nil
}

// These special-use ranges have global-unicast representations but are not
// public destination authority. IPv6 is restricted to native global 2000::/3,
// excluding protocol assignment, documentation and transition mechanisms.
var excludedHTTPSPrefixes = [...]netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
}

func publicHTTPSAddress(address netip.Addr) bool {
	if !address.IsValid() || address.Zone() != "" || address.Is4In6() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() {
		return false
	}
	if address.Is6() && !netip.MustParsePrefix("2000::/3").Contains(address) {
		return false
	}
	for _, prefix := range excludedHTTPSPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func httpsBodyMatches(body []byte, digest string) bool {
	if len(body) != len("golib-sso=")+64 || len(digest) != 64 {
		return false
	}
	return subtle.ConstantTimeCompare(body, []byte("golib-sso="+digest)) == 1
}

func (f *HTTPSFetcher) fetch(ctx context.Context, domain, digest string) (sso.DomainObservationClass, error) {
	if f == nil || ctx == nil {
		return sso.DomainObservedMalformed, ErrInvalidInput
	}
	canonical, err := canonicalDomain(domain)
	if err != nil || canonical != domain || len(digest) != 64 {
		return sso.DomainObservedMalformed, ErrInvalidInput
	}
	for _, character := range digest {
		if !(character >= 'a' && character <= 'f' || character >= '0' && character <= '9') {
			return sso.DomainObservedMalformed, ErrInvalidInput
		}
	}
	if err = ctx.Err(); err != nil {
		return sso.DomainObservedTimeout, err
	}
	bounded, cancel := context.WithTimeout(ctx, f.timeout)
	defer cancel()
	addresses, err := f.resolver.LookupNetIP(bounded, "ip", domain+".")
	if err != nil {
		return httpsNetworkFailure(ctx, bounded, err)
	}
	if len(addresses) == 0 || len(addresses) > 16 {
		return sso.DomainObservedMalformed, ErrUnavailable
	}
	for _, address := range addresses {
		if !publicHTTPSAddress(address) {
			return sso.DomainObservedMalformed, ErrUnavailable
		}
	}
	destination := netip.AddrPortFrom(addresses[0], 443)
	transport := &http.Transport{
		Proxy: nil, DisableKeepAlives: true, DisableCompression: true,
		MaxConnsPerHost: 1, MaxIdleConns: 1, MaxIdleConnsPerHost: 1,
		MaxResponseHeaderBytes: 4096, ResponseHeaderTimeout: f.timeout,
		TLSHandshakeTimeout: f.timeout, ForceAttemptHTTP2: false,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: domain, RootCAs: f.roots},
		DialContext: func(dialCtx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != net.JoinHostPort(domain, "443") {
				return nil, ErrUnavailable
			}
			conn, dialErr := f.dial(dialCtx, "tcp", destination.String())
			if dialErr != nil {
				if conn != nil {
					_ = conn.Close()
				}
				return nil, ErrUnavailable
			}
			if conn == nil {
				return nil, ErrUnavailable
			}
			peer, parseErr := netip.ParseAddrPort(conn.RemoteAddr().String())
			if parseErr != nil || peer != destination {
				_ = conn.Close()
				return nil, ErrUnavailable
			}
			return conn, nil
		},
	}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(bounded, http.MethodGet, "https://"+domain+"/.well-known/golib-sso", nil)
	if err != nil {
		return sso.DomainObservedMalformed, ErrInvalidInput
	}
	request.Header.Set("Accept", "text/plain")
	// RoundTrip returns redirects as responses. No general client, environment
	// proxy, alternate transport, second resolution or target retry is involved.
	response, err := transport.RoundTrip(request)
	if err != nil {
		return httpsNetworkFailure(ctx, bounded, err)
	}
	defer response.Body.Close()
	if response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
		return sso.DomainObservedMalformed, ErrUnavailable
	}
	if response.StatusCode == http.StatusNotFound {
		return sso.DomainObservedNoData, nil
	}
	if response.StatusCode != http.StatusOK {
		return sso.DomainObservedMalformed, ErrUnavailable
	}
	media, parameters, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || media != "text/plain" || len(parameters) != 0 || len(response.Header.Values("Content-Type")) != 1 || response.Header.Get("Content-Encoding") != "" || response.ContentLength > 128 {
		return sso.DomainObservedMalformed, ErrUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 129))
	defer clear(body)
	if err != nil {
		return httpsNetworkFailure(ctx, bounded, err)
	}
	if len(body) > 128 {
		return sso.DomainObservedMalformed, ErrUnavailable
	}
	if httpsBodyMatches(body, digest) {
		return sso.DomainObservedMatch, nil
	}
	return sso.DomainObservedMismatch, nil
}

func httpsNetworkFailure(ctx, bounded context.Context, cause error) (sso.DomainObservationClass, error) {
	if err := ctx.Err(); err != nil {
		return sso.DomainObservedTimeout, err
	}
	if bounded.Err() != nil {
		return sso.DomainObservedTimeout, ErrUnavailable
	}
	var timeout net.Error
	if errors.As(cause, &timeout) && timeout.Timeout() {
		return sso.DomainObservedTimeout, ErrUnavailable
	}
	return sso.DomainObservedMalformed, ErrUnavailable
}

// NewHTTPSEngine explicitly selects the HTTPS-only profile while NewEngine
// retains DNS-only behavior. The fixed path is /.well-known/golib-sso, media is
// exactly text/plain without parameters, body exactly golib-sso=<issued digest>
// without whitespace. Freshness begins before DNS and is capped by the profile
// observation TTL and issued expiry; HTTPS cache headers never renew it.
func NewHTTPSEngine(profile Profile, fetcher *HTTPSFetcher) (*Engine, error) {
	if profile.config.Clock == nil || fetcher == nil || fetcher.timeout < time.Millisecond || fetcher.timeout > 30*time.Second || fetcher.resolver == nil || fetcher.dial == nil {
		return nil, ErrInvalidInput
	}
	return &Engine{profile: profile, https: fetcher, active: make(chan struct{}, profile.config.MaxConcurrent)}, nil
}

func (e *Engine) observeHTTPS(ctx context.Context, request sso.DomainProofRequest) (sso.DomainProofObservation, error) {
	if request.Method() != sso.DomainProofHTTPS {
		return sso.DomainProofObservation{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return sso.DomainProofObservation{}, err
	}
	select {
	case e.active <- struct{}{}:
		defer func() { <-e.active }()
	default:
		return sso.DomainProofObservation{}, ErrThrottled
	}
	bounded, cancel := context.WithTimeout(ctx, e.profile.config.MaximumDuration)
	defer cancel()
	started := e.profile.config.Clock.Now().UTC().Truncate(time.Microsecond)
	if started.Before(request.IssuedAt()) || !started.Before(request.ExpiresAt()) {
		return sso.DomainProofObservation{}, ErrInvalidInput
	}
	class, err := e.https.fetch(bounded, request.Claim().Domain, request.ChallengeDigest())
	if ctx.Err() != nil {
		return sso.DomainProofObservation{}, ctx.Err()
	}
	until := started.Add(e.profile.config.ObservationTTL)
	if request.ExpiresAt().Before(until) {
		until = request.ExpiresAt()
	}
	if !until.After(e.profile.config.Clock.Now()) {
		return sso.DomainProofObservation{}, ErrUnavailable
	}
	observation, buildErr := sso.NewDomainProofObservation(request, class, started, until, sso.DomainSourceHTTPS)
	if buildErr != nil {
		return sso.DomainProofObservation{}, ErrInvalidInput
	}
	return observation, err
}
