package domainverification

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-clock"
	sso "github.com/faustbrian/go-sso"
	"github.com/miekg/dns"
)

// The fixture changes network delivery only. The production TLS handshake still
// authenticates example.com with an explicit test CA, not InsecureSkipVerify.
type pinnedFixtureConn struct {
	net.Conn
	destination net.Addr
}

func (c pinnedFixtureConn) RemoteAddr() net.Addr { return c.destination }

type httpsFixture struct {
	config            HTTPSFetcherConfig
	queries, requests atomic.Int32
	address           atomic.Value
	server            *httptest.Server
}

func newHTTPSFixture(t *testing.T, handler http.HandlerFunc) *httpsFixture {
	t.Helper()
	f := &httpsFixture{}
	f.address.Store("93.184.216.34")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "HTTPS fixture"}, DNSNames: []string{"example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	f.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		if r.Host != "example.com" || r.URL.Path != "/.well-known/golib-sso" || r.URL.RawQuery != "" || r.TLS == nil || r.TLS.ServerName != "example.com" {
			t.Error("HTTPS widened exact host/path/SNI")
		}
		handler(w, r)
	}))
	f.server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	f.server.StartTLS()
	t.Cleanup(f.server.Close)
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{PacketConn: packet, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		f.queries.Add(1)
		m := new(dns.Msg).SetReply(q)
		m.Authoritative = true
		if len(q.Question) != 1 || (q.Question[0].Name != "example.com." && q.Question[0].Name != "other.example.com.") {
			t.Error("resolver widened canonical FQDN")
		}
		if q.Question[0].Qtype == dns.TypeA {
			m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP(f.address.Load().(string))}}
		}
		_ = w.WriteMsg(m)
	})}
	done := make(chan error, 1)
	go func() { done <- server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown(); <-done })
	f.config = HTTPSFetcherConfig{Timeout: time.Second, RootCAs: roots, Resolver: &net.Resolver{PreferGo: true, StrictErrors: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp4", packet.LocalAddr().String())
	}}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "93.184.216.34:443" {
			t.Error("dial was not pinned to vetted address and port 443")
			return nil, errors.New("fixture destination rejected")
		}
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", f.server.Listener.Addr().String())
		if err != nil {
			return nil, err
		}
		return pinnedFixtureConn{Conn: conn, destination: &net.TCPAddr{IP: net.ParseIP("93.184.216.34"), Port: 443}}, nil
	}}
	return f
}

func TestHTTPSVerifiedTLSExactPublicationAndNoAmbientProxy(t *testing.T) {
	digest := strings.Repeat("a", 64)
	f := newHTTPSFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("golib-sso=" + digest))
	})
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	fetcher, err := NewHTTPSFetcher(f.config)
	if err != nil {
		t.Fatal(err)
	}
	class, err := fetcher.fetch(t.Context(), "example.com", digest)
	if err != nil || class != sso.DomainObservedMatch || f.requests.Load() != 1 {
		t.Fatal("verified exact HTTPS publication not matched", class, err)
	}
	// A fresh DNS answer becoming private must fail before any second request.
	f.address.Store("127.0.0.1")
	class, err = fetcher.fetch(t.Context(), "example.com", digest)
	if err == nil || class == sso.DomainObservedMatch || f.requests.Load() != 1 {
		t.Fatal("private re-resolution reached HTTPS", class, err)
	}
}

func TestHTTPSRejectsTLSRedirectAndUnboundedOrAmbiguousBodies(t *testing.T) {
	digest := strings.Repeat("a", 64)
	for _, name := range []string{"untrusted", "wrong-host", "redirect", "oversized-header", "oversized-body", "encoding", "media", "newline", "status"} {
		t.Run(name, func(t *testing.T) {
			f := newHTTPSFixture(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				switch name {
				case "redirect":
					w.Header().Set("Location", "https://127.0.0.1/private")
					w.WriteHeader(http.StatusFound)
					return
				case "oversized-header":
					w.Header().Set("X-Oversize", strings.Repeat("x", 8192))
				case "oversized-body":
					_, _ = w.Write([]byte(strings.Repeat("x", 8192)))
					return
				case "encoding":
					w.Header().Set("Content-Encoding", "gzip")
				case "media":
					w.Header().Set("Content-Type", "application/json")
				case "newline":
					_, _ = w.Write([]byte("golib-sso=" + digest + "\n"))
					return
				case "status":
					w.WriteHeader(http.StatusNotFound)
					return
				}
				_, _ = w.Write([]byte("golib-sso=" + digest))
			})
			if name == "untrusted" {
				f.config.RootCAs = x509.NewCertPool()
			}
			fetcher, err := NewHTTPSFetcher(f.config)
			if err != nil {
				t.Fatal(err)
			}
			domain := "example.com"
			if name == "wrong-host" {
				domain = "other.example.com"
			}
			class, _ := fetcher.fetch(t.Context(), domain, digest)
			if class == sso.DomainObservedMatch {
				t.Fatal("hostile response admitted")
			}
			if f.requests.Load() > 1 {
				t.Fatal("redirect or retry issued another request")
			}
		})
	}
}

func TestHTTPSPublicAddressPolicy(t *testing.T) {
	for _, value := range []string{"127.0.0.1", "10.0.0.1", "100.64.0.1", "169.254.169.254", "192.0.0.1", "192.0.2.1", "198.18.0.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "240.0.0.1", "::", "::1", "::ffff:127.0.0.1", "fc00::1", "fe80::1", "2001:db8::1", "2002::1"} {
		if publicHTTPSAddress(netip.MustParseAddr(value)) {
			t.Fatal("unsafe HTTPS destination admitted", value)
		}
	}
	for _, value := range []string{"93.184.216.34", "2606:4700:4700::1111"} {
		if !publicHTTPSAddress(netip.MustParseAddr(value)) {
			t.Fatal("public HTTPS destination rejected", value)
		}
	}
}

func TestHTTPSEngineRejectsUnconstructedFetcher(t *testing.T) {
	profile, err := NewProfile(ProfileConfig{Clock: clock.System{}, MaximumDuration: time.Second, ObservationTTL: time.Minute, MaxConcurrent: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NewHTTPSEngine(profile, &HTTPSFetcher{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("zero fetcher admitted to public engine constructor", err)
	}
}

func TestHTTPSCancellationClosesActiveBodyAndRejectsForeignPeer(t *testing.T) {
	started := make(chan struct{}, 1)
	closed := make(chan struct{}, 1)
	f := newHTTPSFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		started <- struct{}{}
		<-r.Context().Done()
		closed <- struct{}{}
	})
	f.config.Timeout = 5 * time.Second
	fetcher, err := NewHTTPSFetcher(f.config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := fetcher.fetch(ctx, "example.com", strings.Repeat("a", 64)); done <- err }()
	select {
	case <-started:
	case err := <-done:
		t.Fatal("active body never reached", err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("active cancellation lost", err)
		}
	case <-time.After(time.Second):
		t.Error("active body did not cancel promptly")
		<-done
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("canceled connection remained open")
	}

	// A startup dial seam returning a different peer cannot evade the vetted-IP
	// check, even if that peer presents a trusted certificate for the host.
	f.config.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", f.server.Listener.Addr().String())
	}
	fetcher, err = NewHTTPSFetcher(f.config)
	if err != nil {
		t.Fatal(err)
	}
	if class, err := fetcher.fetch(t.Context(), "example.com", strings.Repeat("a", 64)); err == nil || class == sso.DomainObservedMatch {
		t.Fatal("foreign peer admitted")
	}
	if f.requests.Load() != 1 {
		t.Fatal("foreign peer reached HTTPS handler")
	}
}

func FuzzHTTPSBody(f *testing.F) {
	for _, seed := range []string{"golib-sso=" + strings.Repeat("a", 64), "", strings.Repeat("a", 8192), "golib-sso=bad\n"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		if httpsBodyMatches([]byte(body), strings.Repeat("a", 64)) && body != "golib-sso="+strings.Repeat("a", 64) {
			t.Fatal("nonexact HTTPS body matched")
		}
	})
}
