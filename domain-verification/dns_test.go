package domainverification

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestCanonicalDomainPolicy(t *testing.T) {
	for input, want := range map[string]string{"example.com": "example.com", "BÜCHER.de": "xn--bcher-kva.de", "EXAMPLE.COM": "example.com"} {
		got, err := canonicalDomain(input)
		if err != nil || got != want {
			t.Fatal("canonical domain rejected", err)
		}
	}
	for _, input := range []string{"com", "co.uk", "example.com.", "127.0.0.1", "*.example.com", "a..com", "a.local", "-bad.example", strings.Repeat("a", 64) + ".com"} {
		if _, err := canonicalDomain(input); !errors.Is(err, ErrInvalidInput) {
			t.Fatal("unsafe domain admitted", err)
		}
	}
}

func TestDNSResolverDiagnosticsDoNotExposeInfrastructure(t *testing.T) {
	resolver, err := NewDNSResolver("127.0.0.1:12345", time.Second, 1232, 8)
	if err != nil {
		t.Fatal(err)
	}
	if text := fmt.Sprintf("%+v %#v %+v %#v", resolver, resolver, *resolver, *resolver); strings.Contains(text, "127.0.0.1") {
		t.Fatal("resolver address leaked into ordinary diagnostics")
	}
}

func TestDNSResolverUsesExactTXTQuestionAndPreservesTTL(t *testing.T) {
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{PacketConn: packet, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		if len(q.Question) != 1 || q.Question[0].Name != "_golib-sso.example.com." || q.Question[0].Qtype != dns.TypeTXT {
			t.Error("query broadened exact TXT scope")
		}
		m := new(dns.Msg).SetReply(q)
		m.Authoritative = true
		m.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 42}, Txt: []string{"golib-sso=", strings.Repeat("a", 64)}}}
		_ = w.WriteMsg(m)
	})}
	done := make(chan error, 1)
	go func() { done <- server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown(); <-done })
	r, err := NewDNSResolver(packet.LocalAddr().String(), time.Second, 1232, 8)
	if err != nil {
		t.Fatal(err)
	}
	answer, err := r.lookup(t.Context(), "_golib-sso.example.com.")
	if err != nil || answer.class != dnsAnswer || answer.ttl != 42*time.Second || len(answer.records) != 1 || answer.records[0] != "golib-sso="+strings.Repeat("a", 64) {
		t.Fatal("exact bounded TXT response lost", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := r.lookup(ctx, "_golib-sso.example.com."); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
}

func TestDNSCancellationStopsAnActiveRead(t *testing.T) {
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan struct{}, 1)
	server := &dns.Server{PacketConn: packet, Handler: dns.HandlerFunc(func(dns.ResponseWriter, *dns.Msg) { seen <- struct{}{} })}
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown(); <-serverDone })
	resolver, err := NewDNSResolver(packet.LocalAddr().String(), 5*time.Second, 1232, 8)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	finished := make(chan error, 1)
	go func() { _, err := resolver.lookup(ctx, "_golib-sso.example.com."); finished <- err }()
	select {
	case <-seen:
	case err := <-finished:
		t.Fatal("lookup never reached independent server", err)
	}
	cancel()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("active cancellation was not retained", err)
		}
	case <-deadline.C:
		t.Error("canceled DNS read waited for resolver timeout")
		<-finished // Join the bounded original call even in the failing state.
	}
}

func TestDNSResponseClassificationFailsClosed(t *testing.T) {
	query := new(dns.Msg).SetQuestion("_golib-sso.example.com.", dns.TypeTXT)
	tests := []struct {
		name   string
		class  dnsClass
		change func(*dns.Msg)
	}{
		{"nodata", dnsNoData, func(*dns.Msg) {}},
		{"nxdomain", dnsNXDOMAIN, func(m *dns.Msg) { m.Rcode = dns.RcodeNameError }},
		{"servfail", dnsServerFailure, func(m *dns.Msg) { m.Rcode = dns.RcodeServerFailure }},
		{"truncated", dnsTruncated, func(m *dns.Msg) { m.Truncated = true }},
		{"wrong-question", dnsMalformed, func(m *dns.Msg) { m.Question[0].Name = "other.example.com." }},
		{"alias", dnsMalformed, func(m *dns.Msg) {
			m.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: "other.example.com."}}
		}},
		{"wrong-owner", dnsMalformed, func(m *dns.Msg) {
			m.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: "other.example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{"value"}}}
		}},
		{"oversized-record", dnsMalformed, func(m *dns.Msg) {
			m.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{strings.Repeat("x", 1233)}}}
		}},
		{"record-count", dnsMalformed, func(m *dns.Msg) {
			for range 9 {
				m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{"value"}})
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			m := new(dns.Msg).SetReply(query)
			m.Question = append([]dns.Question(nil), query.Question...)
			test.change(m)
			if got := classifyDNSAnswer(query, m, 8, 1232); got.class != test.class {
				t.Fatal("unsafe DNS classification", got.class)
			}
		})
	}
}

func FuzzCanonicalDomain(f *testing.F) {
	for _, seed := range []string{"example.com", "BÜCHER.de", "co.uk", "127.0.0.1", "*.example.com", "example.com.", "a..com"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		domain, err := canonicalDomain(input)
		if err == nil {
			again, e := canonicalDomain(domain)
			if e != nil || again != domain || len(domain) > 253 || strings.HasSuffix(domain, ".") {
				t.Fatal("canonicalization changed accepted scope")
			}
		}
	})
}

func FuzzDNSResponse(f *testing.F) {
	query := new(dns.Msg).SetQuestion("_golib-sso.example.com.", dns.TypeTXT)
	answer := new(dns.Msg).SetReply(query)
	answer.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{"golib-sso=" + strings.Repeat("a", 64)}}}
	wire, _ := answer.Pack()
	f.Add(wire)
	f.Add([]byte{0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > 4096 {
			return
		}
		var response dns.Msg
		if response.Unpack(wire) != nil {
			return
		}
		observed := classifyDNSAnswer(query, &response, 8, 1232)
		if len(observed.records) > 8 {
			t.Fatal("unbounded records")
		}
		for _, record := range observed.records {
			if len(record) > 1232 {
				t.Fatal("unbounded record")
			}
		}
	})
}
