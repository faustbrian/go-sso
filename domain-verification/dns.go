// Package domainverification implements the selected bounded DNS TXT profile.
// It never issues challenges, persists proof, changes ownership or routes SSO.
// HTTPS, CNAME aliases, DNSSEC validation, retries and local caches are disabled.
package domainverification

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/faustbrian/go-clock"
	sso "github.com/faustbrian/go-sso"
	"github.com/miekg/dns"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// Error is a stable redacted implementation failure, never a raw resolver error.
type Error string

func (e Error) Error() string { return string(e) }

const (
	ErrInvalidInput Error = "sso/domain-verification: invalid input"
	ErrUnavailable  Error = "sso/domain-verification: unavailable"
	ErrThrottled    Error = "sso/domain-verification: concurrency exhausted"
)

// Clock supplies read-start time; the configured clock must be concurrency-safe.
type Clock = clock.Clock

// ProfileConfig explicitly selects DNS only. MaximumDuration is 1ms..30s;
// ObservationTTL is 1s..24h and cannot extend DNS remaining TTL or challenge
// expiry. MaxConcurrent is 1..1024, with immediate rejection rather than a queue.
type ProfileConfig struct {
	MaximumDuration, ObservationTTL time.Duration
	MaxConcurrent                   int
	Clock                           Clock
}

// Profile is immutable and valid only when returned by NewProfile.
type Profile struct{ config ProfileConfig }

func NewProfile(c ProfileConfig) (Profile, error) {
	if c.Clock == nil || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second || c.ObservationTTL < time.Second || c.ObservationTTL > 24*time.Hour || c.MaxConcurrent < 1 || c.MaxConcurrent > 1024 {
		return Profile{}, ErrInvalidInput
	}
	return Profile{config: c}, nil
}

// DNSResolver queries a trusted configured numeric resolver endpoint. This
// profile uses bounded UDP only; TC rejects rather than silently changing the
// transport/size policy. The endpoint is startup policy, not request input.
// It starts no goroutines and owns each socket only for the duration of lookup.
type DNSResolver struct {
	address        string
	timeout        time.Duration
	maximumBytes   uint16
	maximumRecords int
}

func (DNSResolver) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("domainverification.DNSResolver(redacted)"))
}

// NewDNSResolver requires a numeric host:port, timeout 1ms..30s, wire budget
// 512..4096 and total record budget 1..64. There is no search suffix or fallback.
func NewDNSResolver(address string, timeout time.Duration, maximumBytes uint16, maximumRecords int) (*DNSResolver, error) {
	endpoint, e := netip.ParseAddrPort(address)
	if e != nil || endpoint.Port() == 0 || endpoint.Addr().IsUnspecified() || timeout < time.Millisecond || timeout > 30*time.Second || maximumBytes < 512 || maximumBytes > 4096 || maximumRecords < 1 || maximumRecords > 64 {
		return nil, ErrInvalidInput
	}
	return &DNSResolver{address: address, timeout: timeout, maximumBytes: maximumBytes, maximumRecords: maximumRecords}, nil
}

type dnsClass uint8

const (
	dnsAnswer dnsClass = iota
	dnsNoData
	dnsNXDOMAIN
	dnsServerFailure
	dnsTruncated
	dnsMalformed
)

type dnsObservation struct {
	class   dnsClass
	records []string
	ttl     time.Duration
}

func (r *DNSResolver) lookup(ctx context.Context, owner string) (dnsObservation, error) {
	if r == nil || ctx == nil {
		return dnsObservation{}, ErrInvalidInput
	}
	if e := ctx.Err(); e != nil {
		return dnsObservation{}, e
	}
	bounded, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	query := new(dns.Msg).SetQuestion(owner, dns.TypeTXT)
	query.SetEdns0(r.maximumBytes, false)
	client := dns.Client{Net: "udp", UDPSize: r.maximumBytes, Timeout: r.timeout}
	connection, e := client.DialContext(bounded, r.address)
	if e != nil {
		if ctx.Err() != nil {
			return dnsObservation{}, ctx.Err()
		}
		if bounded.Err() != nil {
			return dnsObservation{}, bounded.Err()
		}
		var timeout net.Error
		if errors.As(e, &timeout) && timeout.Timeout() {
			return dnsObservation{}, context.DeadlineExceeded
		}
		return dnsObservation{}, ErrUnavailable
	}
	defer connection.Close()
	// miekg/dns ExchangeContext applies deadlines, but does not interrupt an
	// active read on early cancellation (client.go v1.1.73). Own the socket
	// cancellation and join that bounded callback before returning.
	closed := make(chan struct{})
	stop := context.AfterFunc(bounded, func() { _ = connection.Close(); close(closed) })
	defer func() {
		if !stop() {
			<-closed
		}
	}()
	answer, _, e := client.ExchangeWithConnContext(bounded, query, connection)
	if e != nil {
		if ctx.Err() != nil {
			return dnsObservation{}, ctx.Err()
		}
		if bounded.Err() != nil {
			return dnsObservation{}, bounded.Err()
		}
		var timeout net.Error
		if errors.As(e, &timeout) && timeout.Timeout() {
			return dnsObservation{}, context.DeadlineExceeded
		}
		return dnsObservation{class: dnsMalformed}, ErrUnavailable
	}
	return classifyDNSAnswer(query, answer, r.maximumRecords, int(r.maximumBytes)), nil
}

func classifyDNSAnswer(query, answer *dns.Msg, maximumRecords, maximumBytes int) dnsObservation {
	if query == nil || answer == nil || len(query.Question) != 1 {
		return dnsObservation{class: dnsMalformed}
	}
	owner := query.Question[0].Name
	if !answer.Response || answer.Opcode != dns.OpcodeQuery || len(answer.Question) != 1 || answer.Question[0] != query.Question[0] || len(answer.Answer)+len(answer.Ns)+len(answer.Extra) > maximumRecords {
		return dnsObservation{class: dnsMalformed}
	}
	if answer.Truncated {
		return dnsObservation{class: dnsTruncated}
	}
	switch answer.Rcode {
	case dns.RcodeNameError:
		return dnsObservation{class: dnsNXDOMAIN}
	case dns.RcodeSuccess:
	default:
		return dnsObservation{class: dnsServerFailure}
	}
	observed := dnsObservation{class: dnsNoData}
	for _, rr := range answer.Answer {
		// RFC 1034 aliases change the exact queried owner. This selected profile
		// intentionally permits zero alias depth rather than following targets.
		if _, alias := rr.(*dns.CNAME); alias {
			return dnsObservation{class: dnsMalformed}
		}
		txt, ok := rr.(*dns.TXT)
		if !ok || !strings.EqualFold(txt.Hdr.Name, owner) || txt.Hdr.Class != dns.ClassINET {
			return dnsObservation{class: dnsMalformed}
		}
		var record strings.Builder
		for _, chunk := range txt.Txt {
			if record.Len()+len(chunk) > maximumBytes {
				return dnsObservation{class: dnsMalformed}
			}
			record.WriteString(chunk)
		}
		observed.records = append(observed.records, record.String())
		ttl := time.Duration(txt.Hdr.Ttl) * time.Second
		if len(observed.records) == 1 || ttl < observed.ttl {
			observed.ttl = ttl
		}
		observed.class = dnsAnswer
	}
	return observed
}

// Engine performs only Observe. The semaphore owns bounded active calls; no
// locks are held over DNS or callbacks. Callers own its borrowed resolver/clock.
type Engine struct {
	profile  Profile
	resolver *DNSResolver
	active   chan struct{}
}

func (Engine) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("domainverification.Engine(redacted)"))
}

var _ sso.DomainProofEngine = (*Engine)(nil)

func NewEngine(profile Profile, resolver *DNSResolver) (*Engine, error) {
	if profile.config.Clock == nil || resolver == nil {
		return nil, ErrInvalidInput
	}
	return &Engine{profile: profile, resolver: resolver, active: make(chan struct{}, profile.config.MaxConcurrent)}, nil
}

func canonicalDomain(input string) (string, error) {
	if len(input) < 3 || len(input) > 253 || strings.HasSuffix(input, ".") || strings.Contains(input, "*") {
		return "", ErrInvalidInput
	}
	if _, e := netip.ParseAddr(input); e == nil {
		return "", ErrInvalidInput
	}
	domain, e := idna.Lookup.ToASCII(input)
	if e != nil || len(domain) > 253 {
		return "", ErrInvalidInput
	}
	domain = strings.ToLower(domain)
	for _, label := range strings.Split(domain, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", ErrInvalidInput
		}
		for _, b := range []byte(label) {
			if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-') {
				return "", ErrInvalidInput
			}
		}
	}
	suffix, icann := publicsuffix.PublicSuffix(domain)
	// Unknown single-label suffixes (including local search namespaces) are
	// unsupported. Private PSL suffixes remain usable for their registrants.
	if suffix == domain || !icann && !strings.Contains(suffix, ".") {
		return "", ErrInvalidInput
	}
	if _, e = publicsuffix.EffectiveTLDPlusOne(domain); e != nil {
		return "", ErrInvalidInput
	}
	return domain, nil
}

func (e *Engine) Observe(ctx context.Context, request sso.DomainProofRequest) (sso.DomainProofObservation, error) {
	if e == nil || ctx == nil || request.Validate() != nil || request.Method() != sso.DomainProofDNS {
		return sso.DomainProofObservation{}, ErrInvalidInput
	}
	domain, err := canonicalDomain(request.Claim().Domain)
	if err != nil || domain != request.Claim().Domain {
		return sso.DomainProofObservation{}, ErrInvalidInput
	}
	if err = ctx.Err(); err != nil {
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
	owner := "_golib-sso." + domain + "."
	// RFC 1035 limits the complete wire name to 255 octets, including label
	// lengths and root. The extra TXT-owner label must fit, not just the domain.
	if len(owner) > 254 {
		return sso.DomainProofObservation{}, ErrInvalidInput
	}
	answer, err := e.resolver.lookup(bounded, owner)
	class := sso.DomainObservedNoData
	switch answer.class {
	case dnsNXDOMAIN:
		class = sso.DomainObservedNXDOMAIN
	case dnsServerFailure:
		class = sso.DomainObservedServerFailure
	case dnsTruncated:
		class = sso.DomainObservedTruncated
	case dnsMalformed:
		class = sso.DomainObservedMalformed
	case dnsAnswer:
		class = sso.DomainObservedMismatch
		want := "golib-sso=" + request.ChallengeDigest()
		matched := 0
		for _, record := range answer.records {
			matched |= subtle.ConstantTimeCompare([]byte(record), []byte(want))
		}
		if matched == 1 {
			class = sso.DomainObservedMatch
		}
	}
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return sso.DomainProofObservation{}, context.Canceled
		}
		if errors.Is(err, context.DeadlineExceeded) {
			class = sso.DomainObservedTimeout
		} else {
			class = sso.DomainObservedMalformed
		}
	}
	until := started.Add(e.profile.config.ObservationTTL)
	if answer.class == dnsAnswer && started.Add(answer.ttl).Before(until) {
		until = started.Add(answer.ttl)
	}
	if request.ExpiresAt().Before(until) {
		until = request.ExpiresAt()
	}
	if !until.After(e.profile.config.Clock.Now()) {
		return sso.DomainProofObservation{}, ErrUnavailable
	}
	observation, buildErr := sso.NewDomainProofObservation(request, class, started, until, sso.DomainSourceDNS)
	if buildErr != nil {
		return sso.DomainProofObservation{}, ErrInvalidInput
	}
	// Classified transient failures never become ownership loss or success.
	if err != nil || class == sso.DomainObservedServerFailure || class == sso.DomainObservedTruncated || class == sso.DomainObservedMalformed {
		return observation, ErrUnavailable
	}
	return observation, nil
}
