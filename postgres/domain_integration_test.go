//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	capability "github.com/faustbrian/go-capability/v2"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	ratelimit "github.com/faustbrian/go-rate-limit/v2"
	"github.com/faustbrian/go-rate-limit/v2/memory"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	sso "github.com/faustbrian/go-sso"
	domainverification "github.com/faustbrian/go-sso/domain-verification"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/miekg/dns"
)

// The independent task-owned authoritative server speaks DNS wire protocol.
// Only its external TXT publication seam is controlled; proof/claim/session/
// policy/transaction custody uses actual public native owners below.
type dnsZone struct {
	mu           sync.RWMutex
	records      map[string]string
	queries      atomic.Int32
	ttl          uint32
	httpsGate    <-chan struct{}
	httpsStarted chan<- struct{}
}

func (z *dnsZone) publish(owner, value string) {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.records[owner] = value
}
func (z *dnsZone) serve(w dns.ResponseWriter, q *dns.Msg) {
	z.queries.Add(1)
	m := new(dns.Msg).SetReply(q)
	m.Authoritative = true
	if len(q.Question) != 1 || q.Question[0].Qtype != dns.TypeTXT {
		m.Rcode = dns.RcodeFormatError
		_ = w.WriteMsg(m)
		return
	}
	z.mu.RLock()
	value, ok := z.records[q.Question[0].Name]
	ttl := z.ttl
	z.mu.RUnlock()
	if !ok {
		m.Rcode = dns.RcodeNameError
	} else {
		m.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl}, Txt: []string{value}}}
	}
	_ = w.WriteMsg(m)
}

type domainFixture struct {
	org           *orgFixture
	store         *ssopg.Store
	config        sso.DomainConfig
	zone          *dnsZone
	service       *sso.Service
	custody       ssopg.Config
	httpsRequests *atomic.Int32
	engine        *domainverification.Engine
}

func nativeDomainFixture(t *testing.T) *domainFixture {
	return nativeDomainFixtureMethod(t, false)
}

func nativeDomainFixtureMethod(t *testing.T, https bool) *domainFixture {
	t.Helper()
	sources := []migrations.Source{organizationpg.DomainClaimMigrationSource{Version: 310}, organizationpg.DomainEvidenceMigrationSource{Version: 311}, ssopg.DomainChallengeMigrationSource{Version: 312}}
	if https {
		sources = append(sources, ssopg.DomainChallengeMethodMigrationSource{Version: 313})
	}
	f := newOrgFixtureWithIdentities(t, []identity.TenantID{"org-test-basic", "org-test-other"}, []identity.UserID{"owner"}, sources...)
	provider, e := keyring.New(map[string][]byte{"domain-custody": bytes.Repeat([]byte{0x91}, 32)})
	if e != nil {
		t.Fatal(e)
	}
	crypto, e := envelope.NewService(provider)
	if e != nil {
		t.Fatal(e)
	}
	custody := ssopg.Config{MaximumDuration: time.Second, Envelope: crypto, KeyReference: "domain-custody"}
	store, e := ssopg.NewStore(f.pool, custody)
	if https {
		store, e = ssopg.NewHTTPSStore(f.pool, custody)
	}
	if e != nil {
		t.Fatal(e)
	}
	packet, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	zone := &dnsZone{records: map[string]string{}, ttl: 60}
	server := &dns.Server{PacketConn: packet, Handler: dns.HandlerFunc(zone.serve)}
	resolver, e := domainverification.NewDNSResolver(packet.LocalAddr().String(), time.Second, 1232, 8)
	if e != nil {
		t.Fatal(e)
	}
	profile, e := domainverification.NewProfile(domainverification.ProfileConfig{Clock: clock.System{}, MaximumDuration: time.Second, ObservationTTL: time.Minute, MaxConcurrent: 4})
	if e != nil {
		t.Fatal(e)
	}
	engine, e := domainverification.NewEngine(profile, resolver)
	if e != nil {
		t.Fatal(e)
	}
	requests := new(atomic.Int32)
	if https {
		web := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			if r.Host != "example.com" || r.URL.Path != "/.well-known/golib-sso" || r.TLS.ServerName != "example.com" {
				t.Error("HTTPS publication scope changed")
			}
			w.Header().Set("Content-Type", "text/plain")
			zone.mu.RLock()
			body := zone.records["https-body"]
			gate, started := zone.httpsGate, zone.httpsStarted
			zone.mu.RUnlock()
			if gate != nil {
				started <- struct{}{}
				select {
				case <-gate:
				case <-r.Context().Done():
					return
				}
			}
			_, _ = w.Write([]byte(body))
		}))
		t.Cleanup(web.Close)
		roots := x509.NewCertPool()
		roots.AddCert(web.Certificate())
		// The resolver fixture is independent DNS wire protocol; dial routing is
		// a network-only simulation. Production still verifies SNI and the CA.
		server.Handler = dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
			m := new(dns.Msg).SetReply(q)
			if len(q.Question) != 1 || q.Question[0].Name != "example.com." {
				t.Error("unexpected HTTPS DNS scope")
			}
			if q.Question[0].Qtype == dns.TypeA {
				m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("93.184.216.34")}}
			}
			_ = w.WriteMsg(m)
		})
		fetcher, err := domainverification.NewHTTPSFetcher(domainverification.HTTPSFetcherConfig{Timeout: time.Second, RootCAs: roots, Resolver: &net.Resolver{PreferGo: true, StrictErrors: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "udp4", packet.LocalAddr().String())
		}}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address != "93.184.216.34:443" {
				return nil, errors.New("unpinned fixture destination")
			}
			conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", web.Listener.Addr().String())
			if err != nil {
				return nil, err
			}
			return domainHTTPSConn{Conn: conn}, nil
		}})
		if err != nil {
			t.Fatal(err)
		}
		engine, e = domainverification.NewHTTPSEngine(profile, fetcher)
		if e != nil {
			t.Fatal(e)
		}
	}
	// Select the handler before starting its owning goroutine. Mutating an
	// active dns.Server races its initialization even before the first query.
	done := make(chan error, 1)
	go func() { done <- server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown(); <-done })
	signer, e := capability.NewHMACSHA256Signer("domain-signing", bytes.Repeat([]byte{0x92}, 32))
	if e != nil {
		t.Fatal(e)
	}
	verifier, e := capability.NewHMACSHA256Verifier(bytes.Repeat([]byte{0x92}, 32))
	if e != nil {
		t.Fatal(e)
	}
	limiter, e := memory.New(memory.Options{MaxKeys: 100, Shards: 1})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = limiter.Close() })
	rate, e := ratelimit.NewService(limiter)
	if e != nil {
		t.Fatal(e)
	}
	// The refill interval is longer than any bounded call, so exhaustion tests
	// cannot cross a wall-clock window boundary and accidentally regain capacity.
	policy, e := ratelimit.NewPolicy(ratelimit.PolicySpec{ID: "sso-domain", Revision: "1", Algorithm: ratelimit.TokenBucket, Capacity: 100, Period: time.Hour})
	if e != nil {
		t.Fatal(e)
	}
	c := sso.DomainConfig{Clock: clock.System{}, MaximumDuration: 4 * time.Second, ChallengeTTL: time.Hour, Issuer: "domain-issuer", Audience: "domain-observer", Signer: signer, Resolver: capability.ResolverFunc(func(context.Context, string, capability.Algorithm) (capability.ResolvedKey, error) {
		return capability.ResolvedKey{Issuer: "domain-issuer", Verifier: verifier}, nil
	}), Authorization: fixturePolicy{}, PolicyVersion: 1, Rate: rate, RatePolicy: policy}
	observer, e := sso.NewDomainObserver(c, store, engine)
	if https {
		observer, e = sso.NewHTTPSDomainObserver(c, store, engine)
	}
	if e != nil {
		t.Fatal(e)
	}
	f.domainEvidence, e = organizationpg.NewDomainEvidenceSource(observer, [32]byte{0x93})
	if e != nil {
		t.Fatal(e)
	}
	f.domains = organization.DomainConfig{Version: 1, MaximumClaims: 10, EvidenceMaximumAge: time.Hour}
	f.compose(t)
	f.create(t, "org-test-basic")
	factory, e := ssopg.NewDomainEvidenceFactory(f.service)
	if e != nil {
		t.Fatal(e)
	}
	service, e := sso.NewService(c, f.service, factory, store, f.auth("org-test-basic", "owner"), "127.0.0.1")
	if https {
		service, e = sso.NewHTTPSService(c, f.service, factory, store, f.auth("org-test-basic", "owner"), "127.0.0.1")
	}
	if e != nil {
		t.Fatal(e)
	}
	return &domainFixture{org: f, store: store, config: c, zone: zone, service: service, custody: custody, httpsRequests: requests, engine: engine}
}

type domainHTTPSConn struct{ net.Conn }

func (domainHTTPSConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("93.184.216.34"), Port: 443}
}

func TestNativeHTTPSChallengeCurrentProofAndOriginalRecovery(t *testing.T) {
	f := nativeDomainFixtureMethod(t, true)
	issued := f.issue(t, "https-proof", "example.com", 1)
	url, body := issued.HTTPSWellKnown()
	if url != "https://example.com/.well-known/golib-sso" || issued.Request().Method() != sso.DomainProofHTTPS {
		t.Fatal("HTTPS profile not selected")
	}
	f.zone.publish("https-body", body)
	result, err := f.service.VerifyDomain(f.org.ctx, issued.Request())
	if err != nil || result.Receipt.Outcome != identity.CommitOutcomeCommitted || result.Proof.Method != organization.DomainHTTPS {
		t.Fatal("native HTTPS proof not committed", result.Receipt.Outcome, err)
	}
	key := organization.DomainProofKey(result.Proof)
	if current, err := f.service.GetDomainProof(f.org.ctx, key); err != nil || current != result.Proof {
		t.Fatal("HTTPS current organization proof missing", err)
	}
	loaded, err := f.service.LoadDomainRequest(f.org.ctx, sso.DomainChallengeKey{TenantID: key.TenantID, OrganizationID: key.OrganizationID, ClaimID: key.ClaimID})
	if err != nil || loaded.Method() != sso.DomainProofHTTPS {
		t.Fatal("durable method custody missing", err)
	}
	f.zone.publish("https-body", "withdrawn-publication")
	for range 2 {
		recovered, err := f.service.VerifyDomain(f.org.ctx, loaded)
		if err != nil || recovered.Proof != result.Proof {
			t.Fatal("original retry changed proof", err)
		}
	}
	if f.httpsRequests.Load() != 1 {
		t.Fatal("original recovery refetched HTTPS")
	}
	// Old DNS readers cannot reinterpret HTTPS ciphertext. Its method is bound
	// into both capability caveats and AEAD, not just an advisory SQL value.
	old, err := ssopg.NewStore(f.org.pool, f.custody)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = old.LoadDomainChallenge(f.org.ctx, sso.DomainChallengeKey{TenantID: key.TenantID, OrganizationID: key.OrganizationID, ClaimID: key.ClaimID}); err == nil {
		t.Fatal("DNS-only reader opened HTTPS custody")
	}
	factory, _ := ssopg.NewDomainEvidenceFactory(f.org.service)
	foreign, err := sso.NewHTTPSService(f.config, f.org.service, factory, f.store, f.org.auth("org-test-other", "owner"), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := foreign.VerifyDomain(f.org.ctx, loaded); err == nil || got.Proof != (organization.DomainProof{}) {
		t.Fatal("foreign authority recovered HTTPS proof")
	}
	withdraw, err := f.org.service.PrepareWithdrawDomain(f.org.ctx, organization.DomainClaimRequest{Authentication: f.org.auth("org-test-basic", "owner"), CommandID: commandID(t), OrganizationID: key.OrganizationID, ClaimID: key.ClaimID, Domain: key.Domain, OrganizationVersion: 3, ClaimVersion: 1, CorrelationID: "https-withdraw"}, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := f.org.service.Execute(f.org.ctx, withdraw); err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("withdraw HTTPS proof failed", err)
	}
	if got, err := f.service.GetDomainProof(f.org.ctx, key); err == nil || got != (organization.DomainProof{}) {
		t.Fatal("withdrawn historical HTTPS proof still current")
	}
}

func TestNativeHTTPSUnknownNeverRefetchesOrCreatesAuthority(t *testing.T) {
	f := nativeDomainFixtureMethod(t, true)
	issued := f.issue(t, "https-unknown", "example.com", 1)
	_, body := issued.HTTPSWellKnown()
	f.zone.publish("https-body", body)
	factory, _ := ssopg.NewDomainEvidenceFactory(f.org.service)
	service, err := sso.NewHTTPSService(f.config, f.org.service, factory, lostRecoveryACKStore{DomainChallengeStore: f.store}, f.org.auth("org-test-basic", "owner"), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	got, err := service.VerifyDomain(f.org.ctx, issued.Request())
	var unknown identity.UnknownCommitError
	if !errors.As(err, &unknown) || got.Receipt.Outcome != identity.CommitOutcomeUnknown || got.Proof != (organization.DomainProof{}) {
		t.Fatal("lost recovery ACK lost unknown", got.Receipt.Outcome, err)
	}
	f.zone.publish("https-body", "removed")
	for range 2 {
		if retry, err := f.service.VerifyDomain(f.org.ctx, issued.Request()); err == nil || retry.Proof != (organization.DomainProof{}) {
			t.Fatal("unknown original reapplied or refetched")
		}
	}
	if f.httpsRequests.Load() != 1 {
		t.Fatal("unknown repeated HTTPS observation")
	}
	var proofs int
	if err = f.org.pool.Raw().QueryRow(f.org.ctx, `SELECT count(*) FROM organization.domain_evidence`).Scan(&proofs); err != nil || proofs != 0 {
		t.Fatal("unknown manufactured proof", err)
	}
}

func TestNativeHTTPSLostCommitRecoversExactOriginalWithoutRefetch(t *testing.T) {
	f := nativeDomainFixtureMethod(t, true)
	issued := f.issue(t, "https-lost-commit", "example.com", 1)
	_, body := issued.HTTPSWellKnown()
	f.zone.publish("https-body", body)
	lossy, fault := f.org.lostCommitService(t)
	factory, err := ssopg.NewDomainEvidenceFactory(lossy)
	if err != nil {
		t.Fatal(err)
	}
	service, err := sso.NewHTTPSService(f.config, f.org.service, armFactory{base: factory, fault: fault}, f.store, f.org.auth("org-test-basic", "owner"), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	got, err := service.VerifyDomain(f.org.ctx, issued.Request())
	if err == nil || !fault.lost.Load() || got.Receipt.Outcome != identity.CommitOutcomeUnknown || got.Proof != (organization.DomainProof{}) {
		t.Fatal("lost COMMIT response fabricated result", got.Receipt.Outcome, err)
	}
	f.zone.publish("https-body", "removed")
	recovered, err := f.service.RecoverDomain(f.org.ctx, issued.Request())
	if err != nil || recovered.Receipt.Outcome != identity.CommitOutcomeCommitted || recovered.Proof.Method != organization.DomainHTTPS || recovered.Receipt.Binding != got.Receipt.Binding {
		t.Fatal("lost HTTPS COMMIT did not recover original", err)
	}
	if f.httpsRequests.Load() != 1 {
		t.Fatal("lost COMMIT recovery refetched HTTPS")
	}
}

func TestNativeHTTPSCurrentAuthorityAndRequiredEffectsDeny(t *testing.T) {
	for _, boundary := range []string{"mismatch", "expired", "withdrawn", "revoked-session", "audit", "outbox"} {
		t.Run(boundary, func(t *testing.T) {
			f := nativeDomainFixtureMethod(t, true)
			issued := f.issue(t, "https-denial", "example.com", 1)
			_, body := issued.HTTPSWellKnown()
			f.zone.publish("https-body", body)
			service := f.service
			switch boundary {
			case "mismatch":
				f.zone.publish("https-body", "golib-sso="+strings.Repeat("0", 64))
			case "expired":
				config := f.config
				config.Clock = fixedClock{at: issued.Request().ExpiresAt()}
				factory, _ := ssopg.NewDomainEvidenceFactory(f.org.service)
				var err error
				service, err = sso.NewHTTPSService(config, f.org.service, factory, f.store, f.org.auth("org-test-basic", "owner"), "127.0.0.1")
				if err != nil {
					t.Fatal(err)
				}
			case "withdrawn":
				claim := issued.Request().Claim()
				command, err := f.org.service.PrepareWithdrawDomain(f.org.ctx, organization.DomainClaimRequest{Authentication: f.org.auth("org-test-basic", "owner"), CommandID: commandID(t), OrganizationID: claim.OrganizationID, ClaimID: claim.ID, Domain: claim.Domain, ClaimVersion: 1, OrganizationVersion: 2, CorrelationID: "https-before-withdraw"}, "127.0.0.1")
				if err != nil {
					t.Fatal(err)
				}
				if _, err = f.org.service.Execute(f.org.ctx, command); err != nil {
					t.Fatal(err)
				}
			case "revoked-session":
				if _, err := f.org.pool.Raw().Exec(f.org.ctx, `UPDATE organization_sessions.sessions SET state='revoked' WHERE tenant_id='org-test-basic' AND user_id='owner'`); err != nil {
					t.Fatal(err)
				}
			case "audit", "outbox":
				table := "public.identity_outbox_bindings"
				when := ""
				if boundary == "audit" {
					table = "audit.records"
					when = " WHEN (NEW.outcome=1)"
				}
				if _, err := f.org.pool.Raw().Exec(f.org.ctx, `CREATE FUNCTION public.https_required_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'controlled HTTPS required effect failure'; END $$; CREATE TRIGGER https_required_fail BEFORE INSERT ON `+table+` FOR EACH ROW`+when+` EXECUTE FUNCTION public.https_required_fail()`); err != nil {
					t.Fatal(err)
				}
			}
			got, err := service.VerifyDomain(f.org.ctx, issued.Request())
			if err == nil || got.Proof != (organization.DomainProof{}) || got.Receipt.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("required denial created HTTPS authority", boundary, got.Receipt.Outcome, err)
			}
			if boundary == "audit" || boundary == "outbox" {
				if got.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
					t.Fatal("required effect failed without authoritative rollback", got.Receipt.Outcome, err)
				}
			}
			if boundary == "expired" || boundary == "withdrawn" || boundary == "revoked-session" {
				if f.httpsRequests.Load() != 0 {
					t.Fatal("stale authority reached HTTPS")
				}
			}
			var proofs int
			if err = f.org.pool.Raw().QueryRow(f.org.ctx, `SELECT count(*) FROM organization.domain_evidence`).Scan(&proofs); err != nil || proofs != 0 {
				t.Fatal("denial persisted proof", err)
			}
		})
	}
}

func TestNativeHTTPSConcurrentObservationsCancelAndRelease(t *testing.T) {
	f := nativeDomainFixtureMethod(t, true)
	issued := f.issue(t, "https-concurrent", "example.com", 1)
	_, body := issued.HTTPSWellKnown()
	f.zone.publish("https-body", body)
	gate := make(chan struct{})
	started := make(chan struct{}, 4)
	f.zone.mu.Lock()
	f.zone.httpsGate = gate
	f.zone.httpsStarted = started
	f.zone.mu.Unlock()
	ctx, cancel := context.WithCancel(f.org.ctx)
	defer cancel()
	done := make(chan error, 4)
	for range 4 {
		go func() { _, err := f.engine.Observe(ctx, issued.Request()); done <- err }()
	}
	for range 4 {
		select {
		case <-started:
		case err := <-done:
			t.Fatal("bounded active slot never reached independent HTTPS", err)
		}
	}
	if _, err := f.engine.Observe(f.org.ctx, issued.Request()); !errors.Is(err, domainverification.ErrThrottled) {
		t.Fatal("fifth HTTPS call bypassed concurrency bound", err)
	}
	if f.httpsRequests.Load() != 4 {
		t.Fatal("throttled call reached network")
	}
	cancel()
	for range 4 {
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatal("active HTTPS cancellation lost", err)
			}
		case <-time.After(time.Second):
			t.Fatal("active HTTPS call leaked")
		}
	}
	close(gate)
	f.zone.mu.Lock()
	f.zone.httpsGate = nil
	f.zone.httpsStarted = nil
	f.zone.mu.Unlock()
	if observed, err := f.engine.Observe(f.org.ctx, issued.Request()); err != nil || observed.Classification() != sso.DomainObservedMatch {
		t.Fatal("canceled HTTPS slots not released", err)
	}
	var proofs int
	if err := f.org.pool.Raw().QueryRow(f.org.ctx, `SELECT count(*) FROM organization.domain_evidence`).Scan(&proofs); err != nil || proofs != 0 {
		t.Fatal("non-authoritative observation created proof", err)
	}
}

func (f *domainFixture) issue(t *testing.T, id, domain string, epoch uint64) sso.DomainChallengeResult {
	t.Helper()
	o := f.org
	prepared, e := o.service.PrepareReserveDomain(o.ctx, organization.DomainClaimRequest{Authentication: o.auth("org-test-basic", "owner"), CommandID: commandID(t), OrganizationID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", ClaimID: organization.ID(id), Domain: domain, OrganizationVersion: epoch, CorrelationID: "sso-domain-test"}, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	result, e := o.service.Execute(o.ctx, prepared)
	if e != nil || result.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("claim not committed", e)
	}
	issued, e := f.service.ChallengeDomain(o.ctx, sso.DomainChallengeRequest{OrganizationID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", ClaimID: organization.ID(id), CommandID: commandID(t), CorrelationID: "sso-domain-test"})
	if e != nil {
		t.Fatal(e)
	}
	return issued
}

func TestNativeDNSChallengeToCurrentOrganizationProof(t *testing.T) {
	f := nativeDomainFixture(t)
	issued := f.issue(t, "dns-proof", "example.com", 1)
	owner, value := issued.DNSTXT()
	f.zone.publish(owner, value)
	result, e := f.service.VerifyDomain(f.org.ctx, issued.Request())
	if e != nil || result.Receipt.Outcome != identity.CommitOutcomeCommitted || result.Proof.Domain != "example.com" {
		t.Fatal("real DNS proof not committed", result.Receipt.Outcome, "queries", f.zone.queries.Load(), e)
	}
	key := organization.DomainProofKey(result.Proof)
	if current, e := f.service.GetDomainProof(f.org.ctx, key); e != nil || current != result.Proof {
		t.Fatal("current owner proof missing", e)
	}
	loaded, e := f.service.LoadDomainRequest(f.org.ctx, sso.DomainChallengeKey{TenantID: "org-test-basic", OrganizationID: key.OrganizationID, ClaimID: key.ClaimID})
	if e != nil {
		t.Fatal(e)
	}
	recovered, e := f.service.RecoverDomain(f.org.ctx, loaded)
	if e != nil || recovered.Proof != result.Proof {
		t.Fatal("original durable proof not recovered", e)
	}
	if f.zone.queries.Load() != 1 {
		t.Fatal("recovery reobserved DNS")
	}
	var plaintext bool
	if e = f.org.pool.Raw().QueryRow(f.org.ctx, `SELECT position(convert_to('cap1.','UTF8') in capability_envelope)>0 FROM sso.domain_challenges`).Scan(&plaintext); e != nil || plaintext {
		t.Fatal("challenge capability persisted plaintext", e)
	}
	factory, _ := ssopg.NewDomainEvidenceFactory(f.org.service)
	other, e := sso.NewService(f.config, f.org.service, factory, f.store, f.org.auth("org-test-other", "owner"), "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	if got, e := other.VerifyDomain(f.org.ctx, issued.Request()); e == nil || got.Proof != (organization.DomainProof{}) {
		t.Fatal("wrong tenant verified proof")
	}
	withdraw, e := f.org.service.PrepareWithdrawDomain(f.org.ctx, organization.DomainClaimRequest{Authentication: f.org.auth("org-test-basic", "owner"), CommandID: commandID(t), OrganizationID: key.OrganizationID, ClaimID: key.ClaimID, Domain: key.Domain, OrganizationVersion: 3, ClaimVersion: 1, CorrelationID: "withdraw"}, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	if r, e := f.org.service.Execute(f.org.ctx, withdraw); e != nil || r.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("withdraw failed", e)
	}
	if got, e := f.service.GetDomainProof(f.org.ctx, key); e == nil || got != (organization.DomainProof{}) {
		t.Fatal("withdrawn proof still current")
	}
}

func TestNativeDNSMismatchCannotCreateProof(t *testing.T) {
	f := nativeDomainFixture(t)
	issued := f.issue(t, "mismatch", "example.com", 1)
	owner, _ := issued.DNSTXT()
	f.zone.publish(owner, "golib-sso=wrong")
	got, e := f.service.VerifyDomain(f.org.ctx, issued.Request())
	if !errors.Is(e, sso.ErrForbidden) || got.Proof != (organization.DomainProof{}) {
		t.Fatal("mismatch did not preserve bounded denial without proof", e)
	}
	var proofs int
	if e = f.org.pool.Raw().QueryRow(f.org.ctx, `SELECT count(*) FROM organization.domain_evidence`).Scan(&proofs); e != nil || proofs != 0 {
		t.Fatal("mismatch persisted authority", e)
	}
}

func TestNativeDNSUsesCurrentInvokingNetworkAdmission(t *testing.T) {
	f := nativeDomainFixture(t)
	issued := f.issue(t, "network", "example.com", 1)
	owner, value := issued.DNSTXT()
	f.zone.publish(owner, value)
	currentNetwork := "127.0.0.2"
	digest := sha256.Sum256([]byte(currentNetwork))
	key, e := ratelimit.NewKey(ratelimit.KeySpec{Namespace: "sso-domain", Version: "1", Subject: ratelimit.Subject{Kind: "network", Value: hex.EncodeToString(digest[:])}, Hash: true})
	if e != nil {
		t.Fatal(e)
	}
	for range f.config.RatePolicy.Capacity() {
		if _, e = f.config.Rate.Admit(f.org.ctx, ratelimit.Request{Policy: f.config.RatePolicy, Key: key, Cost: 1, Now: time.Now()}); e != nil {
			t.Fatal(e)
		}
	}
	factory, _ := ssopg.NewDomainEvidenceFactory(f.org.service)
	service, e := sso.NewService(f.config, f.org.service, factory, f.store, f.org.auth("org-test-basic", "owner"), currentNetwork)
	if e != nil {
		t.Fatal(e)
	}
	got, e := service.VerifyDomain(f.org.ctx, issued.Request())
	if !errors.Is(e, sso.ErrThrottled) || got.Proof != (organization.DomainProof{}) || f.zone.queries.Load() != 0 {
		t.Fatal("verification used historical challenge network instead of current caller admission", e)
	}
}

func TestNativeDNSChallengeIssuanceIsRateBounded(t *testing.T) {
	f := nativeDomainFixture(t)
	issued := f.issue(t, "issue-rate", "example.com", 1)
	digest := sha256.Sum256([]byte("127.0.0.1"))
	key, e := ratelimit.NewKey(ratelimit.KeySpec{Namespace: "sso-domain", Version: "1", Subject: ratelimit.Subject{Kind: "network", Value: hex.EncodeToString(digest[:])}, Hash: true})
	if e != nil {
		t.Fatal(e)
	}
	exhausted := false
	for range f.config.RatePolicy.Capacity() + 1 {
		_, e = f.config.Rate.Admit(f.org.ctx, ratelimit.Request{Policy: f.config.RatePolicy, Key: key, Cost: 1, Now: time.Now()})
		if errors.Is(e, ratelimit.ErrRejected) {
			exhausted = true
			break
		}
		if e != nil {
			t.Fatal(e)
		}
	}
	if !exhausted {
		t.Fatal("fixture did not exhaust network admission")
	}
	got, e := f.service.ChallengeDomain(f.org.ctx, sso.DomainChallengeRequest{OrganizationID: issued.Request().Claim().OrganizationID, ClaimID: issued.Request().Claim().ID, CommandID: issued.Request().CommandID(), CorrelationID: "sso-domain-test"})
	if !errors.Is(e, sso.ErrThrottled) || got.Request() != (sso.DomainProofRequest{}) || f.zone.queries.Load() != 0 {
		t.Fatal("challenge issuance bypassed bounded rate policy", e)
	}
}

type cancelAfterRecoveryStore struct {
	sso.DomainChallengeStore
	cancel context.CancelFunc
}

type lostRecoveryACKStore struct{ sso.DomainChallengeStore }

func (s lostRecoveryACKStore) SaveDomainRecovery(ctx context.Context, key sso.DomainChallengeKey, binding identity.CommandBinding) error {
	if err := s.DomainChallengeStore.SaveDomainRecovery(ctx, key, binding); err != nil {
		return err
	}
	return sso.ErrUnavailable
}

func TestNativeDNSLostRecoverySaveACKRetainsUnknown(t *testing.T) {
	f := nativeDomainFixture(t)
	issued := f.issue(t, "lost-save-ack", "example.com", 1)
	owner, value := issued.DNSTXT()
	f.zone.publish(owner, value)
	factory, _ := ssopg.NewDomainEvidenceFactory(f.org.service)
	service, e := sso.NewService(f.config, f.org.service, factory, lostRecoveryACKStore{DomainChallengeStore: f.store}, f.org.auth("org-test-basic", "owner"), "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	got, e := service.VerifyDomain(f.org.ctx, issued.Request())
	var unknown identity.UnknownCommitError
	if !errors.As(e, &unknown) || !errors.Is(e, sso.ErrUnavailable) || got.Receipt.Outcome != identity.CommitOutcomeUnknown || got.Proof != (organization.DomainProof{}) || got.OrganizationID != issued.Request().Claim().OrganizationID {
		t.Fatal("lost native recovery CAS response omitted exact unknown custody", got.Receipt.Outcome, e)
	}
	key := sso.DomainChallengeKey{TenantID: issued.Request().Claim().TenantID, OrganizationID: issued.Request().Claim().OrganizationID, ClaimID: issued.Request().Claim().ID}
	state, e := f.store.LoadDomainChallenge(f.org.ctx, key)
	if e != nil || state.Recovery != got.Receipt.Binding || state.Recovery.CommandID != issued.Request().CommandID() {
		t.Fatal("original native CAS scope not retained", e)
	}
	if recovered, e := f.service.RecoverDomain(f.org.ctx, issued.Request()); e == nil || recovered.Proof != (organization.DomainProof{}) || recovered.Receipt.Outcome == identity.CommitOutcomeNotCommitted {
		t.Fatal("absent or denied command became rollback proof", e)
	}
	if retried, e := f.service.VerifyDomain(f.org.ctx, issued.Request()); e == nil || retried.Proof != (organization.DomainProof{}) {
		t.Fatal("save response loss automatically reapplied")
	}
	if f.zone.queries.Load() != 1 {
		t.Fatal("lost save response repeated DNS")
	}
	var proofs int
	if e = f.org.pool.Raw().QueryRow(f.org.ctx, `SELECT count(*) FROM organization.domain_evidence`).Scan(&proofs); e != nil || proofs != 0 {
		t.Fatal("save failure applied domain proof", e)
	}
}

func (s cancelAfterRecoveryStore) SaveDomainRecovery(ctx context.Context, key sso.DomainChallengeKey, binding identity.CommandBinding) error {
	if err := s.DomainChallengeStore.SaveDomainRecovery(ctx, key, binding); err != nil {
		return err
	}
	s.cancel()
	return nil
}

func TestNativeDNSSavedPreparationWithoutApplyRetainsUnknown(t *testing.T) {
	f := nativeDomainFixture(t)
	issued := f.issue(t, "saved-not-applied", "example.com", 1)
	owner, value := issued.DNSTXT()
	f.zone.publish(owner, value)
	ctx, cancel := context.WithCancel(f.org.ctx)
	defer cancel()
	factory, _ := ssopg.NewDomainEvidenceFactory(f.org.service)
	service, e := sso.NewService(f.config, f.org.service, factory, cancelAfterRecoveryStore{DomainChallengeStore: f.store, cancel: cancel}, f.org.auth("org-test-basic", "owner"), "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	got, e := service.VerifyDomain(ctx, issued.Request())
	if e == nil || got.Receipt.Outcome != identity.CommitOutcomeUnknown || got.Proof != (organization.DomainProof{}) {
		t.Fatal("canceled apply did not retain original unknown recovery scope", got.Receipt.Outcome, e)
	}
	f.zone.publish(owner, "golib-sso=gone")
	for range 2 {
		recovered, e := f.service.RecoverDomain(f.org.ctx, issued.Request())
		// The generic coordinator intentionally makes absent and denied queries
		// indistinguishable. A concurrent original could still execute, so this
		// is neither known rollback nor permission to repeat external observation.
		if e == nil || recovered.Receipt.Outcome == identity.CommitOutcomeNotCommitted || recovered.Receipt.Outcome == identity.CommitOutcomeCommitted || recovered.Proof != (organization.DomainProof{}) {
			t.Fatal("undisclosed absent command became fabricated terminal outcome", recovered.Receipt.Outcome, e)
		}
	}
	if retried, e := f.service.VerifyDomain(f.org.ctx, issued.Request()); e == nil || retried.Proof != (organization.DomainProof{}) {
		t.Fatal("saved unknown preparation was automatically reexecuted")
	}
	state, e := f.store.LoadDomainChallenge(f.org.ctx, sso.DomainChallengeKey{TenantID: issued.Request().Claim().TenantID, OrganizationID: issued.Request().Claim().OrganizationID, ClaimID: issued.Request().Claim().ID})
	if e != nil || state.Recovery != got.Receipt.Binding {
		t.Fatal("original unknown binding was replaced", e)
	}
	if f.zone.queries.Load() != 1 {
		t.Fatal("unapplied recovery repeated DNS")
	}
	var proofs int
	if e = f.org.pool.Raw().QueryRow(f.org.ctx, `SELECT count(*) FROM organization.domain_evidence`).Scan(&proofs); e != nil || proofs != 0 {
		t.Fatal("unapplied recovery manufactured proof", e)
	}
}

type fixedClock struct{ at time.Time }

func (c fixedClock) Now() time.Time { return c.at }

func TestNativeDNSExpiredAndWithdrawnChallengesDenyBeforeObservation(t *testing.T) {
	for _, kind := range []string{"expired", "withdrawn"} {
		t.Run(kind, func(t *testing.T) {
			f := nativeDomainFixture(t)
			issued := f.issue(t, kind, "example.com", 1)
			owner, value := issued.DNSTXT()
			f.zone.publish(owner, value)
			service := f.service
			if kind == "expired" {
				config := f.config
				config.Clock = fixedClock{at: issued.Request().ExpiresAt()}
				factory, _ := ssopg.NewDomainEvidenceFactory(f.org.service)
				var e error
				service, e = sso.NewService(config, f.org.service, factory, f.store, f.org.auth("org-test-basic", "owner"), "127.0.0.1")
				if e != nil {
					t.Fatal(e)
				}
			} else {
				claim := issued.Request().Claim()
				c, e := f.org.service.PrepareWithdrawDomain(f.org.ctx, organization.DomainClaimRequest{Authentication: f.org.auth("org-test-basic", "owner"), CommandID: commandID(t), OrganizationID: claim.OrganizationID, ClaimID: claim.ID, Domain: claim.Domain, ClaimVersion: 1, OrganizationVersion: 2, CorrelationID: "withdraw-before-verify"}, "127.0.0.1")
				if e != nil {
					t.Fatal(e)
				}
				if r, e := f.org.service.Execute(f.org.ctx, c); e != nil || r.Receipt.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("withdraw failed", e)
				}
			}
			if r, e := service.VerifyDomain(f.org.ctx, issued.Request()); e == nil || r.Proof != (organization.DomainProof{}) || f.zone.queries.Load() != 0 {
				t.Fatal("expired or withdrawn challenge observed", e)
			}
		})
	}
}

func TestNativeDNSExpiredProofCannotUseHistoricalRecovery(t *testing.T) {
	f := nativeDomainFixture(t)
	f.zone.mu.Lock()
	f.zone.ttl = 1
	f.zone.mu.Unlock()
	issued := f.issue(t, "proof-expiry", "example.com", 1)
	owner, value := issued.DNSTXT()
	f.zone.publish(owner, value)
	committed, e := f.service.VerifyDomain(f.org.ctx, issued.Request())
	if e != nil || committed.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("short TTL proof not committed", e)
	}
	if committed.Proof.ExpiresAt.Sub(committed.Proof.ObservedAt) != time.Second {
		t.Fatal("DNS TTL was not retained")
	}
	timer := time.NewTimer(time.Until(committed.Proof.ExpiresAt) + time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-f.org.ctx.Done():
		t.Fatal(f.org.ctx.Err())
	}
	if got, e := f.service.GetDomainProof(f.org.ctx, organization.DomainProofKey(committed.Proof)); e == nil || got != (organization.DomainProof{}) {
		t.Fatal("expired proof remained current")
	}
	recovered, e := f.service.RecoverDomain(f.org.ctx, issued.Request())
	if e != nil || recovered.Proof != committed.Proof {
		t.Fatal("expiry changed historical original result", e)
	}
	if f.zone.queries.Load() != 1 {
		t.Fatal("historical recovery renewed DNS evidence")
	}
}

func TestNativeDNSRevokedSessionCannotVerify(t *testing.T) {
	f := nativeDomainFixture(t)
	issued := f.issue(t, "revoked-session", "example.com", 1)
	owner, value := issued.DNSTXT()
	f.zone.publish(owner, value)
	if _, e := f.org.pool.Raw().Exec(f.org.ctx, `UPDATE organization_sessions.sessions SET state='revoked' WHERE tenant_id='org-test-basic' AND user_id='owner'`); e != nil {
		t.Fatal(e)
	}
	if got, e := f.service.VerifyDomain(f.org.ctx, issued.Request()); e == nil || got.Proof != (organization.DomainProof{}) || f.zone.queries.Load() != 0 {
		t.Fatal("revoked caller reached DNS or proof", e)
	}
}

func TestNativeDNSAlternateManagerCannotUseOriginalActorsChallenge(t *testing.T) {
	f := nativeDomainFixture(t)
	issued := f.issue(t, "actor-bound", "example.com", 1)
	owner, value := issued.DNSTXT()
	f.zone.publish(owner, value)
	f.org.seedUser(t, "org-test-basic", "second")
	f.org.add(t, "org-test-basic", "second", organization.RoleAdministrator, 2)
	factory, _ := ssopg.NewDomainEvidenceFactory(f.org.service)
	manager, e := sso.NewService(f.config, f.org.service, factory, f.store, f.org.auth("org-test-basic", "second"), "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	if got, e := manager.VerifyDomain(f.org.ctx, issued.Request()); !errors.Is(e, sso.ErrForbidden) || got.Proof != (organization.DomainProof{}) || f.zone.queries.Load() != 0 {
		t.Fatal("same-tenant manager reused original actor's challenge", e)
	}
}

func TestNativeDNSConcurrentVerificationCommitsOneAuthoritativeProof(t *testing.T) {
	f := nativeDomainFixture(t)
	issued := f.issue(t, "concurrent", "example.com", 1)
	owner, value := issued.DNSTXT()
	f.zone.publish(owner, value)
	results := make(chan organization.DomainEvidenceResult, 2)
	var callers sync.WaitGroup
	callers.Add(2)
	for range 2 {
		go func() {
			defer callers.Done()
			result, _ := f.service.VerifyDomain(f.org.ctx, issued.Request())
			results <- result
		}()
	}
	callers.Wait()
	close(results)
	var original organization.DomainProof
	for result := range results {
		if result.Receipt.Outcome == identity.CommitOutcomeCommitted {
			if original != (organization.DomainProof{}) && result.Proof != original {
				t.Fatal("concurrent callers received competing committed proof")
			}
			original = result.Proof
		} else if result.Proof != (organization.DomainProof{}) {
			t.Fatal("noncommitted concurrent result released proof")
		}
	}
	if original == (organization.DomainProof{}) {
		t.Fatal("no concurrent caller committed original proof")
	}
	var proofs int
	if e := f.org.pool.Raw().QueryRow(f.org.ctx, `SELECT count(*) FROM organization.domain_evidence`).Scan(&proofs); e != nil || proofs != 1 {
		t.Fatal("concurrent calls duplicated authoritative proof", proofs, e)
	}
	if current, e := f.service.GetDomainProof(f.org.ctx, organization.DomainProofKey(original)); e != nil || current != original {
		t.Fatal("concurrent result was not current sole proof", e)
	}
	if observed := f.zone.queries.Load(); observed < 1 || observed > 2 {
		t.Fatal("concurrent verification repeated unbounded observation", observed)
	}
}

// Arming after real preparation changes only the network fault timing. All
// observation, preparation, reservation, mutation and recovery remain native.
type armFactory struct {
	base  sso.DomainEvidenceFactory
	fault *commitResponseLoss
}

func (a armFactory) DomainEvidence(auth organization.Authentication, network string, binding identity.CommandBinding) (sso.DomainEvidenceAuthority, error) {
	owner, e := a.base.DomainEvidence(auth, network, binding)
	if e != nil {
		return nil, e
	}
	return armAuthority{DomainEvidenceAuthority: owner, fault: a.fault}, nil
}

type armAuthority struct {
	sso.DomainEvidenceAuthority
	fault *commitResponseLoss
}

func (a armAuthority) Prepare(ctx context.Context, r organization.DomainEvidenceRequest) (organization.DomainEvidenceCommand, error) {
	c, e := a.DomainEvidenceAuthority.Prepare(ctx, r)
	if e == nil {
		a.fault.armed.Store(true)
	}
	return c, e
}

func TestNativeDNSUnknownRecoveryNeverReobserves(t *testing.T) {
	f := nativeDomainFixture(t)
	issued := f.issue(t, "unknown", "example.com", 1)
	owner, value := issued.DNSTXT()
	f.zone.publish(owner, value)
	lossy, fault := f.org.lostCommitService(t)
	factory, e := ssopg.NewDomainEvidenceFactory(lossy)
	if e != nil {
		t.Fatal(e)
	}
	service, e := sso.NewService(f.config, f.org.service, armFactory{base: factory, fault: fault}, f.store, f.org.auth("org-test-basic", "owner"), "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	got, e := service.VerifyDomain(f.org.ctx, issued.Request())
	if e == nil || !fault.lost.Load() || got.Receipt.Outcome != identity.CommitOutcomeUnknown || got.Proof != (organization.DomainProof{}) {
		t.Fatal("lost response fabricated committed proof", got.Receipt.Outcome, e)
	}
	// Remove the external evidence before recovery; success must come exclusively
	// from the sole durable command's original result, never a new DNS query.
	f.zone.publish(owner, "golib-sso=removed")
	recovered, e := f.service.RecoverDomain(f.org.ctx, issued.Request())
	if e != nil || recovered.Receipt.Outcome != identity.CommitOutcomeCommitted || recovered.Proof.Domain != "example.com" {
		t.Fatal("original unknown command did not recover", e)
	}
	if f.zone.queries.Load() != 1 {
		t.Fatal("unknown recovery repeated DNS")
	}
	if _, e = f.service.VerifyDomain(f.org.ctx, issued.Request()); e != nil {
		var unknown identity.UnknownCommitError
		if !errors.As(e, &unknown) {
			t.Fatal(e)
		}
	}
	if f.zone.queries.Load() != 1 {
		t.Fatal("verify retry repeated original observation")
	}
}
