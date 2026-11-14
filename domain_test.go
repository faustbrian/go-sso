package sso

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

func testProofRequest() DomainProofRequest {
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	return DomainProofRequest{record: ChallengeRecord{Claim: organization.DomainClaim{TenantID: "tenant", OrganizationID: "org", ID: "claim", Domain: "example.com", Version: 1, State: organization.DomainRequested}, ActorID: "actor", CommandID: identity.CommandID("AAAAAAAAAAAAAAAAAAAAAQ"), Method: DomainProofDNS, Purpose: domainPurpose, CorrelationID: "contract", Capability: "test-only-token", NetworkDigest: strings.Repeat("b", 64), ChallengeDigest: strings.Repeat("a", 64), IssuedAt: now, ExpiresAt: now.Add(time.Hour)}}
}

func TestObservationBindsExactRequestAndCannotRenewExpiry(t *testing.T) {
	r := testProofRequest()
	at := r.record.IssuedAt.Add(time.Minute)
	o, err := NewDomainProofObservation(r, DomainObservedMatch, at, at.Add(time.Minute), DomainSourceDNS)
	if err != nil || o.Request() != r || o.Classification() != DomainObservedMatch || o.ExpiresAt() != at.Add(time.Minute) {
		t.Fatal("exact observed binding lost", err)
	}
	for _, test := range []struct{ at, until time.Time }{{at, r.record.ExpiresAt.Add(time.Second)}, {at, at}, {r.record.IssuedAt.Add(-time.Second), at}} {
		if _, err := NewDomainProofObservation(r, DomainObservedMatch, test.at, test.until, DomainSourceDNS); !errors.Is(err, ErrInvalidInput) {
			t.Fatal("invalid observation lifetime accepted", err)
		}
	}
	if _, err := NewDomainProofObservation(DomainProofRequest{}, DomainObservedMatch, at, at.Add(time.Minute), DomainSourceDNS); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("unissued request observed", err)
	}
}

func TestChallengeCustodyIsRedacted(t *testing.T) {
	r := testProofRequest()
	r.record.Capability = "sensitive-capability-value"
	result := DomainChallengeResult{request: r}
	if strings.Contains(fmt.Sprintf("%+v %#v %+v %#v", r, r.record, result, result), r.record.Capability) {
		t.Fatal("capability disclosed by formatting")
	}
	for _, v := range []any{r, r.record, result} {
		if _, err := json.Marshal(v); !errors.Is(err, ErrSensitiveSerialization) {
			t.Fatal("custody serialized", err)
		}
	}
}

func TestChallengeDigestLengthRejectsBeforeDecodingAllocation(t *testing.T) {
	oversized := strings.Repeat("a", 1<<20)
	var accepted bool
	allocations := testing.AllocsPerRun(20, func() { accepted = canonicalDigest(oversized) })
	if accepted || allocations != 0 {
		t.Fatal("oversized encoded commitment allocated before its fixed length bound", allocations)
	}
	r := testProofRequest()
	r.record.ChallengeDigest = oversized
	if !errors.Is(r.Validate(), ErrInvalidInput) {
		t.Fatal("public projection admitted oversized commitment")
	}
}

func TestHTTPSChallengeMethodAndObservationStayBound(t *testing.T) {
	r := testProofRequest()
	r.record.Method = DomainProofHTTPS
	if err := r.Validate(); err != nil {
		t.Fatal("issued HTTPS custody rejected", err)
	}
	result := DomainChallengeResult{request: r}
	url, body := result.HTTPSWellKnown()
	if url != "https://example.com/.well-known/golib-sso" || body != "golib-sso="+r.ChallengeDigest() {
		t.Fatal("HTTPS publication widened exact host/path/body")
	}
	if owner, value := result.DNSTXT(); owner != "" || value != "" {
		t.Fatal("HTTPS issuance exposed DNS downgrade")
	}
	at := r.IssuedAt().Add(time.Minute)
	if _, err := NewDomainProofObservation(r, DomainObservedMatch, at, at.Add(time.Minute), DomainSourceHTTPS); err != nil {
		t.Fatal("HTTPS observation rejected", err)
	}
	if _, err := NewDomainProofObservation(r, DomainObservedMatch, at, at.Add(time.Minute), DomainSourceDNS); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("DNS observation substituted for HTTPS", err)
	}
	if use := capabilityUse(DomainConfig{}, r.record); use.Caveats["method"] != "https-well-known" {
		t.Fatal("capability did not bind HTTPS method")
	}
}

func FuzzChallengeDigest(f *testing.F) {
	for _, seed := range []string{strings.Repeat("a", 64), "", strings.Repeat("A", 64), strings.Repeat("f", 65), "not-hex"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, digest string) {
		r := testProofRequest()
		r.record.ChallengeDigest = digest
		if r.Validate() == nil && (len(digest) != 64 || !canonicalDigest(digest)) {
			t.Fatal("invalid encoded commitment admitted")
		}
	})
}
