// Package sso implements explicitly selected enterprise federation workflows.
// The current profile issues DNS challenges and delegates proof authority to
// organization; provider registration, routing and login are not implemented.
package sso

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/faustbrian/go-authorization/v3"
	capability "github.com/faustbrian/go-capability/v2"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	ratelimit "github.com/faustbrian/go-rate-limit/v2"
)

// Error is a stable redacted failure category; dependency diagnostics are never
// included. Cancellation remains the original context error.
type Error string

func (e Error) Error() string { return string(e) }

const (
	ErrInvalidInput           Error = "sso: invalid input"
	ErrForbidden              Error = "sso: forbidden"
	ErrConflict               Error = "sso: conflict"
	ErrUnavailable            Error = "sso: unavailable"
	ErrThrottled              Error = "sso: throttled"
	ErrSensitiveSerialization Error = "sso: sensitive serialization forbidden"
	domainPurpose                   = "identity.sso.domain-verify"
)

// DomainProofMethod is the closed immutable observation profile. HTTPS is
// reserved, not supported by the selected DNS-only service.
type DomainProofMethod uint8

const (
	DomainProofMethodInvalid DomainProofMethod = iota
	DomainProofDNS
	DomainProofHTTPS
)

// DomainObservationClass distinguishes positive evidence from bounded denials
// and unavailable network outcomes. Only Match may reach organization admission.
type DomainObservationClass string

const (
	DomainObservedMatch         DomainObservationClass = "match"
	DomainObservedMismatch      DomainObservationClass = "mismatch"
	DomainObservedNXDOMAIN      DomainObservationClass = "nxdomain"
	DomainObservedNoData        DomainObservationClass = "nodata"
	DomainObservedServerFailure DomainObservationClass = "server-failure"
	DomainObservedTimeout       DomainObservationClass = "timeout"
	DomainObservedTruncated     DomainObservationClass = "truncated"
	DomainObservedMalformed     DomainObservationClass = "malformed"
)

// DomainObservationSource is attribution, never a DNSSEC or ownership claim.
type DomainObservationSource string

const DomainSourceDNS DomainObservationSource = "dns-response"

// DomainChallengeKey selects exactly one tenant/org/immutable claim. There is no
// domain search, competing-owner discovery, automatic renewal or takeover.
type DomainChallengeKey struct {
	TenantID                identity.TenantID
	OrganizationID, ClaimID organization.ID
}

// ChallengeRecord is trusted adapter projection, not public ownership evidence.
// Capability must be envelope-encrypted by durable adapters. Never log it or
// store a JSON representation. The original binding is immutable per claim.
type ChallengeRecord struct {
	Claim                                                              organization.DomainClaim
	ActorID                                                            identity.UserID
	CommandID                                                          identity.CommandID
	Method                                                             DomainProofMethod
	Purpose, ChallengeDigest, Capability, CorrelationID, NetworkDigest string
	IssuedAt, ExpiresAt                                                time.Time
}

func (r ChallengeRecord) Key() DomainChallengeKey {
	return DomainChallengeKey{TenantID: r.Claim.TenantID, OrganizationID: r.Claim.OrganizationID, ClaimID: r.Claim.ID}
}

// Validate checks the safe structural projection. Capability authenticity and
// current claim/session authority are separate, mandatory admission checks.
func (r ChallengeRecord) Validate() error {
	if !safe(string(r.Claim.TenantID)) || !safe(string(r.Claim.OrganizationID)) || !safe(string(r.Claim.ID)) || !safe(string(r.ActorID)) || !safe(r.CorrelationID) || len(r.Capability) > 16<<10 || !canonicalDigest(r.NetworkDigest) {
		return ErrInvalidInput
	}
	domain, err := organization.CanonicalDomain(r.Claim.Domain)
	_, commandErr := identity.ParseCommandID(string(r.CommandID))
	if err != nil || domain != r.Claim.Domain || commandErr != nil || !canonicalDigest(r.ChallengeDigest) {
		return ErrInvalidInput
	}
	if r.Claim.State != organization.DomainRequested || r.Claim.Version != 1 || r.Method != DomainProofDNS || r.Purpose != domainPurpose {
		return ErrInvalidInput
	}
	if r.IssuedAt.IsZero() || !r.ExpiresAt.After(r.IssuedAt) || r.ExpiresAt.Sub(r.IssuedAt) > 24*time.Hour {
		return ErrInvalidInput
	}
	return nil
}

func canonicalDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	digest, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(digest) == value
}

func (ChallengeRecord) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("sso.ChallengeRecord(redacted)"))
}
func (ChallengeRecord) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (ChallengeRecord) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// DomainChallengeState retains only challenge custody and the original safe
// organization recovery scope. It deliberately has no commit result/proof state.
type DomainChallengeState struct {
	Challenge ChallengeRecord
	Recovery  identity.CommandBinding
}

// DomainChallengeStore persists one immutable encrypted challenge per claim.
// Create returns the identical existing record only for the same CommandID and
// actor/scope; changed input conflicts. SaveRecovery is compare-and-set from
// empty to the exact original binding before any Apply. It never stores outcomes.
type DomainChallengeStore interface {
	CreateDomainChallenge(context.Context, ChallengeRecord) (ChallengeRecord, error)
	LoadDomainChallenge(context.Context, DomainChallengeKey) (DomainChallengeState, error)
	SaveDomainRecovery(context.Context, DomainChallengeKey, identity.CommandBinding) error
}

// DomainProofRequest is immutable issued challenge custody. Zero is invalid.
// Getters expose non-authoritative observation inputs only, never the capability.
type DomainProofRequest struct{ record ChallengeRecord }

func (r DomainProofRequest) Claim() organization.DomainClaim { return r.record.Claim }
func (r DomainProofRequest) Method() DomainProofMethod       { return r.record.Method }
func (r DomainProofRequest) Purpose() string                 { return r.record.Purpose }
func (r DomainProofRequest) ChallengeDigest() string         { return r.record.ChallengeDigest }
func (r DomainProofRequest) IssuedAt() time.Time             { return r.record.IssuedAt }
func (r DomainProofRequest) ExpiresAt() time.Time            { return r.record.ExpiresAt }
func (r DomainProofRequest) CommandID() identity.CommandID   { return r.record.CommandID }
func (r DomainProofRequest) Validate() error                 { return r.record.Validate() }
func (DomainProofRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("sso.DomainProofRequest(redacted)"))
}
func (DomainProofRequest) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (DomainProofRequest) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// DomainProofObservation is immutable non-authoritative evidence. It cannot
// authorize routing or construct an organization proof. Zero is invalid.
type DomainProofObservation struct {
	request   DomainProofRequest
	class     DomainObservationClass
	source    DomainObservationSource
	at, until time.Time
}

func (DomainProofObservation) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("sso.DomainProofObservation(redacted)"))
}
func (DomainProofObservation) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (DomainProofObservation) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

func (o DomainProofObservation) Request() DomainProofRequest            { return o.request }
func (o DomainProofObservation) Classification() DomainObservationClass { return o.class }
func (o DomainProofObservation) Source() DomainObservationSource        { return o.source }
func (o DomainProofObservation) ObservedAt() time.Time                  { return o.at }
func (o DomainProofObservation) ExpiresAt() time.Time                   { return o.until }

// NewDomainProofObservation is for deployment-selected trusted engines. It
// cannot manufacture organization admission and cannot extend issued freshness.
func NewDomainProofObservation(r DomainProofRequest, class DomainObservationClass, at, until time.Time, source DomainObservationSource) (DomainProofObservation, error) {
	at = at.UTC().Truncate(time.Microsecond)
	until = until.UTC().Truncate(time.Microsecond)
	if r.Validate() != nil || source != DomainSourceDNS || at.Before(r.IssuedAt()) || !until.After(at) || until.After(r.ExpiresAt()) {
		return DomainProofObservation{}, ErrInvalidInput
	}
	switch class {
	case DomainObservedMatch, DomainObservedMismatch, DomainObservedNXDOMAIN, DomainObservedNoData, DomainObservedServerFailure, DomainObservedTimeout, DomainObservedTruncated, DomainObservedMalformed:
	default:
		return DomainProofObservation{}, ErrInvalidInput
	}
	return DomainProofObservation{request: r, class: class, source: source, at: at.UTC().Truncate(time.Microsecond), until: until.UTC().Truncate(time.Microsecond)}, nil
}

// DomainProofEngine observes once outside durable locks. Engines must bound
// network/concurrency/resources and honor cancellation. No other method exists.
type DomainProofEngine interface {
	Observe(context.Context, DomainProofRequest) (DomainProofObservation, error)
}

// DomainConfig fixes deployment policy; borrowed owners must outlive calls and
// support concurrent use. It starts no background work. Authentication/network
// are invocation-scoped trusted transport input, never arbitrary client headers.
type DomainConfig struct {
	Clock                         clock.Clock
	MaximumDuration, ChallengeTTL time.Duration
	Issuer, Audience              string
	Signer                        capability.Signer
	Resolver                      capability.Resolver
	Authorization                 authorization.Service
	PolicyVersion                 uint64
	Rate                          *ratelimit.Service
	RatePolicy                    ratelimit.Policy
}

func (DomainConfig) Format(s fmt.State, _ rune)   { _, _ = s.Write([]byte("sso.DomainConfig(redacted)")) }
func (DomainConfig) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (DomainConfig) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

func (c DomainConfig) valid() bool {
	if c.Clock == nil || c.Signer == nil || c.Resolver == nil || c.Authorization == nil || c.Rate == nil {
		return false
	}
	if c.MaximumDuration <= 0 || c.MaximumDuration > time.Minute {
		return false
	}
	if c.ChallengeTTL < 15*time.Minute || c.ChallengeTTL > 24*time.Hour || c.ChallengeTTL%time.Second != 0 {
		return false
	}
	if !safe(c.Issuer) || !safe(c.Audience) || c.PolicyVersion == 0 {
		return false
	}
	return c.RatePolicy.ID() != "" && c.RatePolicy.FailureMode() == ratelimit.FailClosed && c.RatePolicy.Algorithm() != ratelimit.Concurrency
}

func safe(s string) bool {
	if len(s) == 0 || len(s) > 128 || !utf8.ValidString(s) {
		return false
	}
	for _, character := range s {
		if character <= ' ' || character == 127 {
			return false
		}
	}
	return true
}

func publicError(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	for _, known := range []error{ErrInvalidInput, ErrForbidden, ErrConflict, ErrUnavailable, ErrThrottled, context.Canceled, context.DeadlineExceeded} {
		if errors.Is(err, known) {
			return known
		}
	}
	for _, known := range []error{organization.ErrInvalidInput, organization.ErrForbidden, organization.ErrConflict, organization.ErrUnavailable, organization.ErrLimit} {
		if errors.Is(err, known) {
			switch known {
			case organization.ErrInvalidInput:
				return ErrInvalidInput
			case organization.ErrForbidden:
				return ErrForbidden
			case organization.ErrConflict:
				return ErrConflict
			case organization.ErrLimit:
				return ErrThrottled
			}
		}
	}
	return ErrUnavailable
}

func capabilityUse(c DomainConfig, r ChallengeRecord) capability.Use {
	return capability.Use{Issuer: c.Issuer, Audience: c.Audience, Subject: string(r.ActorID), Resource: string(r.Claim.ID), Operation: domainPurpose, Tenant: string(r.Claim.TenantID), Caveats: map[string]string{"organization": string(r.Claim.OrganizationID), "domain": r.Claim.Domain, "claim-version": strconv.FormatUint(r.Claim.Version, 10), "method": "dns-txt"}}
}

// DomainObserver is the trusted deployment-selected organization observer. Its
// store contains challenge custody only; organization remains sole proof owner.
type DomainObserver struct {
	config DomainConfig
	store  DomainChallengeStore
	engine DomainProofEngine
}

func (DomainObserver) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("sso.DomainObserver(redacted)"))
}
func (*DomainObserver) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (*DomainObserver) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// This private invocation binds current admission to the native observer call.
// It carries no proof authority and is neither persisted nor globally selected.
type domainInvocationKey struct{}
type domainInvocation struct {
	request       DomainProofRequest
	networkDigest string
}

var _ organization.DomainEvidenceObserver = (*DomainObserver)(nil)

func NewDomainObserver(c DomainConfig, store DomainChallengeStore, engine DomainProofEngine) (*DomainObserver, error) {
	if !c.valid() || store == nil || engine == nil {
		return nil, ErrInvalidInput
	}
	return &DomainObserver{config: c, store: store, engine: engine}, nil
}

func (o *DomainObserver) ObserveDomain(ctx context.Context, claim organization.DomainClaim) (out organization.DomainObservation, err error) {
	defer func() {
		if recover() != nil {
			out, err = organization.DomainObservation{}, ErrUnavailable
		}
		// This seam is owned by organization. Preserve its recognized safe error
		// categories rather than making a bounded mismatch look like an outage.
		switch err {
		case ErrInvalidInput:
			err = organization.ErrInvalidInput
		case ErrForbidden:
			err = organization.ErrForbidden
		case ErrConflict:
			err = organization.ErrConflict
		case ErrThrottled:
			err = organization.ErrLimit
		case ErrUnavailable:
			err = organization.ErrUnavailable
		}
	}()
	if o == nil || ctx == nil {
		return out, ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, o.config.MaximumDuration)
	defer cancel()
	state, e := o.store.LoadDomainChallenge(bounded, DomainChallengeKey{TenantID: claim.TenantID, OrganizationID: claim.OrganizationID, ClaimID: claim.ID})
	if e != nil {
		return out, publicError(bounded, e)
	}
	r := state.Challenge
	now := o.config.Clock.Now()
	invocation, invoked := bounded.Value(domainInvocationKey{}).(domainInvocation)
	if !invoked || invocation.request.record != r || !canonicalDigest(invocation.networkDigest) {
		return out, ErrForbidden
	}
	if r.Validate() != nil || len(r.Capability) == 0 || r.Claim != claim || !now.Before(r.ExpiresAt) || now.Before(r.IssuedAt) || state.Recovery.CommandID != "" {
		return out, ErrForbidden
	}
	grant, e := capability.Verify(bounded, r.Capability, o.config.Resolver, capability.VerifyOptions{Issuer: o.config.Issuer, Now: now, Limits: capability.DefaultLimits()})
	if e != nil || grant.Authorize(capabilityUse(o.config, r)) != nil || grant.Payload().ID != string(r.CommandID) || !grant.Payload().ExpiresAt.Equal(r.ExpiresAt) {
		return out, ErrForbidden
	}
	digest := sha256.Sum256([]byte(r.Capability))
	encoded := hex.EncodeToString(digest[:])
	if subtle.ConstantTimeCompare([]byte(encoded), []byte(r.ChallengeDigest)) != 1 {
		return out, ErrForbidden
	}
	if e := admitDomain(bounded, o.config, claim, invocation.networkDigest); e != nil {
		return out, e
	}
	request := DomainProofRequest{record: r}
	observed, e := o.engine.Observe(bounded, request)
	if e != nil {
		return out, publicError(bounded, e)
	}
	now = o.config.Clock.Now()
	if bounded.Err() != nil {
		return out, bounded.Err()
	}
	if observed.request != request || observed.class != DomainObservedMatch || observed.source != DomainSourceDNS || observed.at.Before(r.IssuedAt) || observed.at.After(now) || !observed.until.After(now) || observed.until.After(r.ExpiresAt) {
		return out, ErrForbidden
	}
	return organization.DomainObservation{Claim: claim, Method: organization.DomainDNS, ObservedAt: observed.at, ExpiresAt: observed.until, Verified: true}, nil
}

func admitDomain(ctx context.Context, config DomainConfig, claim organization.DomainClaim, networkDigest string) error {
	organizationScope := sha256.Sum256([]byte(strconv.Itoa(len(claim.TenantID)) + ":" + string(claim.TenantID) + string(claim.OrganizationID)))
	for _, subject := range []ratelimit.Subject{{Kind: "tenant", Value: string(claim.TenantID)}, {Kind: "organization", Value: hex.EncodeToString(organizationScope[:])}, {Kind: "domain", Value: claim.Domain}, {Kind: "network", Value: networkDigest}} {
		key, e := ratelimit.NewKey(ratelimit.KeySpec{Namespace: "sso-domain", Version: "1", Subject: subject, Hash: true})
		if e != nil {
			return ErrInvalidInput
		}
		d, e := config.Rate.Admit(ctx, ratelimit.Request{Policy: config.RatePolicy, Key: key, Cost: 1, Now: config.Clock.Now()})
		if e != nil || !d.Allowed {
			if errors.Is(e, ratelimit.ErrRejected) || e == nil {
				return ErrThrottled
			}
			return publicError(ctx, e)
		}
	}
	return nil
}

// DomainClaimReader is the current authorized primary organization read seam.
type DomainClaimReader interface {
	GetDomainClaim(context.Context, organization.DomainClaimReadRequest) (organization.View, error)
}

// DomainEvidenceAuthority is one existing invocation's organization-owned
// preparation, transition/recovery and current-proof read contract.
type DomainEvidenceAuthority interface {
	organization.DomainEvidenceTransition
	organization.DomainProofReader
	Prepare(context.Context, organization.DomainEvidenceRequest) (organization.DomainEvidenceCommand, error)
}

// DomainEvidenceFactory binds current private authentication and optional exact
// original recovery scope. The native adapter implements this composition seam.
type DomainEvidenceFactory interface {
	DomainEvidence(organization.Authentication, string, identity.CommandBinding) (DomainEvidenceAuthority, error)
}

// Service is an immutable invocation-scoped DNS challenge orchestrator. The
// supplied current bearer and canonical network must come from trusted transport.
// Reconstruct a Service with fresh authentication for recovery after process loss.
type Service struct {
	config         DomainConfig
	claims         DomainClaimReader
	factory        DomainEvidenceFactory
	store          DomainChallengeStore
	authentication organization.Authentication
	network        string
}

func (Service) Format(s fmt.State, _ rune)    { _, _ = s.Write([]byte("sso.Service(redacted)")) }
func (*Service) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (*Service) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

func NewService(c DomainConfig, claims DomainClaimReader, factory DomainEvidenceFactory, store DomainChallengeStore, authentication organization.Authentication, network string) (*Service, error) {
	address, e := netip.ParseAddr(network)
	if !c.valid() || claims == nil || factory == nil || store == nil || !safe(string(authentication.TenantID)) || e != nil || address.String() != network {
		return nil, ErrInvalidInput
	}
	return &Service{config: c, claims: claims, factory: factory, store: store, authentication: authentication, network: network}, nil
}

// DomainChallengeRequest selects an existing organization-owned claim and a
// caller-generated canonical command ID retained across all retries.
type DomainChallengeRequest struct {
	OrganizationID, ClaimID organization.ID
	CommandID               identity.CommandID
	CorrelationID           string
}

// DomainChallengeResult exposes only the exact public DNS commitment, not a
// bearer capability. Keep Request for verification or reload it by exact key.
type DomainChallengeResult struct{ request DomainProofRequest }

func (DomainChallengeResult) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("sso.DomainChallengeResult(redacted)"))
}
func (DomainChallengeResult) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (DomainChallengeResult) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

func (r DomainChallengeResult) Request() DomainProofRequest { return r.request }
func (r DomainChallengeResult) DNSTXT() (string, string) {
	return "_golib-sso." + r.request.Claim().Domain + ".", "golib-sso=" + r.request.ChallengeDigest()
}

func (s *Service) authorize(ctx context.Context, op string, v organization.View, correlation string) error {
	d, e := s.config.Authorization.Decide(ctx, authorization.DecisionContext{PolicyRevision: authorization.Revision(s.config.PolicyVersion), CorrelationID: correlation, Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(v.Actor.UserID)}, Action: authorization.Action(op), Resource: authorization.Resource{Type: "organization", ID: authorization.ResourceID(v.Organization.ID), Attributes: authorization.Attributes{"organization.policy-version": authorization.StringValue(strconv.FormatUint(v.Organization.Version, 10))}}, Tenant: authorization.TenantID(v.Organization.TenantID), Environment: authorization.Environment{Time: s.config.Clock.Now()}}})
	if e != nil {
		return publicError(ctx, e)
	}
	if d.Outcome != authorization.Allow || d.Revision != authorization.Revision(s.config.PolicyVersion) {
		return ErrForbidden
	}
	return nil
}

func (s *Service) claim(ctx context.Context, key DomainChallengeKey, correlation string) (organization.View, error) {
	if key.TenantID != s.authentication.TenantID || !safe(string(key.OrganizationID)) || !safe(string(key.ClaimID)) || !safe(correlation) {
		return organization.View{}, ErrInvalidInput
	}
	v, e := s.claims.GetDomainClaim(ctx, organization.DomainClaimReadRequest{Authentication: s.authentication, OrganizationID: key.OrganizationID, ClaimID: key.ClaimID, CorrelationID: correlation})
	if e != nil {
		return organization.View{}, publicError(ctx, e)
	}
	claimMatches := v.DomainClaim.TenantID == key.TenantID && v.DomainClaim.OrganizationID == key.OrganizationID && v.DomainClaim.ID == key.ClaimID
	organizationMatches := v.Organization.TenantID == key.TenantID && v.Organization.ID == key.OrganizationID && v.Organization.Active
	memberMatches := v.Actor.TenantID == key.TenantID && v.Actor.OrganizationID == key.OrganizationID && safe(string(v.Actor.UserID)) && v.Actor.Active
	manager := v.Actor.Role == organization.RoleOwner || v.Actor.Role == organization.RoleAdministrator
	if !claimMatches || !organizationMatches || !memberMatches || !manager {
		return organization.View{}, ErrForbidden
	}
	return v, nil
}

// ChallengeDomain issues only after current organization and SSO-write policy
// admission. An issuance retry cannot change or renew the immutable challenge.
func (s *Service) ChallengeDomain(ctx context.Context, r DomainChallengeRequest) (out DomainChallengeResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = DomainChallengeResult{}, ErrUnavailable
		}
	}()
	if s == nil || ctx == nil {
		return out, ErrInvalidInput
	}
	if _, e := identity.ParseCommandID(string(r.CommandID)); e != nil {
		return out, ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	v, e := s.claim(bounded, DomainChallengeKey{TenantID: s.authentication.TenantID, OrganizationID: r.OrganizationID, ClaimID: r.ClaimID}, r.CorrelationID)
	if e != nil {
		return out, e
	}
	if v.DomainClaim.State != organization.DomainRequested {
		return out, ErrForbidden
	}
	if e = s.authorize(bounded, "identity.sso.domain-challenge", v, r.CorrelationID); e != nil {
		return out, e
	}
	at := s.config.Clock.Now().UTC().Truncate(time.Second)
	network := sha256.Sum256([]byte(s.network))
	if len("_golib-sso."+v.DomainClaim.Domain+".") > 254 {
		return out, ErrInvalidInput
	}
	if e = admitDomain(bounded, s.config, v.DomainClaim, hex.EncodeToString(network[:])); e != nil {
		return out, e
	}
	record := ChallengeRecord{Claim: v.DomainClaim, ActorID: v.Actor.UserID, CommandID: r.CommandID, Method: DomainProofDNS, Purpose: domainPurpose, CorrelationID: r.CorrelationID, NetworkDigest: hex.EncodeToString(network[:]), IssuedAt: at, ExpiresAt: at.Add(s.config.ChallengeTTL)}
	use := capabilityUse(s.config, record)
	token, e := capability.Issue(bounded, capability.Payload{Version: 1, Issuer: use.Issuer, Audiences: []string{use.Audience}, Subject: use.Subject, Resource: use.Resource, Operation: use.Operation, IssuedAt: at, NotBefore: at, ExpiresAt: record.ExpiresAt, ID: string(record.CommandID), Tenant: use.Tenant, Caveats: use.Caveats}, s.config.Signer, capability.DefaultLimits())
	if e != nil {
		return out, publicError(bounded, e)
	}
	digest := sha256.Sum256([]byte(token))
	record.Capability = token
	record.ChallengeDigest = hex.EncodeToString(digest[:])
	saved, e := s.store.CreateDomainChallenge(bounded, record)
	if e != nil {
		return out, publicError(bounded, e)
	}
	if saved.Validate() != nil || saved.Key() != record.Key() || saved.ActorID != record.ActorID || saved.CommandID != record.CommandID || !s.config.Clock.Now().Before(saved.ExpiresAt) {
		return out, ErrConflict
	}
	return DomainChallengeResult{request: DomainProofRequest{record: saved}}, nil
}

// LoadDomainRequest reloads exact challenge custody under fresh current owner
// authentication. It does not refresh the challenge or create proof authority.
func (s *Service) LoadDomainRequest(ctx context.Context, key DomainChallengeKey) (DomainProofRequest, error) {
	if s == nil || ctx == nil {
		return DomainProofRequest{}, ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	v, e := s.claim(bounded, key, "sso-domain-load")
	if e != nil {
		return DomainProofRequest{}, e
	}
	if e = s.authorize(bounded, domainPurpose, v, "sso-domain-load"); e != nil {
		return DomainProofRequest{}, e
	}
	state, e := s.store.LoadDomainChallenge(bounded, key)
	if e != nil {
		return DomainProofRequest{}, publicError(bounded, e)
	}
	if state.Challenge.Validate() != nil || state.Challenge.Key() != key || state.Challenge.ActorID != v.Actor.UserID {
		return DomainProofRequest{}, ErrForbidden
	}
	return DomainProofRequest{record: state.Challenge}, nil
}

// VerifyDomain observes only a new original attempt. SaveRecovery precedes
// Apply, so every retry/restart after an attempted mutation queries the sole
// organization coordinator and never repeats DNS. Historical recovery is not a
// current routing authorization; always use GetDomainProof for current trust.
func (s *Service) VerifyDomain(ctx context.Context, r DomainProofRequest) (out organization.DomainEvidenceResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = organization.DomainEvidenceResult{}, ErrUnavailable
		}
	}()
	if s == nil || ctx == nil || r.Validate() != nil || r.Claim().TenantID != s.authentication.TenantID {
		return out, ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	state, e := s.store.LoadDomainChallenge(bounded, r.record.Key())
	if e != nil {
		return out, publicError(bounded, e)
	}
	if state.Challenge != r.record {
		return out, ErrForbidden
	}
	if state.Recovery.CommandID != "" {
		return s.recover(bounded, r, state)
	}
	v, e := s.claim(bounded, r.record.Key(), r.record.CorrelationID)
	if e != nil {
		return out, e
	}
	if v.DomainClaim != r.Claim() || v.Actor.UserID != r.record.ActorID || !s.config.Clock.Now().Before(r.ExpiresAt()) {
		return out, ErrForbidden
	}
	if e = s.authorize(bounded, domainPurpose, v, r.record.CorrelationID); e != nil {
		return out, e
	}
	owner, e := s.factory.DomainEvidence(s.authentication, s.network, identity.CommandBinding{})
	if e != nil {
		return out, publicError(bounded, e)
	}
	networkDigest := sha256.Sum256([]byte(s.network))
	observationContext := context.WithValue(bounded, domainInvocationKey{}, domainInvocation{request: r, networkDigest: hex.EncodeToString(networkDigest[:])})
	command, e := owner.Prepare(observationContext, organization.DomainEvidenceRequest{Claim: organization.DomainClaimRequest{CommandID: r.record.CommandID, OrganizationID: r.Claim().OrganizationID, ClaimID: r.Claim().ID, OrganizationVersion: v.Organization.Version, ClaimVersion: r.Claim().Version, Domain: r.Claim().Domain, CorrelationID: r.record.CorrelationID}})
	if e != nil {
		return out, publicError(bounded, e)
	}
	input, e := command.Command().Input()
	if e != nil {
		return out, ErrUnavailable
	}
	if e = s.store.SaveDomainRecovery(bounded, r.record.Key(), input.Binding); e != nil {
		// The native autocommit may have persisted this scope before its response
		// was lost. Do not apply or infer rollback after an uncertain save.
		return unknownDomainEvidence(input.Binding, input.Organization.ID, publicError(bounded, e))
	}
	result, applyError := owner.ApplyDomainEvidence(bounded, command)
	if result.Receipt.Outcome == identity.CommitOutcomeInvalid {
		// A cancellation before native admission can return no receipt at all.
		// The saved scope may already be visible to another process; absence of
		// a receipt is not authoritative rollback. Only original recovery decides.
		return unknownDomainEvidence(input.Binding, input.Organization.ID, publicError(bounded, applyError))
	}
	// Keep the sole owner's precise receipt/error; Unknown never returns proof.
	return result, applyError
}

func unknownDomainEvidence(binding identity.CommandBinding, organizationID organization.ID, cause error) (organization.DomainEvidenceResult, error) {
	result := organization.DomainEvidenceResult{StoreResult: organization.StoreResult{OrganizationID: organizationID, Receipt: identity.CommandResult{Binding: binding, Outcome: identity.CommitOutcomeUnknown, Feature: &identity.FeatureReceipt{Operation: organization.ApplyDomainProof.Descriptor()}}}}
	return result, errors.Join(identity.UnknownCommitError{CommandID: binding.CommandID}, cause)
}

func (s *Service) recover(ctx context.Context, r DomainProofRequest, state DomainChallengeState) (organization.DomainEvidenceResult, error) {
	if state.Challenge != r.record || state.Recovery.CommandID != r.CommandID() || state.Recovery.TenantID != s.authentication.TenantID {
		return organization.DomainEvidenceResult{}, ErrForbidden
	}
	v, e := s.claim(ctx, r.record.Key(), r.record.CorrelationID)
	if e != nil {
		return organization.DomainEvidenceResult{}, e
	}
	if v.Actor.UserID != r.record.ActorID {
		return organization.DomainEvidenceResult{}, ErrForbidden
	}
	if e = s.authorize(ctx, domainPurpose, v, r.record.CorrelationID); e != nil {
		return organization.DomainEvidenceResult{}, e
	}
	owner, e := s.factory.DomainEvidence(s.authentication, s.network, state.Recovery)
	if e != nil {
		return organization.DomainEvidenceResult{}, publicError(ctx, e)
	}
	return owner.RecoverDomainEvidence(ctx, r.CommandID())
}

// RecoverDomain queries only the original durable command. Missing preparation
// is not a license to observe or apply. Current native authority remains required.
func (s *Service) RecoverDomain(ctx context.Context, r DomainProofRequest) (organization.DomainEvidenceResult, error) {
	if s == nil || ctx == nil || r.Validate() != nil || r.Claim().TenantID != s.authentication.TenantID {
		return organization.DomainEvidenceResult{}, ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	state, e := s.store.LoadDomainChallenge(bounded, r.record.Key())
	if e != nil {
		return organization.DomainEvidenceResult{}, publicError(bounded, e)
	}
	return s.recover(bounded, r, state)
}

// GetDomainProof reads current organization-owned primary proof; saved
// challenges and recovered historical results never substitute for this read.
func (s *Service) GetDomainProof(ctx context.Context, key organization.DomainProofKey) (organization.DomainProof, error) {
	if s == nil || ctx == nil || key.TenantID != s.authentication.TenantID {
		return organization.DomainProof{}, ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	v, e := s.claim(bounded, DomainChallengeKey{TenantID: key.TenantID, OrganizationID: key.OrganizationID, ClaimID: key.ClaimID}, "sso-proof-read")
	if e != nil {
		return organization.DomainProof{}, e
	}
	if e = s.authorize(bounded, domainPurpose, v, "sso-proof-read"); e != nil {
		return organization.DomainProof{}, e
	}
	owner, e := s.factory.DomainEvidence(s.authentication, s.network, identity.CommandBinding{})
	if e != nil {
		return organization.DomainProof{}, publicError(bounded, e)
	}
	return owner.GetDomainProof(bounded, key)
}
