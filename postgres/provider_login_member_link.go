package postgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	organization "github.com/faustbrian/go-organization"
	"github.com/faustbrian/go-sso"
)

// ProviderLinkConfig enables explicit enterprise account linking from a fresh
// local password cookie. Borrow the native primary-backed session service and
// its retained keys. The initial profile requires known-empty MFA state and
// an active member, not an administrator's authorization over another user.
type ProviderLinkConfig struct {
	ConfigurationID string
	Sessions        session.SessionService
	Profile         sessionpg.IdentifierAdmissionConfig
	LookupKeys      []session.DigestKey
	CSRFKeys        []session.CSRFKey
}

// Format redacts the selected key and session configuration.
func (ProviderLinkConfig) Format(s fmt.State, _ rune) {
	fmt.Fprint(s, "sso.postgres.ProviderLinkConfig(redacted)")
}

// MarshalJSON rejects export of native authority configuration.
func (ProviderLinkConfig) MarshalJSON() ([]byte, error) { return nil, sso.ErrSensitiveSerialization }

// ProviderLinkBrowser carries the authenticated local cookie and explicit
// same-origin consent for link initiation. Browser origin/network/device come
// from trusted transport and cannot be selected by the provider callback.
type ProviderLinkBrowser struct {
	Session authentication.BearerCredential
	CSRF    session.CSRFToken
	Origin  string
	Network netip.Addr
	Device  string
}

// Format redacts the cookie, CSRF material and network information.
func (ProviderLinkBrowser) Format(s fmt.State, _ rune) {
	fmt.Fprint(s, "sso.postgres.ProviderLinkBrowser(redacted)")
}

// MarshalJSON rejects export of private browser inputs.
func (ProviderLinkBrowser) MarshalJSON() ([]byte, error) { return nil, sso.ErrSensitiveSerialization }

// NewProviderLoginServiceWithLink adds opt-in authenticated member linking
// without changing the existing anonymous constructor or its durable intent.
// It performs no I/O. The composition must use the native callback owner and
// install the same provider, capability, and prepared transaction histories.
func NewProviderLoginServiceWithLink(router *ProviderRouter, base ProviderLoginConfig, link ProviderLinkConfig) (*ProviderLoginService, error) {
	if !providerID(link.ConfigurationID) || !link.Sessions.Configured() || link.Profile.Validate() != nil ||
		link.Profile.AuthenticationMethod != "password" || link.Profile.CredentialKind != identity.CredentialPassword || link.Profile.CredentialOwner != "identity/password" ||
		len(link.LookupKeys) == 0 || len(link.LookupKeys) > 32 || len(link.CSRFKeys) == 0 || len(link.CSRFKeys) > 32 {
		return nil, sso.ErrInvalidInput
	}
	for _, key := range link.CSRFKeys {
		if key.Version() == 0 {
			return nil, sso.ErrInvalidInput
		}
	}
	service, err := NewProviderLoginService(router, base)
	if err != nil {
		return nil, err
	}
	link.LookupKeys, link.CSRFKeys = slices.Clone(link.LookupKeys), slices.Clone(link.CSRFKeys)
	service.link = &link
	return service, nil
}

// LinkStart creates the original member-bound one-use provider transaction and
// returns its redirect only after the native commit is known. Use a fresh
// password cookie, same-origin CSRF, and Remember=false (linking issues no
// session). The provider/domain and callback allowlists match SigninStart.
func (s *ProviderLoginService) LinkStart(ctx context.Context, request sso.SigninStartRequest, browser ProviderLinkBrowser) (sso.SigninStartResult, error) {
	if s == nil || s.link == nil {
		return sso.SigninStartResult{}, sso.ErrForbidden
	}
	policy, err := request.LoginIntent.RememberPolicy()
	if err != nil {
		return sso.SigninStartResult{}, sso.ErrInvalidInput
	}
	spec, err := policy.Bindings()
	if err != nil || spec.Choice != session.BrowserSession {
		return sso.SigninStartResult{}, sso.ErrInvalidInput
	}
	transport := ProviderLoginBrowser{Origin: browser.Origin, Network: browser.Network, Device: browser.Device}
	return s.startProviderTransaction(ctx, request, transport, &providerLoginMemberAdmission{browser: browser})
}

type providerLoginMemberAdmission struct {
	browser  ProviderLinkBrowser
	observed session.GetResult
	user     identity.UserID
}

func (p *providerLoginPhase) readOriginalBrowser(ctx context.Context) error {
	if p.member == nil {
		return p.readBrowser(ctx)
	}
	link, browser := p.service.link, p.member.browser
	token, err := session.ParseToken(browser.Session.Token())
	if err != nil {
		return identity.ForbiddenError{}
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		return identity.ForbiddenError{}
	}
	observed, err := link.Sessions.Get(ctx, session.GetRequest{TenantID: p.service.config.TenantID, Credential: credential})
	if err != nil {
		return err
	}
	now := p.service.router.config.Clock.Now().UTC()
	bound, err := observed.Session.Bindings()
	if err != nil || observed.ValidateAt(now) != nil || bound.TenantID != p.service.config.TenantID || !link.possesses(browser.Session, observed.Session, now) || !link.validCSRF(browser.CSRF, observed.Session) {
		return identity.ForbiddenError{}
	}
	// A committed redirect re-reads independently rather than modifying the
	// original admission that the coordinator just fenced.
	p.member = &providerLoginMemberAdmission{browser: browser, observed: observed, user: bound.UserID}
	return nil
}

func (c *ProviderLinkConfig) possesses(bearer authentication.BearerCredential, original session.Session, now time.Time) bool {
	b, err := original.Bindings()
	if err != nil {
		return false
	}
	life, err := original.Lifetime(now)
	if err != nil || !life.Fresh {
		return false
	}
	token, err := session.ParseToken(bearer.Token())
	if err != nil {
		return false
	}
	for _, key := range c.LookupKeys {
		digest, err := token.Digest(key, string(b.TenantID))
		if err == nil && digest.KeyVersion == b.Lookup.KeyVersion && hmac.Equal(digest.Sum[:], b.Lookup.Sum[:]) {
			return true
		}
	}
	return false
}

func (c *ProviderLinkConfig) validCSRF(csrf session.CSRFToken, original session.Session) bool {
	b, err := original.Bindings()
	if err != nil {
		return false
	}
	scope := session.CSRFBinding{TenantID: b.TenantID, SessionID: b.SessionID, SessionVersion: b.Version}
	for _, key := range c.CSRFKeys {
		if original.CSRFState().Check(scope, csrf, key) == nil {
			return true
		}
	}
	return false
}

func (p *providerLoginPhase) linkRequestIntent() (identity.RequestIntent, error) {
	member := p.member
	original, err := sessionpg.OriginalSessionFields(member.observed.Session)
	if err != nil {
		return identity.RequestIntent{}, identity.ForbiddenError{}
	}
	r := p.request
	frame, err := json.Marshal(struct {
		Configuration                       [32]byte
		Link                                string
		Session                             []identity.FeatureField
		Request                             identity.CommandID
		Provider, Domain, Callback, Failure string
		Origin, Network, Device             string
	}{p.service.profileDigest, p.service.link.ConfigurationID, original, r.CommandID, r.ProviderID, r.Domain,
		r.SuccessCallback.String(), r.ErrorCallback.String(), p.browser.Origin, p.browser.Network.String(), p.browser.Device})
	defer clear(frame)
	if err != nil {
		return identity.RequestIntent{}, identity.UnavailableError{}
	}
	p.intent = sha256.Sum256(frame)
	return identity.NewRequestIntent([]identity.FeatureField{{Name: "sso.signin.intent", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: p.intent[:]}}})
}

func (p *providerLoginPhase) freezeMember(ctx context.Context, input *providerLoginStartInput, now time.Time) error {
	s, member := p.service, p.member
	if member.observed.ValidateAt(now) != nil {
		return identity.ForbiddenError{}
	}
	record := member.observed.Session
	bound, err := record.Bindings()
	if err != nil {
		return identity.ForbiddenError{}
	}
	if _, _, _, err := sessionpg.OriginalSessionAdmission(s.link.Profile, record, identity.CommandBinding(input.Command)); err != nil {
		return err
	}
	query := organization.CredentialAuthorityQuery{TenantID: s.config.TenantID, OrganizationID: input.Proof.OrganizationID, ActorID: member.user}
	authority, err := s.router.organizations.ObserveCredentialAuthority(ctx, query)
	if err != nil {
		return err
	}
	factors, err := mfapg.ReadSSOOIDCExplicitLinkFactors(ctx, s.router.pool, query.TenantID, query.ActorID, s.config.Session.MaximumDuration)
	if err != nil {
		return err
	}
	fields, err := sessionpg.OriginalSessionFields(record)
	if err != nil {
		return err
	}
	current := s.router.config.Clock.Now().UTC()
	if authority.Validate(query, current) != nil || member.observed.ValidateAt(current) != nil ||
		authority.Version != input.Organization.Version || authority.CredentialVersion != input.Organization.CredentialVersion {
		return identity.ForbiddenError{}
	}
	life, err := record.Lifetime(current)
	policy, policyErr := bound.Remember.Bindings()
	if err != nil || policyErr != nil || !life.Fresh {
		return identity.ForbiddenError{}
	}
	freshDeadline := bound.Authentication.Proof.IssuedAt.Add(policy.FreshFor)
	input.Expires = earlierLoginTime(input.Expires, earlierLoginTime(life.ExpiresAt, freshDeadline)).Truncate(time.Second)
	input.MemberAuthority = &authority
	input.MemberReadUntil = earlierLoginTime(authority.ValidUntil, member.observed.ValidUntil())
	input.Link = &providerLoginMemberIntent{OriginalSession: fields, ConsentedAt: now, OrganizationVersion: authority.Version,
		OrganizationCredentialVersion: authority.CredentialVersion, MembershipVersion: authority.Actor.Version,
		AuthorizationVersion: authority.Actor.AuthorizationVersion, FactorVersion: factors.Version()}
	if !current.Before(input.Expires) || !current.Before(input.MemberReadUntil) {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *providerLoginPhase) originalMember(input *providerLoginStartInput, now time.Time) (session.Session, error) {
	if p.member == nil || input.Link == nil || input.MemberAuthority == nil || p.member.user != input.Command.UserID {
		return session.Session{}, identity.ForbiddenError{}
	}
	scope := organization.CredentialAuthorityQuery{TenantID: input.Command.TenantID, OrganizationID: input.Proof.OrganizationID, ActorID: input.Command.UserID}
	member, link := input.MemberAuthority, input.Link
	if member.Validate(scope, member.VerifiedAt) != nil || !link.ConsentedAt.Equal(input.Started) || input.MemberReadUntil.IsZero() || input.MemberReadUntil.After(member.ValidUntil) ||
		link.OrganizationVersion != member.Version || link.OrganizationCredentialVersion != member.CredentialVersion ||
		link.MembershipVersion != member.Actor.Version || link.AuthorizationVersion != member.Actor.AuthorizationVersion {
		return session.Session{}, identity.ForbiddenError{}
	}
	record, err := sessionpg.OriginalSessionFromFields(scope.TenantID, scope.ActorID, link.OriginalSession)
	if err != nil || !p.service.link.possesses(p.member.browser.Session, record, now) || !p.service.link.validCSRF(p.member.browser.CSRF, record) {
		return session.Session{}, identity.ForbiddenError{}
	}
	return record, nil
}

func (p *providerLoginPhase) requireStartBrowser(input *providerLoginStartInput, now time.Time) error {
	if p.member == nil {
		return p.requireBrowser(p.flow, now)
	}
	if input != nil {
		_, err := p.originalMember(input, now)
		return err
	}
	if p.member.observed.ValidateAt(now) != nil ||
		!p.service.link.possesses(p.member.browser.Session, p.member.observed.Session, now) ||
		!p.service.link.validCSRF(p.member.browser.CSRF, p.member.observed.Session) {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *providerLoginPhase) requireLinkStartAuthority(ctx context.Context, work kernel.Work, command identity.Command) error {
	s, input := p.service, p.input
	now, err := work.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	record, err := p.originalMember(input, now)
	if err != nil || !now.Before(input.MemberReadUntil) {
		return identity.ForbiddenError{}
	}
	_, credential, authz, err := sessionpg.OriginalSessionAdmission(s.link.Profile, record, identity.CommandBinding(input.Command))
	if err != nil {
		return err
	}
	if _, err := work.RequireActiveCredential(ctx, p, credential); err != nil {
		return err
	}
	if err := work.RequireActiveUserAuthorization(ctx, p, authz); err != nil {
		return err
	}
	if err := sessionpg.RequireSession(ctx, work, s.config.Session, record); err != nil {
		return err
	}
	if _, err := mfapg.RequireSSOOIDCExplicitLinkFactors(ctx, work, p, command, input.Link.FactorVersion); err != nil {
		return err
	}
	return s.router.organizations.RequireCredentialAuthority(ctx, work, p, *input.MemberAuthority)
}

func (s *ProviderLoginService) checkRetainedMember(ctx context.Context, org organization.ID, member identity.UserID, link *providerLoginMemberIntent) (organization.CredentialAuthorityObservation, error) {
	if link == nil || member == "" {
		return organization.CredentialAuthorityObservation{}, identity.ForbiddenError{}
	}
	query := organization.CredentialAuthorityQuery{TenantID: s.config.TenantID, OrganizationID: org, ActorID: member}
	authority, err := s.router.organizations.ObserveCredentialAuthority(ctx, query)
	if err != nil {
		return organization.CredentialAuthorityObservation{}, err
	}
	if authority.Validate(query, s.router.config.Clock.Now().UTC()) != nil || authority.Version != link.OrganizationVersion ||
		authority.CredentialVersion != link.OrganizationCredentialVersion || authority.Actor.Version != link.MembershipVersion ||
		authority.Actor.AuthorizationVersion != link.AuthorizationVersion {
		return organization.CredentialAuthorityObservation{}, identity.ForbiddenError{}
	}
	return authority, nil
}

func (p *providerLoginPhase) startScope() kernel.RequestKeyScope {
	if p.protocol == providerProtocolSAML {
		scope := p.service.requestScope()
		scope.Method, scope.RouteID = "GET", p.operation().OperationID
		return scope
	}
	if p.member == nil {
		return p.service.requestScope()
	}
	return kernel.RequestKeyScope{TenantID: p.service.config.TenantID, ActorID: identity.ActorID(p.member.user), ActorKind: authorization.SubjectUser,
		Method: "POST", RouteID: providerSigninStart}
}

func (p *providerLoginPhase) startCaller() authorization.DecisionContext {
	caller := p.service.caller()
	if p.protocol == providerProtocolSAML {
		operation := p.operation().OperationID
		caller.Request.Action = authorization.Action(operation)
		caller.Request.Resource.ID = authorization.ResourceID(operation)
	}
	if p.member != nil {
		caller.Request.Subject = authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(p.member.user)}
	}
	return caller
}
