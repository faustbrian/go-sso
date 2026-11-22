package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	organization "github.com/faustbrian/go-organization"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
)

const providerSigninStart = "identity.sso.signin-start"
const providerOIDCCallback = "identity.sso.oidc-callback"

// The encrypted request map holds several independently bounded URLs. JSON
// escaping can expand their wire representation even though each is valid.
const providerLoginRequestPlainLimit = 128 << 10
const providerLoginRequestWireLimit = 192 << 10

type providerLoginStoredCommand identity.CommandBinding
type providerLoginStoredRequestKey kernel.RequestKeyPreparationBinding

// Only the original durable request mapping can reconstruct this projection.
// The projected route carries the original observations, not renewed authority.
type providerLoginStartInput struct {
	Command                                       providerLoginStoredCommand
	Intent                                        [32]byte
	ProviderID                                    sso.ProviderID
	ProviderVersion, Generation, RoutePolicy      uint64
	Proof                                         organization.DomainProofKey
	RouteObservedAt, RouteValidUntil              time.Time
	Organization                                  organization.CredentialAuthorityObservation
	GlobalVersion, TenantVersion, MappingVersion  uint64
	Issuer, AuthorizationEndpoint, ClientID       string
	ProtocolRedirectURI                           string
	BrowserOrigin, SuccessCallback, ErrorCallback string
	Remember                                      session.RememberPolicySpec
	Started, Issued, Expires                      time.Time
}

func (i providerLoginStartInput) authority() (providerLoginAuthority, error) {
	proof := sso.DomainProofCheckpoint{Key: i.Proof, ProofVersion: i.Proof.ProofVersion}
	route, err := sso.NewDomainRoute(sso.DomainRouteBinding{
		ProviderID: i.ProviderID, ProviderVersion: i.ProviderVersion, CredentialGeneration: i.Generation,
		PolicyVersion: i.RoutePolicy, Proof: proof, ObservedAt: i.RouteObservedAt, ValidUntil: i.RouteValidUntil,
	})
	if err != nil {
		return providerLoginAuthority{}, identity.ForbiddenError{}
	}
	return providerLoginAuthority{route: route, organization: i.Organization}, nil
}

func (i providerLoginStartInput) payload() providerLoginPayloadInput {
	return providerLoginPayloadInput{
		Command: identity.CommandBinding(i.Command), OrganizationID: string(i.Proof.OrganizationID),
		ProviderID: string(i.ProviderID), ProviderVersion: i.ProviderVersion, CredentialGeneration: i.Generation, MappingVersion: i.MappingVersion,
		Issuer: i.Issuer, ClientID: i.ClientID, RedirectURI: i.ProtocolRedirectURI,
		BrowserOrigin: i.BrowserOrigin, SuccessCallback: i.SuccessCallback, ErrorCallback: i.ErrorCallback, Remember: i.Remember,
		InputFingerprint: i.Intent, IssuedAt: i.Issued, ExpiresAt: i.Expires,
	}
}

type providerLoginPhase struct {
	service  *ProviderLoginService
	request  sso.SigninStartRequest
	browser  ProviderLoginBrowser
	flow     session.PreAuthTransaction
	intent   [32]byte
	input    *providerLoginStartInput
	registry *kernel.ContributorRegistry
	restored providerLoginRestoration
	denied   bool
}

func (p *providerLoginPhase) readBrowser(ctx context.Context) error {
	pool := p.service.router.pool.Raw()
	var started, now time.Time
	if err := pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&started); err != nil {
		return identity.UnavailableError{}
	}
	flow, err := sessionpg.ReadPreAuth(ctx, pool, p.service.config.Session, p.service.config.TenantID, p.browser.FlowID)
	if err != nil {
		return err
	}
	if err := pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return identity.UnavailableError{}
	}
	if now.Before(started) || !now.Before(started.Add(20*time.Second)) {
		return identity.ForbiddenError{}
	}
	if err := p.requireBrowser(flow, now.UTC()); err != nil {
		return err
	}
	p.flow = flow
	return nil
}

func (p *providerLoginPhase) requireBrowser(flow session.PreAuthTransaction, now time.Time) error {
	remember, err := p.request.LoginIntent.RememberPolicy()
	if err != nil {
		return identity.ForbiddenError{}
	}
	return p.service.requireProviderLoginBrowser(flow, now, p.browser, p.request.SuccessCallback.String(), remember)
}

func (s *ProviderLoginService) requireProviderLoginBrowser(flow session.PreAuthTransaction, now time.Time, browser ProviderLoginBrowser, successCallback string, remember session.RememberPolicy) error {
	spec, err := flow.Bindings()
	if err != nil {
		return identity.ForbiddenError{}
	}
	b, c := spec.Binding, s.config
	i := b.Intent
	if b.ID != browser.FlowID || i.TenantID != c.TenantID || i.Purpose != session.PreAuthSessionIssuance ||
		i.Action != providerOIDCCallback || i.IdentifierBinding != ([32]byte{}) || i.Origin != browser.Origin ||
		i.CallbackURL != successCallback || i.PolicyID != c.PolicyID || i.PolicyVersion != s.policyVersion || i.Remember != remember {
		return identity.ForbiddenError{}
	}
	token, err := session.ParseToken(browser.FlowCookie.Token())
	if err != nil {
		return identity.ForbiddenError{}
	}
	for _, key := range c.FlowKeys {
		digest, err := token.PreAuthDigest(key, b)
		if err == nil && flow.Check(now, b, digest) == nil {
			return nil
		}
	}
	return identity.ForbiddenError{}
}

func (p *providerLoginPhase) requestIntent() (identity.RequestIntent, error) {
	flow, err := p.flow.Bindings()
	if err != nil {
		return identity.RequestIntent{}, err
	}
	b, i, r := flow.Binding, flow.Binding.Intent, p.request
	remember, err := i.Remember.Bindings()
	if err != nil {
		return identity.RequestIntent{}, err
	}
	// Hash the original session-owned intent and token digest, never the bearer
	// or raw idempotency key. The coordinator separately keys this commitment.
	frame, err := json.Marshal(struct {
		Configuration                       [32]byte
		Request                             identity.CommandID
		Flow                                identity.PreAuthTransactionID
		FlowVersion                         uint64
		Nonce                               [32]byte
		CookieKeyVersion                    uint32
		CookieDigest                        [32]byte
		FlowIssued, FlowExpires             time.Time
		Remember                            session.RememberPolicySpec
		Provider, Domain, Callback, Failure string
		Origin, Network, Device             string
	}{p.service.profileDigest, r.CommandID, b.ID, flow.Version, i.Nonce, flow.Cookie.KeyVersion, flow.Cookie.Sum,
		b.IssuedAt, b.ExpiresAt, remember, r.ProviderID, r.Domain, r.SuccessCallback.String(), r.ErrorCallback.String(),
		p.browser.Origin, p.browser.Network.String(), p.browser.Device})
	if err != nil {
		return identity.RequestIntent{}, identity.UnavailableError{}
	}
	defer clear(frame)
	p.intent = sha256.Sum256(frame)
	return identity.NewRequestIntent([]identity.FeatureField{{Name: "sso.signin.intent", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: p.intent[:]}}})
}

func (p *providerLoginPhase) commandBinding(command identity.CommandID) identity.CommandBinding {
	op, c := providerSigninOperation(), p.service.config
	return identity.CommandBinding{
		CommandID: command, TenantID: c.TenantID, ActorID: c.ActorID, ActorKind: authorization.SubjectServiceAccount,
		OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion,
		RecordID: string(command), AnonymousFlowID: string(p.browser.FlowID), CorrelationID: string(command),
		PolicyID: c.PolicyID, PolicyVersion: p.service.policyVersion,
	}
}

func (p *providerLoginPhase) requestKeyContext(k kernel.RequestKeyPreparationBinding) (envelope.Context, error) {
	if k.Feature != p.registration() || k.Namespace != p.service.config.RequestKeys.Namespace || k.Scope != p.service.requestScope() ||
		k.PolicyVersion != p.service.policyVersion || k.IntentDigest == ([32]byte{}) || k.Admission.FingerprintKeyVersion == 0 {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	if _, err := identity.ParseCommandID(string(k.Admission.CommandID)); err != nil {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	frame, err := json.Marshal(providerLoginStoredRequestKey(k))
	if err != nil {
		return envelope.Context{}, identity.UnavailableError{}
	}
	defer clear(frame)
	digest := sha256.Sum256(frame)
	return envelope.NewContext(map[string]string{"profile": "sso-oidc-login-request-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}

func (p *providerLoginPhase) PrepareRequestKey(ctx context.Context, k kernel.RequestKeyPreparationBinding, intent identity.RequestIntent) (wire []byte, err error) {
	defer func() {
		var forbidden identity.ForbiddenError
		p.denied = errors.Is(err, sso.ErrForbidden) || errors.As(err, &forbidden)
	}()
	aad, err := p.requestKeyContext(k)
	if err != nil {
		return nil, err
	}
	fields, ok := intent.Fields()
	if !ok || len(fields) != 1 || !p.matchesIntent(fields[0]) {
		return nil, identity.ForbiddenError{}
	}
	s := p.service
	var now time.Time
	if err := s.router.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return nil, identity.UnavailableError{}
	}
	now = now.UTC()
	if err := p.requireBrowser(p.flow, now); err != nil {
		return nil, err
	}
	directory, err := s.directory.GetDirectoryAuthority(ctx, s.directoryQuery())
	if err != nil {
		return nil, err
	}
	if !directory.Enabled {
		return nil, identity.ForbiddenError{}
	}
	selected, profile, err := s.selectRoute(ctx, p.request)
	if err != nil {
		return nil, err
	}
	// Check the complete wire-size bound before reserving an irreversible
	// generation. Real public values use the same fixed base64url length.
	const publicFieldShape = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if _, err := profile.authorizationRedirect(providerLoginPublicState{State: publicFieldShape, Nonce: publicFieldShape, Challenge: publicFieldShape}); err != nil {
		return nil, identity.ForbiddenError{}
	}
	authority, err := s.router.observeProviderLoginAuthority(ctx, selected)
	if err != nil {
		return nil, err
	}
	route, err := selected.Bindings()
	if err != nil {
		return nil, err
	}
	flow, err := p.flow.Bindings()
	if err != nil {
		return nil, err
	}
	remember, err := flow.Binding.Intent.Remember.Bindings()
	if err != nil {
		return nil, err
	}
	issued := now.Truncate(time.Second)
	expires := earlierLoginTime(issued.Add(s.config.StateLifetime), flow.Binding.ExpiresAt).Truncate(time.Second)
	if !expires.After(now) {
		return nil, identity.ForbiddenError{}
	}
	input := providerLoginStartInput{
		Command: providerLoginStoredCommand(p.commandBinding(k.Admission.CommandID)), Intent: p.intent,
		ProviderID: route.ProviderID, ProviderVersion: route.ProviderVersion, Generation: route.CredentialGeneration,
		RoutePolicy: route.PolicyVersion, Proof: route.Proof.Key,
		RouteObservedAt: route.ObservedAt, RouteValidUntil: route.ValidUntil, Organization: authority.organization,
		GlobalVersion: directory.GlobalVersion, TenantVersion: directory.TenantVersion, MappingVersion: profile.configured.MappingVersion,
		Issuer: profile.issuer, AuthorizationEndpoint: profile.authorizationEndpoint,
		ClientID: profile.configured.ClientID, ProtocolRedirectURI: profile.configured.ProtocolRedirectURI,
		BrowserOrigin: p.browser.Origin, SuccessCallback: p.request.SuccessCallback.String(), ErrorCallback: p.request.ErrorCallback.String(),
		Remember: remember,
		Started:  now, Issued: issued, Expires: expires,
	}
	if err := input.payload().validate(); err != nil {
		return nil, err
	}
	plain, err := json.Marshal(input)
	defer clear(plain)
	if err != nil || len(plain) > providerLoginRequestPlainLimit {
		return nil, identity.UnavailableError{}
	}
	sealed, err := s.config.Envelope.Encrypt(ctx, envelope.EncryptRequest{Plaintext: plain, KeyReference: s.config.KeyReference, Context: aad})
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	wire, err = sealed.MarshalBinary()
	if err != nil || len(wire) > providerLoginRequestWireLimit {
		clear(wire)
		return nil, identity.UnavailableError{}
	}
	return wire, nil
}

func (p *providerLoginPhase) restoreInput(ctx context.Context, k kernel.RequestKeyPreparationBinding, wire []byte) error {
	input, err := p.openOriginalInput(ctx, k, wire)
	if err != nil {
		return err
	}
	if input.Intent != p.intent {
		return identity.ForbiddenError{}
	}
	remember, err := p.request.LoginIntent.RememberPolicy()
	if err != nil {
		return identity.ForbiddenError{}
	}
	rememberSpec, err := remember.Bindings()
	if err != nil || input.Remember != rememberSpec || input.BrowserOrigin != p.browser.Origin ||
		input.SuccessCallback != p.request.SuccessCallback.String() || input.ErrorCallback != p.request.ErrorCallback.String() {
		return identity.ForbiddenError{}
	}
	p.input = &input
	return nil
}

func (p *providerLoginPhase) openOriginalInput(ctx context.Context, k kernel.RequestKeyPreparationBinding, wire []byte) (providerLoginStartInput, error) {
	aad, err := p.requestKeyContext(k)
	if err != nil {
		return providerLoginStartInput{}, err
	}
	if len(wire) == 0 || len(wire) > providerLoginRequestWireLimit {
		return providerLoginStartInput{}, identity.ForbiddenError{}
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return providerLoginStartInput{}, identity.ForbiddenError{}
	}
	plain, err := p.service.config.Envelope.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	defer clear(plain)
	var input providerLoginStartInput
	if err != nil || len(plain) == 0 || len(plain) > providerLoginRequestPlainLimit || json.Unmarshal(plain, &input) != nil {
		return providerLoginStartInput{}, identity.ForbiddenError{}
	}
	want := p.commandBinding(k.Admission.CommandID)
	if identity.CommandBinding(input.Command) != want || want.ValidateFor(providerSigninOperation()) != nil ||
		input.Proof.TenantID != want.TenantID || input.GlobalVersion == 0 || input.TenantVersion == 0 ||
		!input.Issued.Equal(input.Started.Truncate(time.Second)) || !input.Expires.After(input.Started) ||
		input.Expires.After(input.Issued.Add(p.service.config.StateLifetime)) {
		return providerLoginStartInput{}, identity.ForbiddenError{}
	}
	profile, ok := p.service.profiles[providerLoginProfileKey{input.Proof.OrganizationID, input.ProviderID}]
	if !ok || profile.Domain != input.Proof.Domain || profile.ProviderVersion != input.ProviderVersion ||
		profile.CredentialGeneration != input.Generation || profile.MappingVersion != input.MappingVersion ||
		profile.ClientID != input.ClientID || profile.ProtocolRedirectURI != input.ProtocolRedirectURI {
		return providerLoginStartInput{}, identity.ForbiddenError{}
	}
	if _, err := input.authority(); err != nil {
		return providerLoginStartInput{}, err
	}
	return input, nil
}

func earlierLoginTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}
