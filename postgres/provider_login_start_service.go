package postgres

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	organization "github.com/faustbrian/go-organization"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// ProviderLoginBrowser carries the original browser's opaque pre-authentication
// cookie and flow. The origin, network, and device must come from the trusted
// transport adapter, never forwarding headers or client-supplied policy fields.
type ProviderLoginBrowser struct {
	FlowID     identity.PreAuthTransactionID
	FlowCookie authentication.BearerCredential
	Origin     string
	Network    netip.Addr
	Device     string
}

// ProviderLoginConfig opts one tenant into static OIDC start for exact installed
// profiles. Install the provider/login, pre-authentication, prepared-command,
// capability, risk and audit/outbox migrations on the router's primary first.
// ConfigurationID and retained keys must remain compatible with pending retries.
type ProviderLoginConfig struct {
	TenantID                            identity.TenantID
	ActorID                             identity.ActorID
	Origin, PolicyID, GlobalAuthorityID string
	ConfigurationID                     string
	CallbackAllowlist                   []string
	Profiles                            []StaticOIDCLoginProfile
	Session                             sessionpg.Config
	FlowKeys                            []session.DigestKey
	Risk                                risk.AuthenticationAdmissionCustodyConfig
	Coordinator                         kernel.CoordinatorConfig
	RequestKeys                         kernel.RequestKeyConfig
	Capability                          capabilitypg.IssuerConfig
	CapabilityPreparation               capabilitypg.IssuancePreparationConfig
	Envelope                            *envelope.Service
	KeyReference                        string
	StateKeys, PKCEKeys                 map[uint32][32]byte
	CurrentStateKey, CurrentPKCEKey     uint32
	AuditRetentionPolicyVersion         uint64
	StateLifetime                       time.Duration
}

// ProviderLoginService owns native anonymous enterprise sign-in initiation. It
// borrows the router's primary; it does not issue sessions or own HTTP routes.
type ProviderLoginService struct {
	router            *ProviderRouter
	directory         *kernel.Repository
	config            ProviderLoginConfig
	policyVersion     uint64
	profiles          map[providerLoginProfileKey]StaticOIDCLoginProfile
	providerDomains   map[sso.ProviderID]string
	callbacks         map[string]struct{}
	profileDigest     [32]byte
	oauthProfiles     map[providerLoginProfileKey]StaticOAuth2LoginProfile
	oauthDigest       [32]byte
	oauthStartAdapter *providerOAuth2StartAdapter
	payload           providerLoginPayloadConfig
	callbackVerifier  capability.Service
	callbackLimits    capability.Limits
	custody           risk.AuthenticationAdmissionCustody
	link              *ProviderLinkConfig
}

type providerLoginProfileKey struct {
	organization organization.ID
	provider     sso.ProviderID
}

// NewProviderLoginService composes the explicitly selected static OIDC native
// start profile on the router's primary, without I/O or background work.
func NewProviderLoginService(router *ProviderRouter, config ProviderLoginConfig) (*ProviderLoginService, error) {
	return newProviderLoginService(router, config, nil)
}

// NewProviderLoginServiceWithOAuth2 opts into explicitly selected static OAuth
// 2.0 profiles on a protocol-aware router. OIDC profiles in config are optional.
// Install LoginTransactionProtocolMigrationSource before enabling OAuth start.
// The OAuth browser must carry a pre-authentication flow for the exact
// identity.sso.oauth-callback action; an OIDC flow cannot substitute for it.
func NewProviderLoginServiceWithOAuth2(router *ProviderRouter, config ProviderLoginConfig, oauthProfiles []StaticOAuth2LoginProfile) (*ProviderLoginService, error) {
	if router == nil || !router.protocolRegistry || len(oauthProfiles) == 0 || len(oauthProfiles) > 128 {
		return nil, sso.ErrInvalidInput
	}
	return newProviderLoginService(router, config, oauthProfiles)
}

func newProviderLoginService(router *ProviderRouter, config ProviderLoginConfig, oauthProfiles []StaticOAuth2LoginProfile) (*ProviderLoginService, error) {
	if router == nil || router.pool == nil || router.pool.Raw() == nil || config.Envelope == nil ||
		!providerID(string(config.TenantID)) || !providerID(string(config.ActorID)) || !providerID(config.PolicyID) ||
		!providerID(config.GlobalAuthorityID) || !providerID(config.ConfigurationID) || !providerID(config.KeyReference) ||
		config.AuditRetentionPolicyVersion == 0 || !validProviderLoginOrigin(config.Origin) {
		return nil, sso.ErrInvalidInput
	}
	if config.Coordinator.MaximumDuration < time.Millisecond || config.Coordinator.MaximumDuration > 30*time.Second ||
		config.StateLifetime < time.Minute || config.StateLifetime > 10*time.Minute || config.StateLifetime%time.Second != 0 ||
		config.Session.MaximumDuration <= 0 || config.Session.MaximumDuration > config.Coordinator.MaximumDuration ||
		len(config.FlowKeys) == 0 || len(config.FlowKeys) > 32 || len(config.Profiles)+len(oauthProfiles) == 0 || len(config.Profiles) > 128 ||
		len(config.CallbackAllowlist) == 0 || len(config.CallbackAllowlist) > 64 {
		return nil, sso.ErrInvalidInput
	}
	query, admission := config.Coordinator.QueryPolicy, config.Coordinator.AdmissionPolicy
	if query == nil || admission == nil || admission.PolicyVersion == 0 || query.PolicyVersion != admission.PolicyVersion ||
		config.RequestKeys.Policy.PolicyVersion != admission.PolicyVersion || router.config.PolicyVersion != admission.PolicyVersion {
		return nil, sso.ErrInvalidInput
	}
	profiles := make(map[providerLoginProfileKey]StaticOIDCLoginProfile, len(config.Profiles))
	domains := make(map[sso.ProviderID]string, len(config.Profiles))
	normalized := make([]StaticOIDCLoginProfile, 0, len(config.Profiles))
	for _, configured := range config.Profiles {
		profile, err := normalizeStaticOIDCLoginProfile(configured)
		if err != nil {
			return nil, sso.ErrInvalidInput
		}
		key := providerLoginProfileKey{profile.OrganizationID, profile.ProviderID}
		if _, exists := profiles[key]; exists {
			return nil, sso.ErrInvalidInput
		}
		profiles[key] = profile
		normalized = append(normalized, profile)
		if _, duplicate := domains[profile.ProviderID]; duplicate {
			domains[profile.ProviderID] = ""
		} else {
			domains[profile.ProviderID] = profile.Domain
		}
	}
	slices.SortFunc(normalized, func(a, b StaticOIDCLoginProfile) int {
		if c := cmp.Compare(a.OrganizationID, b.OrganizationID); c != 0 {
			return c
		}
		return cmp.Compare(a.ProviderID, b.ProviderID)
	})
	callbacks := make(map[string]struct{}, len(config.CallbackAllowlist))
	for _, callback := range config.CallbackAllowlist {
		if !validProviderLoginCallback(callback) {
			return nil, sso.ErrInvalidInput
		}
		callbacks[callback] = struct{}{}
	}
	if !validProviderLoginKeys(config) {
		return nil, sso.ErrInvalidInput
	}
	issuer, err := capabilitypg.NewIssuer(config.Capability)
	if err != nil {
		return nil, sso.ErrInvalidInput
	}
	callbackVerifier, err := capability.NewService(config.Capability.Crypto)
	if err != nil {
		return nil, sso.ErrInvalidInput
	}
	callbackLimits := config.Capability.Crypto.Limits
	codec, err := capabilitypg.NewIssuancePreparationCodec(issuer, config.CapabilityPreparation)
	if err != nil {
		return nil, sso.ErrInvalidInput
	}
	custody, err := risk.NewAuthenticationAdmissionCustody(config.Risk)
	if err != nil {
		return nil, sso.ErrInvalidInput
	}
	directory, err := kernel.NewRepository(router.pool, kernel.Config{MaximumDuration: config.Coordinator.MaximumDuration})
	if err != nil {
		return nil, sso.ErrInvalidInput
	}
	if _, err := sessionpg.NewRepository(router.pool, config.Session); err != nil {
		return nil, sso.ErrInvalidInput
	}
	frame, err := json.Marshal(struct {
		Tenant, Actor, Origin, Policy, Global, Configuration, Session, Risk string
		CapabilityIssuer, Audience                                          string
		PolicyVersion, AuditRetention                                       uint64
		TTL                                                                 time.Duration
		Callbacks                                                           map[string]struct{}
		Profiles                                                            []StaticOIDCLoginProfile
	}{string(config.TenantID), string(config.ActorID), config.Origin, config.PolicyID, config.GlobalAuthorityID,
		config.ConfigurationID, config.Session.Schema, config.Risk.ConfigurationID, config.Capability.Crypto.Issuer,
		config.Capability.Audience, admission.PolicyVersion, config.AuditRetentionPolicyVersion, config.StateLifetime,
		callbacks, normalized})
	if err != nil {
		return nil, sso.ErrInvalidInput
	}
	defer clear(frame)
	admissionCopy, queryCopy := *admission, *query
	config.Coordinator.AdmissionPolicy, config.Coordinator.QueryPolicy = &admissionCopy, &queryCopy
	config.Coordinator.RetainedFingerprintKeys = cloneProviderLoginKeys(config.Coordinator.RetainedFingerprintKeys)
	config.Coordinator.FinalAuthentication = nil
	config.FlowKeys = slices.Clone(config.FlowKeys)
	config.CallbackAllowlist, config.Profiles = nil, nil
	payload := providerLoginPayloadConfig{
		Envelope: config.Envelope, KeyReference: config.KeyReference, Issuer: issuer, Codec: codec,
		CapabilityIssuer: config.Capability.Crypto.Issuer, Audience: config.Capability.Audience,
		StateKeys: cloneProviderLoginKeys(config.StateKeys), PKCEKeys: cloneProviderLoginKeys(config.PKCEKeys),
		CurrentStateKey: config.CurrentStateKey, CurrentPKCEKey: config.CurrentPKCEKey,
	}
	// Do not retain caller-owned signing, envelope or replay-key configuration
	// after construction; the specific immutable owners keep only their inputs.
	config.Capability = capabilitypg.IssuerConfig{}
	config.CapabilityPreparation = capabilitypg.IssuancePreparationConfig{}
	config.StateKeys, config.PKCEKeys, config.Risk.Keys = nil, nil, nil
	s := &ProviderLoginService{
		router: router, config: config, directory: directory, policyVersion: admissionCopy.PolicyVersion,
		profiles: profiles, providerDomains: domains, callbacks: callbacks, profileDigest: sha256.Sum256(frame),
		payload: payload, callbackVerifier: callbackVerifier, callbackLimits: callbackLimits, custody: custody,
	}
	if _, _, err := s.coordinator(&providerLoginPhase{service: s}); err != nil {
		return nil, sso.ErrInvalidInput
	}
	if len(oauthProfiles) != 0 {
		if err := s.snapshotOAuth2StartProfiles(oauthProfiles); err != nil {
			return nil, err
		}
		if _, _, err := s.coordinator(&providerLoginPhase{service: s, protocol: providerProtocolOAuth2}); err != nil {
			return nil, sso.ErrInvalidInput
		}
	}
	return s, nil
}

func (s *ProviderLoginService) snapshotOAuth2StartProfiles(configured []StaticOAuth2LoginProfile) error {
	profiles := make(map[providerLoginProfileKey]StaticOAuth2LoginProfile, len(configured))
	normalized := make([]StaticOAuth2LoginProfile, 0, len(configured))
	for _, configured := range configured {
		profile, err := normalizeStaticOAuth2LoginProfile(configured)
		if err != nil {
			return err
		}
		key := providerLoginProfileKey{profile.OrganizationID, profile.ProviderID}
		if _, duplicate := profiles[key]; duplicate {
			return sso.ErrInvalidInput
		}
		if _, mixed := s.profiles[key]; mixed {
			return sso.ErrInvalidInput
		}
		profiles[key] = profile
		normalized = append(normalized, profile)
	}
	slices.SortFunc(normalized, func(a, b StaticOAuth2LoginProfile) int {
		if c := cmp.Compare(a.OrganizationID, b.OrganizationID); c != 0 {
			return c
		}
		return cmp.Compare(a.ProviderID, b.ProviderID)
	})
	frame, err := json.Marshal(struct {
		Profile string
		Shared  [32]byte
		OAuth2  []StaticOAuth2LoginProfile
	}{"native-sso-oauth2-start-v1", s.profileDigest, normalized})
	if err != nil {
		return sso.ErrInvalidInput
	}
	defer clear(frame)
	s.oauthProfiles, s.oauthDigest = profiles, sha256.Sum256(frame)
	return nil
}

// SigninStart authorizes the original browser and returns a redirect only
// after a matching committed native login transaction has been acknowledged.
func (s *ProviderLoginService) SigninStart(ctx context.Context, request sso.SigninStartRequest, browser ProviderLoginBrowser) (out sso.SigninStartResult, err error) {
	return s.startProviderTransaction(ctx, request, browser, nil)
}

func (s *ProviderLoginService) startProviderTransaction(ctx context.Context, request sso.SigninStartRequest, browser ProviderLoginBrowser, member *providerLoginMemberAdmission) (out sso.SigninStartResult, err error) {
	return s.startProviderTransactionForProtocol(ctx, request, browser, member, "")
}

// SigninStartOAuth2 commits the exact anonymous OAuth provider selection and
// encrypted state/PKCE custody before returning a query-code/S256 redirect.
// It requires both provider and domain; it never falls back to OIDC.
func (s *ProviderLoginService) SigninStartOAuth2(ctx context.Context, request sso.SigninStartRequest, browser ProviderLoginBrowser) (sso.SigninStartResult, error) {
	if s == nil || len(s.oauthProfiles) == 0 || request.ProviderID == "" || request.Domain == "" {
		return sso.SigninStartResult{}, sso.ErrForbidden
	}
	return s.startProviderTransactionForProtocol(ctx, request, browser, nil, providerProtocolOAuth2)
}

func (s *ProviderLoginService) startProviderTransactionForProtocol(ctx context.Context, request sso.SigninStartRequest, browser ProviderLoginBrowser, member *providerLoginMemberAdmission, protocol string) (out sso.SigninStartResult, err error) {
	if s == nil || s.router == nil || ctx == nil || request.Validate() != nil {
		return out, sso.ErrInvalidInput
	}
	if browser.Origin != s.config.Origin || !browser.Network.IsValid() || browser.Network.Is4In6() ||
		browser.Network.Zone() != "" || !providerID(browser.Device) || member == nil && browser.FlowID == "" {
		return out, sso.ErrForbidden
	}
	if _, ok := s.callbacks[request.SuccessCallback.String()]; !ok {
		return out, sso.ErrForbidden
	}
	if _, ok := s.callbacks[request.ErrorCallback.String()]; !ok {
		return out, sso.ErrForbidden
	}
	ctx, cancel := context.WithTimeout(ctx, s.config.Coordinator.MaximumDuration)
	defer cancel()
	defer func() {
		if recover() != nil {
			out, err = sso.SigninStartResult{}, sso.ErrUnavailable
		}
	}()
	p := &providerLoginPhase{service: s, request: request, browser: browser, member: member, protocol: protocol}
	if err := p.readOriginalBrowser(ctx); err != nil {
		return out, providerError(ctx, err)
	}
	intent, err := p.requestIntent()
	if err != nil {
		return out, providerError(ctx, err)
	}
	coordinator, registry, err := s.coordinator(p)
	if err != nil {
		return out, providerError(ctx, err)
	}
	p.registry = registry
	key, wire, err := coordinator.ResolvePreparedRequestKey(ctx, p.startScope(), request.IdempotencyKey, intent, p.startCaller(), p.registration(), p)
	if err != nil {
		// The generic request mapper masks contributor errors. Preserve only a
		// denial observed by this invocation, never a dependency or commit error.
		var unavailable identity.UnavailableError
		if ctx.Err() == nil && p.denied && errors.As(err, &unavailable) {
			return out, sso.ErrForbidden
		}
		return out, providerError(ctx, err)
	}
	defer clear(wire)
	if err := p.restoreInput(ctx, key, wire); err != nil {
		return out, providerError(ctx, err)
	}
	command, err := p.command()
	if err != nil {
		return out, providerError(ctx, err)
	}
	plan, err := p.plan(registry, nil)
	if err != nil {
		return out, providerError(ctx, err)
	}
	completion, err := coordinator.ExecutePreparedFeature(ctx, command, plan)
	if completion.Validate() == nil && completion.Binding == identity.CommandBinding(p.input.Command) {
		out.Completion = completion
	}
	if err != nil {
		return out, providerError(ctx, err)
	}
	if out.Completion.Outcome != identity.CommitOutcomeCommitted || out.Completion.Feature == nil ||
		out.Completion.Feature.Operation != p.operation() || out.Completion.Feature.AfterVersion != 1 {
		return out, identity.UnknownCommitError{CommandID: key.Admission.CommandID}
	}
	return p.committedRedirect(ctx, out)
}

func (s *ProviderLoginService) requestScope() kernel.RequestKeyScope {
	return kernel.RequestKeyScope{TenantID: s.config.TenantID, ActorID: s.config.ActorID,
		ActorKind: authorization.SubjectServiceAccount, Method: "POST", RouteID: providerSigninStart}
}

func (s *ProviderLoginService) caller() authorization.DecisionContext {
	return authorization.DecisionContext{PolicyRevision: authorization.Revision(s.policyVersion), Request: authorization.Request{
		Tenant:   authorization.TenantID(s.config.TenantID),
		Subject:  authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: authorization.SubjectID(s.config.ActorID)},
		Action:   providerSigninStart,
		Resource: authorization.Resource{Type: "identity.request-admission", ID: providerSigninStart},
	}}
}

func (s *ProviderLoginService) directoryQuery() kernel.DirectoryAuthorityQuery {
	return kernel.DirectoryAuthorityQuery{GlobalAuthorityID: s.config.GlobalAuthorityID, TenantID: s.config.TenantID}
}

func (s *ProviderLoginService) selectRoute(ctx context.Context, r sso.SigninStartRequest) (sso.DomainRoute, providerLoginProfile, error) {
	provider, domain := sso.ProviderID(r.ProviderID), r.Domain
	if domain == "" {
		domain = s.providerDomains[provider]
	}
	lookup, err := sso.NewDomainRouteRequest(s.config.TenantID, domain, provider)
	if err != nil {
		return sso.DomainRoute{}, providerLoginProfile{}, sso.ErrForbidden
	}
	route, err := s.router.Route(ctx, lookup)
	if err != nil {
		return sso.DomainRoute{}, providerLoginProfile{}, err
	}
	b, err := route.Bindings()
	if err != nil {
		return sso.DomainRoute{}, providerLoginProfile{}, err
	}
	configured, ok := s.profiles[providerLoginProfileKey{b.Proof.Key.OrganizationID, b.ProviderID}]
	if !ok {
		return sso.DomainRoute{}, providerLoginProfile{}, sso.ErrForbidden
	}
	profile, err := s.router.readProviderLoginProfile(ctx, route, configured)
	return route, profile, err
}

func (p *providerLoginPhase) selectRoute(ctx context.Context) (sso.DomainRoute, providerLoginProfile, error) {
	s, r := p.service, p.request
	if p.protocol == "" {
		return s.selectRoute(ctx, r)
	}
	lookup, err := sso.NewDomainRouteRequest(s.config.TenantID, r.Domain, sso.ProviderID(r.ProviderID))
	if err != nil {
		return sso.DomainRoute{}, providerLoginProfile{}, sso.ErrForbidden
	}
	route, err := s.router.RouteOAuth2(ctx, lookup)
	if err != nil {
		return sso.DomainRoute{}, providerLoginProfile{}, err
	}
	b, err := route.Bindings()
	if err != nil {
		return sso.DomainRoute{}, providerLoginProfile{}, sso.ErrForbidden
	}
	configured, ok := s.oauthProfiles[providerLoginProfileKey{b.Proof.Key.OrganizationID, b.ProviderID}]
	if !ok {
		return sso.DomainRoute{}, providerLoginProfile{}, sso.ErrForbidden
	}
	profile, err := s.router.readProviderOAuth2LoginProfile(ctx, route, configured)
	if err != nil {
		return sso.DomainRoute{}, providerLoginProfile{}, err
	}
	return route, providerLoginProfile{configured: StaticOIDCLoginProfile(profile.configured), protocol: providerProtocolOAuth2,
		issuer: profile.issuer, authorizationEndpoint: profile.authorizationEndpoint, oauthConfiguration: profile.installed}, nil
}

func (s *ProviderLoginService) coordinator(p *providerLoginPhase) (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
	auditing, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, nil, err
	}
	lifecycle, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, nil, err
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{s.directory, auditing, lifecycle, p, s.payload.Issuer})
	if err != nil {
		return nil, nil, err
	}
	coordinator, err := kernel.NewCoordinatorWithRequestKeys(s.router.pool, registry, s.config.Coordinator, s.config.RequestKeys)
	return coordinator, registry, err
}

func validProviderLoginKeys(c ProviderLoginConfig) bool {
	if len(c.StateKeys) < 1 || len(c.StateKeys) > 32 || len(c.PKCEKeys) < 1 || len(c.PKCEKeys) > 32 ||
		c.StateKeys[c.CurrentStateKey] == ([32]byte{}) || c.PKCEKeys[c.CurrentPKCEKey] == ([32]byte{}) {
		return false
	}
	for version, state := range c.StateKeys {
		if version == 0 || state == ([32]byte{}) {
			return false
		}
		for _, pkce := range c.PKCEKeys {
			if state == pkce {
				return false
			}
		}
	}
	for version, pkce := range c.PKCEKeys {
		if version == 0 || pkce == ([32]byte{}) {
			return false
		}
	}
	return true
}

func cloneProviderLoginKeys(source map[uint32][32]byte) map[uint32][32]byte {
	keys := make(map[uint32][32]byte, len(source))
	for version, key := range source {
		keys[version] = key
	}
	return keys
}

func validProviderLoginOrigin(raw string) bool {
	if !validProviderLoginCallback(raw) || strings.ContainsAny(raw, "?#") {
		return false
	}
	u, err := url.Parse(raw)
	return err == nil && u.Path == "" && u.RawQuery == ""
}

func validProviderLoginCallback(raw string) bool {
	if len(raw) == 0 || len(raw) > 2048 || strings.Contains(raw, "#") {
		return false
	}
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil &&
		u.Opaque == "" && u.String() == raw
}

func (ProviderLoginBrowser) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("sso.postgres.ProviderLoginBrowser(redacted)"))
}
func (ProviderLoginBrowser) MarshalJSON() ([]byte, error) { return nil, sso.ErrSensitiveSerialization }
func (ProviderLoginBrowser) MarshalText() ([]byte, error) { return nil, sso.ErrSensitiveSerialization }
func (ProviderLoginConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("sso.postgres.ProviderLoginConfig(redacted)"))
}
func (ProviderLoginConfig) MarshalJSON() ([]byte, error) { return nil, sso.ErrSensitiveSerialization }
func (ProviderLoginConfig) MarshalText() ([]byte, error) { return nil, sso.ErrSensitiveSerialization }
func (*ProviderLoginService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("sso.postgres.ProviderLoginService(redacted)"))
}
func (*ProviderLoginService) MarshalJSON() ([]byte, error) { return nil, sso.ErrSensitiveSerialization }
func (*ProviderLoginService) MarshalText() ([]byte, error) { return nil, sso.ErrSensitiveSerialization }
