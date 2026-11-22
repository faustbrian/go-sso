package postgres

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"

	auditpg "github.com/faustbrian/go-audit/postgres"
	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	organization "github.com/faustbrian/go-organization"
	"github.com/faustbrian/go-sso"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// StaticOIDCCompletionProfile pins one installed login selection to a trusted
// static OIDC transport and signing-key verifier. Endpoints must match the
// original authenticated installed configuration. No discovery, caller-provided
// issuer, key-set failover or fallback provider is selected by this service.
type StaticOIDCCompletionProfile struct {
	OrganizationID       organization.ID
	ProviderID           sso.ProviderID
	Metadata             sso.OIDCStaticMetadataSpec
	ClientAuthentication oauth.ClientAuthentication
	Algorithms           []string
	ClaimNames           []string
	Keys                 oauth.SigningKeySet
	HTTPClient           *http.Client
}

// ProviderLoginCompletionConfig opts specific static-OIDC profiles into
// existing-linked-member sign-in. Issuer and CSRF keys must be dedicated to
// this session deployment. The service uses the start owner's primary clock.
type ProviderLoginCompletionConfig struct {
	Audience, PolicyNamespace string
	Issuer                    session.IssuerConfig
	CSRFKey                   session.CSRFKey
	Profiles                  []StaticOIDCCompletionProfile
}

// ProviderLoginCallbackRequest is for an owned query transport after parsing
// the bounded callback. ReceivedRedirectURI must come from trusted local
// routing, never from the query, Host header, or a forwarded request URL.
// The caller retains input custody and must destroy it after the call.
type ProviderLoginCallbackRequest struct {
	Input               identity.OAuthCallbackInput
	Browser             ProviderLoginBrowser
	ReceivedRedirectURI string
}

// Format redacts borrowed browser and callback custody.
func (ProviderLoginCallbackRequest) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "postgres.ProviderLoginCallbackRequest(redacted)")
}

// MarshalJSON refuses implicit callback credential serialization.
func (ProviderLoginCallbackRequest) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}

// MarshalText refuses implicit callback credential serialization.
func (ProviderLoginCallbackRequest) MarshalText() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}

// ProviderLoginCallbackResult lends session and CSRF only for an acknowledged
// new successful commit. Replay, ambiguity and denial never return them.
type ProviderLoginCallbackResult struct {
	Completion  identity.CommandResult
	Issuance    session.IssueResult
	CSRF        session.CSRFToken
	RedirectURI string
}

// Format redacts the authenticated result and redirect.
func (ProviderLoginCallbackResult) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "postgres.ProviderLoginCallbackResult(redacted)")
}

// MarshalJSON refuses implicit session credential serialization.
func (ProviderLoginCallbackResult) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}

// MarshalText refuses implicit session credential serialization.
func (ProviderLoginCallbackResult) MarshalText() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}

// ProviderLoginCompletionService borrows the already configured native login
// owner and its primary. It owns no HTTP route, worker, provider registry or pool
// lifecycle. Independent requests have independent command and bearer custody.
type ProviderLoginCompletionService struct {
	start               *ProviderLoginService
	profiles            map[providerLoginProfileKey]providerLoginCallbackTransport
	protocolProfiles    map[providerLoginProfileKey]oauth.ProviderProfile
	roleMappings        map[providerLoginProfileKey]providerLoginRoleMapping
	jitPolicies         map[providerLoginProfileKey]providerLoginJITPolicy
	policy              sessionpg.IdentifierAdmissionConfig
	effect              *sessionpg.SSOOIDCSigninEffect
	issuer              session.IssuerConfig
	csrfKey             session.CSRFKey
	oidcCallbackFactory OIDCCallbackAdapterFactory
}

// NewProviderLoginCompletionService validates trusted composition without
// querying the provider or primary. Install the native SSO/session/account,
// MFA, capability and prepared-command migrations before calling SigninCallback.
func NewProviderLoginCompletionService(start *ProviderLoginService, config ProviderLoginCompletionConfig) (*ProviderLoginCompletionService, error) {
	if start == nil || start.router == nil || start.router.organizations == nil || len(config.Profiles) < 1 || len(config.Profiles) > len(start.profiles) ||
		config.Issuer.MaximumDuration > start.config.Coordinator.MaximumDuration {
		return nil, sso.ErrInvalidInput
	}
	policy := sessionpg.IdentifierAdmissionConfig{GlobalAuthorityID: start.config.GlobalAuthorityID, PolicyNamespace: config.PolicyNamespace,
		Audience: config.Audience, AuthenticationMethod: "sso-oidc", CredentialKind: identity.CredentialProvider, CredentialOwner: "sso"}
	effect, err := sessionpg.NewSSOOIDCSigninEffect(start.config.Session, policy, start.router.organizations)
	if err != nil {
		return nil, sso.ErrInvalidInput
	}
	config.Issuer.Clock = start.router.config.Clock
	if _, err := session.NewSSOOIDCSessionIssuerWithCSRF(&providerLoginCallbackPhase{}, config.Issuer, config.CSRFKey); err != nil {
		return nil, sso.ErrInvalidInput
	}
	owners := make(map[providerLoginProfileKey]providerLoginCallbackTransport, len(config.Profiles))
	protocolProfiles := make(map[providerLoginProfileKey]oauth.ProviderProfile, len(config.Profiles))
	for _, profile := range config.Profiles {
		key := providerLoginProfileKey{organization: profile.OrganizationID, provider: profile.ProviderID}
		selected, available := start.profiles[key]
		if _, duplicate := owners[key]; duplicate || !available || profile.Keys == nil ||
			(profile.ClientAuthentication != oauth.ClientSecretBasic && profile.ClientAuthentication != oauth.ClientSecretPost) {
			return nil, sso.ErrInvalidInput
		}
		if _, err := sso.NewOIDCStaticMetadata(profile.Metadata); err != nil {
			return nil, sso.ErrInvalidInput
		}
		transport := providerLoginCallbackTransport{metadata: profile.Metadata, authentication: profile.ClientAuthentication,
			algorithms: slices.Clone(profile.Algorithms), claims: slices.Clone(profile.ClaimNames), keys: profile.Keys, client: profile.HTTPClient}
		// Apply the same Golib endpoint, algorithm, key and transport checks at
		// construction without opening any installed client credential.
		check := providerLoginOIDCExchangeInput{profile: selected, metadata: transport.metadata, clientAuthentication: transport.authentication,
			algorithms: transport.algorithms, claimNames: transport.claims, keys: transport.keys, client: transport.client, clock: config.Issuer.Clock}
		validator, err := check.newOIDCProvider([]byte("configuration-validation"))
		if err != nil {
			return nil, sso.ErrInvalidInput
		}
		protocolProfiles[key] = validator.Profile()
		validator.Close()
		owners[key] = transport
	}
	return &ProviderLoginCompletionService{start: start, profiles: owners, protocolProfiles: protocolProfiles, policy: policy, effect: effect, issuer: config.Issuer, csrfKey: config.CSRFKey}, nil
}

// NewProviderLoginCompletionServiceWithRoleSync explicitly selects repeat-login
// custom role synchronization for configured static OIDC profiles. Mappings
// must match the installed login mapping versions and selected claim projection.
// Install the organization grant and native provider source migrations first.
// Unselected providers retain ordinary existing-linked-member sign-in.
func NewProviderLoginCompletionServiceWithRoleSync(start *ProviderLoginService, config ProviderLoginCompletionConfig, mappings []StaticOIDCRoleMapping) (*ProviderLoginCompletionService, error) {
	if len(mappings) == 0 || len(mappings) > len(config.Profiles) {
		return nil, sso.ErrInvalidInput
	}
	service, err := NewProviderLoginCompletionService(start, config)
	if err != nil {
		return nil, err
	}
	service.roleMappings = make(map[providerLoginProfileKey]providerLoginRoleMapping, len(mappings))
	for _, selection := range mappings {
		key := providerLoginProfileKey{organization: selection.OrganizationID, provider: selection.ProviderID}
		transport, available := service.profiles[key]
		_, duplicate := service.roleMappings[key]
		if !available || duplicate || selection.MappingVersion != start.profiles[key].MappingVersion {
			return nil, sso.ErrInvalidInput
		}
		mapping, err := newProviderLoginRoleMapping(selection, transport.claims)
		if err != nil {
			return nil, err
		}
		service.roleMappings[key] = mapping
	}
	return service, nil
}

// SigninCallback processes the original query authorization code natively.
// It authenticates the original browser and state, then delegates admission,
// one-use reservation, generation, final Work and acknowledgment to the owning
// coordinator. It never retries an ambiguous exchange or returns its provider
// tokens. It only signs in an already linked, active organization member.
func (s *ProviderLoginCompletionService) SigninCallback(ctx context.Context, request ProviderLoginCallbackRequest) (ProviderLoginCallbackResult, error) {
	return s.signinCallback(ctx, request, nil)
}

func (s *ProviderLoginCompletionService) signinCallback(ctx context.Context, request ProviderLoginCallbackRequest, parsed *oauth.QueryCallback) (out ProviderLoginCallbackResult, err error) {
	if s == nil || s.start == nil || s.effect == nil || ctx == nil || request.ReceivedRedirectURI == "" {
		return out, sso.ErrInvalidInput
	}
	ctx, cancel := context.WithTimeout(ctx, s.start.config.Coordinator.MaximumDuration)
	defer cancel()
	var entered identity.CommandID
	defer func() {
		if recover() != nil {
			out = ProviderLoginCallbackResult{}
			if entered == "" {
				err = sso.ErrUnavailable
			} else {
				err = identity.UnknownCommitError{CommandID: entered}
			}
		}
	}()
	var state string
	if err := request.Input.Use(ctx, func(_ context.Context, _, value []byte) error { state = string(value); return nil }); err != nil {
		return out, providerError(ctx, err)
	}
	found, err := s.start.lookupProviderLoginCallback(ctx, state)
	if err != nil {
		return out, err
	}
	defer clear(found.Binding.Proof)
	if found.CompletedAt != nil || found.Binding.Metadata.Input.Link != nil {
		return out, sso.ErrForbidden
	}
	key := providerLoginProfileKey{organization: organization.ID(found.Row.OrganizationID), provider: sso.ProviderID(found.Row.ProviderID)}
	transport, available := s.profiles[key]
	if !available || transport.metadata.Issuer != found.Binding.Metadata.Input.Issuer {
		return out, sso.ErrForbidden
	}
	selection, err := s.selectOIDCCallback(key, parsed, request.ReceivedRedirectURI)
	if err != nil {
		return out, err
	}
	var assignedRoles *providerLoginRoleMapping
	if mapping, selected := s.roleMappings[key]; selected {
		if mapping.mappingVersion != found.Row.MappingVersion {
			return out, sso.ErrForbidden
		}
		assignedRoles = &mapping
	}
	var assignedJIT *providerLoginJITPolicy
	if execution, selected := s.jitPolicies[key]; selected {
		if execution.MappingVersion != found.Row.MappingVersion {
			return out, sso.ErrForbidden
		}
		assignedJIT = &execution
	}
	command, err := s.start.prepareProviderLoginCallbackCommand(ctx, found, request.ReceivedRedirectURI, request.Browser, request.Input)
	if err != nil {
		return out, err
	}
	flow, err := s.start.authenticateProviderLoginCallbackBrowser(ctx, found, request.Browser)
	if err != nil {
		return out, err
	}
	original, err := s.start.readProviderLoginCallbackOrigin(ctx, found, flow)
	if err != nil {
		return out, err
	}
	authority, err := s.start.observeProviderLoginCallbackAuthority(ctx, found, original)
	if err != nil {
		return out, err
	}
	grant, err := s.start.prepareProviderLoginCallbackGrant(ctx, found)
	if err != nil {
		return out, err
	}
	phase := &providerLoginCallbackPhase{
		providerLoginCallbackInvocation: providerLoginCallbackInvocation{service: s.start, found: found, original: original, authority: authority, flow: flow, browser: request.Browser, command: command},
		grant:                           grant, transport: transport, oidc: selection, input: request.Input, effect: s.effect, policy: s.policy, roleMapping: assignedRoles, jitPolicy: assignedJIT,
	}
	defer func() {
		if phase.refusal != nil {
			clear(phase.refusal.Terminal)
		}
		if phase.execution != nil {
			clear(phase.execution.terminal)
			clear(phase.execution.tokens.Ciphertext)
		}
	}()
	phase.issuer, err = session.NewSSOOIDCSessionIssuerWithCSRF(phase, s.issuer, s.csrfKey)
	if err != nil {
		return out, sso.ErrUnavailable
	}
	coordinator, err := s.callbackCoordinator(phase)
	if err != nil {
		return out, sso.ErrUnavailable
	}
	plan, err := phase.plan()
	if err != nil {
		return out, providerError(ctx, err)
	}
	plan, err = coordinator.PrepareFeaturePreparationPlan(command, plan)
	if err != nil {
		return out, providerError(ctx, err)
	}
	entered = found.Binding.Metadata.CallbackCommand
	result, err := coordinator.ExecutePreparedFeature(ctx, command, plan)
	out.Completion = result
	if err != nil {
		// An occupied mailbox, occupied subject or admission conflict must
		// not provide a separate browser-visible account-discovery signal.
		var conflict identity.ConflictError
		if phase.execution != nil && phase.execution.jit != nil && ctx.Err() == nil &&
			(errors.As(err, &conflict) || errors.Is(err, organization.ErrConflict)) {
			return out, sso.ErrForbidden
		}
		return out, providerError(ctx, err)
	}
	if result.Validate() != nil || result.Binding.CommandID != entered || result.Outcome != identity.CommitOutcomeCommitted {
		return out, sso.ErrUnavailable
	}
	if phase.execution == nil || phase.prepared == (session.PreparedIssuance{}) {
		return out, nil // Historical/prepared recovery may confirm commit without bearer custody.
	}
	// The restored command is the exact native coordinator invocation. Bind
	// disclosure to that instance, not the earlier pre-serialization command.
	bound, err := phase.issuer.BindSSOOIDC(phase.prepared, phase.execution.command)
	if err != nil {
		return out, providerError(ctx, err)
	}
	phase.acknowledged, phase.canDisclose = result, true
	issued, err := phase.issuer.Issue(ctx, bound)
	if err != nil {
		return out, providerError(ctx, err)
	}
	csrf, err := bound.CSRFToken()
	if err != nil || issued.Replayed || issued.Token == (session.Token{}) {
		return out, sso.ErrUnavailable
	}
	out.Issuance, out.CSRF, out.RedirectURI = issued, csrf, original.SuccessCallback
	return out, nil
}

func (s *ProviderLoginCompletionService) callbackCoordinator(phase *providerLoginCallbackPhase) (*kernel.Coordinator, error) {
	return providerLoginCallbackCoordinator(s.start, phase)
}

func providerLoginCallbackCoordinator(start *ProviderLoginService, phase *providerLoginCallbackPhase) (*kernel.Coordinator, error) {
	auditing, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, err
	}
	lifecycle, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, err
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{start.directory, auditing, lifecycle, phase, capabilitypg.NewParticipant()})
	if err != nil {
		return nil, err
	}
	phase.registry = registry
	return kernel.NewCoordinatorWithRequestKeys(start.router.pool, registry, start.config.Coordinator, start.config.RequestKeys)
}
