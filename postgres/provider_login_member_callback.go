package postgres

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/oauth"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	organization "github.com/faustbrian/go-organization"
	"github.com/faustbrian/go-sso"
)

// ProviderLinkCallbackRequest carries the original local cookie and the query
// callback from the trusted transport. Same-origin CSRF is required at LinkStart,
// not sent through the external IdP. Origin, network, device and the received
// redirect URI are supplied by the transport rather than provider parameters.
type ProviderLinkCallbackRequest struct {
	Session             authentication.BearerCredential
	Input               identity.OAuthCallbackInput
	ReceivedRedirectURI string
	Origin              string
	Network             netip.Addr
	Device              string
}

// Format redacts the state, code and local bearer.
func (ProviderLinkCallbackRequest) Format(s fmt.State, _ rune) {
	fmt.Fprint(s, "sso.postgres.ProviderLinkCallbackRequest(redacted)")
}

// MarshalJSON rejects export of private callback inputs.
func (ProviderLinkCallbackRequest) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}

// MarshalText rejects export of private callback inputs.
func (ProviderLinkCallbackRequest) MarshalText() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}

// ProviderLinkCallbackResult acknowledges only the link and selected redirect.
// A successful link advances credential authority; it never issues a session.
type ProviderLinkCallbackResult struct {
	Completion  identity.CommandResult
	RedirectURI string
}

// Format avoids disclosing correlated command and redirect information.
func (ProviderLinkCallbackResult) Format(s fmt.State, _ rune) {
	fmt.Fprint(s, "sso.postgres.ProviderLinkCallbackResult(redacted)")
}

// MarshalJSON rejects serialization of the native result itself. Transport
// owners project the known outcome and configured redirect explicitly.
func (ProviderLinkCallbackResult) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}

// MarshalText rejects serialization of the native result itself.
func (ProviderLinkCallbackResult) MarshalText() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}

// LinkCallback finishes the exact transaction created by LinkStart using the
// original browser cookie. The one-use reservation, account link, encrypted
// token custody, audit, and lifecycle event share the native coordinator.
func (s *ProviderLoginCompletionService) LinkCallback(ctx context.Context, request ProviderLinkCallbackRequest) (out ProviderLinkCallbackResult, err error) {
	if s == nil || s.start == nil || s.start.link == nil || ctx == nil || request.ReceivedRedirectURI == "" {
		return out, sso.ErrInvalidInput
	}
	ctx, cancel := context.WithTimeout(ctx, s.start.config.Coordinator.MaximumDuration)
	defer cancel()
	var entered identity.CommandID
	defer func() {
		if recover() != nil {
			out, err = ProviderLinkCallbackResult{}, sso.ErrUnavailable
			if entered != "" {
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
	key := providerLoginProfileKey{organization: organization.ID(found.Row.OrganizationID), provider: sso.ProviderID(found.Row.ProviderID)}
	transport, supported := s.profiles[key]
	if found.CompletedAt != nil || !supported || transport.metadata.Issuer != found.Binding.Metadata.Input.Issuer {
		return out, sso.ErrForbidden
	}
	invocation, err := s.start.memberCallbackInvocation(ctx, found, request)
	if err != nil {
		return out, err
	}
	grant, err := s.start.prepareProviderLoginCallbackGrant(ctx, found)
	if err != nil {
		return out, err
	}
	p := &providerLoginCallbackPhase{providerLoginCallbackInvocation: invocation, grant: grant,
		transport: transport, input: request.Input, policy: s.policy}
	defer func() {
		if p.refusal != nil {
			clear(p.refusal.Terminal)
		}
		if p.execution != nil {
			clear(p.execution.terminal)
			clear(p.execution.tokens.Ciphertext)
		}
	}()
	coordinator, err := s.callbackCoordinator(p)
	if err != nil {
		return out, sso.ErrUnavailable
	}
	plan, err := p.plan()
	if err != nil {
		return out, providerError(ctx, err)
	}
	plan, err = coordinator.PrepareFeaturePreparationPlan(p.command, plan)
	if err != nil {
		return out, providerError(ctx, err)
	}
	entered = found.Binding.Metadata.CallbackCommand
	result, err := coordinator.ExecutePreparedFeature(ctx, p.command, plan)
	out.Completion = result
	if err != nil {
		var conflict identity.ConflictError
		if ctx.Err() == nil && errors.As(err, &conflict) {
			return out, sso.ErrForbidden
		}
		return out, providerError(ctx, err)
	}
	if result.Validate() != nil || result.Binding.CommandID != entered || result.Outcome != identity.CommitOutcomeCommitted {
		return out, sso.ErrUnavailable
	}
	out.RedirectURI = invocation.original.SuccessCallback
	return out, nil
}

type providerLoginCallbackMember struct {
	cookie     authentication.BearerCredential
	original   session.Session
	admission  session.GetResult
	directory  kernel.DirectoryAuthorityAdmission
	credential kernel.CredentialAdmission
	policy     kernel.UserAuthorizationAdmission
	membership organization.CredentialAuthorityObservation
	factor     uint64
}

func (s *ProviderLoginService) memberCallbackInvocation(ctx context.Context, found providerLoginCallbackLookup, req ProviderLinkCallbackRequest) (providerLoginCallbackInvocation, error) {
	metadata := found.Binding.Metadata
	input, link := metadata.Input, metadata.Input.Link
	got, frozen, err := s.authenticateProviderLoginMemberCallbackCookie(ctx, found, req)
	if err != nil {
		return providerLoginCallbackInvocation{}, err
	}
	browser := ProviderLoginBrowser{Origin: req.Origin, Network: req.Network, Device: req.Device}
	startPhase := &providerLoginPhase{service: s, browser: browser, member: &providerLoginMemberAdmission{user: input.Command.UserID}}
	original, err := s.readProviderLoginCallbackStart(ctx, found, startPhase)
	if err != nil {
		return providerLoginCallbackInvocation{}, err
	}
	authority, err := s.observeProviderLoginCallbackAuthority(ctx, found, original)
	if err != nil {
		return providerLoginCallbackInvocation{}, err
	}
	membership, err := s.checkRetainedMember(ctx, original.Proof.OrganizationID, input.Command.UserID, link)
	if err != nil {
		return providerLoginCallbackInvocation{}, providerError(ctx, err)
	}
	authority.deadline = earliestProviderLoginCallbackTime(authority.deadline, got.ValidUntil(), membership.ValidUntil).UTC().Truncate(time.Microsecond)
	operation := kernel.SSOOIDCExplicitLinkCallbackOperation()
	binding := input.Command
	binding.CommandID, binding.CorrelationID, binding.RecordID = metadata.CallbackCommand, string(metadata.CallbackCommand), string(found.Row.StartCommandID)
	binding.OperationID, binding.SchemaID, binding.SchemaVersion = operation.OperationID, operation.SchemaID, operation.SchemaVersion
	if !validProviderLoginCallbackDispositionScope(binding, found, authority.deadline) || membership.Version != authority.organization.Version {
		return providerLoginCallbackInvocation{}, sso.ErrForbidden
	}
	directory, actor, policy, err := sessionpg.OriginalSessionAdmission(s.link.Profile, frozen, binding)
	if err != nil || directory.Query != s.directoryQuery() || directory.GlobalVersion != original.GlobalVersion || directory.TenantVersion != original.TenantVersion {
		return providerLoginCallbackInvocation{}, sso.ErrForbidden
	}
	intent, err := s.providerLoginCallbackIntent(ctx, found, req.ReceivedRedirectURI, browser, req.Input)
	if err != nil {
		return providerLoginCallbackInvocation{}, err
	}
	command, err := identity.NewFeatureSessionCommand(identity.FeatureCommandSpec{Operation: operation, Binding: binding, Fields: intent}, req.Session)
	if err != nil {
		return providerLoginCallbackInvocation{}, providerError(ctx, err)
	}
	p := providerLoginCallbackInvocation{service: s, found: found, original: original, authority: authority, browser: browser, command: command,
		member: &providerLoginCallbackMember{cookie: req.Session, original: frozen, admission: got, directory: directory,
			credential: actor, policy: policy, membership: membership, factor: link.FactorVersion}}
	if err := p.checkOriginal(s.router.config.Clock.Now().UTC()); err != nil {
		return providerLoginCallbackInvocation{}, providerError(ctx, err)
	}
	return p, nil
}

// Quota attribution and protected completion must authenticate the same original
// fresh local cookie. This read grants neither link authority nor a reservation;
// memberCallbackInvocation separately observes and fences every protected owner.
func (s *ProviderLoginService) authenticateProviderLoginMemberCallbackCookie(ctx context.Context, found providerLoginCallbackLookup, req ProviderLinkCallbackRequest) (session.GetResult, session.Session, error) {
	input, link := found.Binding.Metadata.Input, found.Binding.Metadata.Input.Link
	if s == nil || s.link == nil || link == nil || found.CompletedAt != nil || req.ReceivedRedirectURI != input.RedirectURI ||
		req.Origin != s.config.Origin || req.Origin != input.BrowserOrigin || !req.Network.IsValid() || req.Network.Is4In6() ||
		req.Network.Zone() != "" || !providerID(req.Device) {
		return session.GetResult{}, session.Session{}, sso.ErrForbidden
	}
	token, err := session.ParseToken(req.Session.Token())
	if err != nil {
		return session.GetResult{}, session.Session{}, sso.ErrForbidden
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		return session.GetResult{}, session.Session{}, sso.ErrForbidden
	}
	got, err := s.link.Sessions.Get(ctx, session.GetRequest{TenantID: input.Command.TenantID, Credential: credential})
	if err != nil {
		return session.GetResult{}, session.Session{}, providerError(ctx, err)
	}
	now := s.router.config.Clock.Now().UTC()
	frozen, err := sessionpg.OriginalSessionFromFields(input.Command.TenantID, input.Command.UserID, link.OriginalSession)
	if err != nil || got.ValidateAt(now) != nil || !s.link.possesses(req.Session, frozen, now) {
		return session.GetResult{}, session.Session{}, sso.ErrForbidden
	}
	fields, err := sessionpg.OriginalSessionFields(got.Session)
	if err != nil || !reflect.DeepEqual(fields, link.OriginalSession) {
		return session.GetResult{}, session.Session{}, sso.ErrForbidden
	}
	return got, frozen, nil
}

func (p *providerLoginCallbackInvocation) checkOriginalMember(now time.Time) error {
	m := p.member
	if m == nil || p.service.link == nil || m.admission.ValidateAt(now) != nil || !p.service.link.possesses(m.cookie, m.original, now) ||
		m.membership.Validate(organization.CredentialAuthorityQuery{TenantID: p.found.Row.TenantID,
			OrganizationID: p.original.Proof.OrganizationID, ActorID: p.original.Command.UserID}, now) != nil {
		return identity.ForbiddenError{}
	}
	return nil
}

// Check the actual native authorities under locks. Once Apply advances the
// credential epoch, the kernel checks that exact successor, not the pre-link
// credential epoch. No original session or authority evidence is renewed.
func (p *providerLoginCallbackInvocation) requireMemberCallbackAuthority(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, predecessor bool) error {
	m := p.member
	if err := w.RequireActiveDirectoryAuthority(ctx, owner, m.directory); err != nil {
		return err
	}
	if predecessor {
		if _, err := w.RequireActiveCredential(ctx, owner, m.credential); err != nil {
			return err
		}
	}
	if err := w.RequireActiveUserAuthorization(ctx, owner, m.policy); err != nil {
		return err
	}
	if err := sessionpg.RequireSession(ctx, w, p.service.config.Session, m.original); err != nil {
		return err
	}
	if _, err := mfapg.RequireSSOOIDCExplicitLinkFactors(ctx, w, owner, command, m.factor); err != nil {
		return err
	}
	if err := p.service.router.organizations.RequireCredentialAuthority(ctx, w, owner, m.membership); err != nil {
		return err
	}
	return requireProviderLoginCallbackDispositionAt(ctx, w, p.found, p.authority.deadline, false)
}

func (p *providerLoginCallbackPhase) generateMemberAccepted(ctx context.Context, generation uint64, admission risk.AuthenticationAdmission) ([]byte, error) {
	aad, err := p.outputContext(generation)
	if err != nil {
		return nil, err
	}
	result, err := p.exchangeAcknowledged(ctx, p.input, p.transport, admission)
	defer result.Tokens.Destroy()
	if err != nil {
		var disposition *oauth.Error
		if ctx.Err() == nil && errors.As(err, &disposition) && disposition.Kind() == oauth.Refused {
			return p.sealProviderLoginCallbackRefusal(ctx, generation)
		}
		return nil, err
	}
	now := p.service.router.config.Clock.Now().UTC()
	until := earlierLoginTime(p.authority.deadline, result.Identity.EvidenceExpiresAt()).Truncate(time.Microsecond)
	if err := p.checkOriginal(now); err != nil {
		return nil, err
	}
	if err := admission.CheckAt(ctx, now); err != nil {
		return nil, err
	}
	issuer, subject := result.Identity.Issuer(), result.Identity.Subject()
	if !result.providerEnabled || !now.Before(until) || issuer != p.original.Issuer || subject == "" {
		return p.sealProviderLoginCallbackRefusal(ctx, generation)
	}
	provider, err := SSOOIDCAccountProviderNamespace(p.original.Proof.OrganizationID, p.original.ProviderID)
	if err != nil {
		return nil, err
	}
	binding, _ := p.command.Feature()
	account := identity.Account{ID: identity.AccountID(binding.Binding.CommandID), TenantID: binding.Binding.TenantID,
		UserID: binding.Binding.UserID, Provider: provider, Issuer: issuer, Subject: subject, Version: 1}
	state, err := p.service.directory.GetAccountLinkState(ctx, identity.AccountLinkQuery{Account: account, Mode: identity.AccountLinkExplicit})
	if err != nil {
		return nil, err
	}
	if state.RecordVersion != 0 || state.SubjectOwner != nil || state.SocialLinkVersion != 1 || state.CredentialVersion != p.member.credential.CredentialAuthorityVersion {
		return p.sealProviderLoginCallbackRefusal(ctx, generation)
	}
	method := identity.LoginMethod{Credential: identity.CredentialRef{ID: identity.CredentialID(account.ID), TenantID: account.TenantID,
		UserID: account.UserID, Kind: identity.CredentialProvider, Owner: "sso", Version: 1}, AccountID: account.ID, Usable: true}
	change := identity.AccountLinkChange{Mode: identity.AccountLinkExplicit, Account: account, Method: &method,
		ExpectedUserVersion: state.Access.User.Version, ExpectedSocialLinkVersion: state.SocialLinkVersion, ExpectedCredentialVersion: state.CredentialVersion}
	intent := kernel.SSOOIDCExplicitLinkIntent{Change: change, ActorCredential: p.member.credential, ValidUntil: until}
	field, err := kernel.SSOOIDCExplicitLinkField(intent)
	if err != nil {
		return nil, err
	}
	fields := []identity.FeatureField{field}
	command, err := p.memberCallbackCommand(fields)
	if err != nil {
		return nil, err
	}
	tokens, err := p.service.prepareProviderLoginAccountTokens(ctx, p.found, command, generation, result.Tokens, account, state.SocialLinkVersion+1)
	if err != nil {
		return nil, err
	}
	defer clear(tokens.Ciphertext)
	terminal, err := p.service.payload.sealProviderLoginCallbackTerminal(ctx, p.found)
	if err != nil {
		return nil, err
	}
	defer clear(terminal)
	plain, err := providerLoginPayloadEncode(providerLoginCallbackOutput{Schema: 1, Fields: fields, Risk: providerLoginStoredAdmission(admission.Prepared()),
		ObservedAt: p.found.ObservedAt, ValidUntil: until, Terminal: terminal, Tokens: tokens, Link: &change})
	defer clear(plain)
	if err != nil || len(plain) > providerLoginCallbackPlainLimit {
		return nil, identity.UnavailableError{}
	}
	return p.service.payload.seal(ctx, aad, plain, providerLoginCallbackCipherLimit)
}

func (p *providerLoginCallbackPhase) memberCallbackCommand(fields []identity.FeatureField) (identity.Command, error) {
	original, ok := p.command.Feature()
	if !ok || len(original.Fields) != 1 || original.Operation != kernel.SSOOIDCExplicitLinkCallbackOperation() {
		return identity.Command{}, identity.ForbiddenError{}
	}
	original.Fields = append(original.Fields, fields...)
	return identity.NewFeatureSessionCommand(original, p.member.cookie)
}

func (p *providerLoginCallbackPhase) restoreMemberAccepted(ctx context.Context, generation uint64, digest [32]byte, saved providerLoginCallbackOutput) error {
	if saved.Link == nil || saved.JIT != nil || saved.RoleUpdate != nil || saved.Link.Account != saved.Tokens.Account ||
		saved.Tokens.SocialLinkVersion != 2 || !equalProviderLoginPayloadInput(saved.Tokens.Input, p.found.Binding.Metadata.Input) {
		return identity.ForbiddenError{}
	}
	original, _ := p.command.Feature()
	account := saved.Link.Account
	provider, err := SSOOIDCAccountProviderNamespace(p.original.Proof.OrganizationID, p.original.ProviderID)
	if err != nil || account.ID != identity.AccountID(original.Binding.CommandID) || account.UserID != original.Binding.UserID ||
		account.TenantID != original.Binding.TenantID || account.Provider != provider || account.Issuer != p.original.Issuer ||
		saved.Link.Method == nil || saved.Link.Method.Credential.ID != identity.CredentialID(account.ID) || saved.Tokens.Callback != original.Binding {
		return identity.ForbiddenError{}
	}
	intent := kernel.SSOOIDCExplicitLinkIntent{Change: *saved.Link, ActorCredential: p.member.credential, ValidUntil: saved.ValidUntil}
	field, err := kernel.SSOOIDCExplicitLinkField(intent)
	if err != nil || !reflect.DeepEqual([]identity.FeatureField{field}, saved.Fields) {
		return identity.ForbiddenError{}
	}
	command, err := p.memberCallbackCommand(saved.Fields)
	if err != nil {
		return err
	}
	terminal, err := p.service.payload.openProviderLoginCallbackTerminal(ctx, p.found.Row, saved.Terminal)
	if err != nil || !equalProviderLoginBindingMetadata(terminal.Metadata, p.found.Binding.Metadata) {
		return identity.ForbiddenError{}
	}
	if err := p.service.validateProviderLoginTokens(ctx, saved.Tokens); err != nil {
		return err
	}
	scope, subject := p.riskScope()
	admission, err := p.service.custody.Restore(ctx, risk.PreparedAuthenticationAdmission(saved.Risk), scope, subject)
	if err != nil {
		return err
	}
	p.execution = &providerLoginCallbackExecution{command: command, admission: admission, tokens: saved.Tokens, terminal: saved.Terminal,
		generation: generation, digest: digest, validUntil: earlierLoginTime(saved.ValidUntil, p.authority.deadline), link: &intent}
	return nil
}

func (p *providerLoginCallbackPhase) applyMemberCallback(ctx context.Context, work kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	if p.execution.link == nil {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	if err := p.requireMemberCallbackAuthority(ctx, work, p, command, true); err != nil {
		return identity.FeatureReceipt{}, err
	}
	linked, err := p.service.directory.ApplySSOOIDCExplicitLink(ctx, work, p, command, *p.execution.link)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.service.persistProviderLoginAccountTokens(ctx, work, p, command, p.execution.tokens, p.execution.digest, &linked); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.service.completeProviderLoginCallback(ctx, work, p, command, p.found, p.execution.validUntil, p.execution.terminal); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: p.operation(), BeforeVersion: 1, AfterVersion: 2}, nil
}
