package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	organization "github.com/faustbrian/go-organization"
	"github.com/faustbrian/go-sso"
)

// Every native invocation owns its own observations; neither a restored
// output nor a current route is allowed to renew the original evidence.
type providerLoginCallbackInvocation struct {
	service         *ProviderLoginService
	found           providerLoginCallbackLookup
	original        providerLoginStartInput
	authority       providerLoginCallbackAuthority
	flow            session.PreAuthTransaction
	browser         ProviderLoginBrowser
	command         identity.Command
	authenticatedAt time.Time
}

// This is trusted callback deployment configuration, not a request projection.
// It is separate from start's profile digest so opting in to completion does
// not invalidate previously authenticated start preparations.
type providerLoginCallbackTransport struct {
	metadata       sso.OIDCStaticMetadataSpec
	authentication oauth.ClientAuthentication
	algorithms     []string
	claims         []string
	keys           oauth.SigningKeySet
	client         *http.Client
}

func (p *providerLoginCallbackInvocation) riskScope() (risk.Context, risk.Subject) {
	row := p.found.Row
	// Before identity resolution, bound identifier velocity to the selected
	// tenant/organization/provider, never to a user or a claim from the reply.
	bucket := sha256.Sum256([]byte("sso-oidc-callback-provider\x00" + string(row.TenantID) + "\x00" + row.OrganizationID + "\x00" + row.ProviderID))
	return risk.Context{Tenant: string(row.TenantID), Operation: risk.Action(providerOIDCCallback), Attempt: string(p.found.Binding.Metadata.CallbackCommand)},
		risk.Subject{Network: p.browser.Network.String(), Device: p.browser.Device, IdentifierDigest: hex.EncodeToString(bucket[:])}
}

func (p *providerLoginCallbackInvocation) checkOriginal(now time.Time) error {
	if p == nil || p.service == nil || !validProviderLoginCallbackMaterialInput(p.found, p.original, p.authority, now) {
		return identity.ForbiddenError{}
	}
	remember, err := session.NewRememberPolicy(p.found.Binding.Metadata.Input.Remember)
	if err != nil {
		return identity.ForbiddenError{}
	}
	return p.service.requireProviderLoginBrowser(p.flow, now, p.browser, p.original.SuccessCallback, remember)
}

// admitPrimary is used only in pre-generation Work. In final Apply the
// session owner must lock its rows before organization/provider authority.
func (p *providerLoginCallbackInvocation) admitPrimary(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command) error {
	if p == nil || p.service == nil || ctx == nil || owner == nil || command == (identity.Command{}) || command != p.command {
		return identity.ForbiddenError{}
	}
	binding, feature, _, err := w.FeatureScope(owner)
	original, ok := p.command.Feature()
	if err != nil || !ok || binding != original.Binding || feature.Operation != providerOIDCCallbackOperation() ||
		!validProviderLoginCallbackDispositionScope(binding, p.found, p.authority.deadline) {
		return identity.ForbiddenError{}
	}
	s := p.service
	if err := w.RequireActiveDirectoryAuthority(ctx, owner, kernel.DirectoryAuthorityAdmission{
		Query: s.directoryQuery(), GlobalVersion: p.original.GlobalVersion, TenantVersion: p.original.TenantVersion,
	}); err != nil {
		return err
	}
	if err := sessionpg.RequirePreAuth(ctx, w, s.config.Session, p.flow); err != nil {
		return err
	}
	if err := s.router.organizations.RequireCredentialAuthority(ctx, w, owner, p.authority.organization); err != nil {
		return err
	}
	if err := requireProviderLoginCallbackDisposition(ctx, w, p.found, p.authority.deadline); err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if err := p.checkOriginal(now.UTC()); err != nil {
		return err
	}
	p.authenticatedAt = now.UTC()
	return nil
}

func (p *providerLoginCallbackInvocation) prepareRisk(ctx context.Context, command identity.Command) (risk.AuthenticationAdmission, error) {
	if p == nil || p.service == nil || ctx == nil || p.authenticatedAt.IsZero() || command == (identity.Command{}) || command != p.command {
		return risk.AuthenticationAdmission{}, identity.ForbiddenError{}
	}
	s := p.service
	if err := p.checkOriginal(s.router.config.Clock.Now().UTC()); err != nil {
		return risk.AuthenticationAdmission{}, err
	}
	scope, subject := p.riskScope()
	callback := p.found.Binding.Metadata.CallbackCommand
	result, err := s.config.Risk.Evaluation.Evaluate(ctx, risk.EvaluateRequest{Context: scope, Phase: risk.NonIssuing,
		Subject: subject, Attribution: &risk.DecisionAttribution{CommandID: callback, CorrelationID: callback,
			Actor: audit.ActorInput{Kind: audit.ActorAnonymous}, Subject: identity.SecurityAuthenticationAttempt, SubjectID: string(callback)}})
	if err != nil {
		return risk.AuthenticationAdmission{}, providerError(ctx, err)
	}
	return s.custody.Prepare(ctx, result, scope, subject)
}

type providerLoginCallbackExchange struct {
	oauth.ExchangeResult
	mapping         sso.AttributeMappingSpec
	providerEnabled bool
}

// Called by FeaturePreparationAdmission.Generate only, after acknowledgment of
// the original one-use reservation and generation marker; no Work is retained.
func (p *providerLoginCallbackInvocation) exchangeAcknowledged(ctx context.Context, input identity.OAuthCallbackInput, transport providerLoginCallbackTransport, admission risk.AuthenticationAdmission) (providerLoginCallbackExchange, error) {
	if p == nil || p.service == nil || p.authenticatedAt.IsZero() || ctx == nil {
		return providerLoginCallbackExchange{}, identity.ForbiddenError{}
	}
	s := p.service
	clock := s.router.config.Clock
	now := clock.Now().UTC()
	if err := p.checkOriginal(now); err != nil {
		return providerLoginCallbackExchange{}, err
	}
	if err := admission.CheckAt(ctx, now); err != nil {
		return providerLoginCallbackExchange{}, err
	}
	row := p.found.Row
	profile, ok := s.profiles[providerLoginProfileKey{organization: organization.ID(row.OrganizationID), provider: sso.ProviderID(row.ProviderID)}]
	if !ok {
		return providerLoginCallbackExchange{}, identity.ForbiddenError{}
	}
	material, err := s.readProviderLoginCallbackMaterial(ctx, p.found, p.original, p.authority)
	if err != nil {
		return providerLoginCallbackExchange{}, err
	}
	defer clear(material.credential)
	defer clear(material.credentialContext)
	defer clear(material.verifier)
	now = clock.Now().UTC()
	if err := p.checkOriginal(now); err != nil {
		return providerLoginCallbackExchange{}, err
	}
	if err := admission.CheckAt(ctx, now); err != nil {
		return providerLoginCallbackExchange{}, err
	}
	result, err := s.payload.exchangeProviderLoginOIDC(ctx, providerLoginOIDCExchangeInput{
		original: p.found.Binding.Metadata, observedAt: p.found.ObservedAt, deadline: p.authority.deadline,
		profile: profile, metadata: material.metadata, pinnedMetadata: transport.metadata,
		credential: material.credential, credentialContext: material.credentialContext, credentialVersion: material.credentialVersion, verifier: material.verifier,
		callback: input, clientAuthentication: transport.authentication, algorithms: transport.algorithms,
		claimNames: transport.claims, keys: transport.keys, client: transport.client, clock: clock, beforePost: admission.CheckAt,
	})
	return providerLoginCallbackExchange{ExchangeResult: result, mapping: material.mapping, providerEnabled: material.enabled}, err
}
