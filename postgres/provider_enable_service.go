package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"math"
	"reflect"
	"strconv"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	"github.com/faustbrian/go-sso"
)

// ProviderEnableAuthorization observes the exact fresh org:sso-write decision
// for enablement. The policy and its transaction-fenced epoch must describe
// the same authority. The callback accepts cancellation, supports concurrent
// calls and runs outside all native locks. It is not metadata-update consent.
type ProviderEnableAuthorization interface {
	ObserveProviderEnableAuthorization(context.Context, authorization.DecisionContext, uint64) (ProviderEnableAuthorizationEvidence, error)
}

// ProviderEnableAuthorizationEvidence has the same exact context, decision,
// native actor epoch and exclusive deadline requirements as a provider update.
// Enablement owns a separate policy opt-in; the value is not a bearer grant.
type ProviderEnableAuthorizationEvidence = ProviderUpdateAuthorizationEvidence

// WithProviderEnableAuthorization selects disabled static OIDC enablement on
// an organization-bound service. Install ProviderEnableMigrationSource first.
// The selected service does not start routes or change enforcement.
func (s *ProviderService) WithProviderEnableAuthorization(owner ProviderEnableAuthorization) (*ProviderService, error) {
	if s == nil || s.pool == nil || !providerID(s.updateOrganization) || owner == nil {
		return nil, sso.ErrInvalidInput
	}
	v := reflect.ValueOf(owner)
	if v.Kind() == reflect.Pointer && v.IsNil() {
		return nil, sso.ErrInvalidInput
	}
	bound := *s
	// The proof read and organization version fence must refer to the same
	// primary as Work, including when the base service borrows other readers.
	primary, err := organizationpg.NewRepository(s.pool, organizationpg.Config{MaximumDuration: s.config.MaximumDuration})
	if err != nil {
		return nil, sso.ErrInvalidInput
	}
	bound.config.Organizations = primary
	bound.enableAuthorization = owner
	return &bound, nil
}

func (s *ProviderService) admitEnable(ctx context.Context) (a providerAdmission, err error) {
	defer func() {
		if recover() != nil {
			a, err = providerAdmission{}, sso.ErrUnavailable
		}
	}()
	if s.enableAuthorization == nil {
		return a, sso.ErrForbidden
	}
	a, err = s.admit(ctx, s.updateOrganization, "org:sso-write")
	if err != nil {
		return a, err
	}
	bound, err := a.session.Session.Bindings()
	if err != nil {
		return providerAdmission{}, sso.ErrForbidden
	}
	lifetime, err := a.session.Session.Lifetime(a.verified)
	if err != nil || !lifetime.Fresh {
		return providerAdmission{}, sso.ErrForbidden
	}
	authority, err := bound.Authority.Bindings()
	if err != nil || authority.Authorization.Version == 0 {
		return providerAdmission{}, sso.ErrForbidden
	}
	dc := s.decision(bound.UserID, s.updateOrganization, "org:sso-write")
	dc.Request.Environment.Time = a.verified
	evidence, err := s.enableAuthorization.ObserveProviderEnableAuthorization(ctx, dc.Clone(), authority.Authorization.Version)
	if err != nil {
		return providerAdmission{}, providerError(ctx, err)
	}
	if !reflect.DeepEqual(evidence.Context, dc) || evidence.Decision.Outcome != authorization.Allow || evidence.Decision.Revision != dc.PolicyRevision || evidence.ActorAuthorizationVersion != authority.Authorization.Version || !a.verified.Before(evidence.ValidUntil) {
		return providerAdmission{}, sso.ErrForbidden
	}
	remember, err := bound.Remember.Bindings()
	if err != nil {
		return providerAdmission{}, sso.ErrForbidden
	}
	for _, deadline := range []time.Time{evidence.ValidUntil, bound.Authentication.Proof.IssuedAt.Add(remember.FreshFor)} {
		if deadline.Before(a.until) {
			a.until = deadline
		}
	}
	if !s.config.Clock.Now().Before(a.until) {
		return providerAdmission{}, sso.ErrForbidden
	}
	return a, nil
}

// ObserveProviderCredentialCheckpoint authenticates the current encrypted
// client-secret generation for a disabled provider, after fresh authorized
// administration. It returns no secret and cannot authorize a later write;
// ProviderEnable rechecks the exact existing custody under its own fence.
func (s *ProviderService) ObserveProviderCredentialCheckpoint(ctx context.Context, provider string, version uint64) (sso.CredentialCheckpoint, error) {
	if s == nil || ctx == nil || !providerID(provider) || version == 0 || version == math.MaxUint64 {
		return sso.CredentialCheckpoint{}, sso.ErrInvalidInput
	}
	ctx, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	a, err := s.admitEnable(ctx)
	if err != nil {
		return sso.CredentialCheckpoint{}, err
	}
	current, err := s.observeEnablePredecessor(ctx, provider, version)
	defer clear(current.configuration)
	if err != nil {
		return sso.CredentialCheckpoint{}, err
	}
	if !s.config.Clock.Now().Before(a.until) {
		return sso.CredentialCheckpoint{}, sso.ErrForbidden
	}
	return sso.NewCredentialCheckpoint(sso.CredentialCheckpointBinding{TenantID: s.authentication.TenantID, OrganizationID: organization.ID(s.updateOrganization), ProviderID: provider, ProviderVersion: version, Generation: current.credentialGeneration, ObservedAt: a.verified, ExpiresAt: a.until.UTC().Truncate(time.Microsecond)})
}

// ProviderEnable atomically enables the exact disabled provider and advances
// its version once. Only the selected static OIDC profile with a single
// configured domain is supported. Preserve the original key and checkpoints
// on retry; replay recovers historical metadata, never current route authority.
// This is the authenticated native bearer path; no cookie or HTTP route is
// installed. Cookie callers require a separate transport with origin and CSRF.
func (s *ProviderService) ProviderEnable(ctx context.Context, r sso.ProviderEnableRequest) (sso.ProviderEnableResult, error) {
	var out sso.ProviderEnableResult
	if s == nil || s.pool == nil || ctx == nil || !providerID(s.updateOrganization) || r.Validate() != nil {
		return out, sso.ErrInvalidInput
	}
	checkpoint, _ := r.CredentialCheckpoint.Bindings()
	proof := organization.DomainProof(r.DomainProofCheckpoint.Key)
	if checkpoint.TenantID != s.authentication.TenantID || string(checkpoint.OrganizationID) != s.updateOrganization {
		return out, sso.ErrForbidden
	}
	ctx, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	a, err := s.admitEnable(ctx)
	if err != nil {
		return out, err
	}
	selected := providerEnable{request: r, credential: checkpoint, proof: proof}
	frame, err := json.Marshal(struct {
		Credential sso.CredentialCheckpointBinding
		Proof      organization.DomainProof
	}{checkpoint, proof})
	if err != nil {
		return out, sso.ErrInvalidInput
	}
	digest := sha256.Sum256(frame)
	intent, err := identity.NewRequestIntent([]identity.FeatureField{
		{Name: "organization", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: s.updateOrganization}},
		{Name: "provider", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: r.ProviderID}},
		{Name: "expected-version", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: strconv.FormatUint(r.ExpectedVersion, 10)}},
		{Name: "readiness", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest[:]}},
		{Name: "policy-id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: s.config.PolicyID}},
	})
	if err != nil {
		return out, sso.ErrInvalidInput
	}
	p := &ProviderContributor{service: s, request: sso.ProviderRegisterOidcRequest{OrganizationID: s.updateOrganization}, admission: a, intent: intent, enable: &selected}
	defer func() { clear(p.configuration); clear(selected.predecessor.configuration) }()
	if err = s.composeProvider(p); err != nil {
		return out, err
	}
	bound, _ := a.session.Session.Bindings()
	op := p.operation()
	registration := kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: op}
	scope := kernel.RequestKeyScope{TenantID: s.authentication.TenantID, ActorID: identity.ActorID(bound.UserID), ActorKind: authorization.SubjectUser, Method: "POST", RouteID: op.OperationID}
	caller := s.kernelDecision(bound.UserID, "identity.request-admission", op.OperationID)
	caller.Request.Action = authorization.Action(op.OperationID)
	keyBinding, retained, err := p.coordinator.ResolvePreparedRequestKey(ctx, scope, r.IdempotencyKey, intent, caller, registration, p)
	defer clear(retained)
	if err != nil {
		if p.failure != nil {
			return out, p.failure
		}
		return out, providerError(ctx, err)
	}
	original, err := p.RestoreRequestKey(ctx, keyBinding, retained)
	if err != nil {
		return out, providerError(ctx, err)
	}
	if p.binding != original {
		query := s.kernelDecision(bound.UserID, "identity.user", string(bound.UserID))
		query.Request.Action = authorization.Action(op.OperationID)
		out.Completion, err = p.coordinator.RecoverPreparedFeatureCommand(ctx, providerRecovery(original), query, registration, p)
	} else {
		var plan kernel.CommandPlan
		plan, err = p.plan(false)
		if err == nil {
			out.Completion, err = p.coordinator.ExecutePreparedFeature(ctx, p.command, plan)
		}
	}
	if out.Completion.Outcome != identity.CommitOutcomeCommitted {
		return out, providerError(ctx, err)
	}
	if _, err = s.admitEnable(ctx); err != nil {
		// Disclosure denial does not undo the coordinator's acknowledged commit.
		return out, err
	}
	if out.Completion.Binding != original || out.Completion.Feature == nil || out.Completion.Feature.Operation != op || out.Completion.Feature.BeforeVersion != r.ExpectedVersion || out.Completion.Feature.AfterVersion != r.ExpectedVersion+1 {
		return sso.ProviderEnableResult{}, sso.ErrUnavailable
	}
	out.Provider, err = s.readEnableReceipt(ctx, original, proof.Domain, out.Completion.Feature.AfterVersion)
	return out, err
}
