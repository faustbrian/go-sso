package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strconv"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	"github.com/faustbrian/go-sso"
)

// ProviderDisableAuthorization observes fresh org:sso-write authority for
// disablement. Its epoch must describe the same authority fenced by native
// Work. The callback must support concurrent, cancellable calls and runs
// outside native locks. Enable or metadata-update approval is not sufficient.
type ProviderDisableAuthorization interface {
	ObserveProviderDisableAuthorization(context.Context, authorization.DecisionContext, uint64) (ProviderDisableAuthorizationEvidence, error)
}

// ProviderDisableAuthorizationEvidence binds an exact policy decision, current
// actor epoch and exclusive deadline. It grants no bearer authority.
type ProviderDisableAuthorizationEvidence = ProviderUpdateAuthorizationEvidence

// WithProviderDisableAuthorization opts an organization-bound service into
// native disablement. OAuth 2.0 also requires WithOAuthRegistration.
// The original service is unchanged. Install
// the login transaction and request-key preparation migrations first.
func (s *ProviderService) WithProviderDisableAuthorization(owner ProviderDisableAuthorization) (*ProviderService, error) {
	if s == nil || s.pool == nil || !providerID(s.updateOrganization) || owner == nil {
		return nil, sso.ErrInvalidInput
	}
	v := reflect.ValueOf(owner)
	if v.Kind() == reflect.Pointer && v.IsNil() {
		return nil, sso.ErrInvalidInput
	}
	primary, err := organizationpg.NewRepository(s.pool, organizationpg.Config{MaximumDuration: s.config.MaximumDuration})
	if err != nil {
		return nil, sso.ErrInvalidInput
	}
	bound := *s
	bound.config.Organizations = primary
	bound.disableAuthorization = owner
	return &bound, nil
}

func (s *ProviderService) admitDisable(ctx context.Context) (providerAdmission, error) {
	if s.disableAuthorization == nil {
		return providerAdmission{}, sso.ErrForbidden
	}
	return s.admitFreshProviderWrite(ctx, s.disableAuthorization.ObserveProviderDisableAuthorization)
}

func (s *ProviderService) disableRequestKeys() kernel.RequestKeyConfig {
	keys := s.config.RequestKeys
	// The kernel forbids sharing a namespace between keyed and canonical POST
	// correlation. Derive a bounded, stable subnamespace from trusted config.
	namespace := sha256.Sum256([]byte(keys.Namespace))
	keys.Namespace = "sso-provider-disable." + hex.EncodeToString(namespace[:])
	return keys
}

// ProviderDisable disables one enabled static-OIDC provider version and
// records its predecessor's drain or revoke selection and bounded active count
// atomically. It preserves the organization's domain proof and the installed
// credential but prevents new sign-in starts. It does not complete callbacks,
// delete the provider, or claim transaction cleanup. Matching retries recover
// the original receipt; conflicting intent is not another disable command.
func (s *ProviderService) ProviderDisable(ctx context.Context, r sso.ProviderDisableRequest) (sso.ProviderDisableResult, error) {
	return s.providerDisable(ctx, r, "", providerProtocolOIDC)
}

// ProviderDisableOAuth2 disables one exact enabled OAuth 2.0 provider and
// atomically records the selected predecessor disposition. It retains the
// installed credentials and domain proof. Retry the same request to recover an
// unknown outcome; no callback or external provider action is performed.
func (s *ProviderService) ProviderDisableOAuth2(ctx context.Context, r sso.ProviderDisableRequest) (sso.ProviderDisableResult, error) {
	return s.providerDisable(ctx, r, "", providerProtocolOAuth2)
}

// ProviderDisableSAML disables one exact SAML provider version and records
// the original drain/revoke choice. Current org:sso-write authorization is
// mandatory, but disabling does not require a usable signer or IdP.
func (s *ProviderService) ProviderDisableSAML(ctx context.Context, r sso.ProviderDisableRequest) (sso.ProviderDisableResult, error) {
	return s.providerDisable(ctx, r, "", providerProtocolSAML)
}

// RetryProviderDisable starts or recovers a fresh exact attempt after a
// confirmed NotCommitted result for the same request and actor. The failed
// command ID comes from that result; it is not an idempotency key or proof.
// The coordinator must independently confirm the prior failure and original
// request. Unknown outcomes must be reconciled with the original call first.
func (s *ProviderService) RetryProviderDisable(ctx context.Context, r sso.ProviderDisableRequest, failed identity.CommandID) (sso.ProviderDisableResult, error) {
	if _, err := identity.ParseCommandID(string(failed)); err != nil {
		return sso.ProviderDisableResult{}, sso.ErrInvalidInput
	}
	return s.providerDisable(ctx, r, failed, providerProtocolOIDC)
}

// RetryProviderDisableOAuth2 admits an exact OAuth 2.0 request only after
// the coordinator confirms its original same-protocol attempt did not
// commit. Reconcile unknown outcomes through ProviderDisableOAuth2 first.
func (s *ProviderService) RetryProviderDisableOAuth2(ctx context.Context, r sso.ProviderDisableRequest, failed identity.CommandID) (sso.ProviderDisableResult, error) {
	if _, err := identity.ParseCommandID(string(failed)); err != nil {
		return sso.ProviderDisableResult{}, sso.ErrInvalidInput
	}
	return s.providerDisable(ctx, r, failed, providerProtocolOAuth2)
}

// RetryProviderDisableSAML starts or recovers the same SAML disable intent
// after an authoritative NotCommitted result. Reconcile unknown outcomes
// through ProviderDisableSAML before requesting any new attempt.
func (s *ProviderService) RetryProviderDisableSAML(ctx context.Context, r sso.ProviderDisableRequest, failed identity.CommandID) (sso.ProviderDisableResult, error) {
	if _, err := identity.ParseCommandID(string(failed)); err != nil {
		return sso.ProviderDisableResult{}, sso.ErrInvalidInput
	}
	return s.providerDisable(ctx, r, failed, providerProtocolSAML)
}

func (s *ProviderService) providerDisable(ctx context.Context, r sso.ProviderDisableRequest, failed identity.CommandID, protocol string) (sso.ProviderDisableResult, error) {
	var out sso.ProviderDisableResult
	if s == nil || s.pool == nil || ctx == nil || !providerID(s.updateOrganization) || r.Validate() != nil {
		return out, sso.ErrInvalidInput
	}
	if protocol == providerProtocolOAuth2 && !s.oauthRegistration {
		return out, sso.ErrForbidden
	}
	ctx, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	admission, err := s.admitDisable(ctx)
	if err != nil {
		return out, err
	}
	selection, _ := r.ActiveTransactionDisposition.Bindings()
	version := strconv.FormatUint(selection.ProviderVersion, 10)
	selectorFields := []string{s.updateOrganization, r.ProviderID, version, string(failed)}
	if protocol != providerProtocolOIDC {
		// Keep historical OIDC selectors byte-identical and prevent either
		// protocol from recovering a canonical request owned by the other.
		selectorFields = append(selectorFields, protocol)
	}
	selectorFrame, err := json.Marshal(selectorFields)
	if err != nil {
		return out, sso.ErrInvalidInput
	}
	selector, err := kernel.NewCanonicalRequestKey(selectorFrame)
	if err != nil {
		return out, providerError(ctx, err)
	}
	reason := sha256.Sum256([]byte(r.Reason))
	intent, err := identity.NewRequestIntent([]identity.FeatureField{
		{Name: "organization", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: s.updateOrganization}},
		{Name: "provider", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: r.ProviderID}},
		{Name: "expected-version", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: version}},
		{Name: "disposition", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(selection.Mode)}},
		{Name: "reason-digest", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: reason[:]}},
		{Name: "policy-id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: s.config.PolicyID}},
	})
	if err != nil {
		return out, sso.ErrInvalidInput
	}
	p := &ProviderContributor{
		service: s, request: providerCommandInput{OrganizationID: s.updateOrganization, protocol: protocol},
		admission: admission, intent: intent, disable: &providerDisable{selection: selection, reasonDigest: reason},
	}
	defer func() { clear(p.configuration); clear(p.disable.predecessorEnvelope) }()
	if err = s.composeProvider(p); err != nil {
		return out, err
	}
	bound, _ := admission.session.Session.Bindings()
	op := p.operation()
	registration := kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: op}
	query := s.kernelDecision(bound.UserID, "identity.user", string(bound.UserID))
	query.Request.Action = authorization.Action(op.OperationID)
	if failed != "" {
		prior := identity.RecoveryQuery{CommandID: failed, TenantID: bound.TenantID, UserID: bound.UserID, ActorID: identity.ActorID(bound.UserID), ActorKind: authorization.SubjectUser, OperationID: op.OperationID, RecordID: r.ProviderID}
		if err = p.requireFailedDisable(ctx, prior, query, registration); err != nil {
			return out, err
		}
	}
	scope := kernel.RequestKeyScope{TenantID: bound.TenantID, ActorID: identity.ActorID(bound.UserID), ActorKind: authorization.SubjectUser, Method: "POST", RouteID: op.OperationID}
	caller := s.kernelDecision(bound.UserID, "identity.request-admission", op.OperationID)
	caller.Request.Action = authorization.Action(op.OperationID)
	keyBinding, retained, err := p.coordinator.ResolvePreparedCanonicalRequest(ctx, scope, selector, nil, intent, caller, registration, p)
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
		out.Completion, err = p.coordinator.RecoverPreparedFeatureCommand(ctx, providerRecovery(original), query, registration, p)
	} else {
		var plan kernel.CommandPlan
		plan, err = p.plan(false)
		if err == nil {
			out.Completion, err = p.coordinator.ExecutePreparedFeature(ctx, p.command, plan)
		}
	}
	if err != nil || out.Completion.Outcome != identity.CommitOutcomeCommitted {
		return out, providerError(ctx, err)
	}
	if _, err = s.admitDisable(ctx); err != nil {
		// A disclosure denial cannot undo an acknowledged coordinator commit.
		return out, err
	}
	receipt := out.Completion.Feature
	if out.Completion.Binding != original || receipt == nil || receipt.Operation != op || receipt.BeforeVersion != p.beforeVersion() || receipt.AfterVersion != p.afterVersion() {
		return out, sso.ErrUnavailable
	}
	out.ActiveTransactionCount, err = p.readDisableReceipt(ctx, original)
	if err != nil {
		return out, err
	}
	out.Disabled = true
	return out, nil
}

func (p *ProviderContributor) requireFailedDisable(ctx context.Context, prior identity.RecoveryQuery, caller authorization.DecisionContext, registration kernel.FeatureRegistration) error {
	input, wire, err := p.coordinator.QueryRequestPreparation(ctx, prior, caller, registration, p)
	defer clear(wire)
	if err != nil {
		return providerError(ctx, err)
	}
	original, err := p.RestoreRequestKey(ctx, input, wire)
	if err != nil {
		return providerError(ctx, err)
	}
	if providerRecovery(original) != prior {
		return sso.ErrForbidden
	}
	state, err := p.coordinator.QueryCommand(ctx, prior, caller)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if state.Binding == original && state.Feature != nil && *state.Feature == registration.Operation && state.Outcome == identity.CommitOutcomeNotCommitted {
		// A terminal aborted record can also carry the original safe failure.
		// It cannot change after this primary read; the new attempt still has to
		// pass live admission, the predecessor CAS and its own command custody.
		return nil
	}
	if err != nil {
		return providerError(ctx, err)
	}
	return sso.ErrConflict
}
