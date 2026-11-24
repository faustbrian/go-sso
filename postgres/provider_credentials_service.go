package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strconv"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-sso"
)

// ProviderCredentialsAuthorization is the deployment-selected credentials-only
// policy owner. It evaluates the exact primary-time context and reports the
// earliest absolute policy decision deadline. Invalidating policy changes before
// that deadline must advance the existing native actor authorization epoch.
// The observed epoch is not authority to echo the supplied expected epoch.
// Calls run outside Work, honor bounded cancellation and support concurrency.
type ProviderCredentialsAuthorization interface {
	ObserveProviderCredentialsAuthorization(context.Context, authorization.DecisionContext, uint64) (ProviderCredentialsAuthorizationEvidence, error)
}

// ProviderCredentialsAuthorizationEvidence is one detached exact observation,
// not bearer permission. Context, revision, actor epoch and exclusive deadline
// must all match current native admission. No mutable aliases may be retained.
type ProviderCredentialsAuthorizationEvidence struct {
	Context                   authorization.DecisionContext
	Decision                  authorization.Decision
	ActorAuthorizationVersion uint64
	ValidUntil                time.Time
}

// ProviderCredentialsConfig selects an immutable trusted ingress profile and a
// distinct credentials policy owner. IngressKeyID is configured by deployment,
// never selected by a request. MaximumReferenceLifetime bounds the originally
// sealed lifetime without renewal. Envelope service and clock come exclusively
// from the existing native ProviderService configuration.
type ProviderCredentialsConfig struct {
	Authorization            ProviderCredentialsAuthorization
	IngressKeyID             string
	MaximumReferenceLifetime time.Duration
}

// ProviderCredentialsService initializes or replaces a disabled static
// provider's credential. OAuth 2.0 requires WithOAuthRegistration on the
// organization-bound ProviderService. SAML IdP pins require WithSAMLRegistration;
// SP signing material requires WithSAMLSigningCredentialValidator. Configure the
// base service first and install ProviderCredentialsMigrationSource. No constructor performs
// I/O, grants current authorization or bypasses canonical native risk policy.
// Concurrent calls use independent native contributors; the caller owns all
// existing pool/key/policy resources for the complete recovery lifetime.
type ProviderCredentialsService struct {
	base    *ProviderService
	profile ProviderCredentialsConfig
}

// NewProviderCredentialsService snapshots the organization-bound native service
// and immutable ingress profile. Missing credentials policy, key, clock, native
// owner or lifetime bound is rejected. Generic metadata authorization is never
// substituted for the separate fresh org:sso-credentials owner.
func NewProviderCredentialsService(base *ProviderService, config ProviderCredentialsConfig) (*ProviderCredentialsService, error) {
	if base == nil || base.pool == nil || !providerID(base.updateOrganization) || config.Authorization == nil || !providerID(config.IngressKeyID) || config.MaximumReferenceLifetime <= 0 {
		return nil, sso.ErrInvalidInput
	}
	value := reflect.ValueOf(config.Authorization)
	if value.Kind() == reflect.Pointer && value.IsNil() {
		return nil, sso.ErrInvalidInput
	}
	copy := *base
	return &ProviderCredentialsService{base: &copy, profile: config}, nil
}

func (ProviderCredentialsService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("sso.postgres.ProviderCredentialsService(redacted)"))
}
func (ProviderCredentialsConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("sso.postgres.ProviderCredentialsConfig(redacted)"))
}
func (ProviderCredentialsService) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}
func (ProviderCredentialsService) MarshalText() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}
func (ProviderCredentialsConfig) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}
func (ProviderCredentialsConfig) MarshalText() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}

func (s *ProviderCredentialsService) admit(ctx context.Context) (a providerAdmission, err error) {
	// Admission performs reads only. Contain a trusted owner's panic here so a
	// failed postcommit disclosure check cannot erase a known native receipt.
	defer func() {
		if recover() != nil {
			a, err = providerAdmission{}, sso.ErrUnavailable
		}
	}()
	a, err = s.base.admit(ctx, s.base.updateOrganization, "org:sso-credentials")
	if err != nil {
		return providerAdmission{}, err
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
	dc := s.base.decision(bound.UserID, s.base.updateOrganization, "org:sso-credentials")
	dc.Request.Environment.Time = a.verified
	evidence, err := s.profile.Authorization.ObserveProviderCredentialsAuthorization(ctx, dc.Clone(), authority.Authorization.Version)
	if err != nil {
		return providerAdmission{}, providerError(ctx, err)
	}
	if !reflect.DeepEqual(evidence.Context, dc) || evidence.Decision.Outcome != authorization.Allow || evidence.Decision.Revision != dc.PolicyRevision || evidence.ActorAuthorizationVersion != authority.Authorization.Version || evidence.ValidUntil.IsZero() || !a.verified.Before(evidence.ValidUntil) {
		return providerAdmission{}, sso.ErrForbidden
	}
	remember, err := bound.Remember.Bindings()
	if err != nil {
		return providerAdmission{}, sso.ErrForbidden
	}
	for _, until := range []time.Time{evidence.ValidUntil, bound.Authentication.Proof.IssuedAt.Add(remember.FreshFor)} {
		if until.Before(a.until) {
			a.until = until
		}
	}
	if !s.base.config.Clock.Now().Before(a.until) {
		return providerAdmission{}, sso.ErrForbidden
	}
	return a, nil
}

// ProviderCredentialsRotate preserves one original command and complete intent
// through the existing native request/preparation owners. The internal key is
// derived only from CommandID within native tenant/actor/operation scope; there
// is no external key, new workflow journal or caller-authorized recovery scope.
// Initial and replacement writes advance the shared provider version and
// atomically retain audit/outbox. SAML IdP pin replacement changes only the
// trusted certificate set in provider metadata, not the SP signing key.
// Original retries disclose historical results, not current credential access.
// The ingress protocol must match the authenticated provider metadata.
func (s *ProviderCredentialsService) ProviderCredentialsRotate(ctx context.Context, r sso.ProviderCredentialsRotateRequest) (out sso.ProviderCredentialsRotateResult, err error) {
	_, commandErr := identity.ParseCommandID(string(r.CommandID))
	if s == nil || s.base == nil || ctx == nil || !providerID(r.ProviderID) || commandErr != nil || r.ExpectedVersion == 0 || r.ExpectedVersion == math.MaxUint64 || r.OverlapPolicy.Validate() != nil {
		return out, sso.ErrInvalidInput
	}
	reference := r.CredentialReference.Context()
	if _, contextErr := reference.EncryptionContext(); contextErr != nil || reference.ProviderID != r.ProviderID || reference.ProviderVersion != r.ExpectedVersion || reference.TenantID != string(s.base.authentication.TenantID) || reference.OrganizationID != s.base.updateOrganization || reference.EnvelopeKeyID != s.profile.IngressKeyID || reference.ExpiresAt.Sub(reference.IssuedAt) > s.profile.MaximumReferenceLifetime {
		return out, sso.ErrForbidden
	}
	if reference.Protocol == providerProtocolOAuth2 && !s.base.oauthRegistration {
		return out, sso.ErrForbidden
	}
	if reference.Protocol == providerProtocolSAML {
		if reference.Purpose == sso.SAMLIDPSigningCertificatesPurpose {
			if s.base.samlValidator == nil || s.base.samlOrigin == "" {
				return out, sso.ErrForbidden
			}
		} else if s.base.samlSigningValidator == nil {
			return out, sso.ErrForbidden
		}
	}
	wire, err := r.CredentialReference.EncryptedEnvelope().MarshalBinary()
	if err != nil || len(wire) == 0 || len(wire) > 32768 {
		return out, sso.ErrInvalidInput
	}
	ctx, cancel := context.WithTimeout(ctx, s.base.config.MaximumDuration)
	defer cancel()
	a, err := s.admit(ctx)
	if err != nil {
		return out, err
	}
	contextWire, _ := json.Marshal(reference)
	contextHash, credentialHash := sha256.Sum256(contextWire), sha256.Sum256(wire)
	intent, err := identity.NewRequestIntent([]identity.FeatureField{
		{Name: "organization", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: s.base.updateOrganization}},
		{Name: "provider", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: r.ProviderID}},
		{Name: "command", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(r.CommandID)}},
		{Name: "expected-version", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: strconv.FormatUint(r.ExpectedVersion, 10)}},
		{Name: "credential", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: credentialHash[:]}},
		{Name: "credential-context", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: contextHash[:]}},
		{Name: "overlap", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "none"}},
		{Name: "policy-id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: s.base.config.PolicyID}},
	})
	if err != nil {
		return out, sso.ErrInvalidInput
	}
	p := &ProviderCredentialsContributor{service: s, request: r, admission: a, intent: intent, credentialWire: wire}
	defer func() { clear(p.metadata) }()
	if err = p.compose(); err != nil {
		return out, err
	}
	bound, _ := a.session.Session.Bindings()
	op := p.operation()
	scope := kernel.RequestKeyScope{TenantID: s.base.authentication.TenantID, ActorID: identity.ActorID(bound.UserID), ActorKind: authorization.SubjectUser, Method: "POST", RouteID: op.OperationID}
	caller := s.base.kernelDecision(bound.UserID, "identity.request-admission", op.OperationID)
	caller.Request.Action = authorization.Action(op.OperationID)
	key, err := identity.NewIdempotencyKey([]byte("sso-provider-credentials." + string(r.CommandID)))
	if err != nil {
		return out, sso.ErrInvalidInput
	}
	registration := kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: op}
	keyBinding, retained, err := p.coordinator.ResolvePreparedRequestKey(ctx, scope, key, intent, caller, registration, p)
	defer clear(retained)
	if err != nil {
		if p.failure != nil {
			return out, p.failure
		}
		var unknown identity.UnknownCommitError
		if errors.As(err, &unknown) {
			// The native key owner deliberately withholds an unacknowledged
			// binding. Retain uncertainty without inventing a command receipt.
			out.ReconciliationRequired = true
		}
		return out, providerError(ctx, err)
	}
	original, err := p.RestoreRequestKey(ctx, keyBinding, retained)
	if err != nil {
		return out, providerError(ctx, err)
	}
	if p.binding != original {
		query := s.base.kernelDecision(bound.UserID, "identity.user", string(bound.UserID))
		query.Request.Action = authorization.Action(op.OperationID)
		out.Completion, err = p.coordinator.RecoverPreparedFeatureCommand(ctx, providerRecovery(original), query, registration, p)
	} else {
		var plan kernel.CommandPlan
		plan, err = p.plan(false)
		if err == nil {
			out.Completion, err = p.coordinator.ExecutePreparedFeature(ctx, p.command, plan)
		}
	}
	if out.Completion.Outcome == identity.CommitOutcomeUnknown || out.Completion.Outcome == identity.CommitOutcomeInProgress {
		out.ReconciliationRequired = true
	}
	if out.Completion.Outcome == identity.CommitOutcomeCommitted {
		if _, admissionErr := s.admit(ctx); admissionErr != nil {
			return out, admissionErr
		}
		if out.Completion.Feature == nil || out.Completion.Feature.Operation != op || out.Completion.Feature.BeforeVersion != r.ExpectedVersion || out.Completion.Feature.AfterVersion != r.ExpectedVersion+1 {
			return out, sso.ErrUnavailable
		}
		out.ProviderID, out.Version, out.Active = original.RecordID, out.Completion.Feature.AfterVersion, true
	}
	return out, providerError(ctx, err)
}
