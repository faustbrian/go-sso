package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
)

const samlLogoutRelayIssueSubject = "sso_saml_logout_request"

// WithRelayState explicitly selects native one-use RelayState custody for the
// selected providers. Install the kernel request-key and feature-preparation,
// capability-issuance and SAML request migrations first. The namespace must
// differ from the local logout and login namespaces and remain stable across
// retries. Selection performs no I/O, changes no existing service and enables
// no HTTP route. Without this selection the historical no-state profile remains.
func (s *ProviderSAMLLogoutRedirectService) WithRelayState(keys kernel.RequestKeyConfig) (*ProviderSAMLLogoutRedirectService, error) {
	if s == nil || s.local == nil || s.local.login == nil || keys.Namespace == "" ||
		keys.Namespace == s.local.login.config.RequestKeys.Namespace || keys.Namespace == s.local.signinRequestNamespace ||
		keys.Policy.PolicyVersion != s.local.login.policyVersion ||
		s.local.login.payload.Issuer == nil || s.local.login.payload.Codec == nil {
		return nil, sso.ErrInvalidInput
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{s.local.login.directory})
	if err != nil {
		return nil, sso.ErrInvalidInput
	}
	if _, err := kernel.NewCoordinatorWithRequestKeys(s.local.login.router.pool, registry, s.local.login.config.Coordinator, keys); err != nil {
		return nil, sso.ErrInvalidInput
	}
	out := *s
	out.relayKeys = &keys
	return &out, nil
}

// This is encrypted request custody, never a browser proof. Only the issuer
// creates Proof; the independent random Handle carries no authority by itself.
type samlLogoutRelayIssueCustody struct {
	IssueCommand        providerLoginStoredCommand
	SettlementCommandID identity.CommandID
	Handle              string
	Proof               []byte
	Plan                providerLoginStoredPlan
	IssuedAt, ExpiresAt time.Time
	RequestDigest       [32]byte
}

func (samlLogoutRelayIssueCustody) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("sso.postgres.samlLogoutRelayIssueCustody(redacted)"))
}

type samlLogoutRelayIssueInput struct {
	Command      providerLoginStoredCommand
	LocalCommand providerLoginStoredCommand
	Intent       [32]byte
	Payload      samlLogoutRequestBinding
	Route        samlLogoutRelayStoredRoute
	Organization organization.CredentialAuthorityObservation
	IssuedAt     time.Time
	ExpiresAt    time.Time
}

// The public checkpoint refuses serialization. Retain its scalar projection
// only inside the native authenticated envelope, as the login owner does.
type samlLogoutRelayStoredRoute struct {
	ProviderID                                                         sso.ProviderID
	ProviderVersion, CredentialGeneration, PolicyVersion, ProofVersion uint64
	Proof                                                              organization.DomainProofKey
	ObservedAt, ValidUntil                                             time.Time
}

func retainSAMLLogoutRelayRoute(r sso.DomainRouteBinding) samlLogoutRelayStoredRoute {
	return samlLogoutRelayStoredRoute{ProviderID: r.ProviderID, ProviderVersion: r.ProviderVersion, CredentialGeneration: r.CredentialGeneration, PolicyVersion: r.PolicyVersion, ProofVersion: r.Proof.ProofVersion, Proof: r.Proof.Key, ObservedAt: r.ObservedAt, ValidUntil: r.ValidUntil}
}
func (r samlLogoutRelayStoredRoute) binding() sso.DomainRouteBinding {
	return sso.DomainRouteBinding{ProviderID: r.ProviderID, ProviderVersion: r.ProviderVersion, CredentialGeneration: r.CredentialGeneration, PolicyVersion: r.PolicyVersion, Proof: sso.DomainProofCheckpoint{Key: r.Proof, ProofVersion: r.ProofVersion}, ObservedAt: r.ObservedAt, ValidUntil: r.ValidUntil}
}

type samlLogoutRelayIssueOutput struct {
	Generation uint64
	Row        samlLogoutRequestRow
	Payload    samlLogoutRequestBinding
	Checkpoint []byte
	Envelope   []byte
}

type samlLogoutRelayIssuePhase struct {
	service      *ProviderSAMLLogoutRedirectService
	local        *providerSAMLLogoutStartPhase
	profile      samlLogoutSelectedProfile
	route        sso.DomainRouteBinding
	payload      samlLogoutRequestBinding
	maximum      time.Time
	intent       [32]byte
	input        *samlLogoutRelayIssueInput
	output       *samlLogoutRelayIssueOutput
	outputDigest [32]byte
	issuance     capabilitypg.PreparedIssuance
	registry     *kernel.ContributorRegistry
}

func (p *samlLogoutRelayIssuePhase) login() *ProviderLoginService { return p.service.local.login }
func (*samlLogoutRelayIssuePhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.SSOSAMLLogoutRelayIssueDescriptor()
}
func (*samlLogoutRelayIssuePhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{kernel.SSOSAMLLogoutRelayIssueOperation()}
}
func (p *samlLogoutRelayIssuePhase) registration() kernel.FeatureRegistration {
	return kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: kernel.SSOSAMLLogoutRelayIssueOperation()}
}
func (p *samlLogoutRelayIssuePhase) scope() kernel.RequestKeyScope {
	local := p.local.input.binding()
	return kernel.RequestKeyScope{TenantID: local.TenantID, ActorID: local.ActorID, ActorKind: local.ActorKind, Method: "POST", RouteID: kernel.SSOSAMLLogoutRelayIssueOperation().OperationID}
}
func (p *samlLogoutRelayIssuePhase) caller(resource, id string) authorization.DecisionContext {
	scope := p.scope()
	return authorization.DecisionContext{PolicyRevision: authorization.Revision(p.login().policyVersion), Request: authorization.Request{Tenant: authorization.TenantID(scope.TenantID), Subject: authorization.Subject{Kind: scope.ActorKind, ID: authorization.SubjectID(scope.ActorID)}, Action: authorization.Action(scope.RouteID), Resource: authorization.Resource{Type: authorization.ResourceType(resource), ID: authorization.ResourceID(id)}}}
}
func (p *samlLogoutRelayIssuePhase) binding(id identity.CommandID) identity.CommandBinding {
	b := p.local.input.binding()
	op := kernel.SSOSAMLLogoutRelayIssueOperation()
	b.CommandID, b.RecordID, b.CorrelationID = id, string(id), string(b.CommandID)
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	return b
}

func (p *samlLogoutRelayIssuePhase) requestIntent() (identity.RequestIntent, error) {
	frame, err := providerLoginPayloadEncode(struct {
		Local   providerLoginStoredCommand
		Digest  [32]byte
		Payload samlLogoutRequestBinding
		Profile ProviderSAMLLogoutRedirectProfile
	}{providerLoginStoredCommand(p.local.input.binding()), p.local.inputDigest, p.payload, p.profile.config})
	defer clear(frame)
	if err != nil {
		return identity.RequestIntent{}, identity.UnavailableError{}
	}
	p.intent = sha256.Sum256(frame)
	return identity.NewRequestIntent([]identity.FeatureField{{Name: "sso.saml.logout.relay-intent", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: p.intent[:]}}})
}

func (p *samlLogoutRelayIssuePhase) requestAAD(k kernel.RequestKeyPreparationBinding) (envelope.Context, error) {
	if k.Namespace != p.service.relayKeys.Namespace || k.Scope != p.scope() || k.Feature != p.registration() || k.PolicyVersion != p.login().policyVersion || k.IntentDigest == ([32]byte{}) || p.binding(k.Admission.CommandID).ValidateFor(kernel.SSOSAMLLogoutRelayIssueOperation()) != nil || k.Admission.CommandID == p.local.input.binding().CommandID {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	frame, err := providerLoginPayloadEncode(providerLoginStoredRequestKey(k))
	defer clear(frame)
	if err != nil {
		return envelope.Context{}, identity.UnavailableError{}
	}
	digest := sha256.Sum256(frame)
	return envelope.NewContext(map[string]string{"profile": "sso-saml-logout-relay-input-v1", "request": base64.RawURLEncoding.EncodeToString(digest[:])})
}

func (p *samlLogoutRelayIssuePhase) PrepareRequestKey(ctx context.Context, k kernel.RequestKeyPreparationBinding, req identity.RequestIntent) ([]byte, error) {
	aad, err := p.requestAAD(k)
	if err != nil {
		return nil, err
	}
	fields, ok := req.Fields()
	if !ok || len(fields) != 1 || fields[0].Name != "sso.saml.logout.relay-intent" || fields[0].Value.Kind != identity.FeatureBytes || !bytes.Equal(fields[0].Value.Bytes, p.intent[:]) {
		return nil, identity.ForbiddenError{}
	}
	route, err := sso.NewSAMLDomainRoute(p.route)
	if err != nil {
		return nil, err
	}
	authority, err := p.login().router.observeProviderLoginAuthority(ctx, route)
	if err != nil {
		return nil, err
	}
	// Whole-second truncation can only shorten the local command's original
	// maximum; a delayed first provider attempt cannot start a fresh window.
	issued := p.local.input.StartedAt.UTC().Truncate(time.Second)
	expires := p.maximum.UTC().Truncate(time.Second)
	if !p.login().router.config.Clock.Now().Before(expires) || !expires.After(issued) {
		return nil, identity.ForbiddenError{}
	}
	in := samlLogoutRelayIssueInput{Command: providerLoginStoredCommand(p.binding(k.Admission.CommandID)), LocalCommand: providerLoginStoredCommand(p.local.input.binding()), Intent: p.intent, Payload: p.payload, Route: retainSAMLLogoutRelayRoute(p.route), Organization: authority.organization, IssuedAt: issued, ExpiresAt: expires}
	frame, err := providerLoginPayloadEncode(in)
	defer clear(frame)
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return p.login().payload.seal(ctx, aad, frame, providerLoginRequestWireLimit)
}

func (p *samlLogoutRelayIssuePhase) restoreRequest(ctx context.Context, k kernel.RequestKeyPreparationBinding, wire []byte) error {
	aad, err := p.requestAAD(k)
	if err != nil {
		return err
	}
	frame, err := p.login().payload.open(ctx, aad, wire, providerLoginRequestWireLimit, providerLoginRequestPlainLimit)
	defer clear(frame)
	if err != nil {
		return err
	}
	var in samlLogoutRelayIssueInput
	if providerLoginPayloadDecode(frame, &in) != nil || in.Command != providerLoginStoredCommand(p.binding(k.Admission.CommandID)) || in.LocalCommand != providerLoginStoredCommand(p.local.input.binding()) || in.Intent != p.intent || in.Payload != p.payload || in.IssuedAt != p.local.input.StartedAt.UTC().Truncate(time.Second) || in.ExpiresAt.After(p.maximum) || !in.ExpiresAt.After(in.IssuedAt) || in.ExpiresAt.Sub(in.IssuedAt) > samlLogoutRequestLife || in.ExpiresAt.Nanosecond() != 0 || in.Payload.Relay != nil {
		return identity.ForbiddenError{}
	}
	canonical, err := providerLoginPayloadEncode(in)
	defer clear(canonical)
	if err != nil || !bytes.Equal(canonical, frame) {
		return identity.ForbiddenError{}
	}
	p.input = &in
	return nil
}

func (p *samlLogoutRelayIssuePhase) issueIntent(generated bool) kernel.SSOSAMLLogoutRelayIssueIntent {
	in := p.input
	out := kernel.SSOSAMLLogoutRelayIssueIntent{LocalCommandID: identity.CommandBinding(in.LocalCommand).CommandID, OrganizationID: in.Payload.Anchor.Organization, ProviderID: in.Payload.Anchor.Provider, IssuedAt: in.IssuedAt, ExpiresAt: in.ExpiresAt}
	if generated {
		out.RequestDigest = p.output.Payload.Relay.RequestDigest
		out.ExpiresAt = p.output.Row.ExpiresAt
	}
	return out
}
func (p *samlLogoutRelayIssuePhase) command(generated bool) (identity.Command, error) {
	if p.input == nil || generated && p.output == nil {
		return identity.Command{}, identity.ForbiddenError{}
	}
	fields, err := kernel.SSOSAMLLogoutRelayIssuePreparationFields(p.issueIntent(false))
	if generated {
		fields, err = kernel.SSOSAMLLogoutRelayIssueFields(p.issueIntent(true))
	}
	if err != nil {
		return identity.Command{}, err
	}
	return identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: identity.CommandBinding(p.input.Command), Operation: kernel.SSOSAMLLogoutRelayIssueOperation(), Fields: fields})
}

func (p *samlLogoutRelayIssuePhase) ValidateFeatureCommand(command identity.Command, plan kernel.CommandPlan) error {
	want, err := p.command(true)
	actual, ok := command.Feature()
	if err != nil || !ok {
		return identity.ForbiddenError{}
	}
	expected, _ := want.Feature()
	if actual.Binding != expected.Binding || actual.Operation != expected.Operation || !equalProviderLogoutFields(actual.Fields, expected.Fields) {
		return identity.ForbiddenError{}
	}
	return nil
}
func (p *samlLogoutRelayIssuePhase) ValidateFeaturePreparation(command identity.Command, plan kernel.CommandPlan) error {
	want, err := p.command(false)
	a, ok := command.Feature()
	b, _ := want.Feature()
	if err != nil || !ok || a.Binding != b.Binding || a.Operation != b.Operation || !equalProviderLogoutFields(a.Fields, b.Fields) || plan.CapabilityIssuance != nil {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *samlLogoutRelayIssuePhase) outputAAD(generation uint64) (envelope.Context, error) {
	if p.input == nil || generation == 0 {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	frame, err := providerLoginPayloadEncode(p.input)
	defer clear(frame)
	if err != nil {
		return envelope.Context{}, identity.UnavailableError{}
	}
	digest := sha256.Sum256(frame)
	return envelope.NewContext(map[string]string{"profile": "sso-saml-logout-relay-output-v1", "input": base64.RawURLEncoding.EncodeToString(digest[:]), "generation": strconv.FormatUint(generation, 10)})
}

type samlLogoutRelayAdmission struct{ phase *samlLogoutRelayIssuePhase }

func (a samlLogoutRelayAdmission) Check(ctx context.Context) error {
	p := a.phase
	if ctx == nil || p.input == nil || p.login().router.config.Clock.Now().Before(p.input.IssuedAt) || !p.login().router.config.Clock.Now().Before(minSAMLLogoutTime(p.input.ExpiresAt, minSAMLLogoutTime(p.input.Route.ValidUntil, p.input.Organization.ValidUntil))) {
		return identity.ForbiddenError{}
	}
	return ctx.Err()
}
func (a samlLogoutRelayAdmission) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	if err := a.Check(ctx); err != nil {
		return nil, err
	}
	return a.phase.generate(ctx, generation)
}
func (p *samlLogoutRelayIssuePhase) PrepareFeatureAdmission(ctx context.Context, command identity.Command) (kernel.FeaturePreparationAdmission, error) {
	if err := p.ValidateFeaturePreparation(command, kernel.CommandPlan{}); err != nil {
		return nil, err
	}
	a := samlLogoutRelayAdmission{p}
	return a, a.Check(ctx)
}
func (*samlLogoutRelayIssuePhase) GenerateFeaturePreparation(context.Context, identity.Command, uint64) ([]byte, error) {
	return nil, identity.ForbiddenError{}
}
func (p *samlLogoutRelayIssuePhase) RestoreFeatureAdmission(ctx context.Context, c identity.Command, generation uint64, wire []byte) (kernel.FeaturePreparationAdmission, error) {
	if _, _, err := p.RestoreFeaturePreparation(ctx, c, generation, wire); err != nil {
		return nil, err
	}
	a := samlLogoutRelayAdmission{p}
	return a, a.Check(ctx)
}
