package postgres

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	organization "github.com/faustbrian/go-organization"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
	"github.com/faustbrian/go-sso/oidc"
)

const providerLogoutIntentField = "sso.oidc.logout.intent"
const providerLogoutInputField = "sso.oidc.logout.prepared"

type providerLogoutStartPhase struct {
	service           *ProviderLogoutService
	request           ProviderLogoutStartRequest
	browser           ProviderLogoutBrowser
	original          session.Session
	observed          session.GetResult
	session           session.SessionSpec
	csrfKey           session.CSRFKey
	historical        bool
	deniedPreparation bool
	intent            [32]byte
	input             *providerLogoutStartInput
	inputDigest       [32]byte
}

type providerLogoutStartInput struct {
	Command       providerLoginStoredCommand
	Intent        [32]byte
	Organization  string
	Provider      string
	Issuer        string
	FinalRedirect string
	StartedAt     time.Time
	ValidUntil    time.Time
	Remote        *providerLogoutRemote `json:",omitempty"`
}

// Raw state is recoverable only in the coordinator's encrypted request
// preparation, for redelivery after lost acknowledgement. The independently
// sealed callback binding never contains raw browser state.
type providerLogoutRemote struct {
	Raw               [32]byte
	StateKeyVersion   uint32
	CompletionCommand identity.CommandID
	ExpiresAt         time.Time
	Wire              []byte
}

func (i providerLogoutStartInput) binding() identity.CommandBinding {
	return identity.CommandBinding(i.Command)
}

func (i providerLogoutStartInput) row(key [32]byte) providerLogoutRow {
	b := i.binding()
	return providerLogoutRow{TenantID: b.TenantID, StartCommandID: b.CommandID, StateKeyVersion: i.Remote.StateKeyVersion,
		StateDigest: providerLogoutStateDigest(b.TenantID, key, oidc.NewRPLogoutState(i.Remote.Raw)), IssuedAt: i.StartedAt, ExpiresAt: i.Remote.ExpiresAt}
}

func (p *providerLogoutStartPhase) DescriptorOperation() identity.FeatureOperation {
	return kernel.SSOOIDCLogoutOperation()
}

func (*providerLogoutStartPhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.SSOOIDCLogoutDescriptor()
}

func (p *providerLogoutStartPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{p.DescriptorOperation()}
}

func (p *providerLogoutStartPhase) registration() kernel.FeatureRegistration {
	return kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: p.DescriptorOperation()}
}

func (p *providerLogoutStartPhase) binding(id identity.CommandID) identity.CommandBinding {
	b, op := p.session, p.DescriptorOperation()
	return identity.CommandBinding{CommandID: id, TenantID: b.TenantID, UserID: b.UserID,
		ActorID: identity.ActorID(b.UserID), ActorKind: p.scope().ActorKind, PolicyID: p.service.login.config.PolicyID,
		PolicyVersion: p.service.login.policyVersion, OperationID: op.OperationID, SchemaID: op.SchemaID,
		SchemaVersion: op.SchemaVersion, RecordID: b.SessionID, CorrelationID: string(id)}
}

func (p *providerLogoutStartPhase) selected() (StaticOIDCLoginProfile, oidc.RPLogoutProfile, bool, error) {
	v, err := p.session.Authority.Bindings()
	if err != nil || !v.Organization.Present {
		return StaticOIDCLoginProfile{}, oidc.RPLogoutProfile{}, false, identity.ForbiddenError{}
	}
	k := providerLoginProfileKey{organization.ID(v.ActiveOrganizationID), sso.ProviderID(p.request.ProviderID)}
	configured, ok := p.service.login.profiles[k]
	if !ok || configured.ProviderVersion != p.session.Authentication.ProofVersion {
		return StaticOIDCLoginProfile{}, oidc.RPLogoutProfile{}, false, identity.ForbiddenError{}
	}
	wire, remote := p.service.profiles[k]
	return configured, wire, remote, nil
}

func (p *providerLogoutStartPhase) requestIntent() (identity.RequestIntent, error) {
	source, err := sessionpg.OriginalSessionFields(p.original)
	if err != nil {
		return identity.RequestIntent{}, err
	}
	frame, err := json.Marshal(struct {
		Source                        []identity.FeatureField
		Provider, FinalTarget, Origin string
	}{source, p.request.ProviderID, p.request.FinalRedirect, p.browser.Origin})
	defer clear(frame)
	if err != nil {
		return identity.RequestIntent{}, identity.UnavailableError{}
	}
	p.intent = sha256.Sum256(frame)
	return identity.NewRequestIntent([]identity.FeatureField{{Name: providerLogoutIntentField, Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: p.intent[:]}}})
}

func (p *providerLogoutStartPhase) keyAAD(k kernel.RequestKeyPreparationBinding) (envelope.Context, error) {
	if k.Feature != p.registration() || k.Scope != p.scope() || k.Namespace != p.service.login.config.RequestKeys.Namespace ||
		k.PolicyVersion != p.service.login.policyVersion || k.IntentDigest == ([32]byte{}) || k.Admission.FingerprintKeyVersion == 0 ||
		p.binding(k.Admission.CommandID).ValidateFor(p.DescriptorOperation()) != nil {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	frame, err := json.Marshal(providerLoginStoredRequestKey(k))
	if err != nil {
		return envelope.Context{}, identity.UnavailableError{}
	}
	defer clear(frame)
	digest := sha256.Sum256(frame)
	return envelope.NewContext(map[string]string{"profile": "sso-oidc-rp-logout-request-v1", "request": base64.RawURLEncoding.EncodeToString(digest[:])})
}

func (p *providerLogoutStartPhase) PrepareRequestKey(ctx context.Context, k kernel.RequestKeyPreparationBinding, request identity.RequestIntent) (wire []byte, err error) {
	defer func() {
		var denied identity.ForbiddenError
		p.deniedPreparation = errors.As(err, &denied)
	}()
	aad, err := p.keyAAD(k)
	if err != nil {
		return nil, err
	}
	fields, ok := request.Fields()
	if !ok || len(fields) != 1 || fields[0].Name != providerLogoutIntentField || fields[0].Value.Kind != identity.FeatureBytes || !bytes.Equal(fields[0].Value.Bytes, p.intent[:]) || p.historical {
		return nil, identity.ForbiddenError{}
	}
	configured, profile, remote, err := p.selected()
	if err != nil {
		return nil, err
	}
	issuer, err := p.readIssuer(ctx, configured)
	if err != nil {
		return nil, err
	}
	now := p.service.login.router.config.Clock.Now().UTC().Truncate(time.Microsecond)
	until := p.observed.ValidUntil().UTC().Truncate(time.Microsecond)
	if !providerLogoutTime(now) || p.observed.ValidateAt(now) != nil || !now.Before(until) {
		return nil, identity.ForbiddenError{}
	}
	i := providerLogoutStartInput{
		Command: providerLoginStoredCommand(p.binding(k.Admission.CommandID)), Intent: p.intent,
		Organization: string(configured.OrganizationID), Provider: string(configured.ProviderID), Issuer: issuer,
		FinalRedirect: p.request.FinalRedirect, StartedAt: now, ValidUntil: until,
	}
	if remote {
		protocol, err := profile.Spec()
		if err != nil || protocol.Issuer != issuer {
			return nil, identity.ForbiddenError{}
		}
		err = p.prepareRemote(ctx, &i, protocol)
		defer clear(i.Remote.Raw[:])
		if err != nil {
			return nil, err
		}
	}
	frame, err := json.Marshal(i)
	defer clear(frame)
	if err != nil || len(frame) > providerLoginRequestPlainLimit {
		return nil, identity.UnavailableError{}
	}
	return p.service.login.payload.seal(ctx, aad, frame, providerLoginRequestWireLimit)
}

func (p *providerLogoutStartPhase) prepareRemote(ctx context.Context, i *providerLogoutStartInput, protocol oidc.RPLogoutProfileConfig) error {
	s := p.service.login
	i.Remote = &providerLogoutRemote{StateKeyVersion: s.payload.CurrentStateKey, ExpiresAt: i.StartedAt.Add(s.config.StateLifetime)}
	if _, err := rand.Read(i.Remote.Raw[:]); err != nil || i.Remote.Raw == ([32]byte{}) {
		return identity.UnavailableError{}
	}
	completed, err := identity.NewCommandID()
	if err != nil {
		return identity.UnavailableError{}
	}
	i.Remote.CompletionCommand = completed
	i.Remote.Wire, err = sealProviderLogoutBinding(ctx, s.payload, p.row(*i), p.remoteBinding(*i, protocol))
	return err
}

func (p *providerLogoutStartPhase) row(i providerLogoutStartInput) providerLogoutRow {
	login := p.service.login
	return i.row(login.payload.StateKeys[i.Remote.StateKeyVersion])
}

func (p *providerLogoutStartPhase) remoteBinding(i providerLogoutStartInput, protocol oidc.RPLogoutProfileConfig) providerLogoutBinding {
	s := p.session
	return providerLogoutBinding{UserID: s.UserID, OrganizationID: i.Organization, ProviderID: i.Provider, SessionID: s.SessionID,
		CredentialID: s.Authentication.CredentialID, CredentialVersion: s.Authentication.CredentialVersion,
		SessionVersion: s.Version, ProviderVersion: s.Authentication.ProofVersion, CompletionCommandID: i.Remote.CompletionCommand,
		Protocol: protocol, FinalRedirect: i.FinalRedirect}
}

func (p *providerLogoutStartPhase) RestoreRequestKey(ctx context.Context, k kernel.RequestKeyPreparationBinding, wire []byte) (identity.CommandBinding, error) {
	aad, err := p.keyAAD(k)
	if err != nil {
		return identity.CommandBinding{}, err
	}
	s := p.service.login
	frame, err := s.payload.open(ctx, aad, wire, providerLoginRequestWireLimit, providerLoginRequestPlainLimit)
	defer clear(frame)
	if err != nil {
		return identity.CommandBinding{}, err
	}
	var input providerLogoutStartInput
	if json.Unmarshal(frame, &input) != nil || input.binding() != p.binding(k.Admission.CommandID) || input.Intent != p.intent ||
		input.FinalRedirect != p.request.FinalRedirect || !providerLogoutTime(input.StartedAt) || !providerLogoutTime(input.ValidUntil) ||
		!input.ValidUntil.After(input.StartedAt) || input.ValidUntil.After(input.StartedAt.Add(20*time.Second)) || !validProviderLoginCallback(input.Issuer) {
		return identity.CommandBinding{}, identity.ForbiddenError{}
	}
	canonical, err := json.Marshal(input)
	defer clear(canonical)
	if err != nil || !bytes.Equal(canonical, frame) {
		return identity.CommandBinding{}, identity.ForbiddenError{}
	}
	configured, profile, remote, err := p.selected()
	if err != nil || input.Organization != string(configured.OrganizationID) || input.Provider != string(configured.ProviderID) || (input.Remote != nil) != remote {
		return identity.CommandBinding{}, identity.ForbiddenError{}
	}
	if remote {
		protocol, err := profile.Spec()
		if err != nil || protocol.Issuer != input.Issuer {
			return identity.CommandBinding{}, identity.ForbiddenError{}
		}
		binding, err := openProviderLogoutBinding(ctx, s.payload, p.row(input), input.Remote.Wire)
		if err != nil || binding != p.remoteBinding(input, protocol) {
			return identity.CommandBinding{}, identity.ForbiddenError{}
		}
	}
	if p.input != nil && p.input.Remote != nil {
		clear(p.input.Remote.Raw[:])
		clear(p.input.Remote.Wire)
	}
	p.input, p.inputDigest = &input, sha256.Sum256(frame)
	return input.binding(), nil
}
