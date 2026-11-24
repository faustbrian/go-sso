package postgres

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"time"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-sso/saml"
)

func (p *samlLogoutRelayIssuePhase) generate(ctx context.Context, generation uint64) ([]byte, error) {
	aad, err := p.outputAAD(generation)
	if err != nil {
		return nil, err
	}
	var nonce [32]byte
	defer clear(nonce[:])
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, identity.UnavailableError{}
	}
	settlement, err := identity.NewCommandID()
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	in := p.input
	local := identity.CommandBinding(in.LocalCommand)
	out := samlLogoutRelayIssueOutput{Generation: generation, Row: samlLogoutRequestRow{Tenant: local.TenantID, Command: local.CommandID, Organization: in.Payload.Anchor.Organization, Provider: in.Payload.Anchor.Provider, IssuedAt: in.IssuedAt, ExpiresAt: in.ExpiresAt}, Payload: in.Payload}
	relay := &samlLogoutRelayIssueCustody{IssueCommand: in.Command, SettlementCommandID: settlement, Handle: base64.RawURLEncoding.EncodeToString(nonce[:]), IssuedAt: in.IssuedAt, ExpiresAt: in.ExpiresAt}
	if settlement == local.CommandID || settlement == identity.CommandBinding(in.Command).CommandID {
		return nil, identity.ForbiddenError{}
	}
	request := saml.LogoutRequest{ID: out.Row.requestID(), IssuedAt: in.IssuedAt, SessionIndex: in.Payload.Subject.SessionIndex, RelayState: relay.Handle, NameID: saml.LogoutNameID{Value: in.Payload.Subject.ProviderSubject, SubjectFormat: in.Payload.Subject.SubjectFormat, NameQualifier: in.Payload.Subject.NameQualifier, SPNameQualifier: in.Payload.Subject.SPNameQualifier}}
	err = p.login().router.withRouteCredential(ctx, in.Route.binding(), providerProtocolSAML, func(ctx context.Context, bundle []byte) error {
		wire, cutoff, err := p.profile.wire.RedirectWithSPSigningCredential(ctx, request, bundle, p.login().router.config.Clock.Now())
		if err != nil {
			return err
		}
		redirect, err := wire.URL()
		if err != nil {
			return err
		}
		out.Payload.Redirect = redirect.String()
		out.Row.ExpiresAt = minSAMLLogoutTime(out.Row.ExpiresAt, cutoff.UTC().Truncate(time.Second))
		relay.ExpiresAt = out.Row.ExpiresAt
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !out.Row.ExpiresAt.After(out.Row.IssuedAt) || !p.login().router.config.Clock.Now().Before(out.Row.ExpiresAt) {
		return nil, identity.ForbiddenError{}
	}
	relay.RequestDigest = sha256.Sum256([]byte(out.Payload.Redirect))
	b := identity.CommandBinding(in.Command)
	issued, err := p.login().payload.Issuer.Prepare(ctx, b, []capability.Payload{{Version: 1, Issuer: p.login().payload.CapabilityIssuer, Audiences: []string{p.login().payload.Audience}, Subject: string(b.UserID), Tenant: string(b.TenantID), Resource: b.RecordID, CorrelationID: b.CorrelationID, Operation: kernel.SSOSAMLLogoutRelaySettlementOperation().OperationID, IssuedAt: relay.IssuedAt, NotBefore: relay.IssuedAt, ExpiresAt: relay.ExpiresAt, MaxUses: 1, Caveats: map[string]string{"identity.sso.saml.logout.request": base64.RawURLEncoding.EncodeToString(relay.RequestDigest[:])}}})
	if err != nil {
		return nil, err
	}
	plan, err := issued.Plan()
	if err != nil || len(plan.Grants) != 1 {
		return nil, identity.ForbiddenError{}
	}
	relay.Plan = providerLoginStoredPlan{Contributor: plan.Contributor, Grant: providerLoginStoredGrant(plan.Grants[0])}
	out.Checkpoint, err = p.login().payload.Codec.CheckpointPreparation(ctx, issued, generation, func(ctx context.Context, index uint16, proof []byte) error {
		if index != 0 || len(relay.Proof) != 0 || len(proof) == 0 || len(proof) > 32768 {
			return identity.ForbiddenError{}
		}
		relay.Proof = bytes.Clone(proof)
		return ctx.Err()
	})
	defer clear(relay.Proof)
	defer clear(out.Checkpoint)
	if err != nil {
		return nil, err
	}
	out.Payload.Relay = relay
	requestAAD, err := out.Row.aad()
	if err != nil {
		return nil, err
	}
	requestFrame, err := providerLoginPayloadEncode(out.Payload)
	defer clear(requestFrame)
	if err != nil || len(requestFrame) > samlLogoutRequestPlainMaximum {
		return nil, identity.UnavailableError{}
	}
	out.Envelope, err = p.login().payload.seal(ctx, requestAAD, requestFrame, samlLogoutRequestWireMaximum)
	if err != nil {
		return nil, err
	}
	frame, err := providerLoginPayloadEncode(out)
	defer clear(frame)
	if err != nil || len(frame) > providerLoginRequestPlainLimit {
		return nil, identity.UnavailableError{}
	}
	return p.login().payload.seal(ctx, aad, frame, providerLoginRequestWireLimit)
}

func (p *samlLogoutRelayIssuePhase) RestoreFeaturePreparation(ctx context.Context, original identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	if err := p.ValidateFeaturePreparation(original, kernel.CommandPlan{}); err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	aad, err := p.outputAAD(generation)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	frame, err := p.login().payload.open(ctx, aad, wire, providerLoginRequestWireLimit, providerLoginRequestPlainLimit)
	defer clear(frame)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	var out samlLogoutRelayIssueOutput
	if providerLoginPayloadDecode(frame, &out) != nil || out.Generation != generation || len(out.Checkpoint) == 0 || len(out.Envelope) == 0 || len(out.Envelope) > samlLogoutRequestWireMaximum || out.Payload.Relay == nil {
		return identity.Command{}, kernel.CommandPlan{}, identity.ForbiddenError{}
	}
	relay := out.Payload.Relay
	base := out.Payload
	base.Redirect = ""
	base.Relay = nil
	if base != p.input.Payload || out.Row.Tenant != p.local.input.binding().TenantID || out.Row.Command != p.local.input.binding().CommandID || out.Row.Organization != base.Anchor.Organization || out.Row.Provider != base.Anchor.Provider || out.Row.IssuedAt != p.input.IssuedAt || out.Row.ExpiresAt.After(p.input.ExpiresAt) || !out.Row.ExpiresAt.After(out.Row.IssuedAt) || relay.IssueCommand != p.input.Command || relay.IssuedAt != out.Row.IssuedAt || relay.ExpiresAt != out.Row.ExpiresAt || !validSAMLLogoutRelayCustody(out.Row, out.Payload) {
		return identity.Command{}, kernel.CommandPlan{}, identity.ForbiddenError{}
	}
	canonical, err := providerLoginPayloadEncode(out)
	defer clear(canonical)
	if err != nil || !bytes.Equal(canonical, frame) {
		return identity.Command{}, kernel.CommandPlan{}, identity.ForbiddenError{}
	}
	prepared, err := p.login().payload.Codec.RestorePreparation(ctx, identity.CommandBinding(p.input.Command), generation, relay.Plan.native(), out.Checkpoint)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	p.output = &out
	p.outputDigest = sha256.Sum256(wire)
	p.issuance = prepared
	command, err := p.command(true)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	plan, err := p.plan(true)
	return command, plan, err
}

func validSAMLLogoutRelayCustody(row samlLogoutRequestRow, payload samlLogoutRequestBinding) bool {
	r := payload.Relay
	if r == nil || len(r.Handle) != 43 || len(r.Proof) == 0 || len(r.Proof) > 32768 || !r.IssuedAt.Equal(row.IssuedAt) || !r.ExpiresAt.Equal(row.ExpiresAt) || r.RequestDigest != sha256.Sum256([]byte(payload.Redirect)) {
		return false
	}
	handle, err := base64.RawURLEncoding.Strict().DecodeString(r.Handle)
	if err != nil || len(handle) != 32 {
		return false
	}
	clear(handle)
	b := identity.CommandBinding(r.IssueCommand)
	if b.ValidateFor(kernel.SSOSAMLLogoutRelayIssueOperation()) != nil || b.CommandID == row.Command || b.RecordID != string(b.CommandID) || b.CorrelationID != string(row.Command) || b.TenantID != row.Tenant || string(b.UserID) != payload.Anchor.User || r.SettlementCommandID == row.Command || r.SettlementCommandID == b.CommandID {
		return false
	}
	if _, err := identity.ParseCommandID(string(r.SettlementCommandID)); err != nil {
		return false
	}
	redirect, err := parseRetainedSAMLRedirect(payload.Redirect, r.Handle)
	return err == nil && matchesSAMLRedirectEndpoint(redirect, payload.Endpoint) && r.Plan.Contributor == (kernel.ContributorDescriptor{Owner: "capability/postgres", ContractID: "capability.issuance", Version: 1}) && string(kernel.CapabilityPlan(r.Plan.Grant).Purpose) == kernel.SSOSAMLLogoutRelaySettlementOperation().OperationID && kernel.CapabilityPlan(r.Plan.Grant).ExpiresAt.Equal(row.ExpiresAt)
}
