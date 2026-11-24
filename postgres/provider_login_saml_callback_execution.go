package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"reflect"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

type samlLoginCallbackPhase struct {
	effect         *sessionpg.SSOSAMLSigninEffect
	admitted       samlCallbackAdmission
	replay         samlCallbackReplay
	logoutSubject  *samlStoredLogoutSubject
	logoutCustody  *SAMLLogoutSubjectCustody
	preparedLogout *samlPreparedLogoutSubject
}

// Persist the replay commitment and the original reconciliation cutoff, not
// either raw SAML identifier or provider response. Replay custody is created
// by the coordinator Work, never by the trusted verifier or this preparation.
type samlCallbackReplay struct {
	Response, Assertion [32]byte
	RetainUntil         time.Time
}

type samlCallbackOutput struct {
	Schema                 uint8
	Fields                 []identity.FeatureField
	Risk                   providerLoginStoredAdmission
	ObservedAt, ValidUntil time.Time
	Replay                 samlCallbackReplay
	Terminal               []byte
	LogoutSubject          *samlStoredLogoutSubject   `json:",omitempty"`
	LogoutCustody          *samlPreparedLogoutSubject `json:",omitempty"`
}

func encodeSAMLCallbackOutput(saved samlCallbackOutput, subject *samlStoredLogoutSubject) ([]byte, error) {
	if subject != nil {
		saved.Schema, saved.LogoutSubject = 2, subject
	}
	return providerLoginPayloadEncode(saved)
}

func decodeSAMLCallbackOutput(plain []byte, selected *samlStoredLogoutSubject) (samlCallbackOutput, error) {
	var saved samlCallbackOutput
	if err := providerLoginPayloadDecode(plain, &saved); err != nil {
		clearSAMLCallbackOutput(saved)
		return samlCallbackOutput{}, err
	}
	valid := saved.Schema == 1 && saved.LogoutSubject == nil && selected == nil
	if selected != nil {
		valid = saved.Schema == 2 && saved.LogoutSubject != nil && *saved.LogoutSubject == *selected
	}
	if !valid {
		clearSAMLCallbackOutput(saved)
		return samlCallbackOutput{}, identity.ForbiddenError{}
	}
	return saved, nil
}

func clearSAMLCallbackOutput(saved samlCallbackOutput) {
	clear(saved.Terminal)
	if saved.LogoutCustody != nil {
		clear(saved.LogoutCustody.Envelope)
	}
}

var _ kernel.SSOSAMLSigninContributor = (*providerLoginCallbackPhase)(nil)

func (p *providerLoginCallbackPhase) samlOutputContext(generation uint64) (envelope.Context, error) {
	f, ok := p.command.Feature()
	if !ok || generation == 0 || p.service == nil || p.service.saml == nil {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	encoded, err := providerLoginPayloadEncode(struct {
		Original                  identity.FeatureCommandSpec
		StartProfile              [32]byte
		Generation                uint64
		Audience, PolicyNamespace string
	}{f, p.service.saml.digest, generation, p.policy.Audience, p.policy.PolicyNamespace})
	defer clear(encoded)
	if err != nil {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	digest := sha256.Sum256(encoded)
	return envelope.NewContext(map[string]string{"owner": "sso/postgres", "purpose": "saml-acs-output-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}

func (p *providerLoginCallbackPhase) generateSAMLAccepted(ctx context.Context, generation uint64, admission risk.AuthenticationAdmission, aad envelope.Context) ([]byte, error) {
	now := p.service.router.config.Clock.Now().UTC().Truncate(time.Microsecond)
	selected := p.saml.admitted
	until := selected.validUntil.UTC().Truncate(time.Microsecond)
	if !now.Before(until) || selected.recipient.member.Version != p.authority.organization.Version {
		return nil, identity.ForbiddenError{}
	}
	if err := p.checkOriginal(now); err != nil {
		return nil, err
	}
	if err := admission.CheckAt(ctx, now); err != nil {
		return nil, err
	}
	retained, err := samlReplayRetainUntil(selected.validatedAt, selected.evidence.AssertionExpiresAt)
	if err != nil {
		return nil, err
	}
	replay := samlCallbackReplay{Response: sha256.Sum256([]byte(selected.evidence.ResponseID)),
		Assertion: sha256.Sum256([]byte(selected.evidence.AssertionID)), RetainUntil: retained}
	fields, command, err := p.prepareCallbackSession(selected.recipient, now, until, selected.recipient.member.Version, nil)
	if err != nil {
		return nil, err
	}
	var logout *samlPreparedLogoutSubject
	if p.saml.logoutCustody != nil {
		record, err := sessionpg.SSOSAMLSigninSession(command)
		if err != nil {
			return nil, err
		}
		feature, _ := command.Feature()
		scope := p.logoutIssuerScope()
		anchor, err := samlLogoutSubjectAnchor(feature.Binding, record, scope)
		if err != nil {
			return nil, err
		}
		logout, err = p.saml.logoutCustody.prepare(ctx, p.service.payload.Envelope, anchor, scope, p.saml.logoutSubject)
		if err != nil {
			return nil, err
		}
		defer clear(logout.Envelope)
	}
	terminal, err := p.service.payload.sealProviderLoginProtocolCallbackTerminal(ctx, p.found, providerProtocolSAML)
	if err != nil {
		return nil, err
	}
	defer clear(terminal)
	plain, err := encodeSAMLCallbackOutput(samlCallbackOutput{Schema: 1, Fields: fields, Risk: providerLoginStoredAdmission(admission.Prepared()),
		ObservedAt: p.found.ObservedAt, ValidUntil: until, Replay: replay, Terminal: terminal, LogoutCustody: logout}, p.saml.logoutSubject)
	defer clear(plain)
	if err != nil || len(plain) > providerLoginCallbackPlainLimit {
		return nil, identity.UnavailableError{}
	}
	return p.service.payload.seal(ctx, aad, plain, providerLoginCallbackCipherLimit)
}

func (p *providerLoginCallbackPhase) restoreSAMLAccepted(ctx context.Context, generation uint64, wire []byte) error {
	digest := sha256.Sum256(wire)
	if p.execution != nil {
		if p.execution.generation == generation && p.execution.digest == digest {
			return nil
		}
		return identity.ForbiddenError{}
	}
	aad, err := p.samlOutputContext(generation)
	if err != nil {
		return err
	}
	plain, err := p.service.payload.open(ctx, aad, wire, providerLoginCallbackCipherLimit, providerLoginCallbackPlainLimit)
	if err != nil {
		return err
	}
	defer clear(plain)
	var saved samlCallbackOutput
	owned := false
	defer func() {
		if !owned {
			clearSAMLCallbackOutput(saved)
		}
	}()
	saved, err = decodeSAMLCallbackOutput(plain, p.saml.logoutSubject)
	if err != nil {
		return identity.ForbiddenError{}
	}
	selected := p.saml.admitted
	if saved.ObservedAt.Before(p.found.Row.IssuedAt) || saved.ObservedAt.After(p.found.ObservedAt) ||
		!saved.ValidUntil.After(saved.ObservedAt) || saved.ValidUntil.After(saved.ObservedAt.Add(20*time.Second)) ||
		saved.ValidUntil.After(p.found.Row.ExpiresAt) || !saved.Replay.RetainUntil.After(saved.ValidUntil) ||
		saved.Replay.RetainUntil.Nanosecond()%1000 != 0 || saved.Replay.Response == saved.Replay.Assertion ||
		saved.Replay.Response != sha256.Sum256([]byte(selected.evidence.ResponseID)) || saved.Replay.Assertion != sha256.Sum256([]byte(selected.evidence.AssertionID)) {
		return identity.ForbiddenError{}
	}
	command, err := p.callbackCommandWithOutput(saved.Fields)
	if err != nil {
		return err
	}
	record, err := sessionpg.SSOSAMLSigninSession(command)
	if err != nil {
		return err
	}
	account, err := kernel.SSOSAMLSigninAccount(command)
	if err != nil || !reflect.DeepEqual(account, selected.recipient.account) {
		return identity.ForbiddenError{}
	}
	fields, err := p.callbackAccountSessionFields(record, account)
	if err != nil || !reflect.DeepEqual(fields, saved.Fields) {
		return identity.ForbiddenError{}
	}
	if err := p.checkRestoredSession(record, account, providerLoginCallbackOutput{ObservedAt: saved.ObservedAt, ValidUntil: saved.ValidUntil}, selected.recipient.member.Version); err != nil {
		return err
	}
	bindings, err := record.Bindings()
	if err != nil {
		return err
	}
	vector, err := bindings.Authority.Bindings()
	if err != nil || vector.Factor.Binding.Version != selected.recipient.factorVersion || vector.Authorization.Version != selected.recipient.policyVersion {
		return identity.ForbiddenError{}
	}
	if (p.saml.logoutCustody == nil) != (saved.LogoutCustody == nil) {
		return identity.ForbiddenError{}
	}
	if p.saml.logoutCustody != nil {
		feature, _ := command.Feature()
		scope := p.logoutIssuerScope()
		anchor, err := samlLogoutSubjectAnchor(feature.Binding, record, scope)
		if err != nil || p.saml.logoutCustody.validatePrepared(saved.LogoutCustody, anchor, scope, saved.LogoutSubject) != nil {
			return identity.ForbiddenError{}
		}
	}
	terminal, err := p.service.payload.openProviderLoginProtocolCallbackTerminal(ctx, p.found.Row, saved.Terminal, providerProtocolSAML)
	if err != nil || terminal.Metadata != p.found.Binding.Metadata {
		return identity.ForbiddenError{}
	}
	scope, subject := p.riskScope()
	admission, err := p.service.custody.Restore(ctx, risk.PreparedAuthenticationAdmission(saved.Risk), scope, subject)
	if err != nil {
		return err
	}
	p.execution = &providerLoginCallbackExecution{command: command, record: record, admission: admission, terminal: saved.Terminal,
		generation: generation, digest: digest, validUntil: earlierLoginTime(saved.ValidUntil, selected.validUntil)}
	p.saml.replay = saved.Replay
	p.saml.logoutSubject = saved.LogoutSubject
	p.saml.preparedLogout = saved.LogoutCustody
	owned = true
	return nil
}

func (p *providerLoginCallbackPhase) applySAMLCallback(ctx context.Context, work kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	binding, fingerprint, generation, err := work.FeatureCommandIdentity(p)
	if err != nil {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	row, replay := p.found.Row, p.saml.replay
	claim := samlReplayClaim{Tenant: binding.TenantID, OrganizationID: row.OrganizationID, ProviderID: row.ProviderID,
		IssuerDigest: sha256.Sum256([]byte(p.original.Issuer)), ResponseDigest: replay.Response, AssertionDigest: replay.Assertion,
		Fingerprint: fingerprint, CommandID: binding.CommandID, Generation: generation, RetainUntil: replay.RetainUntil}
	if err := reserveSAMLReplayInWork(ctx, work, p, claim); err != nil {
		return identity.FeatureReceipt{}, err
	}
	receipt, err := p.saml.effect.Apply(ctx, work, p, command, p.flow)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.checkProviderCurrent(ctx, work); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.saml.logoutCustody != nil {
		anchor, err := samlLogoutSubjectAnchor(binding, p.execution.record, p.logoutIssuerScope())
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		if err := persistSAMLLogoutSubject(ctx, work, p, command, anchor, p.saml.preparedLogout); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	if err := p.service.completeProviderLoginCallback(ctx, work, p, command, p.found, p.execution.validUntil, p.execution.terminal); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return receipt, nil
}

func (p *providerLoginCallbackPhase) logoutIssuerScope() samlLogoutIssuerScope {
	row := p.found.Row
	return samlLogoutIssuerScope{row.OrganizationID, row.ProviderID, p.original.Issuer}
}

func (p *providerLoginCallbackPhase) recoverSAMLCallback(ctx context.Context, work kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	status, err := p.saml.effect.Recover(ctx, work, p)
	if err != nil || status != kernel.RecoveryNotCommitted {
		return status, err
	}
	if p.saml.logoutCustody != nil {
		status, err = recoverSAMLLogoutSubjectAbsence(ctx, work, p)
		if err != nil || status != kernel.RecoveryNotCommitted {
			return status, err
		}
	}
	// A recovery invocation can settle only an uncommitted original command.
	// Any retained replay member contradicts that claim. Do not select by
	// current fingerprint or expiry: a different member is unknown too.
	return verifySAMLReplayAbsentInRecovery(ctx, work, p)
}
