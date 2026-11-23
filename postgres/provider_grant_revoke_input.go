package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

type providerGrantRevokeInput struct {
	Command          providerLoginStoredCommand
	Grant            providerLoginStoredTokenBinding
	CiphertextDigest [32]byte
	Intent           [32]byte
	Session          []identity.FeatureField
	StartedAt        time.Time
	ValidUntil       time.Time
}

const providerGrantRevocationReadSQL = `SELECT organization_id,provider_id,start_command_id,callback_command_id,callback_generation::text,
 tenant_id::text,user_id::text,account_id::text,account_provider::text,issuer,subject,account_version::text,social_link_version::text,
 token_version::text,provider_version::text,credential_generation::text,mapping_version::text,requested_scopes,granted_scopes,
 scope_reported,received_at_seconds,received_at_nanoseconds,access_expires_at_seconds,access_expires_at_nanoseconds,token_ciphertext
FROM sso_providers.provider_login_token_sets
WHERE tenant_id=$1 AND callback_command_id=$2 AND user_id=$3 AND origin_operation='identity.sso.oauth-callback'`

func (p *providerGrantRevokePhase) readGrant(ctx context.Context) (b providerLoginStoredTokenBinding, ciphertext []byte, err error) {
	start := p.service.completion.start
	row := start.router.pool.Raw().QueryRow(ctx, providerGrantRevocationReadSQL, string(p.ref.TenantID), string(p.ref.CommandID), string(p.record.UserID))
	var tenant, user, account, startID, callback string
	var receivedSec, receivedNS, expiresSec, expiresNS int64
	var generation, accountVersion, linkVersion, version, providerVersion, credVersion, mapping string
	err = row.Scan(&b.Organization, &b.Provider, &startID, &callback, &generation,
		&tenant, &user, &account, &b.Account.Provider, &b.Account.Issuer, &b.Account.Subject, &accountVersion, &linkVersion,
		&version, &providerVersion, &credVersion, &mapping, &b.RequestedScopes, &b.GrantedScopes, &b.ScopeReported,
		&receivedSec, &receivedNS, &expiresSec, &expiresNS, &ciphertext)
	if err != nil {
		clear(ciphertext)
		return b, nil, providerError(ctx, err)
	}
	b.Start, b.Callback = identity.CommandID(startID), identity.CommandID(callback)
	b.Account.TenantID, b.Account.UserID, b.Account.ID = identity.TenantID(tenant), identity.UserID(user), identity.AccountID(account)
	b.ReceivedAt, b.AccessExpiresAt = time.Unix(receivedSec, receivedNS).UTC(), time.Unix(expiresSec, expiresNS).UTC()
	for _, field := range []struct {
		wire string
		dst  *uint64
	}{{generation, &b.CallbackGeneration}, {accountVersion, &b.Account.Version}, {linkVersion, &b.SocialLinkVersion},
		{version, &b.Version}, {providerVersion, &b.ProviderVersion}, {credVersion, &b.CredentialGeneration}, {mapping, &b.MappingVersion}} {
		value, err := strconv.ParseUint(field.wire, 10, 64)
		if err != nil || value == 0 {
			clear(ciphertext)
			return providerLoginStoredTokenBinding{}, nil, identity.ForbiddenError{}
		}
		*field.dst = value
	}
	if !p.matchesGrant(b) || len(ciphertext) == 0 || len(ciphertext) > 65536 {
		clear(ciphertext)
		return providerLoginStoredTokenBinding{}, nil, identity.ForbiddenError{}
	}
	return b, ciphertext, nil
}

func (p *providerGrantRevokePhase) matchesGrant(b providerLoginStoredTokenBinding) bool {
	_, err := b.aad()
	return err == nil && b.Account.TenantID == p.ref.TenantID && b.Account.UserID == p.record.UserID &&
		b.Callback == p.ref.CommandID && b.Organization == string(p.ref.OrganizationID) && b.Provider == string(p.ref.ProviderID) &&
		b.Account.Subject == p.ref.ProviderSubject && b.CredentialGeneration == p.ref.CredentialGeneration &&
		b.Version == p.ref.Version && b.ProviderVersion == p.record.Authentication.ProofVersion
}

func (p *providerGrantRevokePhase) newBinding(id identity.CommandID) identity.CommandBinding {
	op, start := p.registration().Operation, p.service.completion.start
	return identity.CommandBinding{CommandID: id, TenantID: p.ref.TenantID, UserID: p.record.UserID, ActorID: identity.ActorID(p.record.UserID),
		ActorKind: p.scope().ActorKind, PolicyID: start.config.PolicyID, PolicyVersion: start.policyVersion,
		OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion,
		RecordID: string(p.ref.CommandID), CorrelationID: string(id)}
}

func (p *providerGrantRevokePhase) requestContext(k kernel.RequestKeyPreparationBinding) (envelope.Context, error) {
	start := p.service.completion.start
	if k.Feature != p.registration() || k.Scope != p.scope() || k.Namespace != start.config.RequestKeys.Namespace ||
		k.PolicyVersion != start.policyVersion || k.IntentDigest == ([32]byte{}) || k.Admission.FingerprintKeyVersion == 0 ||
		p.newBinding(k.Admission.CommandID).ValidateFor(p.registration().Operation) != nil {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	wire, err := json.Marshal(providerLoginStoredRequestKey(k))
	defer clear(wire)
	if err != nil {
		return envelope.Context{}, identity.UnavailableError{}
	}
	digest := sha256.Sum256(wire)
	return envelope.NewContext(map[string]string{"profile": "sso-provider-grant-revoke-request-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}

func (p *providerGrantRevokePhase) PrepareRequestKey(ctx context.Context, k kernel.RequestKeyPreparationBinding, request identity.RequestIntent) ([]byte, error) {
	aad, err := p.requestContext(k)
	if err != nil {
		return nil, err
	}
	fields, ok := request.Fields()
	if !ok || len(fields) != 1 || fields[0].Name != "sso.vault.intent" || fields[0].Value.Kind != identity.FeatureBytes || !bytes.Equal(fields[0].Value.Bytes, p.intent[:]) {
		return nil, identity.ForbiddenError{}
	}
	grant, ciphertext, err := p.readGrant(ctx)
	defer clear(ciphertext)
	if err != nil {
		return nil, err
	}
	start := p.service.completion.start
	original, err := sessionpg.OriginalSessionFields(p.observed.Session)
	if err != nil {
		return nil, err
	}
	until := p.observed.ValidUntil().UTC()
	if cap := p.started.Add(20 * time.Second); cap.Before(until) {
		until = cap
	}
	input := providerGrantRevokeInput{Command: providerLoginStoredCommand(p.newBinding(k.Admission.CommandID)), Grant: grant,
		CiphertextDigest: sha256.Sum256(ciphertext), Intent: p.intent, Session: original, StartedAt: p.started,
		ValidUntil: until}
	now := start.router.config.Clock.Now().UTC()
	if p.observed.ValidateAt(now) != nil || !input.validAt(now) {
		return nil, identity.ForbiddenError{}
	}
	wire, err := json.Marshal(input)
	defer clear(wire)
	if err != nil || len(wire) > providerLoginRequestPlainLimit {
		return nil, identity.UnavailableError{}
	}
	return start.payload.seal(ctx, aad, wire, providerLoginRequestWireLimit)
}

func (p *providerGrantRevokePhase) restoreInput(ctx context.Context, k kernel.RequestKeyPreparationBinding, ciphertext []byte) error {
	aad, err := p.requestContext(k)
	if err != nil {
		return err
	}
	wire, err := p.service.completion.start.payload.open(ctx, aad, ciphertext, providerLoginRequestWireLimit, providerLoginRequestPlainLimit)
	defer clear(wire)
	if err != nil {
		return err
	}
	var input providerGrantRevokeInput
	if providerLoginPayloadDecode(wire, &input) != nil || identity.CommandBinding(input.Command) != p.newBinding(k.Admission.CommandID) ||
		input.CiphertextDigest == ([32]byte{}) || input.Intent != p.intent || !p.matchesGrant(input.Grant) || !input.validAt(input.StartedAt) {
		return identity.ForbiddenError{}
	}
	source, err := sessionpg.OriginalSessionFromFields(p.ref.TenantID, p.record.UserID, input.Session)
	if err != nil {
		return err
	}
	spec, err := source.Bindings()
	if err != nil {
		return err
	}
	p.input, p.original, p.inputDigest = input, source, sha256.Sum256(wire)
	p.command, err = identity.NewFeatureCommand(identity.FeatureCommandSpec{Operation: p.registration().Operation, Binding: p.binding(), Fields: []identity.FeatureField{
		revokeBytes("sso.vault.input", p.inputDigest[:]),
		{Name: "sso.vault.session-id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: spec.SessionID}},
		{Name: "sso.vault.session-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: spec.Version}},
	}})
	return err
}

func (i providerGrantRevokeInput) validAt(now time.Time) bool {
	return !i.StartedAt.IsZero() && !now.Before(i.StartedAt) && now.Before(i.ValidUntil) &&
		!i.ValidUntil.After(i.StartedAt.Add(20*time.Second))
}

func revokeBytes(name string, value []byte) identity.FeatureField {
	return identity.FeatureField{Name: name, Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: value}}
}
