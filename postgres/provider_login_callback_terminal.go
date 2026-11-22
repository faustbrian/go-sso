package postgres

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"reflect"
	"strconv"
	"time"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

// Completed custody is correlation only. In particular, this representation
// cannot encode the original executable capability or issuance plan.
type providerLoginCallbackTerminalBinding struct {
	Schema   uint8
	Metadata providerLoginBindingMetadata
}

func providerLoginCallbackTerminalAAD(row providerLoginRowIdentity) (envelope.Context, error) {
	return providerLoginProtocolCallbackTerminalAAD(row, "")
}

func providerOAuth2LoginCallbackTerminalAAD(row providerLoginRowIdentity) (envelope.Context, error) {
	return providerLoginProtocolCallbackTerminalAAD(row, providerProtocolOAuth2)
}

func providerLoginProtocolCallbackTerminalAAD(row providerLoginRowIdentity, discriminator string) (envelope.Context, error) {
	protocol, _ := providerLoginCryptoProtocol(discriminator)
	if protocol == "" || row.Protocol != discriminator {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	if _, err := row.aad(); err != nil {
		return envelope.Context{}, err
	}
	plain, err := providerLoginPayloadEncode(row)
	defer clear(plain)
	if err != nil {
		return envelope.Context{}, identity.UnavailableError{}
	}
	digest := sha256.Sum256(plain)
	return envelope.NewContext(map[string]string{"profile": "identity-sso-" + protocol + "-login-terminal-v1", "binding": hex.EncodeToString(digest[:])})
}

// Seal only during acknowledged Generate; Apply must not call a potentially
// remote envelope provider while holding Work's transaction and row locks.
func (c providerLoginPayloadConfig) sealProviderLoginCallbackTerminal(ctx context.Context, found providerLoginCallbackLookup) ([]byte, error) {
	return c.sealProviderLoginProtocolCallbackTerminal(ctx, found, "")
}

func (c providerLoginPayloadConfig) sealProviderOAuth2LoginCallbackTerminal(ctx context.Context, found providerLoginCallbackLookup) ([]byte, error) {
	return c.sealProviderLoginProtocolCallbackTerminal(ctx, found, providerProtocolOAuth2)
}

func (c providerLoginPayloadConfig) sealProviderLoginProtocolCallbackTerminal(ctx context.Context, found providerLoginCallbackLookup, discriminator string) ([]byte, error) {
	if err := providerLoginPayloadContext(ctx); err != nil {
		return nil, err
	}
	if !c.ready() || found.CompletedAt != nil || found.ObservedAt.IsZero() || found.ObservedAt.Before(found.Row.IssuedAt) || !found.ObservedAt.Before(found.Row.ExpiresAt) || !c.validProviderLoginPendingBinding(found.Row, found.Binding) {
		return nil, identity.ForbiddenError{}
	}
	aad, err := providerLoginProtocolCallbackTerminalAAD(found.Row, discriminator)
	if err != nil {
		return nil, err
	}
	plain, err := providerLoginPayloadEncode(providerLoginCallbackTerminalBinding{Schema: 1, Metadata: found.Binding.Metadata})
	defer clear(plain)
	if err != nil || len(plain) > 49152 {
		return nil, identity.UnavailableError{}
	}
	return c.seal(ctx, aad, plain, 65536)
}

func (c providerLoginPayloadConfig) openProviderLoginCallbackTerminal(ctx context.Context, row providerLoginRowIdentity, wire []byte) (providerLoginStoredBinding, error) {
	return c.openProviderLoginProtocolCallbackTerminal(ctx, row, wire, "")
}

func (c providerLoginPayloadConfig) openProviderOAuth2LoginCallbackTerminal(ctx context.Context, row providerLoginRowIdentity, wire []byte) (providerLoginStoredBinding, error) {
	return c.openProviderLoginProtocolCallbackTerminal(ctx, row, wire, providerProtocolOAuth2)
}

func (c providerLoginPayloadConfig) openProviderLoginProtocolCallbackTerminal(ctx context.Context, row providerLoginRowIdentity, wire []byte, discriminator string) (providerLoginStoredBinding, error) {
	if err := providerLoginPayloadContext(ctx); err != nil {
		return providerLoginStoredBinding{}, err
	}
	if !c.ready() {
		return providerLoginStoredBinding{}, identity.ForbiddenError{}
	}
	aad, err := providerLoginProtocolCallbackTerminalAAD(row, discriminator)
	if err != nil {
		return providerLoginStoredBinding{}, err
	}
	plain, err := c.open(ctx, aad, wire, 65536, 49152)
	defer clear(plain)
	if err != nil {
		return providerLoginStoredBinding{}, err
	}
	var terminal providerLoginCallbackTerminalBinding
	if providerLoginPayloadDecode(plain, &terminal) != nil || terminal.Schema != 1 || !c.validProviderLoginBindingMetadata(row, terminal.Metadata) {
		return providerLoginStoredBinding{}, identity.ForbiddenError{}
	}
	canonical, err := providerLoginPayloadEncode(terminal)
	defer clear(canonical)
	if err != nil || !bytes.Equal(canonical, plain) {
		return providerLoginStoredBinding{}, identity.ForbiddenError{}
	}
	return providerLoginStoredBinding{Metadata: terminal.Metadata}, nil
}

func (c providerLoginPayloadConfig) validProviderLoginBindingMetadata(row providerLoginRowIdentity, m providerLoginBindingMetadata) bool {
	if m.Schema != 1 || m.Input.validate() != nil || !reflect.DeepEqual(m.Input.rowIdentity(), row) || m.StateKey == 0 || m.PKCEKey == 0 || c.StateKeys[m.StateKey] == ([32]byte{}) || c.PKCEKeys[m.PKCEKey] == ([32]byte{}) || m.PKCECommitment == ([32]byte{}) || m.CallbackCommand == row.StartCommandID {
		return false
	}
	if _, err := identity.ParseCommandID(string(m.CallbackCommand)); err != nil {
		return false
	}
	values := []string{m.Public.State, m.Public.Challenge}
	if row.Protocol == "" {
		values = append(values, m.Public.Nonce)
	} else if m.Public.Nonce != "" {
		return false
	}
	for _, value := range values {
		if len(value) != 43 {
			return false
		}
		raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
		valid := err == nil && len(raw) == 32
		clear(raw)
		if !valid {
			return false
		}
	}
	rawState, _ := base64.RawURLEncoding.Strict().DecodeString(m.Public.State)
	defer clear(rawState)
	digest, err := providerLoginProtocolStateDigest(c.StateKeys[m.StateKey], m.StateKey, row.TenantID, row.Protocol, rawState)
	return err == nil && hmac.Equal(digest[:], m.StateDigest[:])
}

func (c providerLoginPayloadConfig) validProviderLoginPendingBinding(row providerLoginRowIdentity, stored providerLoginStoredBinding) bool {
	if !c.validProviderLoginBindingMetadata(row, stored.Metadata) || c.Issuer == nil {
		return false
	}
	grant := kernel.CapabilityPlan(stored.Plan.Grant)
	_, purpose := providerLoginCryptoProtocol(row.Protocol)
	return purpose != "" && stored.Plan.Contributor == c.Issuer.Descriptor() && grant.Purpose == capability.Purpose(purpose) && grant.MaxUses == 1 && grant.ReplayKeyVersion != 0 && grant.ReplayDigest != ([32]byte{}) && grant.ProofFingerprint != ([32]byte{}) && grant.ExpiresAt.Equal(row.ExpiresAt) && len(stored.Proof) > 0 && len(stored.Proof) <= 32768 && sha256.Sum256(stored.Proof) == grant.ProofFingerprint
}

// Lock the exact pending primary key before evaluating the exclusive completion
// cutoff. A blocked UPDATE must not complete using a timestamp captured before
// its row lock became available. Terminal replay never matches the pending row.
const completeProviderLoginCallbackSQL = `WITH pending AS MATERIALIZED (
 SELECT tenant_id,state_key_version,state_digest FROM sso_providers.login_transactions
 WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3
 AND provider_version=$4::numeric AND credential_generation=$5::numeric AND mapping_version=$6::numeric
 AND start_command_id=$7 AND callback_command_id=$8 AND protocol='oidc'
 AND state_key_version=$9 AND state_digest=$10 AND pkce_key_version=$11 AND pkce_commitment=$12
 AND issued_at=$13::timestamptz AND expires_at=$14::timestamptz
 AND completed_at IS NULL AND verifier_envelope IS NOT NULL FOR UPDATE
 ), cutoff AS MATERIALIZED (SELECT pending.*,clock_timestamp() AS at FROM pending)
 UPDATE sso_providers.login_transactions l
 SET completed_at=cutoff.at,verifier_envelope=NULL,binding_envelope=$16
 FROM cutoff WHERE l.tenant_id=cutoff.tenant_id AND l.state_key_version=cutoff.state_key_version AND l.state_digest=cutoff.state_digest
 AND l.completed_at IS NULL AND l.verifier_envelope IS NOT NULL
 AND cutoff.at>=$13::timestamptz AND cutoff.at<LEAST($14::timestamptz,$15::timestamptz)
 AND octet_length($16::bytea) BETWEEN 1 AND 65536`

func providerLoginCallbackTerminalArgs(found providerLoginCallbackLookup, deadline time.Time, wire []byte) []any {
	row, metadata := found.Row, found.Binding.Metadata
	return []any{string(row.TenantID), row.OrganizationID, row.ProviderID,
		strconv.FormatUint(row.ProviderVersion, 10), strconv.FormatUint(row.CredentialGeneration, 10), strconv.FormatUint(row.MappingVersion, 10),
		string(row.StartCommandID), string(metadata.CallbackCommand), int64(metadata.StateKey), metadata.StateDigest[:],
		int64(metadata.PKCEKey), metadata.PKCECommitment[:], row.IssuedAt, row.ExpiresAt, deadline, wire}
}

// terminalWire belongs to the acknowledged generation's authenticated outer
// preparation output. This helper does no cryptographic or network IO in Work;
// the same Apply owns the session, vault and capability effects before commit.
func (s *ProviderLoginService) completeProviderLoginCallback(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, found providerLoginCallbackLookup, deadline time.Time, terminalWire []byte) error {
	if s == nil || ctx == nil || len(terminalWire) == 0 || len(terminalWire) > 65536 {
		return identity.ForbiddenError{}
	}
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return err
	}
	binding, _, _, err := w.FeatureCommandIdentity(owner)
	if err != nil {
		return err
	}
	if binding.TenantID != s.config.TenantID || !validProviderLoginCallbackDispositionScope(binding, found, deadline) || !s.payload.validProviderLoginPendingBinding(found.Row, found.Binding) {
		return identity.ForbiddenError{}
	}
	return eraseProviderLoginCallbackCustody(ctx, w, found, deadline, terminalWire)
}

func eraseProviderLoginCallbackCustody(ctx context.Context, w kernel.Work, found providerLoginCallbackLookup, deadline time.Time, terminalWire []byte) error {
	if len(terminalWire) == 0 || len(terminalWire) > 65536 {
		return identity.ForbiddenError{}
	}
	if _, err := envelope.ParseEnvelope(terminalWire); err != nil {
		return identity.ForbiddenError{}
	}
	n, err := w.Exec(ctx, completeProviderLoginCallbackSQL, providerLoginCallbackTerminalArgs(found, deadline, terminalWire)...)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ForbiddenError{}
	}
	return nil
}
