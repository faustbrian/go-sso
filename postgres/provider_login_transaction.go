package postgres

import (
	"context"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

// Prepared storage projection. Keep the PKCE verifier separate from the
// binding ciphertext so terminal processing can erase only recoverable custody.
type providerLoginTransactionState struct {
	callbackCommand             identity.CommandID
	stateKey, pkceKey           uint32
	stateDigest, pkceCommitment [32]byte
	binding, verifier           envelope.Envelope
	issuedAt, expiresAt         time.Time
}

const insertProviderLoginPrefixSQL = `INSERT INTO sso_providers.login_transactions
 (tenant_id,organization_id,provider_id,provider_version,credential_generation,mapping_version,
 start_command_id,callback_command_id,protocol,state_key_version,state_digest,pkce_key_version,
 pkce_commitment,binding_envelope,verifier_envelope,issued_at,expires_at)
 SELECT $1,$2,$3,$4::numeric,$5::numeric,$6::numeric,$7,$8,`

const insertProviderLoginSuffixSQL = `,$9,$10,$11,$12,$13,$14,$15,$16
 WHERE $15::timestamptz<=statement_timestamp()
 AND statement_timestamp()<LEAST($16::timestamptz,$17::timestamptz)`

const insertProviderLoginTransactionSQL = insertProviderLoginPrefixSQL + `'oidc'` + insertProviderLoginSuffixSQL
const insertProviderLoginOAuth2TransactionSQL = insertProviderLoginPrefixSQL + `'oauth2'` + insertProviderLoginSuffixSQL
const insertProviderLoginSAMLTransactionSQL = insertProviderLoginPrefixSQL + `'saml',$9,$10,NULL,NULL,$11,NULL,$12,$13
 WHERE $12::timestamptz<=statement_timestamp()
 AND statement_timestamp()<LEAST($13::timestamptz,$14::timestamptz)`

// Stage only during the original enrolled Apply. The calling feature also
// owns pre-auth possession, risk, and capability issuance in this same Work;
// this helper never exposes a redirect or commits a transaction on its own.
func (r *ProviderRouter) persistProviderLoginStart(ctx context.Context, work kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, authority providerLoginAuthority, mapping uint64, state providerLoginTransactionState) error {
	if err := work.RequireFeatureCommand(ctx, owner, command); err != nil {
		return err
	}
	b, _, _, err := work.FeatureCommandIdentity(owner)
	if err != nil {
		return err
	}
	protocol := authority.route.Protocol()
	if _, err := identity.ParseCommandID(string(state.callbackCommand)); err != nil || state.callbackCommand == b.CommandID || b.RecordID != string(b.CommandID) ||
		state.stateKey == 0 || state.stateDigest == ([32]byte{}) || state.issuedAt.IsZero() || !state.issuedAt.Before(state.expiresAt) ||
		state.expiresAt.Sub(state.issuedAt) > providerLoginMaximumStateLifetime(protocol) {
		return identity.ForbiddenError{}
	}
	selected, err := authority.route.Bindings()
	if err != nil {
		return identity.ForbiddenError{}
	}
	sealedBinding, err := state.binding.MarshalBinary()
	defer clear(sealedBinding)
	if err != nil || len(sealedBinding) == 0 || len(sealedBinding) > 65536 {
		return identity.ForbiddenError{}
	}
	if err := r.requireProviderLoginAuthority(ctx, work, owner, authority, mapping); err != nil {
		return err
	}
	if protocol == providerProtocolSAML {
		if state.pkceKey != 0 || state.pkceCommitment != ([32]byte{}) || state.verifier.KeyReference() != "" {
			return identity.ForbiddenError{}
		}
		n, err := work.Exec(ctx, insertProviderLoginSAMLTransactionSQL,
			string(b.TenantID), string(selected.Proof.Key.OrganizationID), string(selected.ProviderID),
			strconv.FormatUint(selected.ProviderVersion, 10), strconv.FormatUint(selected.CredentialGeneration, 10), strconv.FormatUint(mapping, 10),
			string(b.CommandID), string(state.callbackCommand), int64(state.stateKey), state.stateDigest[:],
			sealedBinding, state.issuedAt, state.expiresAt, providerLoginDeadline(selected, authority.organization))
		return providerLoginInsertOutcome(n, err)
	}
	if state.pkceKey == 0 || state.pkceCommitment == ([32]byte{}) {
		return identity.ForbiddenError{}
	}
	sealedVerifier, err := state.verifier.MarshalBinary()
	defer clear(sealedVerifier)
	if err != nil || len(sealedVerifier) == 0 || len(sealedVerifier) > 4096 {
		return identity.ForbiddenError{}
	}
	query := insertProviderLoginTransactionSQL
	if protocol == providerProtocolOAuth2 {
		query = insertProviderLoginOAuth2TransactionSQL
	}
	n, err := work.Exec(ctx, query,
		string(b.TenantID), string(selected.Proof.Key.OrganizationID), string(selected.ProviderID),
		strconv.FormatUint(selected.ProviderVersion, 10), strconv.FormatUint(selected.CredentialGeneration, 10), strconv.FormatUint(mapping, 10),
		string(b.CommandID), string(state.callbackCommand), int64(state.stateKey), state.stateDigest[:], int64(state.pkceKey), state.pkceCommitment[:],
		sealedBinding, sealedVerifier, state.issuedAt, state.expiresAt, providerLoginDeadline(selected, authority.organization))
	return providerLoginInsertOutcome(n, err)
}

func providerLoginInsertOutcome(n int64, err error) error {
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ForbiddenError{}
	}
	return nil
}
