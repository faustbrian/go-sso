package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"math"
	"strconv"
	"strings"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

const providerGrantRefreshPreparationPlainLimit = 96 << 10
const providerGrantRefreshPreparationWireLimit = 100 << 10

func (p *providerGrantPhase) generateRefreshPreparation(ctx context.Context, aad envelope.Context, grant providerLoginStoredTokenBinding,
	ciphertext []byte, generation uint64, transport StaticOAuth2CompletionProfile,
) ([]byte, error) {
	prepared, err := p.service.completion.start.prepareProviderGrantRefresh(ctx, grant, ciphertext, p.binding().CommandID, generation, transport)
	defer prepared.clear()
	if err != nil {
		return nil, err
	}
	if !prepared.validFor(p.input.Grant) {
		return nil, identity.ForbiddenError{}
	}
	plain, err := providerLoginPayloadEncode(prepared)
	defer clear(plain)
	if err != nil || len(plain) > providerGrantRefreshPreparationPlainLimit {
		return nil, identity.UnavailableError{}
	}
	return p.service.outcomes.seal(ctx, aad, plain, providerGrantRefreshPreparationWireLimit)
}

func (p *providerGrantPhase) openRefreshPreparation(ctx context.Context, generation uint64, wire []byte) (providerGrantRefreshPreparation, error) {
	aad, err := p.outcomeContext(generation)
	if err != nil {
		return providerGrantRefreshPreparation{}, err
	}
	// The outer outcome opens only with the local preparation keys. Its
	// independently envelope-sealed successor is copied to the vault as bytes;
	// never invoke the vault key provider inside coordinator Work.
	plain, err := p.service.outcomes.open(ctx, aad, wire, providerGrantRefreshPreparationWireLimit, providerGrantRefreshPreparationPlainLimit)
	defer clear(plain)
	if err != nil {
		return providerGrantRefreshPreparation{}, err
	}
	var prepared providerGrantRefreshPreparation
	if providerLoginPayloadDecode(plain, &prepared) != nil || !prepared.validFor(p.input.Grant) {
		prepared.clear()
		return providerGrantRefreshPreparation{}, identity.ForbiddenError{}
	}
	return prepared, nil
}

// One locked predecessor and its exact acknowledged fence authorize the
// successor and immutable receipt together. Any receipt error rolls the update
// back. A non-success outcome cannot write a new generation.
const settleProviderGrantRefreshSQL = `WITH original AS MATERIALIZED (
 SELECT v.tenant_id,v.callback_command_id,v.token_version
 FROM sso_providers.provider_login_token_sets v
 JOIN sso_providers.provider_grant_fences f
  ON f.tenant_id=v.tenant_id AND f.grant_command_id=v.origin_command_id AND f.token_version=v.token_version
 WHERE v.tenant_id=$1 AND v.user_id=$2 AND v.origin_command_id=$3 AND v.callback_command_id=$4
  AND v.token_version=$5::text::identity.version AND v.origin_operation='identity.sso.oauth-callback'
  AND sha256(v.token_ciphertext)=$8 AND f.grant_purpose='identity.sso.oauth-callback'
  AND f.attempt_command_id=$6 AND f.attempt_purpose='identity.sso.provider-token.refresh'
  AND f.attempt_generation=$7::text::identity.version
 FOR UPDATE OF v FOR SHARE OF f
), rotated AS (
 UPDATE sso_providers.provider_login_token_sets v
 SET token_version=$11::text::identity.version, granted_scopes=string_to_array($12,' '), scope_reported=$13,
  received_at_seconds=$14, received_at_nanoseconds=$15, access_expires_at_seconds=$16,
  access_expires_at_nanoseconds=$17, token_ciphertext=$18
 FROM original o WHERE v.tenant_id=o.tenant_id AND v.callback_command_id=o.callback_command_id
  AND v.token_version=o.token_version AND $11::text IS NOT NULL
  AND $11::text::identity.version=o.token_version+1
 RETURNING v.tenant_id
)
INSERT INTO sso_providers.provider_grant_refresh_receipts
 (tenant_id,user_id,callback_command_id,token_version,attempt_command_id,attempt_generation,intent_digest,outcome,successor_version)
SELECT o.tenant_id,$2,$3,o.token_version,$6,$7::text::identity.version,$9,$10,$11::text::identity.version
FROM original o WHERE $11::text IS NULL OR (SELECT count(*) FROM rotated)=1`

func (p *providerGrantPhase) settleRefreshOutcome(ctx context.Context, w kernel.Work, generation uint64, wire []byte) error {
	prepared, err := p.openRefreshPreparation(ctx, generation, wire)
	defer prepared.clear()
	if err != nil {
		return err
	}
	b := p.binding()
	callback, err := base64.RawURLEncoding.Strict().DecodeString(string(p.ref.CommandID))
	if err != nil {
		return identity.ForbiddenError{}
	}
	attempt, err := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if err != nil {
		return identity.ForbiddenError{}
	}
	args := []any{string(b.TenantID), string(b.UserID), callback, string(p.ref.CommandID), strconv.FormatUint(p.ref.Version, 10),
		attempt, strconv.FormatUint(generation, 10), p.input.CiphertextDigest[:], p.intent[:], string(prepared.Outcome)}
	if next := prepared.Successor; next != nil {
		// Work accepts scalar arguments. Scope validation already excludes
		// spaces inside each item, so this delimiter preserves the exact list.
		args = append(args, strconv.FormatUint(p.ref.Version+1, 10), strings.Join(next.GrantedScopes, " "), next.ScopeReported,
			next.ReceivedAt.Unix(), int32(next.ReceivedAt.Nanosecond()), next.AccessExpiresAt.Unix(), int32(next.AccessExpiresAt.Nanosecond()), next.Ciphertext)
	} else {
		args = append(args, nil, nil, nil, nil, nil, nil, nil, nil)
	}
	count, err := w.Exec(ctx, settleProviderGrantRefreshSQL, args...)
	if err != nil {
		return err
	}
	if count != 1 {
		return identity.ForbiddenError{}
	}
	return nil
}

const readProviderGrantRefreshReceiptSQL = `SELECT tenant_id,user_id,callback_command_id,attempt_command_id,
 token_version::text,attempt_generation::text,intent_digest,outcome,successor_version::text
FROM sso_providers.provider_grant_refresh_receipts
WHERE tenant_id=$1 AND user_id=$2 AND attempt_command_id=$3`

func (p *providerGrantPhase) scanRefreshReceipt(row interface{ Scan(...any) error }) (uint64, ProviderGrantRefreshOutcome, error) {
	var tenant, user, original, generation, outcome string
	var callback, attempt, digest []byte
	var successor *string
	if err := row.Scan(&tenant, &user, &callback, &attempt, &original, &generation, &digest, &outcome, &successor); err != nil {
		return 0, "", err
	}
	b := p.binding()
	format := base64.RawURLEncoding.EncodeToString
	version, err := strconv.ParseUint(generation, 10, 64)
	if tenant != string(b.TenantID) || user != string(b.UserID) || format(callback) != string(p.ref.CommandID) ||
		format(attempt) != string(b.CommandID) || original != strconv.FormatUint(p.ref.Version, 10) ||
		err != nil || version == 0 || generation != strconv.FormatUint(version, 10) || !bytes.Equal(digest, p.intent[:]) {
		return 0, "", identity.ForbiddenError{}
	}
	switch effect := ProviderGrantRefreshOutcome(outcome); effect {
	case ProviderGrantRefreshRotated, ProviderGrantRefreshRetained:
		if successor != nil && p.ref.Version < math.MaxUint64 && *successor == strconv.FormatUint(p.ref.Version+1, 10) {
			return p.ref.Version + 1, effect, nil
		}
	case ProviderGrantRefreshRejected, ProviderGrantRefreshRefused, ProviderGrantRefreshUnknown, ProviderGrantRefreshNotSent:
		if successor == nil {
			return 0, effect, nil
		}
	}
	return 0, "", identity.ForbiddenError{}
}

func (p *providerGrantPhase) recoverRefreshOutcome(ctx context.Context, w kernel.RecoveryWork, attempt []byte) (kernel.RecoveryStatus, error) {
	b := p.binding()
	rows, err := w.Query(ctx, readProviderGrantRefreshReceiptSQL, string(b.TenantID), string(b.UserID), attempt)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	if !rows.Next() {
		return kernel.RecoveryUnknown, rows.Err()
	}
	if _, _, err := p.scanRefreshReceipt(rows); err != nil || rows.Next() || rows.Err() != nil {
		return kernel.RecoveryUnknown, identity.ForbiddenError{}
	}
	return kernel.RecoveryCommitted, nil
}
