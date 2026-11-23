package postgres

import (
	"context"
	"encoding/base64"
	"math"
	"strconv"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/faustbrian/go-sso"
)

// ProviderGrantRevocationReceiptMigrationSource installs empty SSO-owned outcome
// projections after ProviderGrantFenceMigrationSource on the same primary, before
// enabling revocation settlement. Version is a caller-selected unused positive
// history version after that prerequisite. This source owns no deployment,
// migration runner, coordinator journal or transaction lifetime.
//
// Installation bounds foreign-key lock acquisition and neither scans nor changes
// existing grants. Code rollback retains receipts and fences; no destructive down
// SQL is provided. Apply the schema before code that reads or writes receipts.
type ProviderGrantRevocationReceiptMigrationSource struct{ Version migrations.Version }

var _ migrations.Source = ProviderGrantRevocationReceiptMigrationSource{}

// Load returns additive forward-only history without I/O. Invalid input and
// cancellation return no partial history. An existing table is an installation
// error rather than outcome history to adopt silently.
func (s ProviderGrantRevocationReceiptMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, sso.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "sso_provider_grant_revocation_receipts", migrations.TransactionModeDefault, providerGrantRevocationReceiptSQL, "")
	if err != nil {
		return nil, sso.ErrUnavailable
	}
	return []migrations.Migration{m}, nil
}

// No foreign key points to ciphertext: acknowledged settlement must erase it
// while preserving the original attempt fence and immutable outcome projection.
const providerGrantRevocationReceiptSQL = `SET LOCAL lock_timeout='5s';
CREATE TABLE sso_providers.provider_grant_revocation_receipts (
 tenant_id identity.directory_id NOT NULL,
 user_id identity.directory_id NOT NULL,
 callback_command_id bytea NOT NULL CHECK(octet_length(callback_command_id)=16),
 token_version identity.version NOT NULL,
 attempt_command_id bytea NOT NULL CHECK(octet_length(attempt_command_id)=16),
 attempt_purpose text COLLATE "C" NOT NULL DEFAULT 'identity.sso.provider-token.revoke' CHECK(attempt_purpose='identity.sso.provider-token.revoke'),
 attempt_generation identity.version NOT NULL,
 intent_digest bytea NOT NULL CHECK(octet_length(intent_digest)=32),
 outcome text COLLATE "C" NOT NULL CHECK(outcome IN ('acknowledged','refused','unknown','not_sent')),
 local_erased boolean NOT NULL CHECK(local_erased=(outcome='acknowledged')),
 PRIMARY KEY(tenant_id,user_id,attempt_command_id),
 UNIQUE(tenant_id,attempt_command_id),
 FOREIGN KEY(tenant_id,attempt_purpose,attempt_command_id) REFERENCES sso_providers.provider_grant_fences(tenant_id,attempt_purpose,attempt_command_id),
 CHECK(callback_command_id<>attempt_command_id)
);`

type providerGrantRevocationReceipt struct {
	Tenant              identity.TenantID
	User                identity.UserID
	Callback, Attempt   identity.CommandID
	Version, Generation uint64
	IntentDigest        [32]byte
	Outcome             providerGrantRevocationOutcome
	LocalErased         bool
}

func (r providerGrantRevocationReceipt) valid() bool {
	if _, err := identity.ParseIdentifierID(string(r.Tenant)); err != nil {
		return false
	}
	if _, err := identity.ParseIdentifierID(string(r.User)); err != nil {
		return false
	}
	if _, err := identity.ParseCommandID(string(r.Callback)); err != nil {
		return false
	}
	if _, err := identity.ParseCommandID(string(r.Attempt)); err != nil {
		return false
	}
	if r.Callback == r.Attempt || r.Version == 0 || r.Generation == 0 || r.IntentDigest == ([32]byte{}) ||
		r.LocalErased != (r.Outcome == providerGrantAcknowledged) {
		return false
	}
	switch r.Outcome {
	case providerGrantAcknowledged, providerGrantRefused, providerGrantUnknown, providerGrantNotSent:
		return true
	default:
		return false
	}
}

// Lock the exact original custody and fence before either retaining or erasing
// ciphertext. The receipt is inserted only if an acknowledged erasure affected
// exactly one row. A receipt conflict aborts the statement, including erasure.
const settleProviderGrantRevocationSQL = `WITH original AS MATERIALIZED (
 SELECT v.tenant_id,v.callback_command_id,v.token_version
 FROM sso_providers.provider_login_token_sets v
 JOIN sso_providers.provider_grant_fences f
  ON f.tenant_id=v.tenant_id AND f.grant_command_id=v.origin_command_id AND f.token_version=v.token_version
 WHERE v.tenant_id=$1 AND v.user_id=$2 AND v.origin_command_id=$3 AND v.callback_command_id=$4
  AND v.token_version=$5::text::identity.version AND v.origin_operation='identity.sso.oauth-callback'
  AND sha256(v.token_ciphertext)=$8 AND f.grant_purpose='identity.sso.oauth-callback'
  AND f.attempt_command_id=$6 AND f.attempt_purpose='identity.sso.provider-token.revoke'
  AND f.attempt_generation=$7::text::identity.version
 FOR UPDATE OF v FOR SHARE OF f
), erased AS (
 DELETE FROM sso_providers.provider_login_token_sets v USING original o
 WHERE v.tenant_id=o.tenant_id AND v.callback_command_id=o.callback_command_id AND v.token_version=o.token_version
  AND $11::boolean
 RETURNING v.tenant_id
)
INSERT INTO sso_providers.provider_grant_revocation_receipts
 (tenant_id,user_id,callback_command_id,token_version,attempt_command_id,attempt_generation,intent_digest,outcome,local_erased)
SELECT o.tenant_id,$2,$3,o.token_version,$6,$7::text::identity.version,$9,$10,$11
FROM original o WHERE NOT $11::boolean OR (SELECT count(*) FROM erased)=1`

// settleProviderGrantRevocation stages only an SSO-owned outcome projection in
// the caller's Work. The caller owns current/final authorization, correlation
// with the original native request, coordinator completion and transaction
// lifetime. A provider acknowledgement alone is not proof of a committed erasure.
func settleProviderGrantRevocation(ctx context.Context, w kernel.Work, receipt providerGrantRevocationReceipt, ciphertextDigest [32]byte) error {
	if ctx == nil || !receipt.valid() || ciphertextDigest == ([32]byte{}) {
		return identity.ForbiddenError{}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	callback, err := base64.RawURLEncoding.Strict().DecodeString(string(receipt.Callback))
	if err != nil {
		return identity.ForbiddenError{}
	}
	attempt, err := base64.RawURLEncoding.Strict().DecodeString(string(receipt.Attempt))
	if err != nil {
		return identity.ForbiddenError{}
	}
	n, err := w.Exec(ctx, settleProviderGrantRevocationSQL, string(receipt.Tenant), string(receipt.User), callback,
		string(receipt.Callback), strconv.FormatUint(receipt.Version, 10), attempt, strconv.FormatUint(receipt.Generation, 10),
		ciphertextDigest[:], receipt.IntentDigest[:], string(receipt.Outcome), receipt.LocalErased)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ForbiddenError{}
	}
	return nil
}

// Bind tenant/user as native text and the canonical attempt's decoded 16 bytes.
// The primary key makes both a matching receipt and absence an indexed lookup.
const readProviderGrantRevocationReceiptSQL = `SELECT tenant_id,user_id,callback_command_id,attempt_command_id,
 token_version::text,attempt_generation::text,intent_digest,outcome,local_erased
FROM sso_providers.provider_grant_revocation_receipts
WHERE tenant_id=$1 AND user_id=$2 AND attempt_command_id=$3`

func scanProviderGrantRevocationReceipt(row interface{ Scan(...any) error }) (providerGrantRevocationReceipt, error) {
	if row == nil {
		return providerGrantRevocationReceipt{}, identity.ForbiddenError{}
	}
	var receipt providerGrantRevocationReceipt
	var callback, attempt, digest []byte
	var tenant, user, version, generation, outcome string
	if err := row.Scan(&tenant, &user, &callback, &attempt, &version, &generation, &digest, &outcome, &receipt.LocalErased); err != nil {
		return providerGrantRevocationReceipt{}, err
	}
	if len(callback) != 16 || len(attempt) != 16 || len(digest) != len(receipt.IntentDigest) {
		return providerGrantRevocationReceipt{}, identity.ForbiddenError{}
	}
	receipt.Tenant, receipt.User = identity.TenantID(tenant), identity.UserID(user)
	receipt.Callback = identity.CommandID(base64.RawURLEncoding.EncodeToString(callback))
	receipt.Attempt = identity.CommandID(base64.RawURLEncoding.EncodeToString(attempt))
	receipt.Outcome = providerGrantRevocationOutcome(outcome)
	copy(receipt.IntentDigest[:], digest)
	var err error
	receipt.Version, err = strconv.ParseUint(version, 10, 64)
	if err != nil || strconv.FormatUint(receipt.Version, 10) != version {
		return providerGrantRevocationReceipt{}, identity.ForbiddenError{}
	}
	receipt.Generation, err = strconv.ParseUint(generation, 10, 64)
	if err != nil || strconv.FormatUint(receipt.Generation, 10) != generation || !receipt.valid() {
		return providerGrantRevocationReceipt{}, identity.ForbiddenError{}
	}
	return receipt, nil
}
