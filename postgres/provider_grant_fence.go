package postgres

import (
	"context"
	"encoding/base64"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	providerGrantRevokeOperation  = "identity.sso.provider-token.revoke"
	providerGrantRefreshOperation = "identity.sso.provider-token.refresh"
)

type providerGrantFenceClaim struct {
	Tenant           identity.TenantID
	Callback         identity.CommandID
	TokenVersion     uint64
	CiphertextDigest [32]byte
	Attempt          identity.CommandID
	Operation        string
	Generation       uint64
}

// Postgres holds a share lock on the exact custody row until insertion is
// acknowledged. A competing caller cannot claim the same grant generation
// under a different identity command, actor, or refresh/revoke operation.
const claimProviderGrantFenceSQL = `INSERT INTO sso_providers.provider_grant_fences
 (tenant_id,grant_command_id,token_version,attempt_command_id,attempt_purpose,attempt_generation,started_at)
SELECT v.tenant_id,v.origin_command_id,v.token_version,$4,$5,$6::text::identity.version,clock_timestamp()
FROM sso_providers.provider_login_token_sets v
WHERE v.tenant_id=$1 AND v.callback_command_id=$2 AND v.token_version=$3::text::identity.version
 AND v.origin_operation='identity.sso.oauth-callback' AND sha256(v.token_ciphertext)=$7
FOR SHARE OF v
ON CONFLICT DO NOTHING`

// Only an already admitted coordinator generation may call this, using the
// digest of the exact authenticated vault ciphertext. An acknowledged insert
// confers a one-time fence for this invocation, not current authorization or
// a provider outcome. An existing row never authorizes either a retry or a
// send after lost acknowledgement. No lock survives the SQL call.
func claimProviderGrantFence(ctx context.Context, pool *pgxpool.Pool, claim providerGrantFenceClaim) error {
	if ctx == nil || pool == nil || !providerID(string(claim.Tenant)) || claim.TokenVersion == 0 || claim.Generation == 0 ||
		claim.Callback == claim.Attempt || claim.CiphertextDigest == ([32]byte{}) ||
		claim.Operation != providerGrantRevokeOperation && claim.Operation != providerGrantRefreshOperation {
		return identity.ForbiddenError{}
	}
	if _, err := identity.ParseCommandID(string(claim.Callback)); err != nil {
		return identity.ForbiddenError{}
	}
	if _, err := identity.ParseCommandID(string(claim.Attempt)); err != nil {
		return identity.ForbiddenError{}
	}
	attempt, err := base64.RawURLEncoding.Strict().DecodeString(string(claim.Attempt))
	if err != nil {
		return identity.ForbiddenError{}
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	tag, err := pool.Exec(ctx, claimProviderGrantFenceSQL, string(claim.Tenant), string(claim.Callback),
		strconv.FormatUint(claim.TokenVersion, 10), attempt, claim.Operation, strconv.FormatUint(claim.Generation, 10), claim.CiphertextDigest[:])
	if err != nil || ctx.Err() != nil {
		return identity.UnknownCommitError{CommandID: claim.Attempt}
	}
	switch tag.RowsAffected() {
	case 1:
		return nil
	case 0:
		return identity.ConflictError{}
	default:
		return identity.UnknownCommitError{CommandID: claim.Attempt}
	}
}
