//go:build integration

package postgres

import (
	"context"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

const CompleteProviderLoginCallbackSQLForTest = completeProviderLoginCallbackSQL

// Exercise the exact terminal custody SQL without substituting a Work handle.
// Feature authority is tested through the primary-owned composed callback.
func StageProviderLoginCallbackTerminalForTest(ctx context.Context, tx pgx.Tx, service *ProviderLoginService, state string, deadline time.Time) (int64, error) {
	found, err := service.lookupProviderLoginCallback(ctx, state)
	if err != nil {
		return 0, err
	}
	defer clear(found.Binding.Proof)
	wire, err := service.payload.sealProviderLoginCallbackTerminal(ctx, found)
	if err != nil {
		return 0, err
	}
	defer clear(wire)
	result, err := tx.Exec(ctx, completeProviderLoginCallbackSQL, providerLoginCallbackTerminalArgs(found, deadline, wire)...)
	return result.RowsAffected(), err
}

func RecordProviderLoginCallbackTerminalForTest(ctx context.Context, service *ProviderLoginService, state string) (time.Time, error) {
	found, err := service.lookupProviderLoginCallback(ctx, state)
	if err != nil {
		return time.Time{}, err
	}
	defer clear(found.Binding.Proof)
	wire, err := service.payload.sealProviderLoginCallbackTerminal(ctx, found)
	if err != nil {
		return time.Time{}, err
	}
	defer clear(wire)
	deadline := earlierLoginTime(found.ObservedAt.Add(20*time.Second), found.Row.ExpiresAt)
	result, err := service.router.pool.Raw().Exec(ctx, completeProviderLoginCallbackSQL, providerLoginCallbackTerminalArgs(found, deadline, wire)...)
	if err != nil {
		return time.Time{}, err
	}
	if result.RowsAffected() != 1 {
		return time.Time{}, identity.ForbiddenError{}
	}
	var completed time.Time
	err = service.router.pool.Raw().QueryRow(ctx, `SELECT completed_at FROM sso_providers.login_transactions WHERE tenant_id=$1 AND state_key_version=$2 AND state_digest=$3`,
		string(found.Row.TenantID), int64(found.Binding.Metadata.StateKey), found.Binding.Metadata.StateDigest[:]).Scan(&completed)
	return completed, err
}
