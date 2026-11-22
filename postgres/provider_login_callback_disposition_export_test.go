//go:build integration

package postgres

import (
	"context"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

const ProviderLoginCallbackDispositionFenceForTest = providerLoginCallbackDispositionFenceSQL
const ProviderLoginCallbackDrainForTest = providerLoginCallbackDrainSQL

// Exercise the exact provider SQL and native disable binding against a genuine
// committed start. This is a database observation, not a callback Work fixture.
func ObserveProviderLoginCallbackDispositionForTest(ctx context.Context, tx pgx.Tx, service *ProviderLoginService, state string, deadline time.Time) error {
	found, err := service.lookupProviderLoginCallback(ctx, state)
	if err != nil {
		return err
	}
	defer clear(found.Binding.Proof)
	row := found.Row
	args := providerLoginCallbackDispositionArgs(row, deadline)
	var enabled bool
	if err := tx.QueryRow(ctx, providerLoginCallbackDispositionFenceSQL, args...).Scan(&enabled); err != nil {
		return err
	}
	if enabled {
		return nil
	}
	var command string
	var wire []byte
	if err := tx.QueryRow(ctx, providerLoginCallbackDrainSQL, args[0], args[1], args[2], args[3], deadline).Scan(&command, &wire); err != nil {
		return err
	}
	defer clear(wire)
	if !validProviderLoginCallbackDisableBinding(row, command, wire) {
		return identity.ForbiddenError{}
	}
	return nil
}
