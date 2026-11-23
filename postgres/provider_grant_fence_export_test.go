//go:build integration

package postgres

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

type ProviderGrantFenceClaimForTest = providerGrantFenceClaim

func ClaimProviderGrantFenceForTest(ctx context.Context, pool *pgxpool.Pool, claim ProviderGrantFenceClaimForTest) error {
	return claimProviderGrantFence(ctx, pool, claim)
}
