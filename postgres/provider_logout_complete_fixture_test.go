//go:build integration

package postgres

import (
	"context"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-sso/oidc"
)

// ExpireNativeProviderLogoutFixture ages an existing pending integration-test
// row without sleeps or weakening its authenticated immutable timestamps.
func ExpireNativeProviderLogoutFixture(ctx context.Context, s *ProviderLogoutService, rawQuery string) error {
	callback, err := oidc.ParseRPLogoutCallback(rawQuery)
	if err != nil {
		return err
	}
	old, wire, err := s.pendingLogout(ctx, callback.State())
	if err != nil {
		return err
	}
	defer clear(wire)
	bound, err := openProviderLogoutBinding(ctx, s.login.payload, old, wire)
	if err != nil {
		return err
	}
	pool := s.login.router.pool.Raw()
	var now time.Time
	if err := pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return err
	}
	aged := old
	aged.ExpiresAt = now.UTC().Add(-time.Second)
	aged.IssuedAt = aged.ExpiresAt.Add(-old.ExpiresAt.Sub(old.IssuedAt))
	sealed, err := sealProviderLogoutBinding(ctx, s.login.payload, aged, bound)
	if err != nil {
		return err
	}
	defer clear(sealed)
	updated, err := pool.Exec(ctx, `UPDATE sso_providers.logout_transactions SET issued_at=$4,expires_at=$5,binding_envelope=$6
 WHERE (tenant_id,state_key_version,state_digest)=($1,$2,$3) AND completed_at IS NULL AND binding_envelope=$7`,
		string(old.TenantID), int64(old.StateKeyVersion), old.StateDigest[:], aged.IssuedAt, aged.ExpiresAt, sealed, wire)
	if err != nil || updated.RowsAffected() != 1 {
		return identity.UnavailableError{}
	}
	return nil
}
