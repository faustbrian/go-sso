package postgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

type SAMLReplayClaimForTest = samlReplayClaim

func ReserveSAMLReplayForTest(ctx context.Context, tx pgx.Tx, claim SAMLReplayClaimForTest) error {
	return insertSAMLReplayPair(ctx, func(ctx context.Context, sql string, args ...any) (int64, error) {
		tag, err := tx.Exec(ctx, sql, args...)
		return tag.RowsAffected(), err
	}, claim)
}

func ObserveSAMLReplayForTest(ctx context.Context, queryer interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, claim SAMLReplayClaimForTest) (bool, error) {
	return observeSAMLReplayPair(ctx, func(ctx context.Context, sql string, args ...any) (bool, error) {
		rows, err := queryer.Query(ctx, sql, args...)
		if err != nil {
			return false, err
		}
		defer rows.Close()
		var exact bool
		if !rows.Next() || rows.Scan(&exact) != nil || rows.Next() || rows.Err() != nil {
			return false, identity.UnavailableError{}
		}
		return exact, nil
	}, claim)
}
