package postgres

import (
	"context"
	"strconv"

	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-sso"
)

const directoryGroupGenerationKey = `generation_id=$1 AND tenant_id=$2 AND organization_id=$3 AND provider_id=$4 AND connection_id=$5
 AND generation=$6::numeric AND mapping_version=$7::numeric AND provider_version=$8::numeric AND mode='apply'`

const directoryHoldGroupBatchSQL = `UPDATE sso_providers.directory_sync_generations
 SET state='reconciling',pending_batch=$10,version=version+1
 WHERE ` + directoryGroupGenerationKey + ` AND checkpoint=$9 AND state='running' AND pending_batch IS NULL
 AND version<18446744073709551614`

const directoryPendingGroupBatchSQL = `SELECT true FROM sso_providers.directory_sync_generations
 WHERE ` + directoryGroupGenerationKey + ` AND checkpoint=$9 AND pending_batch=$10 AND state IN ('reconciling','canceling')`

const directoryAdvanceGroupBatchSQL = `UPDATE sso_providers.directory_sync_generations
 SET state=CASE state WHEN 'canceling' THEN 'canceled' ELSE 'running' END,checkpoint=$11,pending_batch=NULL,
 version=version+1,read_count=read_count+1,applied_count=applied_count+1
 WHERE ` + directoryGroupGenerationKey + ` AND checkpoint=$9 AND pending_batch=$10 AND state IN ('reconciling','canceling')
 AND clock_timestamp()<$12 AND version<18446744073709551615 AND read_count<18446744073709551615`

func (p *directoryGroupChild) generationArgs() []any {
	b := p.batch
	return []any{string(p.generation.ID), string(b.TenantID), string(b.OrganizationID), string(b.ProviderID), b.ConnectionID,
		strconv.FormatUint(b.Generation, 10), strconv.FormatUint(b.MappingVersion, 10), strconv.FormatUint(p.generation.ProviderVersion, 10),
		b.PredecessorCheckpoint[:], p.commitment[:]}
}

func (p *directoryGroupChild) providerLockArgs() []any {
	return []any{string(p.batch.TenantID), string(p.batch.OrganizationID), string(p.batch.ProviderID),
		strconv.FormatUint(p.generation.ProviderVersion, 10), strconv.FormatUint(p.batch.MappingVersion, 10)}
}

func (p *directoryGroupChild) holdGeneration(ctx context.Context, work kernel.Work) error {
	rows, err := work.Query(ctx, directoryStartLockProviderSQL, p.providerLockArgs()...)
	if err != nil {
		return err
	}
	var provider string
	if !rows.Next() || rows.Scan(&provider) != nil || provider != string(p.batch.ProviderID) || rows.Next() || rows.Err() != nil {
		rows.Close()
		return identity.ForbiddenError{}
	}
	rows.Close()
	n, err := work.Exec(ctx, directoryHoldGroupBatchSQL, p.generationArgs()...)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}

type directoryWorkQuery interface {
	Query(context.Context, string, ...any) (*kernel.WorkRows, error)
}

func (p *directoryGroupChild) requirePendingGeneration(ctx context.Context, work directoryWorkQuery) error {
	rows, err := work.Query(ctx, directoryPendingGroupBatchSQL, p.generationArgs()...)
	if err != nil {
		return err
	}
	defer rows.Close()
	var pending bool
	if !rows.Next() || rows.Scan(&pending) != nil || !pending || rows.Next() || rows.Err() != nil {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *directoryGroupChild) RecoverParticipant(ctx context.Context, work kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	b, registration, _, err := work.FeatureScope(p)
	if err != nil || b != p.binding || registration != p.registration() {
		return kernel.RecoveryUnknown, identity.ForbiddenError{}
	}
	// The exact pending marker and team grant share the original child
	// transaction. Absence cannot prove rollback; a subsequent settlement
	// may have cleared it. No new authority observation can reopen the child.
	if err := p.requirePendingGeneration(ctx, work); err != nil {
		return kernel.RecoveryUnknown, nil
	}
	return kernel.RecoveryCommitted, nil
}

func (p *directoryGroupChild) settle(ctx context.Context, result sso.DirectoryApplyResult) error {
	next, err := result.NextCheckpoint(p.batch)
	if err != nil {
		return sso.ErrDirectoryReconciliation
	}
	provider := p.service.generation.provider
	tx, err := provider.pool.Raw().Begin(ctx)
	if err != nil {
		return sso.ErrDirectoryReconciliation
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), provider.config.MaximumDuration)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	if err := authoritypg.RequireAuthority(ctx, tx, p.admission.scope, p.admission.epoch, provider.config.MaximumDuration); err != nil {
		return sso.ErrDirectoryReconciliation
	}
	var lockedProvider string
	if err := tx.QueryRow(ctx, directoryStartLockProviderSQL, p.providerLockArgs()...).Scan(&lockedProvider); err != nil ||
		lockedProvider != string(p.batch.ProviderID) || !provider.config.Clock.Now().Before(p.admission.validUntil) {
		return sso.ErrDirectoryReconciliation
	}
	args := append(p.generationArgs(), next[:], p.admission.validUntil)
	tag, err := tx.Exec(ctx, directoryAdvanceGroupBatchSQL, args...)
	if err != nil {
		return sso.ErrDirectoryReconciliation
	}
	if tag.RowsAffected() == 0 {
		// An already installed exact successor is replay, not another write.
		// Do not mistake another generation or an unrelated successor for it.
		row := tx.QueryRow(ctx, directoryGenerationReadSQL, string(p.generation.ID), string(p.batch.TenantID),
			string(p.batch.OrganizationID), p.batch.ConnectionID)
		existing, err := scanDirectoryGeneration(p.generation.ID, row.Scan)
		if err != nil || existing.current.Checkpoint != next ||
			(existing.current.State != DirectorySyncRunning && existing.current.State != DirectorySyncCanceled) {
			return sso.ErrDirectoryReconciliation
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return sso.ErrDirectoryReconciliation
	}
	return nil
}
