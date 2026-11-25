package postgres

import (
	"context"
	"slices"
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

const directoryContinueGroupBatchSQL = `SELECT true FROM sso_providers.directory_sync_generations
 WHERE ` + directoryGroupGenerationKey + ` AND checkpoint=$9 AND pending_batch=$10 AND state='reconciling' FOR UPDATE`

// When every child definitively failed, no grant transaction installed a
// hold. That complete batch may settle only while the predecessor remains
// unclaimed; it cannot replace a competing hold or close a canceled run.
const directoryAdvanceGroupBatchSQL = `UPDATE sso_providers.directory_sync_generations
 SET state=CASE state WHEN 'canceling' THEN 'canceled' ELSE 'running' END,checkpoint=$11,pending_batch=NULL,
 version=version+1,read_count=read_count+$13::numeric,applied_count=applied_count+$14::numeric,rejected_count=rejected_count+$15::numeric
 WHERE ` + directoryGroupGenerationKey + ` AND checkpoint=$9
 AND ((pending_batch=$10 AND state IN ('reconciling','canceling'))
 OR (state='running' AND pending_batch IS NULL AND $13::numeric>1 AND $14::numeric=0))
 AND clock_timestamp()<$12 AND version<18446744073709551615 AND read_count<=18446744073709551615-$13::numeric`

const directoryStopGroupBatchSQL = `UPDATE sso_providers.directory_sync_generations
 SET state='canceled',pending_batch=NULL,version=version+1
 WHERE ` + directoryGroupGenerationKey + ` AND checkpoint=$9 AND pending_batch=$10 AND state='canceling'
 AND clock_timestamp()<$11 AND version<18446744073709551615`

func (p *directorySyncChild) generationArgs() []any {
	b := p.batch
	return []any{string(p.generation.ID), string(b.TenantID), string(b.OrganizationID), string(b.ProviderID), b.ConnectionID,
		strconv.FormatUint(b.Generation, 10), strconv.FormatUint(b.MappingVersion, 10), strconv.FormatUint(p.generation.ProviderVersion, 10),
		b.PredecessorCheckpoint[:], p.commitment[:]}
}

func (p *directorySyncChild) providerLockArgs() []any {
	return []any{string(p.batch.TenantID), string(p.batch.OrganizationID), string(p.batch.ProviderID),
		strconv.FormatUint(p.generation.ProviderVersion, 10), strconv.FormatUint(p.batch.MappingVersion, 10)}
}

func (p *directorySyncChild) holdGeneration(ctx context.Context, work kernel.Work) error {
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
	if n == 1 {
		return nil
	}
	if len(p.batch.Deltas) == 1 {
		return identity.ConflictError{}
	}
	// Each original continuation holds the same row until the grant and
	// receipt commit. Cancellation and child effects cannot pass each other.
	return p.requireGroupBatch(ctx, work, directoryContinueGroupBatchSQL)
}

type directoryWorkQuery interface {
	Query(context.Context, string, ...any) (*kernel.WorkRows, error)
}

func (p *directorySyncChild) requirePendingGeneration(ctx context.Context, work directoryWorkQuery) error {
	return p.requireGroupBatch(ctx, work, directoryPendingGroupBatchSQL)
}

func (p *directorySyncChild) requireGroupBatch(ctx context.Context, work directoryWorkQuery, query string) error {
	rows, err := work.Query(ctx, query, p.generationArgs()...)
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

func (p *directorySyncChild) RecoverParticipant(_ context.Context, work kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	b, registration, _, err := work.FeatureScope(p)
	if err != nil || b != p.binding || registration != p.registration() {
		return kernel.RecoveryUnknown, identity.ForbiddenError{}
	}
	// Grant, audit, outbox and the terminal receipt share a transaction.
	// Only the kernel's locked expired pending journal can establish this
	// noncommit, not the presence or absence of the shared batch marker.
	return kernel.RecoveryNotCommitted, nil
}

func (p *directorySyncChild) settle(ctx context.Context, result sso.DirectoryApplyResult) error {
	next, err := result.NextCheckpoint(p.batch)
	if err != nil {
		return sso.ErrDirectoryReconciliation
	}
	var committed int
	for _, receipt := range result.ChildOutcomes {
		if receipt.Outcome == identity.CommitOutcomeCommitted {
			committed++
		}
	}
	observed := len(result.ChildOutcomes)
	args := append(p.generationArgs(), next[:], p.admission.validUntil,
		strconv.Itoa(observed), strconv.Itoa(committed), strconv.Itoa(observed-committed))
	return p.settleGeneration(ctx, directoryAdvanceGroupBatchSQL, args, next, DirectorySyncRunning, DirectorySyncCanceled)
}

func (p *directorySyncChild) settleStopped(ctx context.Context) error {
	args := append(p.generationArgs(), p.admission.validUntil)
	return p.settleGeneration(ctx, directoryStopGroupBatchSQL, args, p.batch.PredecessorCheckpoint, DirectorySyncCanceled)
}

func (p *directorySyncChild) settleGeneration(ctx context.Context, query string, args []any, checkpoint [32]byte, replayStates ...DirectorySyncState) error {
	service := p.service
	tx, err := service.pool.Raw().Begin(ctx)
	if err != nil {
		return sso.ErrDirectoryReconciliation
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), service.scope.MaximumDuration)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	if err := authoritypg.RequireAuthority(ctx, tx, p.admission.scope, p.admission.epoch, service.scope.MaximumDuration); err != nil {
		return sso.ErrDirectoryReconciliation
	}
	var lockedProvider string
	if err := tx.QueryRow(ctx, directoryStartLockProviderSQL, p.providerLockArgs()...).Scan(&lockedProvider); err != nil ||
		lockedProvider != string(p.batch.ProviderID) || !service.scope.Clock.Now().Before(p.admission.validUntil) {
		return sso.ErrDirectoryReconciliation
	}
	tag, err := tx.Exec(ctx, query, args...)
	if err != nil {
		return sso.ErrDirectoryReconciliation
	}
	if tag.RowsAffected() == 0 {
		// An already installed exact successor is replay, not another write.
		// Do not mistake another generation or an unrelated successor for it.
		row := tx.QueryRow(ctx, directoryGenerationReadSQL, string(p.generation.ID), string(p.batch.TenantID),
			string(p.batch.OrganizationID), p.batch.ConnectionID)
		existing, err := scanDirectoryGeneration(p.generation.ID, row.Scan)
		if err != nil || existing.current.Checkpoint != checkpoint {
			return sso.ErrDirectoryReconciliation
		}
		if !slices.Contains(replayStates, existing.current.State) {
			return sso.ErrDirectoryReconciliation
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return sso.ErrDirectoryReconciliation
	}
	return nil
}
