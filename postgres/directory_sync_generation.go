package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"

	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/faustbrian/go-sso"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
	"github.com/jackc/pgx/v5"
)

// DirectorySyncMode fixes whether a generation can apply mapped changes.
type DirectorySyncMode string

const (
	DirectorySyncApply  DirectorySyncMode = "apply"
	DirectorySyncDryRun DirectorySyncMode = "dry-run"
)

// DirectorySyncState describes the persisted generation, not a child outcome.
type DirectorySyncState string

const (
	DirectorySyncRunning     DirectorySyncState = "running"
	DirectorySyncReconciling DirectorySyncState = "reconciling"
	DirectorySyncCanceling   DirectorySyncState = "canceling"
	DirectorySyncCanceled    DirectorySyncState = "canceled"
	DirectorySyncFinished    DirectorySyncState = "finished"
)

// DirectorySyncStartRequest identifies the enabled provider, exact installed
// versions and initial cursor commitment. Zero Checkpoint selects the initial
// checkpoint of the configured source. Key is retained for exact replay.
type DirectorySyncStartRequest struct {
	ProviderID                      sso.ProviderID
	ProviderVersion, MappingVersion uint64
	Mode                            DirectorySyncMode
	Checkpoint                      [32]byte
	Key                             identity.IdempotencyKey
}

func (DirectorySyncStartRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("sso.postgres.DirectorySyncStartRequest(redacted)"))
}

// DirectorySyncGeneration is a safe status projection. The checkpoint is a
// commitment, not a raw source cursor, and does not confer apply authority.
type DirectorySyncGeneration struct {
	ID                                     identity.CommandID
	Provider                               sso.ProviderID
	Number, Version                        uint64
	ProviderVersion, MappingVersion        uint64
	Mode                                   DirectorySyncMode
	State                                  DirectorySyncState
	Checkpoint                             [32]byte
	ReadCount, AppliedCount, RejectedCount uint64
}

// DirectorySyncStartResult preserves the original creation projection on
// replay. Use Status for the latest state. Unknown never returns a generation.
type DirectorySyncStartResult struct {
	Generation DirectorySyncGeneration
	Completion identity.CommandResult
}

// DirectorySyncAuthorization owns the operation's bounded org:sso-write
// decision and matching durable actor authorization epoch. This decision is
// separate from any configured SCIM source and does not authorize child writes.
type DirectorySyncAuthorization interface {
	ObserveDirectorySyncAuthorization(context.Context, authorization.DecisionContext, uint64) (ProviderUpdateAuthorizationEvidence, error)
}

// DirectorySyncService is bound to one existing organization selector and one
// configured source connection. It never starts background workers.
type DirectorySyncService struct {
	provider   *ProviderService
	connection string
	authority  DirectorySyncAuthorization
}

// DirectorySync selects native directory generation administration. Install
// DirectorySyncGenerationMigrationSource first. Selecting a connection ID is
// not proof of current source authority; Apply must separately enlist it.
func (s *ProviderService) DirectorySync(connection string, authority DirectorySyncAuthorization) (*DirectorySyncService, error) {
	if s == nil || s.pool == nil || !providerID(s.updateOrganization) || !providerID(connection) || authority == nil {
		return nil, sso.ErrInvalidInput
	}
	primary, err := organizationpg.NewRepository(s.pool, organizationpg.Config{MaximumDuration: s.config.MaximumDuration})
	if err != nil {
		return nil, sso.ErrInvalidInput
	}
	bound := *s
	bound.config.Organizations = primary
	return &DirectorySyncService{provider: &bound, connection: connection, authority: authority}, nil
}

// Start admits a new run against the enabled provider and its exact mapping.
// It creates only the SSO generation. It does not authenticate a SCIM source,
// apply membership changes, read external data or infer organization roles.
func (s *DirectorySyncService) Start(ctx context.Context, r DirectorySyncStartRequest) (DirectorySyncStartResult, error) {
	var out DirectorySyncStartResult
	if s == nil || s.provider == nil || ctx == nil || !providerID(string(r.ProviderID)) || r.ProviderVersion == 0 ||
		r.MappingVersion == 0 || r.Mode != DirectorySyncApply && r.Mode != DirectorySyncDryRun {
		return out, sso.ErrInvalidInput
	}
	p := s.provider
	ctx, cancel := context.WithTimeout(ctx, p.config.MaximumDuration)
	defer cancel()
	original, err := p.admitFreshProviderWrite(ctx, s.authority.ObserveDirectorySyncAuthorization)
	if err != nil {
		return out, err
	}
	session, err := original.session.Session.Bindings()
	if err != nil {
		return out, sso.ErrForbidden
	}
	r.Checkpoint = s.initialCheckpoint(r.ProviderID, r.Checkpoint)
	phase := &directorySyncStartPhase{service: s, original: original, request: r}
	fields := phase.intentFields()
	intent, err := identity.NewRequestIntent(fields)
	if err != nil {
		return out, sso.ErrInvalidInput
	}
	coordinator, registry, err := s.adminCoordinator(phase)
	if err != nil {
		return out, err
	}
	op := directorySyncStartOperation()
	scope := kernel.RequestKeyScope{TenantID: p.authentication.TenantID, ActorID: identity.ActorID(session.UserID), ActorKind: authorization.SubjectUser, Method: "POST", RouteID: op.OperationID}
	admission, err := coordinator.ResolveRequestKey(ctx, scope, r.Key, intent, p.kernelDecisionFor(session.UserID, "identity.request-admission", op.OperationID, op.OperationID))
	if err != nil {
		return out, providerError(ctx, err)
	}
	id := admission.CommandID
	phase.binding = identity.CommandBinding{CommandID: id, TenantID: scope.TenantID, UserID: session.UserID,
		ActorID: scope.ActorID, ActorKind: scope.ActorKind, OperationID: op.OperationID, SchemaID: op.SchemaID,
		SchemaVersion: op.SchemaVersion, RecordID: string(id), CorrelationID: string(id), PolicyID: p.config.PolicyID, PolicyVersion: p.config.PolicyVersion}

	generation, readErr := s.readGeneration(ctx, id)
	switch {
	case readErr == nil:
		caller := p.kernelDecisionFor(session.UserID, "identity.user", string(session.UserID), op.OperationID)
		out.Completion, err = coordinator.RecoverFeatureCommand(ctx, providerRecovery(phase.binding), caller)
	case errors.Is(readErr, pgx.ErrNoRows):
		out.Completion, err = phase.execute(ctx, coordinator, registry, fields)
		if out.Completion.Outcome == identity.CommitOutcomeCommitted {
			generation, readErr = s.readGeneration(ctx, id)
		}
	default:
		return out, providerError(ctx, readErr)
	}
	if err != nil {
		return out, providerError(ctx, err)
	}
	if out.Completion.Outcome != identity.CommitOutcomeCommitted {
		return out, nil
	}
	if readErr != nil || out.Completion.Binding != phase.binding || generation.current.Provider != r.ProviderID ||
		generation.current.ProviderVersion != r.ProviderVersion || generation.current.MappingVersion != r.MappingVersion ||
		generation.current.Mode != r.Mode || generation.initial != r.Checkpoint {
		return out, sso.ErrUnavailable
	}
	if _, err := p.admitFreshProviderWrite(ctx, s.authority.ObserveDirectorySyncAuthorization); err != nil {
		return out, err
	}
	out.Generation = generation.creation()
	return out, nil
}

// Status reads only the exact organization/source generation after current
// org:sso-read authorization. It does not reveal pending child input.
func (s *DirectorySyncService) Status(ctx context.Context, id identity.CommandID) (DirectorySyncGeneration, error) {
	if s == nil || s.provider == nil || ctx == nil {
		return DirectorySyncGeneration{}, sso.ErrInvalidInput
	}
	if _, err := identity.ParseCommandID(string(id)); err != nil {
		return DirectorySyncGeneration{}, sso.ErrInvalidInput
	}
	p := s.provider
	ctx, cancel := context.WithTimeout(ctx, p.config.MaximumDuration)
	defer cancel()
	if _, err := p.admit(ctx, p.updateOrganization, "org:sso-read"); err != nil {
		return DirectorySyncGeneration{}, err
	}
	stored, err := s.readGeneration(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return DirectorySyncGeneration{}, sso.ErrForbidden
	}
	if err != nil {
		return DirectorySyncGeneration{}, providerError(ctx, err)
	}
	if _, err := p.admit(ctx, p.updateOrganization, "org:sso-read"); err != nil {
		return DirectorySyncGeneration{}, err
	}
	return stored.current, nil
}

func (s *DirectorySyncService) initialCheckpoint(provider sso.ProviderID, requested [32]byte) [32]byte {
	if requested != ([32]byte{}) {
		return requested
	}
	scope := string(s.provider.authentication.TenantID) + "\x00" + s.provider.updateOrganization + "\x00" + string(provider) + "\x00" + s.connection
	return sha256.Sum256([]byte("sso/directory-sync-initial/v1\x00" + scope))
}

func (s *DirectorySyncService) adminCoordinator(phase kernel.Contributor) (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
	p := s.provider
	audits, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, nil, sso.ErrUnavailable
	}
	outbox, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, nil, sso.ErrUnavailable
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{p.directory, p.config.Counters, audits, outbox, phase})
	if err != nil {
		return nil, nil, providerError(nil, err)
	}
	coordinator, err := kernel.NewCoordinatorWithRequestKeys(p.pool, registry, p.config.Coordinator, p.config.RequestKeys)
	return coordinator, registry, providerError(nil, err)
}

type storedDirectoryGeneration struct {
	current DirectorySyncGeneration
	initial [32]byte
}

func (s storedDirectoryGeneration) creation() DirectorySyncGeneration {
	out := s.current
	out.State, out.Version, out.Checkpoint = DirectorySyncRunning, 1, s.initial
	out.ReadCount, out.AppliedCount, out.RejectedCount = 0, 0, 0
	return out
}

const directoryGenerationReadSQL = `SELECT provider_id,generation::text,version::text,provider_version::text,mapping_version::text,
 mode,state,checkpoint,initial_checkpoint,read_count::text,applied_count::text,rejected_count::text
 FROM sso_providers.directory_sync_generations
 WHERE generation_id=$1 AND tenant_id=$2 AND organization_id=$3 AND connection_id=$4`

func (s *DirectorySyncService) readGeneration(ctx context.Context, id identity.CommandID) (storedDirectoryGeneration, error) {
	p := s.provider
	return readDirectoryGeneration(ctx, p.pool, id, p.authentication.TenantID, p.updateOrganization, s.connection)
}

func readDirectoryGeneration(ctx context.Context, pool *database.Pool, id identity.CommandID, tenant identity.TenantID, organization, connection string) (storedDirectoryGeneration, error) {
	row := pool.Raw().QueryRow(ctx, directoryGenerationReadSQL, string(id), string(tenant), organization, connection)
	return scanDirectoryGeneration(id, row.Scan)
}

func scanDirectoryGeneration(id identity.CommandID, scan func(...any) error) (storedDirectoryGeneration, error) {
	out := storedDirectoryGeneration{current: DirectorySyncGeneration{ID: id}}
	current := &out.current
	var values [7]string
	var mode, state string
	var cursor, initial []byte
	err := scan(&current.Provider, &values[0], &values[1], &values[2], &values[3], &mode, &state, &cursor, &initial, &values[4], &values[5], &values[6])
	if err != nil {
		return storedDirectoryGeneration{}, err
	}
	current.Mode, current.State = DirectorySyncMode(mode), DirectorySyncState(state)
	targets := [...]*uint64{&current.Number, &current.Version, &current.ProviderVersion, &current.MappingVersion, &current.ReadCount, &current.AppliedCount, &current.RejectedCount}
	for i, target := range targets {
		*target, err = strconv.ParseUint(values[i], 10, 64)
		if err != nil || i < 4 && *target == 0 {
			return storedDirectoryGeneration{}, sso.ErrUnavailable
		}
	}
	if len(cursor) != len(current.Checkpoint) || len(initial) != len(out.initial) {
		return storedDirectoryGeneration{}, sso.ErrUnavailable
	}
	copy(current.Checkpoint[:], cursor)
	copy(out.initial[:], initial)
	return out, nil
}

func (p *directorySyncStartPhase) execute(ctx context.Context, coordinator *kernel.Coordinator, registry *kernel.ContributorRegistry, intent []identity.FeatureField) (identity.CommandResult, error) {
	config := p.service.provider.config
	fields, err := sessionpg.OriginalSessionFields(p.original.session.Session)
	if err != nil {
		return identity.CommandResult{}, sso.ErrForbidden
	}
	fields = append(fields, intent...)
	command, err := identity.NewFeatureSessionCommand(identity.FeatureCommandSpec{Binding: p.binding, Operation: directorySyncStartOperation(), Fields: fields}, p.service.provider.authentication.Bearer)
	if err != nil {
		return identity.CommandResult{}, sso.ErrInvalidInput
	}
	resource, err := risk.DirectorySyncStartCounterResource(p.service.provider.updateOrganization, p.service.connection, string(p.request.ProviderID))
	if err != nil {
		return identity.CommandResult{}, sso.ErrInvalidInput
	}
	p.command, p.counter, err = config.Counters.PrepareCommandCounters(command,
		risk.Subject{Actor: string(p.binding.ActorID), Resource: resource, Network: p.service.provider.network}, p.original.verified)
	if err != nil {
		return identity.CommandResult{}, providerError(ctx, err)
	}
	plan, err := p.plan(registry)
	if err != nil {
		return identity.CommandResult{}, err
	}
	return executeProviderLogoutCommand(ctx, coordinator, p.binding, p.command, plan)
}
