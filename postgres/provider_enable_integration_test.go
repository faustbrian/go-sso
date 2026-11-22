//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

type enableProofObserver struct{}

func (enableProofObserver) ObserveDomain(ctx context.Context, claim organization.DomainClaim) (organization.DomainObservation, error) {
	if err := ctx.Err(); err != nil {
		return organization.DomainObservation{}, err
	}
	at := time.Now().UTC().Truncate(time.Microsecond)
	return organization.DomainObservation{Claim: claim, Method: organization.DomainDNS, ObservedAt: at, ExpiresAt: at.Add(time.Minute), Verified: true}, nil
}

type enablePolicy struct{ deny bool }

func (p enablePolicy) ObserveProviderEnableAuthorization(ctx context.Context, dc authorization.DecisionContext, _ uint64) (ssopg.ProviderEnableAuthorizationEvidence, error) {
	decision, err := (fixturePolicy{}).Decide(ctx, dc)
	if p.deny || dc.Request.Action != "org:sso-write" {
		decision.Outcome = authorization.Deny
	}
	return ssopg.ProviderEnableAuthorizationEvidence{Context: dc.Clone(), Decision: decision, ActorAuthorizationVersion: 1, ValidUntil: dc.Request.Environment.Time.Add(time.Minute)}, err
}

type enableDisclosurePolicy struct{ calls atomic.Int32 }

func (p *enableDisclosurePolicy) ObserveProviderEnableAuthorization(ctx context.Context, dc authorization.DecisionContext, epoch uint64) (ssopg.ProviderEnableAuthorizationEvidence, error) {
	return (enablePolicy{deny: p.calls.Add(1) > 1}).ObserveProviderEnableAuthorization(ctx, dc, epoch)
}

func enableTestProof(t *testing.T, f *orgFixture, orgID, domain, id string, version uint64) organization.DomainProof {
	t.Helper()
	request := organization.DomainClaimRequest{Authentication: f.auth("org-test-basic", "owner"), CommandID: commandID(t), OrganizationID: organization.ID(orgID), ClaimID: organization.ID(id), OrganizationVersion: version, Domain: domain, CorrelationID: id}
	prepared, err := f.service.PrepareReserveDomain(f.ctx, request, "127.0.0.1")
	if err != nil {
		t.Fatal("prepare organization-owned domain claim", err)
	}
	reserved, err := f.service.Execute(f.ctx, prepared)
	if err != nil || reserved.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("commit organization-owned domain claim", err)
	}
	owner, err := f.service.DomainEvidence(request.Authentication, "127.0.0.1")
	if err != nil {
		t.Fatal("select organization proof authority", err)
	}
	request.CommandID = commandID(t)
	request.OrganizationVersion++
	request.ClaimVersion = 1
	command, err := owner.Prepare(f.ctx, organization.DomainEvidenceRequest{Claim: request})
	if err != nil {
		t.Fatal("prepare organization proof", err)
	}
	proved, err := owner.ApplyDomainEvidence(f.ctx, command)
	if err != nil || proved.Proof.Domain != domain || proved.Proof.ProofVersion != 1 {
		t.Fatal("commit organization-owned proof", err)
	}
	return proved.Proof
}

func installProviderEnable(t *testing.T, f *orgFixture) {
	t.Helper()
	config, err := pgx.ParseConfig(f.dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.Database = f.database
	db := stdlib.OpenDB(*config)
	defer db.Close()
	backend, err := migrationpg.New(db)
	if err != nil {
		t.Fatal(err)
	}
	history := append(migrationList{}, f.history...)
	for _, source := range []migrations.Source{ssopg.ProviderUpdateMigrationSource{Version: 321}, ssopg.ProviderCredentialsMigrationSource{Version: 322}, ssopg.ProviderEnableMigrationSource{Version: 323}} {
		loaded, err := source.Load(f.ctx)
		if err != nil {
			t.Fatal("load optional provider migration", err)
		}
		history = append(history, loaded...)
	}
	runner, err := migrations.NewRunner(history, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = runner.Up(f.ctx); err != nil {
		t.Fatal("install enablement after populated disabled provider schema", err)
	}
}

type providerEnableFixture struct {
	f       *orgFixture
	base    *ssopg.ProviderService
	service *ssopg.ProviderService
	config  ssopg.ProviderServiceConfig
	proof   organization.DomainProof
	request sso.ProviderEnableRequest
}

func newProviderEnableFixture(t *testing.T) providerEnableFixture {
	t.Helper()
	f, base, config := newProviderFixtureWithUpdates(t, false, organizationpg.DomainClaimMigrationSource{Version: 316}, organizationpg.DomainEvidenceMigrationSource{Version: 317})
	f.domains = organization.DomainConfig{Version: 1, MaximumClaims: 5, EvidenceMaximumAge: time.Hour}
	var err error
	f.domainEvidence, err = organizationpg.NewDomainEvidenceSource(enableProofObserver{}, [32]byte{0x43})
	if err != nil {
		t.Fatal(err)
	}
	f.compose(t)
	registration := providerRequest(t, "https://enable.example.com", "original-provider-enable-register")
	registered, err := base.ProviderRegisterOidc(f.ctx, registration)
	if err != nil || registered.Provider.Enabled || registered.Provider.Version != 1 {
		t.Fatal("missing disabled predecessor", err)
	}
	bound, err := base.ForOrganization(registration.OrganizationID)
	if err != nil {
		t.Fatal(err)
	}
	installProviderCredentials(t, f)
	credentials := nativeCredentialService(t, bound)
	rotated, err := credentials.ProviderCredentialsRotate(f.ctx, nativeCredentialRequest(t, f, config, registered.Provider.ID, 1, 1))
	if err != nil || rotated.Version != 2 {
		t.Fatal("missing current encrypted credential", err)
	}
	proof := enableTestProof(t, f, registration.OrganizationID, registration.Domains[0], "test-enable-domain", 1)
	installProviderEnable(t, f)
	service, err := bound.WithProviderEnableAuthorization(enablePolicy{})
	if err != nil {
		t.Fatal("configure explicit enablement authorization", err)
	}
	credential, err := service.ObserveProviderCredentialCheckpoint(f.ctx, registered.Provider.ID, 2)
	if err != nil {
		t.Fatal("observe current encrypted credential without exposing it", err)
	}
	key, err := identity.NewIdempotencyKey([]byte("original-provider-enable"))
	if err != nil {
		t.Fatal(err)
	}
	request := sso.ProviderEnableRequest{ProviderID: registered.Provider.ID, ExpectedVersion: 2, DomainProofCheckpoint: sso.DomainProofCheckpoint{Key: organization.DomainProofKey(proof), ProofVersion: proof.ProofVersion}, CredentialCheckpoint: credential, IdempotencyKey: key}
	return providerEnableFixture{f: f, base: bound, service: service, config: config, proof: proof, request: request}
}

func TestNativeProviderEnableUsesCurrentProofAndCredentialWithExactReplay(t *testing.T) {
	x := newProviderEnableFixture(t)
	f, service, request, proof := x.f, x.service, x.request, x.proof
	denied, err := x.base.WithProviderEnableAuthorization(enablePolicy{deny: true})
	if err != nil {
		t.Fatal(err)
	}
	if result, err := denied.ProviderEnable(f.ctx, request); !errors.Is(err, sso.ErrForbidden) || result.Provider.Enabled {
		t.Fatal("explicit enable policy denial did not fail closed", err)
	}
	forged := request
	forged.DomainProofCheckpoint.Key.ObservedAt = forged.DomainProofCheckpoint.Key.ObservedAt.Add(-time.Microsecond)
	if result, err := service.ProviderEnable(f.ctx, forged); !errors.Is(err, sso.ErrForbidden) || result.Provider.Enabled {
		t.Fatal("plausible but non-authoritative proof was accepted", err)
	}
	for _, stale := range []string{"generation", "expiry"} {
		t.Run(stale, func(t *testing.T) {
			changed := request
			binding, err := request.CredentialCheckpoint.Bindings()
			if err != nil {
				t.Fatal(err)
			}
			if stale == "generation" {
				binding.Generation++
			} else {
				binding.ObservedAt = binding.ObservedAt.Add(-time.Minute)
				binding.ExpiresAt = binding.ExpiresAt.Add(-time.Minute)
			}
			changed.CredentialCheckpoint, err = sso.NewCredentialCheckpoint(binding)
			if err != nil {
				t.Fatal(err)
			}
			if result, err := service.ProviderEnable(f.ctx, changed); !errors.Is(err, sso.ErrForbidden) || result.Provider.Enabled {
				t.Fatal("stale checkpoint changed provider", err)
			}
		})
	}
	enabled, err := service.ProviderEnable(f.ctx, request)
	if err != nil || enabled.Completion.Outcome != identity.CommitOutcomeCommitted || enabled.Provider.ID != request.ProviderID || enabled.Provider.Version != 3 || enabled.Provider.MappingVersion != 1 || !enabled.Provider.Enabled || !reflect.DeepEqual(enabled.Provider.VerifiedDomains, []string{proof.Domain}) {
		t.Fatal("checked provider enablement did not commit", enabled.Completion.Outcome, err)
	}
	replay, err := service.ProviderEnable(f.ctx, request)
	if err != nil || !reflect.DeepEqual(replay.Provider, enabled.Provider) || replay.Completion.Binding != enabled.Completion.Binding || replay.Completion.AuditEventID != enabled.Completion.AuditEventID {
		t.Fatal("original retry did not return original enabled snapshot", err)
	}
	if result, err := service.ProviderEnable(f.ctx, forged); !errors.Is(err, sso.ErrConflict) || result.Provider.Enabled {
		t.Fatal("different checkpoint recovered an original keyed result", err)
	}
	stored, err := service.ProviderGet(f.ctx, sso.ProviderGetRequest{OrganizationID: string(proof.OrganizationID), ProviderID: sso.ProviderID(request.ProviderID)})
	if err != nil || !stored.Provider.Enabled || stored.Provider.Version != 3 {
		t.Fatal("administrative read reports wrong enabled configuration", err)
	}
	listed, err := service.ProviderList(f.ctx, sso.ProviderListRequest{OrganizationID: string(proof.OrganizationID), Limit: 10})
	if err != nil || len(listed.Providers) != 1 || !listed.Providers[0].Enabled || listed.Providers[0].Version != 3 {
		t.Fatal("administrative list reports wrong enabled configuration", err)
	}
	var audits, events int
	if err = f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM audit.records WHERE action='identity.sso.provider.enable' AND outcome=1),(SELECT count(*) FROM outbox_messages WHERE topic='sso.provider_enabled.v1')`).Scan(&audits, &events); err != nil || audits != 1 || events != 1 {
		t.Fatal("success or replay wrote the wrong number of audit/outbox effects", audits, events, err)
	}
}

func revokeEnableTestProof(t *testing.T, x providerEnableFixture) {
	t.Helper()
	f := x.f
	authentication := f.auth("org-test-basic", "owner")
	owner, err := f.service.DomainEvidence(authentication, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	obs, err := x.config.Organizations.ObserveCredentialAuthority(f.ctx, organization.CredentialAuthorityQuery{TenantID: x.proof.TenantID, OrganizationID: x.proof.OrganizationID})
	if err != nil {
		t.Fatal(err)
	}
	r := organization.DomainEvidenceRequest{ProofVersion: x.proof.ProofVersion, Claim: organization.DomainClaimRequest{Authentication: authentication, CommandID: commandID(t), OrganizationID: x.proof.OrganizationID, ClaimID: x.proof.ClaimID, OrganizationVersion: obs.Version, ClaimVersion: x.proof.ClaimVersion, Domain: x.proof.Domain, CorrelationID: "revoke-enable-proof"}}
	command, err := owner.PrepareRevocation(f.ctx, r, organization.DomainProofKey(x.proof))
	if err != nil {
		t.Fatal("prepare authoritative revocation", err)
	}
	revoked, err := owner.ApplyDomainEvidence(f.ctx, command)
	if err != nil || !revoked.Proof.Revoked {
		t.Fatal("commit authoritative revocation", err)
	}
}

func TestNativeProviderEnableRejectsRevokedAuthoritativeProof(t *testing.T) {
	x := newProviderEnableFixture(t)
	revokeEnableTestProof(t, x)
	f := x.f
	if result, err := x.service.ProviderEnable(f.ctx, x.request); !errors.Is(err, sso.ErrForbidden) || result.Provider.Enabled {
		t.Fatal("historical proof passed enablement", err)
	}
}

type enableProofPause struct {
	arrived, resume chan struct{}
	seen            sync.Once
}

func (p *enableProofPause) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	if strings.Contains(d.SQL, "JOIN sso_providers.credentials c USING") {
		p.seen.Do(func() { close(p.arrived) })
		select {
		case <-p.resume:
		case <-ctx.Done():
		}
	}
	return ctx
}

func (*enableProofPause) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func TestNativeProviderEnableFencesProofRevokedAfterObservation(t *testing.T) {
	x := newProviderEnableFixture(t)
	f := x.f
	pause := &enableProofPause{arrived: make(chan struct{}), resume: make(chan struct{})}
	var release sync.Once
	defer release.Do(func() { close(pause.resume) })
	pool, err := database.Connect(f.ctx, database.Config{DSN: f.dsn, MaxConns: 2, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database = f.database
		c.ConnConfig.Tracer = pause
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := pool.Close(ctx); err != nil {
			t.Error("close proof-race pool", err)
		}
	})
	service, err := ssopg.NewProviderService(pool, x.config, f.auth("org-test-basic", "owner"), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	service, err = service.ForOrganization(string(x.proof.OrganizationID))
	if err != nil {
		t.Fatal(err)
	}
	service, err = service.WithProviderEnableAuthorization(enablePolicy{})
	if err != nil {
		t.Fatal(err)
	}
	type reply struct {
		out sso.ProviderEnableResult
		err error
	}
	result := make(chan reply, 1)
	go func() {
		out, err := service.ProviderEnable(f.ctx, x.request)
		result <- reply{out, err}
	}()
	select {
	case <-pause.arrived:
	case ended := <-result:
		t.Fatal("enablement never reached the credential read after its proof observation", ended.err)
	case <-f.ctx.Done():
		t.Fatal("timed out awaiting proof observation")
	}
	revokeEnableTestProof(t, x)
	release.Do(func() { close(pause.resume) })
	ended := <-result
	if ended.err == nil || ended.out.Provider.Enabled || ended.out.Completion.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("proof revocation before Work did not close enablement", ended.out.Completion.Outcome, ended.err)
	}
	var enabled bool
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT enabled FROM sso_providers.providers WHERE provider_id=$1`, x.request.ProviderID).Scan(&enabled); err != nil || enabled {
		t.Fatal("revoked proof changed provider", enabled, err)
	}
}

func TestNativeProviderEnablePreservesKnownCommitWhenDisclosureDenied(t *testing.T) {
	x := newProviderEnableFixture(t)
	service, err := x.base.WithProviderEnableAuthorization(&enableDisclosurePolicy{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.ProviderEnable(x.f.ctx, x.request)
	if !errors.Is(err, sso.ErrForbidden) || result.Provider.Enabled || result.Provider.ID != "" || result.Completion.Outcome != identity.CommitOutcomeCommitted || result.Completion.Binding.CommandID == "" {
		t.Fatal("rejected disclosure erased known outcome or disclosed provider", result.Completion.Outcome, err)
	}
	replay, err := x.service.ProviderEnable(x.f.ctx, x.request)
	if err != nil || !replay.Provider.Enabled || replay.Completion.Binding != result.Completion.Binding {
		t.Fatal("original key did not recover the already committed enablement", err)
	}
}

func TestNativeProviderEnableConcurrentDistinctKeysCommitOneSuccessor(t *testing.T) {
	x := newProviderEnableFixture(t)
	second := x.request
	var err error
	second.IdempotencyKey, err = identity.NewIdempotencyKey([]byte("competing-provider-enable"))
	if err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		result sso.ProviderEnableResult
		err    error
	}
	start := make(chan struct{})
	results := make(chan outcome, 2)
	var wg sync.WaitGroup
	for _, r := range []sso.ProviderEnableRequest{x.request, second} {
		wg.Go(func() {
			<-start
			result, err := x.service.ProviderEnable(x.f.ctx, r)
			results <- outcome{result, err}
		})
	}
	close(start)
	wg.Wait()
	close(results)
	commits, conflicts := 0, 0
	for out := range results {
		switch {
		case out.err == nil && out.result.Completion.Outcome == identity.CommitOutcomeCommitted && out.result.Provider.Version == 3:
			commits++
		case errors.Is(out.err, sso.ErrConflict) && !out.result.Provider.Enabled:
			conflicts++
		default:
			t.Fatal("unexpected contender outcome", out.result.Completion.Outcome, out.err)
		}
	}
	if commits != 1 || conflicts != 1 {
		t.Fatal("contenders did not establish one exact successor", commits, conflicts)
	}
}
