package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
)

// ProviderRouteDefault is trusted deployment selection for one exact tenant,
// organization and domain. It never proves that the provider is eligible.
type ProviderRouteDefault struct {
	TenantID       identity.TenantID
	OrganizationID organization.ID
	Domain         string
	ProviderID     sso.ProviderID
}

// ProviderRouterConfig borrows a clock and the same envelope authority used by
// enablement. Defaults are snapshotted on construction. MaximumProviders
// bounds the complete automatic selection window; explicit/default lookups
// remain exact even when the verified owner's provider set exceeds that limit.
type ProviderRouterConfig struct {
	Clock            clock.Clock
	Envelope         *envelope.Service
	MaximumDuration  time.Duration
	Lifetime         time.Duration
	PolicyVersion    uint64
	MaximumProviders uint32
	Defaults         []ProviderRouteDefault
}

type providerRouteScope struct {
	tenant       identity.TenantID
	organization organization.ID
	domain       string
}

// ProviderRouter is the explicitly composed, concurrent-safe trusted native
// static-OIDC read boundary. It owns no pool lifecycle or background retries.
// It is not an HTTP endpoint, an authentication grant or public discovery.
type ProviderRouter struct {
	pool             *database.Pool
	organizations    *organizationpg.Repository
	config           ProviderRouterConfig
	defaults         map[providerRouteScope]sso.ProviderID
	protocolRegistry bool
}

// NewProviderRouter borrows a migrated primary pool. The organization owner is
// composed on that exact primary so different databases cannot independently
// supply positive provider state and organization authority.
func NewProviderRouter(pool *database.Pool, config ProviderRouterConfig) (*ProviderRouter, error) {
	if pool == nil || pool.Raw() == nil || config.Clock == nil || config.Envelope == nil || config.MaximumDuration <= 0 || config.MaximumDuration > 5*time.Second || config.Lifetime < time.Microsecond || config.Lifetime > 20*time.Second || config.PolicyVersion == 0 || config.MaximumProviders == 0 || config.MaximumProviders > 128 || len(config.Defaults) > 1024 {
		return nil, sso.ErrInvalidInput
	}
	defaults := make(map[providerRouteScope]sso.ProviderID, len(config.Defaults))
	for _, entry := range config.Defaults {
		request, err := sso.NewDomainRouteRequest(entry.TenantID, entry.Domain, entry.ProviderID)
		if err != nil || !providerID(string(entry.OrganizationID)) || entry.ProviderID == "" {
			return nil, sso.ErrInvalidInput
		}
		lookup, _ := request.Bindings()
		scope := providerRouteScope{entry.TenantID, entry.OrganizationID, lookup.Domain}
		if defaults[scope] != "" {
			return nil, sso.ErrInvalidInput
		}
		defaults[scope] = entry.ProviderID
	}
	config.Defaults = nil
	organizations, err := organizationpg.NewRepository(pool, organizationpg.Config{MaximumDuration: config.MaximumDuration})
	if err != nil {
		return nil, sso.ErrInvalidInput
	}
	return &ProviderRouter{pool: pool, organizations: organizations, config: config, defaults: defaults}, nil
}

// WithProtocolRegistry returns an immutable opt-in copy for a primary with both
// ProviderProtocolMigrationSource migrations installed. It performs no I/O and
// leaves the original router's schema requirements unchanged. Selection remains
// OIDC-only: OAuth providers are ineligible, but count toward MaximumProviders;
// unsupported protocol values and malformed OIDC state fail closed. Explicit
// and configured-default foreign-protocol choices never fall back to OIDC.
func (r *ProviderRouter) WithProtocolRegistry() (*ProviderRouter, error) {
	if r == nil || r.pool == nil || r.pool.Raw() == nil {
		return nil, sso.ErrInvalidInput
	}
	selected := *r
	selected.protocolRegistry = true
	return &selected, nil
}

func (ProviderRouter) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("sso.postgres.ProviderRouter(redacted)"))
}
func (ProviderRouter) MarshalJSON() ([]byte, error) { return nil, sso.ErrSensitiveSerialization }
func (ProviderRouter) MarshalText() ([]byte, error) { return nil, sso.ErrSensitiveSerialization }

// Route resolves current organization proof in the supplied tenant, then
// selects the exact explicit provider, verified configured default, or sole
// eligible automatic choice. It never falls back after a negative preferred
// choice. The selected provider's current credential is authenticated without
// disclosure. Callers cannot use the result to skip fresh transactional login
// admission, and a retained result never renews its original bounded lifetime.
func (r *ProviderRouter) Route(ctx context.Context, request sso.DomainRouteRequest) (sso.DomainRoute, error) {
	lookup, err := request.Bindings()
	if r == nil || r.pool == nil || ctx == nil || err != nil {
		return sso.DomainRoute{}, sso.ErrInvalidInput
	}
	ctx, cancel := context.WithTimeout(ctx, min(r.config.MaximumDuration, r.config.Lifetime))
	defer cancel()
	started := r.config.Clock.Now().UTC().Truncate(time.Microsecond)
	proof, err := r.organizations.ResolveDomainProof(ctx, lookup.TenantID, lookup.Domain)
	if err != nil {
		return sso.DomainRoute{}, providerError(ctx, err)
	}
	if proof.TenantID != lookup.TenantID || proof.Domain != lookup.Domain || proof.Revoked || started.Before(proof.ObservedAt) || !started.Before(proof.ExpiresAt) {
		return sso.DomainRoute{}, sso.ErrForbidden
	}
	deadline := started.Add(r.config.Lifetime).UTC().Truncate(time.Microsecond)
	if proof.ExpiresAt.Before(deadline) {
		deadline = proof.ExpiresAt
	}
	preferred := r.defaults[providerRouteScope{proof.TenantID, proof.OrganizationID, proof.Domain}]
	target := lookup.ProviderID
	if target == "" {
		target = preferred
	}
	stored, err := r.readRouteCandidates(ctx, proof, target)
	if err != nil {
		return sso.DomainRoute{}, err
	}
	choices := make([]sso.DomainRoute, 0, len(stored))
	for _, candidate := range stored {
		if r.protocolRegistry {
			switch candidate.protocol {
			case providerProtocolOIDC:
			case providerProtocolOAuth2:
				continue
			default:
				return sso.DomainRoute{}, sso.ErrUnavailable
			}
		}
		if !candidate.enabled {
			continue
		}
		b, err := r.routeBinding(ctx, candidate, proof)
		if err != nil {
			return sso.DomainRoute{}, err
		}
		if b.ProviderID == "" {
			continue
		}
		b.PolicyVersion, b.ObservedAt, b.ValidUntil = r.config.PolicyVersion, started, deadline
		choice, err := sso.NewDomainRoute(b)
		if err != nil {
			return sso.DomainRoute{}, sso.ErrUnavailable
		}
		choices = append(choices, choice)
	}
	route, err := sso.SelectDomainRoute(request, preferred, choices, r.config.Clock.Now())
	if err != nil {
		return sso.DomainRoute{}, err
	}
	b, _ := route.Bindings()
	if err = r.authenticateRouteCredential(ctx, b); err != nil {
		return sso.DomainRoute{}, err
	}
	current, err := r.organizations.GetDomainProof(ctx, b.Proof.Key)
	if err != nil {
		return sso.DomainRoute{}, providerError(ctx, err)
	}
	if current != proof {
		return sso.DomainRoute{}, sso.ErrForbidden
	}
	if err = r.requireCurrentRoute(ctx, b); err != nil {
		return sso.DomainRoute{}, err
	}
	if err = ctx.Err(); err != nil {
		return sso.DomainRoute{}, err
	}
	return sso.SelectDomainRoute(request, preferred, []sso.DomainRoute{route}, r.config.Clock.Now())
}

const routeProviderProjection = `SELECT provider_id,metadata_version::text,enabled,enablement_proof,COALESCE(enablement_credential_generation,0)::text FROM sso_providers.providers WHERE tenant_id=$1 AND organization_id=$2`
const routeExactProviderSQL = routeProviderProjection + ` AND provider_id=$3`

// Apply the limit before filtering by readiness. The existing scoped primary
// key can stop at the limit even when the organization has many disabled rows.
const routeProviderWindowSQL = routeProviderProjection + ` ORDER BY provider_id LIMIT $3`

const routeProtocolProviderProjection = `SELECT p.provider_id,p.metadata_version::text,p.enabled,p.enablement_proof,COALESCE(p.enablement_credential_generation,0)::text,p.protocol FROM sso_providers.providers p WHERE p.tenant_id=$1 AND p.organization_id=$2`
const routeExactProtocolProviderSQL = routeProtocolProviderProjection + ` AND p.provider_id=$3`
const routeProtocolProviderWindowSQL = routeProtocolProviderProjection + ` ORDER BY p.provider_id LIMIT $3`

type routeProviderRecord struct {
	id, version, generation string
	protocol                string
	enabled                 bool
	proof                   []byte
}

func (r *ProviderRouter) readRouteCandidates(ctx context.Context, proof organization.DomainProof, target sso.ProviderID) ([]routeProviderRecord, error) {
	if target != "" {
		var row routeProviderRecord
		query := routeExactProviderSQL
		destinations := []any{&row.id, &row.version, &row.enabled, &row.proof, &row.generation}
		if r.protocolRegistry {
			query = routeExactProtocolProviderSQL
			destinations = append(destinations, &row.protocol)
		}
		if err := r.pool.Raw().QueryRow(ctx, query, string(proof.TenantID), string(proof.OrganizationID), string(target)).Scan(destinations...); err != nil {
			return nil, providerError(ctx, err)
		}
		return []routeProviderRecord{row}, nil
	}
	query := routeProviderWindowSQL
	if r.protocolRegistry {
		query = routeProtocolProviderWindowSQL
	}
	rows, err := r.pool.Raw().Query(ctx, query, string(proof.TenantID), string(proof.OrganizationID), int32(r.config.MaximumProviders+1))
	if err != nil {
		return nil, providerError(ctx, err)
	}
	defer rows.Close()
	result := make([]routeProviderRecord, 0, r.config.MaximumProviders)
	for rows.Next() {
		if len(result) == int(r.config.MaximumProviders) {
			return nil, sso.ErrConflict
		}
		var row routeProviderRecord
		destinations := []any{&row.id, &row.version, &row.enabled, &row.proof, &row.generation}
		if r.protocolRegistry {
			destinations = append(destinations, &row.protocol)
		}
		if err = rows.Scan(destinations...); err != nil {
			return nil, providerError(ctx, err)
		}
		result = append(result, row)
	}
	if err = rows.Err(); err != nil {
		return nil, providerError(ctx, err)
	}
	return result, nil
}

func (r *ProviderRouter) routeBinding(ctx context.Context, row routeProviderRecord, proof organization.DomainProof) (sso.DomainRouteBinding, error) {
	version, versionErr := strconv.ParseUint(row.version, 10, 64)
	generation, generationErr := strconv.ParseUint(row.generation, 10, 64)
	if versionErr != nil || generationErr != nil || version == 0 || generation == 0 || !providerID(row.id) || len(row.proof) == 0 || len(row.proof) > providerEnableProofMaximumBytes {
		return sso.DomainRouteBinding{}, sso.ErrUnavailable
	}
	aad, err := providerEnableProofContext(string(proof.TenantID), string(proof.OrganizationID), row.id, version)
	if err != nil {
		return sso.DomainRouteBinding{}, sso.ErrUnavailable
	}
	sealed, err := envelope.ParseEnvelope(row.proof)
	if err != nil {
		return sso.DomainRouteBinding{}, sso.ErrUnavailable
	}
	plain, err := r.config.Envelope.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	defer clear(plain)
	if err != nil || len(plain) == 0 || len(plain) > 4096 {
		return sso.DomainRouteBinding{}, providerError(ctx, sso.ErrUnavailable)
	}
	var stored organization.DomainProof
	if json.Unmarshal(plain, &stored) != nil {
		return sso.DomainRouteBinding{}, sso.ErrUnavailable
	}
	canonical, err := json.Marshal(stored)
	if err != nil || !bytes.Equal(canonical, plain) || stored.TenantID != proof.TenantID || stored.OrganizationID != proof.OrganizationID {
		return sso.DomainRouteBinding{}, sso.ErrUnavailable
	}
	if stored != proof {
		// An enabled row for a different or retired proof isn't eligible for
		// this domain, even if it belongs to the same current organization.
		return sso.DomainRouteBinding{}, nil
	}
	return sso.DomainRouteBinding{ProviderID: sso.ProviderID(row.id), ProviderVersion: version, CredentialGeneration: generation, Proof: sso.DomainProofCheckpoint{Key: organization.DomainProofKey(proof), ProofVersion: proof.ProofVersion}}, nil
}

const routeCurrentCredentialWhere = ` FROM sso_providers.providers p JOIN sso_providers.credentials c USING(tenant_id,organization_id,provider_id) WHERE p.tenant_id=$1 AND p.organization_id=$2 AND p.provider_id=$3 AND p.metadata_version=$4::numeric AND p.enabled AND p.enablement_credential_generation=$5::numeric AND c.generation=p.enablement_credential_generation`
const routeReadCredentialSQL = `SELECT c.provider_version::text,c.envelope,c.credential_context` + routeCurrentCredentialWhere
const routeCurrentCredentialSQL = `SELECT EXISTS(SELECT 1` + routeCurrentCredentialWhere + `)`

func (r *ProviderRouter) authenticateRouteCredential(ctx context.Context, b sso.DomainRouteBinding) error {
	var installed string
	var wire, contextWire []byte
	proof := b.Proof.Key
	if err := r.pool.Raw().QueryRow(ctx, routeReadCredentialSQL, string(proof.TenantID), string(proof.OrganizationID), string(b.ProviderID), strconv.FormatUint(b.ProviderVersion, 10), strconv.FormatUint(b.CredentialGeneration, 10)).Scan(&installed, &wire, &contextWire); err != nil {
		return providerError(ctx, err)
	}
	version, err := strconv.ParseUint(installed, 10, 64)
	if err != nil || version > b.ProviderVersion {
		return sso.ErrUnavailable
	}
	return authenticateStoredProviderCredential(ctx, r.config.Envelope, string(proof.TenantID), string(proof.OrganizationID), string(b.ProviderID), wire, contextWire, b.CredentialGeneration, version)
}

func (r *ProviderRouter) requireCurrentRoute(ctx context.Context, b sso.DomainRouteBinding) error {
	var current bool
	proof := b.Proof.Key
	if err := r.pool.Raw().QueryRow(ctx, routeCurrentCredentialSQL, string(proof.TenantID), string(proof.OrganizationID), string(b.ProviderID), strconv.FormatUint(b.ProviderVersion, 10), strconv.FormatUint(b.CredentialGeneration, 10)).Scan(&current); err != nil {
		return providerError(ctx, err)
	}
	if !current {
		return sso.ErrForbidden
	}
	return nil
}
