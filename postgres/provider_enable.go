package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
)

const providerEnableProofMaximumBytes = 16 << 10

type providerEnable struct {
	request     sso.ProviderEnableRequest
	credential  sso.CredentialCheckpointBinding
	proof       organization.DomainProof
	predecessor providerEnablePredecessor
	sealedProof []byte
}

type providerEnablePredecessor struct {
	configuration                                  []byte
	domain                                         string
	mappingVersion, credentialGeneration           uint64
	credentialVersion                              uint64
	configurationHash, credentialHash, contextHash [32]byte
}

const providerEnablePredecessorSQL = `SELECT p.metadata_version::text,COALESCE(p.metadata_mapping_version,p.mapping_version)::text,COALESCE(p.metadata_configuration_envelope,p.configuration_envelope),p.pending_domains,p.enabled,c.generation::text,c.provider_version::text,c.envelope,c.credential_context FROM sso_providers.providers p JOIN sso_providers.credentials c USING(tenant_id,organization_id,provider_id) WHERE p.tenant_id=$1 AND p.organization_id=$2 AND p.provider_id=$3`
const providerEnableFenceSQL = providerEnablePredecessorSQL + ` FOR UPDATE OF p`
const enableProviderSQL = `UPDATE sso_providers.providers SET enabled=true,metadata_version=$4::numeric,metadata_configuration_envelope=$5,metadata_mapping_version=$6::numeric,enablement_proof=$7,enablement_credential_generation=$8::numeric WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND metadata_version=$9::numeric AND NOT enabled`
const insertProviderEnableReceiptSQL = `INSERT INTO sso_providers.enable_receipts(command_id,mapping_version) VALUES($1,$2::numeric)`
const readProviderEnableReceiptSQL = `SELECT r.mapping_version::text FROM sso_providers.enable_receipts r JOIN sso_providers.command_effects e USING(command_id) WHERE r.command_id=$1 AND e.tenant_id=$2 AND e.organization_id=$3 AND e.provider_id=$4`

type providerEnableStored struct {
	version, mapping, generation, credentialVersion string
	configuration, credential, credentialContext    []byte
	pending                                         int32
	enabled                                         bool
}

func (r *providerEnableStored) scan(row interface{ Scan(...any) error }) error {
	return row.Scan(&r.version, &r.mapping, &r.configuration, &r.pending, &r.enabled, &r.generation, &r.credentialVersion, &r.credential, &r.credentialContext)
}

func (s *ProviderService) observeEnablePredecessor(ctx context.Context, provider string, version uint64) (providerEnablePredecessor, error) {
	result := providerEnablePredecessor{}
	var row providerEnableStored
	if err := row.scan(s.pool.Raw().QueryRow(ctx, providerEnablePredecessorSQL, string(s.authentication.TenantID), s.updateOrganization, provider)); err != nil {
		return result, providerError(ctx, err)
	}
	if row.version != strconv.FormatUint(version, 10) || row.enabled {
		return result, sso.ErrConflict
	}
	if row.pending != 1 || len(row.credential) == 0 || len(row.credential) > 32768 || len(row.credentialContext) == 0 || len(row.credentialContext) > 4096 {
		return result, sso.ErrForbidden
	}
	mapping, err := strconv.ParseUint(row.mapping, 10, 64)
	if err != nil || mapping == 0 {
		return result, sso.ErrUnavailable
	}
	generation, err := strconv.ParseUint(row.generation, 10, 64)
	if err != nil || generation == 0 {
		return result, sso.ErrUnavailable
	}
	installed, err := strconv.ParseUint(row.credentialVersion, 10, 64)
	if err != nil || installed < 2 || installed > version {
		return result, sso.ErrUnavailable
	}
	if err := authenticateStoredProviderCredential(ctx, s.config.Envelope, string(s.authentication.TenantID), s.updateOrganization, provider, row.credential, row.credentialContext, generation, installed); err != nil {
		return result, err
	}
	codec := ProviderContributor{service: s}
	aad, err := envelope.NewContext(map[string]string{"owner": "sso/provider", "tenant": string(s.authentication.TenantID), "organization": s.updateOrganization, "provider": provider, "protocol": "oidc", "purpose": "static-configuration", "version": row.version})
	if err != nil {
		return result, sso.ErrUnavailable
	}
	plain, err := codec.openUpdateConfiguration(ctx, aad, row.configuration)
	if err != nil {
		return result, err
	}
	var current providerConfiguration
	if json.Unmarshal(plain, &current) != nil || len(current.Domains) != 1 || current.Mapping.Version != mapping {
		clear(plain)
		return result, sso.ErrUnavailable
	}
	canonical, err := organization.CanonicalDomain(current.Domains[0])
	if err != nil || canonical != current.Domains[0] {
		clear(plain)
		return result, sso.ErrUnavailable
	}
	return providerEnablePredecessor{configuration: plain, domain: canonical, mappingVersion: mapping, credentialGeneration: generation, credentialVersion: installed, configurationHash: sha256.Sum256(row.configuration), credentialHash: sha256.Sum256(row.credential), contextHash: sha256.Sum256(row.credentialContext)}, nil
}

func authenticateStoredProviderCredential(ctx context.Context, crypto *envelope.Service, tenant, organization, provider string, wire, contextWire []byte, generation, installed uint64) error {
	return withAuthenticatedStoredProviderCredential(ctx, crypto, tenant, organization, provider, wire, contextWire, generation, installed, func(ctx context.Context, _ []byte) error {
		return ctx.Err()
	})
}

// withAuthenticatedStoredProviderCredential borrows exact installed client
// credentials synchronously, clearing plaintext before returning. The caller
// must already authorize the installed generation and, for exchange, hold the
// original acknowledged callback reservation. This does neither operation.
func withAuthenticatedStoredProviderCredential(ctx context.Context, crypto *envelope.Service, tenant, organization, provider string, wire, contextWire []byte, generation, installed uint64, use func(context.Context, []byte) error) error {
	if ctx == nil || crypto == nil || use == nil || installed < 2 || generation == 0 || len(wire) == 0 || len(wire) > 32768 || len(contextWire) == 0 || len(contextWire) > 4096 {
		return sso.ErrForbidden
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var binding sso.CredentialReferenceContext
	if json.Unmarshal(contextWire, &binding) != nil || binding.TenantID != tenant || binding.OrganizationID != organization || binding.ProviderID != provider || binding.Generation != generation || binding.ProviderVersion != installed-1 {
		return sso.ErrUnavailable
	}
	canonical, err := json.Marshal(binding)
	if err != nil || !bytes.Equal(canonical, contextWire) {
		return sso.ErrUnavailable
	}
	aad, err := binding.EncryptionContext()
	if err != nil {
		return sso.ErrUnavailable
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil || sealed.KeyReference() != binding.EnvelopeKeyID {
		return sso.ErrForbidden
	}
	// The ingress lifetime protects credential installation. This is a read of
	// already installed custody: check authenticity, not the past ingress grant.
	plain, err := crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	defer clear(plain)
	if err != nil || len(plain) == 0 || len(plain) > 32768 {
		return providerError(ctx, sso.ErrForbidden)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return use(ctx, plain)
}

func (p *ProviderContributor) prepareEnable(ctx context.Context) error {
	s, e := p.service, p.enable
	if p.admission.verified.Before(e.credential.ObservedAt) || p.admission.verified.Before(e.proof.ObservedAt) {
		return sso.ErrForbidden
	}
	for _, until := range []time.Time{e.credential.ExpiresAt, e.proof.ExpiresAt} {
		if until.Before(p.admission.until) {
			p.admission.until = until
		}
	}
	if !p.admission.verified.Before(p.admission.until) {
		return sso.ErrForbidden
	}
	// Admission observed the organization version before this exact primary
	// proof read. Domain claim/evidence writes advance that same version under
	// lock; Work later requires it unchanged and checks the original expiry.
	proof, err := s.config.Organizations.GetDomainProof(ctx, e.request.DomainProofCheckpoint.Key)
	if err != nil {
		return providerError(ctx, err)
	}
	if proof != e.proof {
		return sso.ErrForbidden
	}
	e.predecessor, err = s.observeEnablePredecessor(ctx, e.request.ProviderID, e.request.ExpectedVersion)
	if err != nil {
		return err
	}
	if e.predecessor.domain != proof.Domain || e.predecessor.credentialGeneration != e.credential.Generation {
		return sso.ErrForbidden
	}
	p.configuration = e.predecessor.configuration
	return nil
}

func providerEnableProofContext(tenant, organization, provider string, version uint64) (envelope.Context, error) {
	return envelope.NewContext(map[string]string{"owner": "sso/provider", "tenant": tenant, "organization": organization, "provider": provider, "protocol": "oidc", "purpose": "enablement-proof", "version": strconv.FormatUint(version, 10)})
}

func (p *ProviderContributor) sealEnableProof(ctx context.Context) ([]byte, error) {
	aad, err := providerEnableProofContext(string(p.binding.TenantID), p.request.OrganizationID, p.binding.RecordID, p.afterVersion())
	if err != nil {
		return nil, sso.ErrUnavailable
	}
	plain, err := json.Marshal(p.enable.proof)
	if err != nil {
		return nil, sso.ErrUnavailable
	}
	defer clear(plain)
	wire, err := p.seal(ctx, aad, plain)
	if err != nil || len(wire) == 0 || len(wire) > providerEnableProofMaximumBytes {
		return nil, sso.ErrUnavailable
	}
	return wire, nil
}

func (p *ProviderContributor) requireEnablePredecessor(ctx context.Context, w kernel.Work) error {
	e := p.enable
	rows, err := w.Query(ctx, providerEnableFenceSQL, string(p.binding.TenantID), p.request.OrganizationID, p.binding.RecordID)
	if err != nil {
		return err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return err
		}
		return identity.ForbiddenError{}
	}
	var current providerEnableStored
	if err := current.scan(rows); err != nil {
		return err
	}
	if rows.Next() || rows.Err() != nil {
		return identity.UnavailableError{}
	}
	if current.enabled || current.pending != 1 || current.version != strconv.FormatUint(p.beforeVersion(), 10) || current.mapping != strconv.FormatUint(e.predecessor.mappingVersion, 10) {
		return identity.ConflictError{}
	}
	if current.generation != strconv.FormatUint(e.predecessor.credentialGeneration, 10) || current.credentialVersion != strconv.FormatUint(e.predecessor.credentialVersion, 10) {
		return identity.ConflictError{}
	}
	if sha256.Sum256(current.configuration) != e.predecessor.configurationHash || sha256.Sum256(current.credential) != e.predecessor.credentialHash || sha256.Sum256(current.credentialContext) != e.predecessor.contextHash {
		return identity.ConflictError{}
	}
	return nil
}

func (p *ProviderContributor) writeEnable(ctx context.Context, w kernel.Work, b identity.CommandBinding) error {
	if err := p.requireEnablePredecessor(ctx, w); err != nil {
		return err
	}
	// Check again after acquiring the provider row; a blocked writer must not
	// spend expired proof or session authority after the lock becomes available.
	if err := p.admit(ctx, w, p.command); err != nil {
		return err
	}
	e := p.enable
	n, err := w.Exec(ctx, enableProviderSQL, string(b.TenantID), p.request.OrganizationID, b.RecordID, strconv.FormatUint(p.afterVersion(), 10), p.configuration, strconv.FormatUint(e.predecessor.mappingVersion, 10), e.sealedProof, strconv.FormatUint(e.credential.Generation, 10), strconv.FormatUint(p.beforeVersion(), 10))
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}

func (s *ProviderService) readEnableReceipt(ctx context.Context, b identity.CommandBinding, domain string, version uint64) (sso.Provider, error) {
	var mapping string
	if err := s.pool.Raw().QueryRow(ctx, readProviderEnableReceiptSQL, string(b.CommandID), string(b.TenantID), s.updateOrganization, b.RecordID).Scan(&mapping); err != nil {
		return sso.Provider{}, providerError(ctx, err)
	}
	mappingVersion, err := strconv.ParseUint(mapping, 10, 64)
	if err != nil || mappingVersion == 0 {
		return sso.Provider{}, sso.ErrUnavailable
	}
	return sso.Provider{ID: b.RecordID, OrganizationID: s.updateOrganization, Protocol: "oidc", Version: version, Enabled: true, VerifiedDomains: []string{domain}, MappingVersion: mappingVersion}, nil
}
