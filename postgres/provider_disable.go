package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"strconv"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
)

type providerDisable struct {
	selection           sso.ActiveTransactionDispositionBinding
	reasonDigest        [32]byte
	predecessorEnvelope []byte
	predecessorHash     [32]byte
}

type storedDisableBinding struct {
	Binding      providerStoredBinding
	Version      uint64
	Mode         sso.ActiveTransactionDispositionMode
	ReasonDigest [32]byte
}

func (d *providerDisable) storedBinding(b providerStoredBinding) storedDisableBinding {
	return storedDisableBinding{Binding: b, Version: d.selection.ProviderVersion, Mode: d.selection.Mode, ReasonDigest: d.reasonDigest}
}

func (d providerDisable) predecessorVersion() uint64 { return d.selection.ProviderVersion }

const providerDisablePredecessorSQL = `SELECT metadata_version::text,COALESCE(metadata_mapping_version,mapping_version)::text,
 COALESCE(metadata_configuration_envelope,configuration_envelope),pending_domains,enabled
 FROM sso_providers.providers WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3`

const disableProviderSQL = `UPDATE sso_providers.providers SET enabled=false,metadata_version=$4::numeric,
 metadata_configuration_envelope=$5,enablement_proof=NULL,enablement_credential_generation=NULL
 WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND metadata_version=$6::numeric AND enabled
 AND COALESCE(metadata_configuration_envelope,configuration_envelope)=$7`

const readProviderDisableReceiptSQL = `SELECT d.active_transaction_count
 FROM sso_providers.provider_login_dispositions d
 WHERE d.command_id=$1 AND d.tenant_id=$2 AND d.organization_id=$3 AND d.provider_id=$4
 AND d.provider_version=$5::numeric AND d.mode=$6`

const recoverProviderDisableSQL = `SELECT e.binding,e.organization_id,e.provider_id,COALESCE(d.active_transaction_count,-1)
 FROM sso_providers.command_effects e LEFT JOIN sso_providers.provider_login_dispositions d
 ON d.command_id=e.command_id AND d.tenant_id=e.tenant_id AND d.organization_id=e.organization_id AND d.provider_id=e.provider_id
 AND d.provider_version=$3::numeric AND d.mode=$4 WHERE e.command_id=$1 AND e.tenant_id=$2`

func (p *ProviderContributor) prepareDisable(ctx context.Context) error {
	tenant := string(p.service.authentication.TenantID)
	organization, provider := p.request.OrganizationID, string(p.disable.selection.ProviderID)
	var version, mapping string
	var wire []byte
	var domains int32
	var enabled bool
	if err := p.service.pool.Raw().QueryRow(ctx, providerDisablePredecessorSQL, tenant, organization, provider).
		Scan(&version, &mapping, &wire, &domains, &enabled); err != nil {
		return providerError(ctx, err)
	}
	if !enabled || version != strconv.FormatUint(p.beforeVersion(), 10) {
		return sso.ErrConflict
	}
	// Metadata is authenticated against its version. Re-seal the same
	// configuration at the successor without reading credentials or proofs.
	protocol := p.request.providerProtocol()
	aad, err := envelope.NewContext(map[string]string{"owner": "sso/provider", "tenant": tenant, "organization": organization, "provider": provider, "protocol": protocol, "purpose": "static-configuration", "version": version})
	if err != nil {
		return sso.ErrUnavailable
	}
	plain, err := p.openUpdateConfiguration(ctx, aad, wire)
	if err != nil {
		return err
	}
	mappingVersion, err := strconv.ParseUint(mapping, 10, 64)
	if err != nil || mappingVersion == 0 || domains < 1 || domains > 128 {
		clear(plain)
		return sso.ErrUnavailable
	}
	if _, err = readProviderConfigurationDomains(protocol, plain, mappingVersion, int(domains)); err != nil {
		clear(plain)
		return err
	}
	p.configuration = plain
	p.disable.predecessorEnvelope = wire
	p.disable.predecessorHash = sha256.Sum256(wire)
	return nil
}

func (p *ProviderContributor) writeDisable(ctx context.Context, w kernel.Work, b identity.CommandBinding) error {
	n, err := w.Exec(ctx, disableProviderSQL,
		string(b.TenantID), p.request.OrganizationID, b.RecordID, strconv.FormatUint(p.afterVersion(), 10),
		p.configuration, strconv.FormatUint(p.beforeVersion(), 10), p.disable.predecessorEnvelope)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}

func (p *ProviderContributor) readDisableReceipt(ctx context.Context, b identity.CommandBinding) (uint32, error) {
	var count int32
	err := p.service.pool.Raw().QueryRow(ctx, readProviderDisableReceiptSQL, string(b.CommandID), string(b.TenantID),
		p.request.OrganizationID, b.RecordID, strconv.FormatUint(p.beforeVersion(), 10), string(p.disable.selection.Mode)).Scan(&count)
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}
	if err != nil || !validDisableCount(count) {
		return 0, sso.ErrUnavailable
	}
	return uint32(count), nil
}

func (p *ProviderContributor) recoverDisable(ctx context.Context, w kernel.RecoveryWork, b identity.CommandBinding) (kernel.RecoveryStatus, error) {
	rows, err := w.Query(ctx, recoverProviderDisableSQL, string(b.CommandID), string(b.TenantID),
		strconv.FormatUint(p.beforeVersion(), 10), string(p.disable.selection.Mode))
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err = rows.Err(); err != nil {
			return kernel.RecoveryUnknown, err
		}
		return kernel.RecoveryNotCommitted, nil
	}
	var binding []byte
	var organization, provider string
	var count int32
	if err := rows.Scan(&binding, &organization, &provider, &count); err != nil {
		return kernel.RecoveryUnknown, err
	}
	expected, _ := json.Marshal(providerStoredBinding(b))
	if rows.Next() || rows.Err() != nil || !bytes.Equal(binding, expected) || organization != p.request.OrganizationID || provider != b.RecordID || !validDisableCount(count) {
		return kernel.RecoveryUnknown, sso.ErrUnavailable
	}
	return kernel.RecoveryCommitted, nil
}

func validDisableCount(count int32) bool { return count >= 0 && count <= 1_000_000 }
