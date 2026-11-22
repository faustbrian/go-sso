package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// Lock before reading disposition evidence. A disable writer may commit while
// this statement waits; only a subsequent READ COMMITTED statement can see its
// newly inserted receipt. Both statements retain this same Work's provider lock.
const providerLoginCallbackDispositionFenceSQL = `WITH eligible_provider AS MATERIALIZED (
 SELECT p.enabled FROM sso_providers.providers p
 JOIN sso_providers.credentials c USING(tenant_id,organization_id,provider_id)
 WHERE p.tenant_id=$1 AND p.organization_id=$2 AND p.provider_id=$3
 AND c.generation=$5::numeric AND COALESCE(p.metadata_mapping_version,p.mapping_version)=$6::numeric
 AND ((p.enabled AND p.metadata_version=$4::numeric AND p.enablement_credential_generation=$5::numeric)
  OR (NOT p.enabled AND p.metadata_version=$4::numeric+1))
 FOR SHARE OF p
)
SELECT enabled FROM eligible_provider WHERE clock_timestamp() < $7::timestamptz`

const providerLoginCallbackDrainSQL = `SELECT e.command_id,e.binding
 FROM sso_providers.provider_login_dispositions d
 JOIN sso_providers.command_effects e
 ON e.command_id=d.command_id AND e.tenant_id=d.tenant_id
 AND e.organization_id=d.organization_id AND e.provider_id=d.provider_id
 WHERE d.tenant_id=$1 AND d.organization_id=$2 AND d.provider_id=$3
 AND d.provider_version=$4::numeric AND d.mode='drain'
 AND clock_timestamp() < $5::timestamptz`

// Invoke only after the organization authority fence in the callback's sole
// Work. Admission neither consumes the login nor releases its verifier, and a
// drain admits only this unchanged installed predecessor, never a later enable.
func requireProviderLoginCallbackDisposition(ctx context.Context, work kernel.Work, found providerLoginCallbackLookup, deadline time.Time) error {
	if ctx == nil {
		return identity.ForbiddenError{}
	}
	binding, err := work.Scope()
	if err != nil {
		return err
	}
	if !validProviderLoginCallbackDispositionScope(binding, found, deadline) {
		return identity.ForbiddenError{}
	}
	args := providerLoginCallbackDispositionArgs(found.Row, deadline)
	rows, err := work.Query(ctx, providerLoginCallbackDispositionFenceSQL, args...)
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
	var enabled bool
	if err := rows.Scan(&enabled); err != nil {
		return err
	}
	if rows.Next() {
		return identity.UnavailableError{}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()
	if enabled {
		return nil
	}

	rows, err = work.Query(ctx, providerLoginCallbackDrainSQL, args[0], args[1], args[2], args[3], deadline)
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
	var command string
	var wire []byte
	if err := rows.Scan(&command, &wire); err != nil {
		return err
	}
	defer clear(wire)
	if rows.Next() {
		return identity.UnavailableError{}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if !validProviderLoginCallbackDisableBinding(found.Row, command, wire) {
		return identity.ForbiddenError{}
	}
	return nil
}

func providerLoginCallbackDispositionArgs(row providerLoginRowIdentity, deadline time.Time) []any {
	return []any{string(row.TenantID), row.OrganizationID, row.ProviderID,
		strconv.FormatUint(row.ProviderVersion, 10), strconv.FormatUint(row.CredentialGeneration, 10),
		strconv.FormatUint(row.MappingVersion, 10), deadline}
}

func validProviderLoginCallbackDispositionScope(binding identity.CommandBinding, found providerLoginCallbackLookup, deadline time.Time) bool {
	input := found.Binding.Metadata.Input
	original := input.Command
	operation := providerOIDCCallbackOperation()
	if input.validate() != nil || found.Row != input.rowIdentity() || found.CompletedAt != nil ||
		found.ObservedAt.IsZero() || found.ObservedAt.Before(found.Row.IssuedAt) || !found.ObservedAt.Before(found.Row.ExpiresAt) {
		return false
	}
	if deadline.IsZero() || !deadline.After(found.ObservedAt) || deadline.After(found.Row.ExpiresAt) || deadline.After(found.ObservedAt.Add(20*time.Second)) {
		return false
	}
	return binding.ValidateFor(operation) == nil && binding.TenantID == original.TenantID &&
		binding.CommandID == found.Binding.Metadata.CallbackCommand && binding.CommandID != original.CommandID &&
		binding.RecordID == string(original.CommandID) && binding.AnonymousFlowID == original.AnonymousFlowID &&
		binding.UserID == "" && binding.ActorKind == authorization.SubjectServiceAccount && binding.ActorID == original.ActorID &&
		binding.PolicyID == original.PolicyID && binding.PolicyVersion == original.PolicyVersion
}

func validProviderLoginCallbackDisableBinding(row providerLoginRowIdentity, command string, wire []byte) bool {
	if len(wire) < 1 || len(wire) > 4096 {
		return false
	}
	var stored providerStoredBinding
	if json.Unmarshal(wire, &stored) != nil {
		return false
	}
	canonical, err := json.Marshal(stored)
	if err != nil || !bytes.Equal(wire, canonical) {
		return false
	}
	binding := identity.CommandBinding(stored)
	disable := ProviderContributor{disable: &providerDisable{}}
	return binding.ValidateFor(disable.operation()) == nil && string(binding.CommandID) == command &&
		binding.TenantID == row.TenantID && binding.RecordID == row.ProviderID &&
		binding.ActorKind == authorization.SubjectUser && binding.UserID != "" && binding.ActorID == identity.ActorID(binding.UserID)
}
