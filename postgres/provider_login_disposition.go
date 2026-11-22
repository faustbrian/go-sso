package postgres

import (
	"context"
	"strconv"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// Invoke after advancing the disabled provider and recording the native command
// effect in the same Work. The provider write excludes concurrent admissions;
// this statement sees admissions that committed before that fence was acquired.
const recordProviderLoginDispositionSQL = `INSERT INTO sso_providers.provider_login_dispositions
 (tenant_id,organization_id,provider_id,provider_version,mode,command_id,active_transaction_count,recorded_at)
 SELECT e.tenant_id,e.organization_id,e.provider_id,$4::numeric,$5,e.command_id,
  (SELECT count(*)::integer FROM (
   SELECT 1 FROM sso_providers.login_transactions
   WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND provider_version=$4::numeric
   AND completed_at IS NULL AND expires_at>statement_timestamp() LIMIT 1000000
  ) active),statement_timestamp()
 FROM sso_providers.command_effects e JOIN sso_providers.providers p USING(tenant_id,organization_id,provider_id)
 WHERE e.tenant_id=$1 AND e.organization_id=$2 AND e.provider_id=$3 AND e.command_id=$6
 AND NOT p.enabled AND p.metadata_version=$4::numeric+1
 RETURNING active_transaction_count`

func recordProviderLoginDisposition(ctx context.Context, work kernel.Work, organization string, originalVersion uint64, mode string) (uint32, error) {
	binding, err := work.Scope()
	if err != nil {
		return 0, err
	}
	if binding.OperationID != "identity.sso.provider.disable" || !providerID(organization) || originalVersion == 0 || (mode != "drain" && mode != "revoke") {
		return 0, identity.ForbiddenError{}
	}
	rows, err := work.Query(ctx, recordProviderLoginDispositionSQL,
		string(binding.TenantID), organization, binding.RecordID, strconv.FormatUint(originalVersion, 10), mode, string(binding.CommandID))
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return 0, err
		}
		return 0, identity.UnavailableError{}
	}
	var active int32
	if err := rows.Scan(&active); err != nil {
		return 0, err
	}
	if rows.Next() || !validDisableCount(active) {
		return 0, identity.UnavailableError{}
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	return uint32(active), nil
}
