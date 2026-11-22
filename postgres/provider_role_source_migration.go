package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/faustbrian/go-sso"
)

// ProviderRoleSourceMigrationSource opts the native provider table into the
// organization-owned role source projection. Install after the provider
// enablement history and organization's ProviderRoleSourceProjectionMigrationSource.
// Existing providers are not backfilled. Authoritative provider changes,
// including disablement, update eligibility in the same transaction even if
// an older binary issued the statement. Removal retires the source in place.
type ProviderRoleSourceMigrationSource struct{ Version migrations.Version }

func (s ProviderRoleSourceMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, sso.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	migration, err := migrations.NewMigration(s.Version, "sso_provider_role_source_projection", migrations.TransactionModeDefault, providerRoleSourceSQL, "")
	if err != nil {
		return nil, sso.ErrUnavailable
	}
	return []migrations.Migration{migration}, nil
}

// Bind eligibility to the existing durable provider version and effective
// mapping; SSO calls the organization-owned projector rather than changing
// organization storage directly. No trigger fires for unrelated row columns.
const providerRoleSourceSQL = `SET LOCAL lock_timeout='2s';
CREATE FUNCTION sso_providers.project_provider_role_source_change() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $project$
BEGIN
  IF TG_OP='DELETE' THEN
    PERFORM organization.project_provider_role_source(OLD.tenant_id,OLD.organization_id,OLD.provider_id,
      OLD.metadata_version,COALESCE(OLD.metadata_mapping_version,OLD.mapping_version),false);
    RETURN OLD;
  END IF;
  IF TG_OP='UPDATE' THEN
    IF NEW.enabled=OLD.enabled AND NEW.metadata_version=OLD.metadata_version
       AND COALESCE(NEW.metadata_mapping_version,NEW.mapping_version)=COALESCE(OLD.metadata_mapping_version,OLD.mapping_version) THEN
      RETURN NEW;
    END IF;
  END IF;
  PERFORM organization.project_provider_role_source(NEW.tenant_id,NEW.organization_id,NEW.provider_id,
    NEW.metadata_version,COALESCE(NEW.metadata_mapping_version,NEW.mapping_version),NEW.enabled);
  RETURN NEW;
END;
$project$;
CREATE TRIGGER provider_role_source_change
AFTER INSERT OR UPDATE OF enabled,metadata_version,metadata_mapping_version,mapping_version OR DELETE
ON sso_providers.providers FOR EACH ROW EXECUTE FUNCTION sso_providers.project_provider_role_source_change();`
