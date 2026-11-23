package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/faustbrian/go-sso"
)

// SAMLIDPConfirmationMigrationSource installs post-arrival confirmation
// custody for explicitly selected IdP-initiated SAML. Apply after the native
// identity command and SSO provider migrations on the primary, before enabling
// a confirmation writer. No SP login transaction or RelayState is created.
// Installation creates an empty table and does not modify provider history or
// share an SP cursor. Code rollback leaves the table and its custody intact.
type SAMLIDPConfirmationMigrationSource struct{ Version migrations.Version }

var _ migrations.Source = SAMLIDPConfirmationMigrationSource{}

// Load returns forward-only history without I/O. The positive unused version
// is selected by the caller after the required predecessor migrations.
func (s SAMLIDPConfirmationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, sso.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "sso_saml_idp_confirmations", migrations.TransactionModeDefault, samlIDPConfirmationSQL, "")
	if err != nil {
		return nil, sso.ErrUnavailable
	}
	return []migrations.Migration{m}, nil
}

// The arrival command is the opaque pending identifier; it is not an SP start.
// The original recipient is retained without a user-row FK so this transient
// custody does not prevent deletion. Only the current-account checks in the
// final owner's Work can establish the holder's continuing eligibility.
const samlIDPConfirmationSQL = `SET LOCAL lock_timeout='5s';
CREATE TABLE sso_providers.saml_idp_confirmations (
 tenant_id identity.directory_id NOT NULL,
 organization_id text COLLATE "C" NOT NULL CHECK(octet_length(organization_id) BETWEEN 1 AND 128),
 provider_id text COLLATE "C" NOT NULL CHECK(octet_length(provider_id) BETWEEN 1 AND 128),
 user_id identity.directory_id NOT NULL,
 confirmation_id bytea NOT NULL CHECK(octet_length(confirmation_id)=16),
 arrival_purpose text COLLATE "C" GENERATED ALWAYS AS ('identity.sso.saml-idp-prepare'::text) STORED,
 completion_purpose text COLLATE "C" GENERATED ALWAYS AS ('identity.sso.saml-idp-init'::text) STORED,
 completion_command_id bytea CHECK(octet_length(completion_command_id)=16 AND completion_command_id<>confirmation_id),
 binding_envelope bytea CHECK(octet_length(binding_envelope) BETWEEN 1 AND 65536),
 confirmation_key_version bigint CHECK(confirmation_key_version BETWEEN 1 AND 4294967295),
 browser_digest bytea CHECK(octet_length(browser_digest)=32),
 form_digest bytea CHECK(octet_length(form_digest)=32),
 issued_at timestamptz NOT NULL CHECK(isfinite(issued_at)),
 expires_at timestamptz NOT NULL CHECK(isfinite(expires_at) AND expires_at>issued_at AND expires_at<=issued_at+interval '5 minutes'),
 completed_at timestamptz CHECK(isfinite(completed_at) AND completed_at>=issued_at AND completed_at<expires_at),
 PRIMARY KEY (tenant_id,confirmation_id),
 UNIQUE (tenant_id,completion_command_id),
 FOREIGN KEY (tenant_id,organization_id,provider_id) REFERENCES sso_providers.providers(tenant_id,organization_id,provider_id),
 FOREIGN KEY (tenant_id,arrival_purpose,confirmation_id) REFERENCES identity.commands(tenant_id,purpose,command_id),
 FOREIGN KEY (tenant_id,completion_purpose,completion_command_id) REFERENCES identity.commands(tenant_id,purpose,command_id),
 CONSTRAINT saml_idp_confirmation_custody_check CHECK (
   (completed_at IS NULL AND completion_command_id IS NULL AND binding_envelope IS NOT NULL
    AND confirmation_key_version IS NOT NULL AND browser_digest IS NOT NULL AND form_digest IS NOT NULL AND browser_digest<>form_digest)
   OR (completed_at IS NOT NULL AND completion_command_id IS NOT NULL AND binding_envelope IS NULL
    AND confirmation_key_version IS NULL AND browser_digest IS NULL AND form_digest IS NULL)
 )
);
CREATE FUNCTION sso_providers.guard_saml_idp_confirmation() RETURNS trigger
 LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  IF NEW.completed_at IS NULL THEN RETURN NEW; END IF;
 ELSIF OLD.completed_at IS NULL AND NEW.completed_at IS NOT NULL
  AND (NEW.tenant_id,NEW.organization_id,NEW.provider_id,NEW.user_id,NEW.confirmation_id,NEW.issued_at,NEW.expires_at)
   IS NOT DISTINCT FROM (OLD.tenant_id,OLD.organization_id,OLD.provider_id,OLD.user_id,OLD.confirmation_id,OLD.issued_at,OLD.expires_at) THEN
  RETURN NEW;
 END IF;
 RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='saml confirmation custody is immutable';
END;
$$;
CREATE TRIGGER guard_saml_idp_confirmation BEFORE INSERT OR UPDATE ON sso_providers.saml_idp_confirmations
 FOR EACH ROW EXECUTE FUNCTION sso_providers.guard_saml_idp_confirmation();`
