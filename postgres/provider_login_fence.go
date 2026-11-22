package postgres

import (
	"context"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	"github.com/faustbrian/go-sso"
)

type providerLoginAuthority struct {
	route        sso.DomainRoute
	organization organization.CredentialAuthorityObservation
}

func (r *ProviderRouter) observeProviderLoginAuthority(ctx context.Context, route sso.DomainRoute) (providerLoginAuthority, error) {
	if r == nil || r.organizations == nil || ctx == nil {
		return providerLoginAuthority{}, sso.ErrInvalidInput
	}
	selected, err := route.Bindings()
	if err != nil || !r.config.Clock.Now().Before(selected.ValidUntil) {
		return providerLoginAuthority{}, sso.ErrForbidden
	}
	ctx, cancel := context.WithTimeout(ctx, r.config.MaximumDuration)
	defer cancel()
	key := selected.Proof.Key
	// Observe the organization version first: every proof writer takes that row
	// lock and advances its version. The later Work fence can then reject any
	// domain change between this exact proof read and login admission.
	owner, err := r.organizations.ObserveCredentialAuthority(ctx, organization.CredentialAuthorityQuery{TenantID: key.TenantID, OrganizationID: key.OrganizationID})
	if err != nil {
		return providerLoginAuthority{}, providerError(ctx, err)
	}
	proof, err := r.organizations.GetDomainProof(ctx, key)
	if err != nil {
		return providerLoginAuthority{}, providerError(ctx, err)
	}
	if proof != organization.DomainProof(key) || !r.config.Clock.Now().Before(providerLoginDeadline(selected, owner)) {
		return providerLoginAuthority{}, sso.ErrForbidden
	}
	return providerLoginAuthority{route: route, organization: owner}, nil
}

func (r *ProviderRouter) requireProviderLoginAuthority(ctx context.Context, work kernel.Work, owner kernel.FeatureExecutionContributor, authority providerLoginAuthority, mappingVersion uint64) error {
	selected, err := authority.route.Bindings()
	if err != nil || authority.organization.TenantID != selected.Proof.Key.TenantID || authority.organization.OrganizationID != selected.Proof.Key.OrganizationID || authority.organization.Actor.UserID != "" {
		return identity.ForbiddenError{}
	}
	if err := r.organizations.RequireCredentialAuthority(ctx, work, owner, authority.organization); err != nil {
		return err
	}
	return requireProviderLoginAdmission(ctx, work, selected, authority.route.Protocol(), mappingVersion, providerLoginDeadline(selected, authority.organization))
}

func providerLoginDeadline(route sso.DomainRouteBinding, owner organization.CredentialAuthorityObservation) time.Time {
	organizationDeadline := owner.ValidUntil.UTC().Truncate(time.Microsecond)
	if organizationDeadline.Before(route.ValidUntil) {
		return organizationDeadline
	}
	return route.ValidUntil
}

// The shared row lock allows concurrent starts while excluding a provider
// transition. Evaluate the original route deadline outside the materialized
// lock query: time spent waiting for a writer must never renew that deadline.
const providerLoginAdmissionFencePrefixSQL = `WITH eligible_provider AS MATERIALIZED (
 SELECT 1 FROM sso_providers.providers p
 JOIN sso_providers.credentials c USING(tenant_id,organization_id,provider_id)
 WHERE p.tenant_id=$1 AND p.organization_id=$2 AND p.provider_id=$3 AND p.enabled
 AND p.metadata_version=$4::numeric AND p.enablement_credential_generation=$5::numeric
 AND c.generation=$5::numeric AND COALESCE(p.metadata_mapping_version,p.mapping_version)=$6::numeric`

const providerLoginAdmissionFenceSuffixSQL = `
 FOR SHARE OF p
)
SELECT true FROM eligible_provider WHERE clock_timestamp() < $7::timestamptz`

const providerLoginAdmissionFenceSQL = providerLoginAdmissionFencePrefixSQL + providerLoginAdmissionFenceSuffixSQL
const providerLoginOAuth2AdmissionFenceSQL = providerLoginAdmissionFencePrefixSQL + ` AND p.protocol='oauth2'` + providerLoginAdmissionFenceSuffixSQL

// The provider lock grants neither browser possession nor identity authority.
// It must follow the organization proof fence in the same Work.
func requireProviderLoginAdmission(ctx context.Context, work kernel.Work, selected sso.DomainRouteBinding, protocol string, mappingVersion uint64, deadline time.Time) error {
	if mappingVersion == 0 || deadline.IsZero() || deadline.After(selected.ValidUntil) {
		return identity.ForbiddenError{}
	}
	binding, err := work.Scope()
	if err != nil {
		return err
	}
	proof := selected.Proof.Key
	if binding.TenantID != proof.TenantID || binding.OperationID != "identity.sso.signin-start" {
		return identity.ForbiddenError{}
	}
	query := providerLoginAdmissionFenceSQL
	switch protocol {
	case "oidc":
		if binding.SchemaID == kernel.SSOOAuth2SigninStartOperation().SchemaID {
			return identity.ForbiddenError{}
		}
	case providerProtocolOAuth2:
		if binding.SchemaID != kernel.SSOOAuth2SigninStartOperation().SchemaID {
			return identity.ForbiddenError{}
		}
		query = providerLoginOAuth2AdmissionFenceSQL
	default:
		return identity.ForbiddenError{}
	}
	rows, err := work.Query(ctx, query,
		string(proof.TenantID), string(proof.OrganizationID), string(selected.ProviderID),
		strconv.FormatUint(selected.ProviderVersion, 10), strconv.FormatUint(selected.CredentialGeneration, 10),
		strconv.FormatUint(mappingVersion, 10), deadline)
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
	var admitted bool
	if err := rows.Scan(&admitted); err != nil {
		return err
	}
	if rows.Next() || !admitted {
		return identity.UnavailableError{}
	}
	return rows.Err()
}
