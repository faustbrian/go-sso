package postgres

import (
	"context"
	"slices"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

// Kept in the existing encrypted preparation output; never projected to
// transports, tokens, logs or successful login receipts.
type providerLoginRoleUpdateWire struct {
	Grants                      organization.ProviderRoleGrantInput
	Member                      organization.CredentialAuthorityObservation
	Generation                  uint64
	ExpectedOrganizationVersion uint64
}

func (p *providerLoginCallbackPhase) prepareProviderLoginRoleUpdate(ctx context.Context, result oauth.ExchangeResult, recipient providerLoginCallbackRecipient) (*providerLoginRoleUpdateWire, *identity.FeatureField, error) {
	if p.roleMapping == nil {
		return nil, nil, nil
	}
	roles, err := p.roleMapping.desiredRoles(result.VerifiedOIDCClaims())
	if err != nil {
		return nil, nil, err
	}
	user := recipient.account.Account.UserID
	row := p.found.Row
	wire := &providerLoginRoleUpdateWire{
		Grants: organization.ProviderRoleGrantInput{
			Scope: organization.ProviderRoleGrantScope{TenantID: row.TenantID, OrganizationID: organization.ID(row.OrganizationID),
				UserID: user, ProviderID: organization.ID(row.ProviderID)},
			MemberVersion: recipient.member.Actor.Version, MappingVersion: row.MappingVersion,
			OriginalFlowStartedAt: p.roleSyncStartedAt(), AssertedAt: result.Identity.IDTokenIssuedAt(), RoleIDs: roles,
		},
		Member: recipient.member, Generation: row.ProviderVersion,
	}
	grants, err := organization.NewProviderRoleGrantSet(wire.Grants)
	if err != nil {
		return nil, nil, identity.ForbiddenError{}
	}
	planned, err := p.service.router.organizations.PrepareProviderRoleGrantUpdate(ctx, grants, wire.Member, wire.Generation)
	if err != nil {
		return nil, nil, err
	}
	wire.ExpectedOrganizationVersion = planned.ExpectedOrganizationVersion()
	_, field, err := p.restoreProviderLoginRoleUpdate(wire, user)
	if err != nil {
		return nil, nil, err
	}
	return wire, field, nil
}

func (p *providerLoginCallbackPhase) restoreProviderLoginRoleUpdate(wire *providerLoginRoleUpdateWire, user identity.UserID) (update organizationpg.ProviderRoleGrantUpdate, field *identity.FeatureField, err error) {
	if p.roleMapping == nil && wire == nil {
		return update, nil, nil
	}
	if p.roleMapping == nil || wire == nil {
		return update, nil, identity.ForbiddenError{}
	}
	input := wire.Grants
	row := p.found.Row
	if input.Scope.TenantID != row.TenantID || input.Scope.OrganizationID != organization.ID(row.OrganizationID) ||
		input.Scope.UserID != user || input.Scope.ProviderID != organization.ID(row.ProviderID) ||
		wire.Generation != row.ProviderVersion || input.MappingVersion != row.MappingVersion || input.MappingVersion != p.roleMapping.mappingVersion ||
		!input.OriginalFlowStartedAt.Equal(p.roleSyncStartedAt()) || wire.Member.Version != p.authority.organization.Version ||
		wire.Member.CredentialVersion != p.authority.organization.CredentialVersion {
		return update, nil, identity.ForbiddenError{}
	}
	grants, err := organization.NewProviderRoleGrantSet(input)
	if err != nil {
		return update, nil, identity.ForbiddenError{}
	}
	for _, role := range input.RoleIDs {
		if !slices.ContainsFunc(p.roleMapping.rules, func(rule StaticOIDCRoleRule) bool { return rule.RoleID == role }) {
			return update, nil, identity.ForbiddenError{}
		}
	}
	update, err = organizationpg.NewProviderRoleGrantUpdate(grants, wire.Member, wire.Generation, wire.ExpectedOrganizationVersion)
	if err != nil {
		return update, nil, identity.ForbiddenError{}
	}
	binding, err := update.Field()
	if err != nil {
		return update, nil, identity.ForbiddenError{}
	}
	return update, &binding, nil
}

func (p *providerLoginCallbackPhase) roleSyncStartedAt() time.Time {
	// The capability issue time rounds to seconds. Role replacement must order
	// distinct original starts at the precision their durable checkpoint retains.
	return p.original.Started.Truncate(time.Microsecond)
}
