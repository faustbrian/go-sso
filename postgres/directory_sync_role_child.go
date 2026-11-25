package postgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	scimorganization "github.com/faustbrian/go-scim/organization"
	scimpostgres "github.com/faustbrian/go-scim/postgres"
	"github.com/faustbrian/go-sso"
)

type directorySyncRoleChild struct {
	source organizationpg.DirectoryTeamRoleSource
	update organizationpg.DirectoryTeamRoleUpdate
	lock   organizationpg.DirectoryTeamRoleLock
}

func (p *directorySyncChild) prepareRole(intent scimorganization.DirectoryRoleIntent) (*directorySyncChild, error) {
	batch, edge := p.batch, intent.Membership
	scope := organizationpg.DirectoryTeamGrantScope{
		TenantID: batch.TenantID, OrganizationID: batch.OrganizationID, ProviderID: organization.ID(batch.ProviderID),
		ConnectionID: organization.ID(batch.ConnectionID), GroupID: organization.ID(edge.GroupID), TeamID: edge.TeamID, UserID: edge.UserID,
	}
	recordID, err := scope.RecordID()
	if err != nil {
		return nil, sso.ErrForbidden
	}
	child := *p
	child.edge = scimpostgres.DirectoryGroupEdge{GroupID: edge.GroupID, UserID: edge.MemberID, Present: edge.Action == sso.DirectoryMembershipAdd}
	child.role = &directorySyncRoleChild{source: organizationpg.DirectoryTeamRoleSource{
		Scope: scope, MemberResourceID: organization.ID(edge.MemberID), RoleID: intent.RoleID,
		ProviderVersion: p.generation.ProviderVersion, MappingVersion: batch.MappingVersion, ConnectionVersion: p.admission.bindings.ConnectionVersion,
	}}
	child.binding = p.childBinding(edge.CommandID, edge.UserID, sso.DirectoryTeamMembershipOperation(), recordID)
	return &child, nil
}

func (p *directorySyncChild) prepareRoleUpdate(ctx context.Context) error {
	source, active := p.role.source, p.edge.Present
	grant, err := p.observeTeamGrant(ctx, source.Scope, active)
	if err != nil {
		return err
	}
	if grant.RecordID() != p.binding.RecordID {
		return identity.ForbiddenError{}
	}
	var bindingVersion uint64
	if active {
		bindingVersion, err = p.organizations().ObserveDirectoryTeamRoleBinding(ctx, source.Scope, source.RoleID)
		if err != nil {
			return err
		}
	}
	update, err := organizationpg.NewDirectoryTeamRoleUpdate(grant, source, bindingVersion)
	if err != nil {
		return err
	}
	p.update, p.role.update = grant, update
	return nil
}
