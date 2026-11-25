package postgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	scim "github.com/faustbrian/go-scim"
	scimorganization "github.com/faustbrian/go-scim/organization"
	scimpostgres "github.com/faustbrian/go-scim/postgres"
	"github.com/faustbrian/go-sso"
)

type directorySyncUserChild struct {
	source    organizationpg.DirectoryMembershipSource
	evidence  scimpostgres.DirectoryUserMembershipEvidence
	operation identity.FeatureOperation
	action    organizationpg.DirectoryMembershipAction
	limits    directoryUserCapacity
	update    organizationpg.DirectoryMembershipUpdate
	effect    organizationpg.DirectoryMembershipEffect
}

func (p *directorySyncChild) prepareUser(intent scimorganization.DirectoryUserIntent, limits directoryUserCapacity) (*directorySyncChild, error) {
	batch := p.batch
	u := &directorySyncUserChild{
		source: organizationpg.DirectoryMembershipSource{TenantID: batch.TenantID, OrganizationID: batch.OrganizationID,
			ProviderID: organization.ID(batch.ProviderID), ConnectionID: organization.ID(batch.ConnectionID),
			ResourceID: organization.ID(intent.ResourceID), UserID: intent.UserID},
		evidence: scimpostgres.DirectoryUserMembershipEvidence{ResourceID: intent.ResourceID, Revision: scim.Version(intent.SourceRevision)},
		limits:   limits,
	}
	switch intent.Action {
	case scimorganization.DirectoryUserAdmit:
		u.operation, u.action = sso.DirectoryUserAdmissionOperation(), organizationpg.DirectoryMembershipGrant
		u.evidence.State = scimpostgres.DirectoryMembershipUserActive
	case scimorganization.DirectoryUserWithdrawInactive, scimorganization.DirectoryUserWithdrawDeleted:
		u.operation, u.action = sso.DirectoryUserDeprovisionOperation(), organizationpg.DirectoryMembershipWithdraw
		u.evidence.State = scimpostgres.DirectoryMembershipUserInactive
		if intent.Action == scimorganization.DirectoryUserWithdrawDeleted {
			u.evidence.State = scimpostgres.DirectoryMembershipUserDeleted
		}
	default:
		return nil, sso.ErrForbidden
	}
	recordID, err := u.source.RecordID()
	if err != nil {
		return nil, sso.ErrForbidden
	}
	child := *p
	child.user = u
	child.binding = p.childBinding(intent.CommandID, intent.UserID, u.operation, recordID)
	return &child, nil
}

func (p *directorySyncChild) prepareUserUpdate(ctx context.Context) error {
	u, repo := p.user, p.organizations()
	source := u.source
	observation, err := repo.ObserveDirectoryMembership(ctx, source)
	if err != nil {
		return err
	}
	org, err := repo.ObserveCredentialAuthority(ctx, organization.CredentialAuthorityQuery{TenantID: source.TenantID, OrganizationID: source.OrganizationID})
	if err != nil {
		return err
	}
	input := organizationpg.DirectoryMembershipInput{Source: source, ActorID: p.admission.bindings.ActorID,
		Organization: org, MemberVersion: observation.Member.Version, MemberAuthorizationVersion: observation.Member.AuthorizationVersion,
		ExpectedVersion: observation.ContributionVersion, Action: u.action}
	if u.action == organizationpg.DirectoryMembershipGrant {
		user, err := p.service.directory.Get(ctx, identity.GetUserQuery{TenantID: source.TenantID, UserID: source.UserID})
		if err != nil {
			return err
		}
		input.User, input.MaximumMembers, input.MaximumPerUser = user, u.limits.members, u.limits.perUser
	}
	update, err := organizationpg.NewDirectoryMembershipUpdate(input)
	if err != nil || update.RecordID() != p.binding.RecordID {
		return identity.ForbiddenError{}
	}
	u.update = update
	return nil
}
