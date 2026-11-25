package postgres

import (
	"testing"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	scimorganization "github.com/faustbrian/go-scim/organization"
	"github.com/faustbrian/go-sso"
)

func TestDirectoryMixedCommitmentSeparatesExplicitMappedProfiles(t *testing.T) {
	newID := func() identity.CommandID {
		t.Helper()
		id, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	user, err := sso.NewDirectoryUserAdmissionDelta(newID(), "resource-a", `"version-a"`)
	if err != nil {
		t.Fatal(err)
	}
	group, err := sso.NewDirectoryGroupMembershipDelta(newID(), "group-a", "resource-a", sso.DirectoryMembershipAdd)
	if err != nil {
		t.Fatal(err)
	}
	batch := sso.DirectoryDeltaBatch{TenantID: "tenant-a", OrganizationID: "org-a", ProviderID: "provider-a", ConnectionID: "connection-a",
		Generation: 1, MappingVersion: 1, PredecessorCheckpoint: [32]byte{1}, Deltas: []sso.DirectoryDelta{user, group}}
	base, err := batch.Commitment()
	if err != nil {
		t.Fatal(err)
	}
	commit := func(team, role organization.ID, local identity.UserID) [32]byte {
		t.Helper()
		members := []scimorganization.DirectoryMemberUserMapping{{MemberID: "resource-a", UserID: local}}
		users, err := scimorganization.NewDirectoryUserMapper(scimorganization.DirectoryUserMappingConfig{TenantID: batch.TenantID, OrganizationID: batch.OrganizationID,
			ProviderID: batch.ProviderID, ConnectionID: batch.ConnectionID, MappingVersion: batch.MappingVersion, AllowAdmission: true, Members: members})
		if err != nil {
			t.Fatal(err)
		}
		config := scimorganization.DirectoryMappingConfig{TenantID: batch.TenantID, OrganizationID: batch.OrganizationID, ProviderID: batch.ProviderID,
			ConnectionID: batch.ConnectionID, MappingVersion: batch.MappingVersion, Groups: []scimorganization.DirectoryGroupTeamMapping{{GroupID: "group-a", TeamID: team}}, Members: members}
		mixed := scimorganization.DirectoryMixedMappingConfig{Users: users}
		if role == "" {
			mixed.Groups, err = scimorganization.NewDirectoryMapper(config)
		} else {
			mixed.Roles, err = scimorganization.NewDirectoryRoleMapper(scimorganization.DirectoryRoleMappingConfig{Directory: config,
				Roles: []scimorganization.DirectoryGroupRoleMapping{{GroupID: "group-a", TeamID: team, RoleID: role}}})
		}
		if err != nil {
			t.Fatal(err)
		}
		mapper, err := scimorganization.NewDirectoryMixedMapper(mixed)
		if err != nil {
			t.Fatal(err)
		}
		mapped, err := mapper.MapDirectoryMixedDelta(batch)
		if err != nil {
			t.Fatal(err)
		}
		return directoryMixedCommitment(base, mapped.Children)
	}
	plain := commit("team-a", "", "user-a")
	role := commit("team-a", "reader-a", "user-a")
	if plain == base || role == plain || role == commit("team-a", "reader-b", "user-a") ||
		plain == commit("team-b", "", "user-a") || plain == commit("team-a", "", "user-b") ||
		role != commit("team-a", "reader-a", "user-a") {
		t.Fatal("mixed replay identity failed to bind exact profile and targets deterministically")
	}
}
