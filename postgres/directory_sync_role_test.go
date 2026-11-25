package postgres

import (
	"testing"

	scimorganization "github.com/faustbrian/go-scim/organization"
)

func TestDirectoryRoleCommitmentSeparatesProfileAndSelectedTarget(t *testing.T) {
	batch := [32]byte{7}
	selected := scimorganization.DirectoryRoleIntent{
		Membership: scimorganization.DirectoryMembershipIntent{TeamID: "team", UserID: "user"},
		RoleID:     "reader",
	}
	commitment := directoryRoleCommitment(batch, selected)
	if commitment == batch || commitment == ([32]byte{}) || commitment != directoryRoleCommitment(batch, selected) {
		t.Fatal("role custody must be stable and distinct from membership-only custody")
	}
	otherBatch := batch
	otherBatch[0]++
	claims := []scimorganization.DirectoryRoleIntent{selected, selected, selected}
	claims[0].RoleID = "Reader"
	claims[1].Membership.TeamID = "other-team"
	claims[2].Membership.UserID = "other-user"
	for _, claim := range claims {
		if directoryRoleCommitment(batch, claim) == commitment {
			t.Fatal("different role, team or identity reused the pending commitment")
		}
	}
	if directoryRoleCommitment(otherBatch, selected) == commitment {
		t.Fatal("role selection lost original batch custody")
	}
}
