package postgres

import (
	"crypto/sha256"
	"encoding/binary"

	scimorganization "github.com/faustbrian/go-scim/organization"
)

func directoryMixedCommitment(batch [32]byte, children []scimorganization.DirectoryMixedIntent) [32]byte {
	wire := append([]byte("sso/postgres/directory-mixed-batch/v1\x00"), batch[:]...)
	appendTarget := func(target string) {
		wire = binary.BigEndian.AppendUint64(wire, uint64(len(target)))
		wire = append(wire, target...)
	}
	for _, child := range children {
		if user, ok := child.User(); ok {
			wire = append(wire, 1)
			appendTarget(string(user.UserID))
		} else if group, ok := child.Membership(); ok {
			wire = append(wire, 2)
			appendTarget(string(group.TeamID))
			appendTarget(string(group.UserID))
		} else if role, ok := child.Role(); ok {
			wire = append(wire, 3)
			appendTarget(string(role.Membership.TeamID))
			appendTarget(string(role.Membership.UserID))
			appendTarget(string(role.RoleID))
		}
	}
	return sha256.Sum256(wire)
}
