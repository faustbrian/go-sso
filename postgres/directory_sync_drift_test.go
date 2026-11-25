package postgres

import (
	"errors"
	"testing"

	scimorganization "github.com/faustbrian/go-scim/organization"
	scimpostgres "github.com/faustbrian/go-scim/postgres"
	"github.com/faustbrian/go-sso"
)

func TestDirectoryDriftSourcePreservesUnknownAndInactive(t *testing.T) {
	t.Parallel()
	for _, pair := range []struct {
		observed scimpostgres.DirectoryGroupEdgeState
		expected scimorganization.DirectorySourceMembership
	}{
		{scimpostgres.DirectoryGroupEdgePresent, scimorganization.DirectorySourceMembershipPresent},
		{scimpostgres.DirectoryGroupEdgeAbsent, scimorganization.DirectorySourceMembershipAbsent},
		{scimpostgres.DirectoryGroupEdgeInactiveUser, scimorganization.DirectorySourceMembershipInactiveUser},
		{scimpostgres.DirectoryGroupEdgeUnproven, scimorganization.DirectorySourceMembershipUnproven},
	} {
		got, err := directoryDriftSource(pair.observed)
		if err != nil || got != pair.expected {
			t.Fatalf("source %v classified as %v (%v), expected %v", pair.observed, got, err, pair.expected)
		}
	}
	if got, err := directoryDriftSource(0); got != 0 || !errors.Is(err, sso.ErrUnavailable) {
		t.Fatalf("unknown source cannot produce drift evidence: %v (%v)", got, err)
	}
}
