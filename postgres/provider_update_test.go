package postgres_test

import (
	"errors"
	"testing"

	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestProviderUpdateOrganizationBindingRejectsAbsentService(t *testing.T) {
	for _, service := range []*ssopg.ProviderService{nil, new(ssopg.ProviderService)} {
		if bound, err := service.ForOrganization("organization"); !errors.Is(err, sso.ErrInvalidInput) || bound != nil {
			t.Fatal("absent native service acquired an organization binding", err)
		}
	}
}
