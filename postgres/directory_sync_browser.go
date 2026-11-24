package postgres

import (
	"fmt"
	"slices"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	organization "github.com/faustbrian/go-organization"
	database "github.com/faustbrian/go-postgres"
	"github.com/faustbrian/go-sso"
)

// DirectorySyncBrowserConfig is trusted transport/deployment selection for one
// invocation. Cookie contains the original cookie token, never an Authorization
// header. The transport must reject mixed credentials and enforce exact Origin
// on writes before passing the separately decoded CSRF token. Status does not
// need that token. CSRFKeys selects 1..4 currently eligible distinct keys.
type DirectorySyncBrowserConfig struct {
	TenantID                              identity.TenantID
	Network, OrganizationID, ConnectionID string
	Cookie                                authentication.BearerCredential
	CSRF                                  session.CSRFToken
	CSRFKeys                              []session.CSRFKey
	Authority                             DirectorySyncAuthorization
}

func (DirectorySyncBrowserConfig) Format(w fmt.State, _ rune) {
	_, _ = w.Write([]byte("sso.postgres.DirectorySyncBrowserConfig(redacted)"))
}

func (DirectorySyncBrowserConfig) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}

func (DirectorySyncBrowserConfig) MarshalText() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}

type directoryBrowserSession struct {
	token session.CSRFToken
	keys  []session.CSRFKey
}

func (b *directoryBrowserSession) valid(record session.Session, write bool) bool {
	state := record.CSRFState()
	if b == nil {
		return state == (session.CSRFState{})
	}
	bound, err := record.Bindings()
	if err != nil || state == (session.CSRFState{}) {
		return false
	}
	if !write {
		return true
	}
	scope := session.CSRFBinding{TenantID: bound.TenantID, SessionID: bound.SessionID, SessionVersion: bound.Version}
	for _, key := range b.keys {
		if state.Check(scope, b.token, key) == nil {
			return true
		}
	}
	return false
}

// NewDirectorySyncBrowserService selects only directory administration for a
// single original browser request and exact configured organization/source.
// It performs no IO. Each operation authenticates only cookie transport via
// the primary session owner; Start and Cancel also require the original CSRF
// token, fresh password authentication, and the current native action policy.
// Work fences the entire original session record including its CSRF state. This
// selection does not expose general provider management or authorize SCIM Apply.
func NewDirectorySyncBrowserService(pool *database.Pool, c ProviderServiceConfig, b DirectorySyncBrowserConfig) (*DirectorySyncService, error) {
	if len(b.CSRFKeys) < 1 || len(b.CSRFKeys) > 4 {
		return nil, sso.ErrInvalidInput
	}
	keys := slices.Clone(b.CSRFKeys)
	for i, key := range keys {
		if key.Version() == 0 {
			return nil, sso.ErrInvalidInput
		}
		for _, previous := range keys[:i] {
			if previous.Version() == key.Version() {
				return nil, sso.ErrInvalidInput
			}
		}
	}
	// The opaque command token carrier is the same type, but the selected
	// session reader treats it as a cookie and will not accept a bearer record.
	provider, err := NewProviderService(pool, c, organization.Authentication{TenantID: b.TenantID, Bearer: b.Cookie}, b.Network)
	if err != nil {
		return nil, err
	}
	provider, err = provider.ForOrganization(b.OrganizationID)
	if err != nil {
		return nil, err
	}
	provider.directoryBrowser = &directoryBrowserSession{token: b.CSRF, keys: keys}
	return provider.DirectorySync(b.ConnectionID, b.Authority)
}
