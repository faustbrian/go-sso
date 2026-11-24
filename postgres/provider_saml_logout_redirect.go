package postgres

import (
	"context"
	"fmt"
	"net/url"
	"time"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	"github.com/faustbrian/go-sso"
	"github.com/faustbrian/go-sso/saml"
)

// ProviderSAMLLogoutRedirectProfile pins a trusted, separately approved SLO
// Redirect endpoint to one installed provider and signer generation. It does
// not accept an endpoint from a browser, nor confer provider authority.
type ProviderSAMLLogoutRedirectProfile struct {
	Provider                 StaticSAMLLoginProfile
	IdentityProviderEntityID string
	Endpoint                 string
}

// ProviderSAMLLogoutRedirectService adds post-commit provider request custody
// to the protected native local service. It does not contact the provider or
// install HTTP routes.
type ProviderSAMLLogoutRedirectService struct {
	local    *ProviderSAMLLogoutService
	custody  *SAMLLogoutSubjectCustody
	profiles map[sso.ProviderID]samlLogoutSelectedProfile
}

// ProviderSAMLLogoutRedirectResult always retains the local result, including
// on route, signing or remote reservation failure. Access the signed browser
// data explicitly via ProviderRedirect.
type ProviderSAMLLogoutRedirectResult struct {
	ProviderSAMLLogoutStartResult
	redirect string
}

// ProviderRedirect discloses only the signed original reserved request.
func (r ProviderSAMLLogoutRedirectResult) ProviderRedirect() (url.URL, bool) {
	if r.redirect == "" || !r.LocalRevocation.Committed || r.LocalOnly {
		return url.URL{}, false
	}
	u, err := url.Parse(r.redirect)
	if err != nil {
		return url.URL{}, false
	}
	return *u, true
}

func (ProviderSAMLLogoutRedirectResult) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("sso.postgres.ProviderSAMLLogoutRedirectResult(redacted)"))
}

type samlLogoutSelectedProfile struct {
	config ProviderSAMLLogoutRedirectProfile
	wire   saml.LogoutRedirectProfile
}

// WithProviderRedirect wraps the local service with explicit SLO support for the given
// providers. Apply SAMLLogoutSubjectMigrationSource and
// SAMLLogoutRequestMigrationSource before selection. Sign-in must retain the
// original subject using the same custody and retained keys. No I/O occurs
// during selection; other providers and sessions without custody stay local.
func (s *ProviderSAMLLogoutService) WithProviderRedirect(custody *SAMLLogoutSubjectCustody, profiles []ProviderSAMLLogoutRedirectProfile) (*ProviderSAMLLogoutRedirectService, error) {
	if s == nil || s.login == nil || custody == nil || len(profiles) == 0 || len(profiles) > 128 ||
		!s.login.router.protocolRegistry || s.login.router.samlRouteValidate == nil {
		return nil, sso.ErrInvalidInput
	}
	outbound := &ProviderSAMLLogoutRedirectService{local: s, custody: custody, profiles: make(map[sso.ProviderID]samlLogoutSelectedProfile, len(profiles))}
	for _, profile := range profiles {
		provider, err := normalizeStaticSAMLLoginProfile(profile.Provider)
		if err != nil || provider.TrustedOrigin != s.login.config.Origin {
			return nil, sso.ErrInvalidInput
		}
		if _, exists := outbound.profiles[provider.ProviderID]; exists {
			return nil, sso.ErrInvalidInput
		}
		wire, err := saml.NewLogoutRedirectProfile(saml.LogoutRedirectConfig{
			SPEntityID:               provider.TrustedOrigin + "/saml2/" + string(provider.ProviderID) + "/metadata",
			IdentityProviderEntityID: profile.IdentityProviderEntityID, IdentityProviderURL: profile.Endpoint,
		})
		if err != nil {
			return nil, sso.ErrInvalidInput
		}
		outbound.profiles[provider.ProviderID] = samlLogoutSelectedProfile{config: profile, wire: wire}
	}
	return outbound, nil
}

// Start authenticates, revokes and acknowledges the original local session
// before preparing any redirect. Exact authorized retries return the
// original reserved wire while it is unexpired and the route stays current.
func (s *ProviderSAMLLogoutRedirectService) Start(ctx context.Context, request ProviderLogoutStartRequest, browser ProviderLogoutBrowser) (ProviderSAMLLogoutRedirectResult, error) {
	if s == nil || s.local == nil {
		return ProviderSAMLLogoutRedirectResult{}, sso.ErrInvalidInput
	}
	var redirect string
	result, err := s.local.start(ctx, request, browser, func(ctx context.Context, p *providerSAMLLogoutStartPhase, out ProviderSAMLLogoutStartResult) error {
		var err error
		redirect, err = s.reserveProviderRedirect(ctx, p, out)
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return sso.ErrUnavailable
	})
	if redirect != "" {
		result.LocalOnly = false
	}
	return ProviderSAMLLogoutRedirectResult{ProviderSAMLLogoutStartResult: result, redirect: redirect}, err
}

func (s *ProviderSAMLLogoutRedirectService) reserveProviderRedirect(ctx context.Context, p *providerSAMLLogoutStartPhase, out ProviderSAMLLogoutStartResult) (string, error) {
	login := p.service.login
	router := login.router
	profile, selected := s.profiles[sso.ProviderID(p.request.ProviderID)]
	if !selected {
		return "", nil
	}
	scope, err := p.record.Authority.Bindings()
	if err != nil || profile.config.Provider.OrganizationID != organization.ID(scope.ActiveOrganizationID) {
		return "", identity.ForbiddenError{}
	}
	record := p.record
	anchor, issuer, subject, found, err := s.custody.read(ctx, router.pool, router.config.Envelope, record.TenantID, record.SessionID)
	if err != nil || !found {
		return "", err
	}
	if anchor.Organization != scope.ActiveOrganizationID || anchor.Provider != p.request.ProviderID ||
		anchor.User != string(record.UserID) || anchor.Family != record.FamilyID ||
		anchor.Command != string(record.Authentication.Proof.ID) || !anchor.IssuedAt.Equal(record.IssuedAt.UTC().Truncate(time.Microsecond)) ||
		issuer.issuer != profile.config.IdentityProviderEntityID {
		return "", identity.ForbiddenError{}
	}
	// This exact Redirect profile requires one index; do not expand the
	// original login into an IdP-wide subject logout where it lacked one.
	if subject.SessionIndex == "" || !router.config.Clock.Now().Before(anchor.ExpiresAt) {
		return "", nil
	}
	// A retry that first reaches the provider reservation after an outage
	// must not extend the original local command's outbound window.
	deadline := minSAMLLogoutTime(anchor.ExpiresAt, p.input.StartedAt.Add(samlLogoutRequestLife))
	if !router.config.Clock.Now().Before(deadline) {
		return "", identity.ForbiddenError{}
	}
	current, err := router.loadExactSAMLLogoutRoute(ctx, record.TenantID, profile.config)
	if err != nil {
		return "", err
	}
	binding := out.Completion.Binding
	expected := samlLogoutRequestBinding{
		Anchor: anchor, Issuer: issuer.issuer, Subject: subject, Endpoint: profile.config.Endpoint,
		FinalRedirect: p.request.FinalRedirect, SessionVersion: out.LocalRevocation.Version,
		ProviderVersion: current.ProviderVersion, CredentialGeneration: current.CredentialGeneration,
	}
	row, stored, exists, err := login.readSAMLLogoutRequest(ctx, binding.TenantID, binding.CommandID)
	if err != nil {
		return "", err
	}
	if !exists {
		row, stored, err = p.signAndStoreSAMLLogoutRequest(ctx, binding, current, profile, expected, deadline)
		if err != nil {
			return "", err
		}
	}
	redirect := stored.Redirect
	stored.Redirect = ""
	if stored != expected || row.Organization != anchor.Organization || row.Provider != anchor.Provider ||
		row.ExpiresAt.After(deadline) || !validStoredSAMLLogoutRedirect(redirect, expected.Endpoint) {
		return "", identity.ForbiddenError{}
	}
	if err := router.requireSAMLLogoutRoute(ctx, current); err != nil {
		return "", err
	}
	if !router.config.Clock.Now().Before(row.ExpiresAt) {
		return "", identity.ForbiddenError{}
	}
	return redirect, nil
}

func (p *providerSAMLLogoutStartPhase) signAndStoreSAMLLogoutRequest(ctx context.Context, binding identity.CommandBinding, route sso.DomainRouteBinding,
	profile samlLogoutSelectedProfile, payload samlLogoutRequestBinding, deadline time.Time) (samlLogoutRequestRow, samlLogoutRequestBinding, error) {
	login := p.service.login
	router := login.router
	now := router.config.Clock.Now().UTC().Truncate(time.Microsecond)
	row := samlLogoutRequestRow{Tenant: binding.TenantID, Command: binding.CommandID, Organization: payload.Anchor.Organization,
		Provider: payload.Anchor.Provider, IssuedAt: now, ExpiresAt: deadline}
	request := saml.LogoutRequest{ID: row.requestID(), IssuedAt: now, SessionIndex: payload.Subject.SessionIndex,
		NameID: saml.LogoutNameID{Value: payload.Subject.ProviderSubject, SubjectFormat: payload.Subject.SubjectFormat,
			NameQualifier: payload.Subject.NameQualifier, SPNameQualifier: payload.Subject.SPNameQualifier}}
	err := router.withRouteCredential(ctx, route, providerProtocolSAML, func(ctx context.Context, bundle []byte) error {
		wire, cutoff, err := profile.wire.RedirectWithSPSigningCredential(ctx, request, bundle, now)
		if err != nil {
			return err
		}
		redirect, err := wire.URL()
		if err != nil {
			return err
		}
		row.ExpiresAt = minSAMLLogoutTime(row.ExpiresAt, cutoff.UTC().Truncate(time.Microsecond))
		payload.Redirect = redirect.String()
		return nil
	})
	if err != nil {
		return samlLogoutRequestRow{}, samlLogoutRequestBinding{}, err
	}
	if err := router.requireSAMLLogoutRoute(ctx, route); err != nil {
		return samlLogoutRequestRow{}, samlLogoutRequestBinding{}, err
	}
	inserted, err := login.insertSAMLLogoutRequest(ctx, row, payload)
	if err != nil {
		return samlLogoutRequestRow{}, samlLogoutRequestBinding{}, err
	}
	if inserted {
		return row, payload, nil
	}
	// Competing retries can have generated another PSS signature; only the
	// bytes from the one durable winner may ever leave this service.
	row, payload, found, err := login.readSAMLLogoutRequest(ctx, binding.TenantID, binding.CommandID)
	if err == nil && !found {
		err = identity.UnavailableError{}
	}
	return row, payload, err
}

func (r *ProviderRouter) loadExactSAMLLogoutRoute(ctx context.Context, tenant identity.TenantID, profile ProviderSAMLLogoutRedirectProfile) (sso.DomainRouteBinding, error) {
	route, _, err := r.loadExactSAMLLogoutProfile(ctx, tenant, profile)
	return route, err
}

func (r *ProviderRouter) loadExactSAMLLogoutProfile(ctx context.Context, tenant identity.TenantID, profile ProviderSAMLLogoutRedirectProfile) (sso.DomainRouteBinding, providerSAMLLoginProfile, error) {
	configured := profile.Provider
	request, err := sso.NewDomainRouteRequest(tenant, configured.Domain, configured.ProviderID)
	if err != nil {
		return sso.DomainRouteBinding{}, providerSAMLLoginProfile{}, err
	}
	route, err := r.RouteSAML(ctx, request)
	if err != nil {
		return sso.DomainRouteBinding{}, providerSAMLLoginProfile{}, err
	}
	selected, err := r.readProviderSAMLLoginProfile(ctx, route, configured)
	if err != nil {
		return sso.DomainRouteBinding{}, providerSAMLLoginProfile{}, err
	}
	if selected.configuration.EntityID != profile.IdentityProviderEntityID {
		return sso.DomainRouteBinding{}, providerSAMLLoginProfile{}, identity.ForbiddenError{}
	}
	binding, err := route.Bindings()
	return binding, selected, err
}

func (r *ProviderRouter) requireSAMLLogoutRoute(ctx context.Context, route sso.DomainRouteBinding) error {
	current, err := r.organizations.GetDomainProof(ctx, route.Proof.Key)
	if err != nil {
		return err
	}
	now := r.config.Clock.Now()
	if current.Revoked || current.ProofVersion != route.Proof.ProofVersion || now.Before(route.ObservedAt) ||
		!now.Before(current.ExpiresAt) || !now.Before(route.ValidUntil) {
		return identity.ForbiddenError{}
	}
	if err := r.requireCurrentRoute(ctx, route); err != nil {
		return err
	}
	if !r.config.Clock.Now().Before(route.ValidUntil) {
		return identity.ForbiddenError{}
	}
	return ctx.Err()
}

func validStoredSAMLLogoutRedirect(raw, endpoint string) bool {
	redirect, err := url.Parse(raw)
	return err == nil && raw != "" && len(raw) <= 16<<10 && redirect.String() == raw &&
		matchesSAMLRedirectEndpoint(*redirect, endpoint) && redirect.Query().Get("SAMLRequest") != "" &&
		redirect.Query().Get("SigAlg") == saml.SignatureAlgorithmRSAPSSSHA256 && redirect.Query().Get("Signature") != "" &&
		!redirect.Query().Has("RelayState")
}
