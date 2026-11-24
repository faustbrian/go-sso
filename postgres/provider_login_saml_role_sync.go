package postgres

import (
	"context"
	"reflect"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	"github.com/faustbrian/go-sso"
	"github.com/faustbrian/go-sso/saml"
)

type samlRoleSyncProfile struct {
	mappings  map[sso.ProviderID]providerLoginSAMLRoleMapping
	clockSkew time.Duration
}

// WithRoleSync returns a copy selecting signed role replacement for the listed
// installed SP providers. It never enables JIT or grants membership. Other
// providers keep the original verifier. Install the provider-role source and
// grants history first; changing a rule requires a new mapping version.
func (s *ProviderSAMLLoginCompletionService) WithRoleSync(mappings []StaticSAMLRoleMapping, clockSkew time.Duration) (*ProviderSAMLLoginCompletionService, error) {
	if s == nil || s.start == nil || s.start.saml == nil || s.effect == nil || s.roleSync != nil ||
		len(mappings) == 0 || len(mappings) > len(s.start.saml.profiles) || clockSkew < 0 || clockSkew > 5*time.Minute {
		return nil, sso.ErrInvalidInput
	}
	profiles := make(map[sso.ProviderID]providerLoginSAMLRoleMapping, len(mappings))
	for _, candidate := range mappings {
		installed, ok := s.start.saml.profiles[candidate.ProviderID]
		if !ok || installed.OrganizationID != candidate.OrganizationID || installed.MappingVersion != candidate.MappingVersion {
			return nil, sso.ErrInvalidInput
		}
		if _, duplicate := profiles[candidate.ProviderID]; duplicate {
			return nil, sso.ErrInvalidInput
		}
		mapping, err := newProviderLoginSAMLRoleMapping(candidate)
		if err != nil {
			return nil, err
		}
		profiles[candidate.ProviderID] = mapping
	}
	selected := *s
	selected.roleSync = &samlRoleSyncProfile{mappings: profiles, clockSkew: clockSkew}
	return &selected, nil
}

type samlRoleSelection struct {
	policyDigest [32]byte
	assertedAt   time.Time
	roleIDs      []organization.ID
}

func (s *samlRoleSyncProfile) verify(ctx context.Context, installed providerSAMLLoginProfile, input SAMLResponseVerificationInput, policy providerLoginSAMLRoleMapping) (SAMLVerifiedResponse, *samlStoredLogoutSubject, *samlRoleSelection, error) {
	deny := func() (SAMLVerifiedResponse, *samlStoredLogoutSubject, *samlRoleSelection, error) {
		return SAMLVerifiedResponse{}, nil, nil, sso.ErrForbidden
	}
	profile, err := saml.NewPOSTResponseProfile(saml.POSTResponseConfig{SPEntityID: input.SPEntityID, IdentityProviderEntityID: input.IdentityProviderEntityID,
		AssertionConsumerURL: input.AssertionConsumerURL, SigningCertificates: input.SigningCertificates, ClockSkew: s.clockSkew})
	if err != nil {
		return deny()
	}
	mapping, err := sso.NewAttributeMapping(installed.mapping)
	if err != nil {
		return deny()
	}
	approved := installed.configured
	profile, err = profile.WithAssertionMapping(sso.Provider{ID: string(approved.ProviderID), OrganizationID: string(approved.OrganizationID), Protocol: "saml",
		Enabled: true, Version: approved.ProviderVersion, MappingVersion: approved.MappingVersion}, mapping)
	if err != nil {
		return deny()
	}
	profile, err = profile.WithRoleClaims(policy.claimNames)
	if err != nil {
		return deny()
	}
	verified, err := profile.Validate(ctx, saml.POSTResponseInput{SAMLResponse: input.SAMLResponse, RequestID: input.RequestID,
		IssuedAt: input.IssuedAt, ExpiresAt: input.ExpiresAt, Now: input.Now})
	if err != nil {
		return deny()
	}
	evidence, err := verified.Evidence()
	if err != nil {
		return deny()
	}
	assertion, err := verified.ProtocolAssertion()
	if err != nil || assertion.ProviderSubject != evidence.ProviderSubject {
		return deny()
	}
	assertedAt, err := verified.AssertionIssuedAt()
	// The role checkpoint is stored in PostgreSQL at microsecond precision.
	// Reject unrepresentable ordering evidence rather than rounding it upward or
	// treating two distinct signed instants as equal.
	if err != nil || assertedAt.Year() < 1970 || assertedAt.Nanosecond()%1000 != 0 {
		return deny()
	}
	roles, err := policy.desiredRoles(assertion, input.IdentityProviderEntityID, approved.ProviderVersion)
	if err != nil {
		return deny()
	}
	logout, err := verified.LogoutSubject()
	if err != nil {
		return deny()
	}
	subject := samlStoredLogoutSubject(logout)
	return SAMLVerifiedResponse(evidence), &subject, &samlRoleSelection{policyDigest: policy.digest, assertedAt: assertedAt, roleIDs: roles}, nil
}

func (p *providerLoginCallbackPhase) samlRoleGrantInput() organization.ProviderRoleGrantInput {
	row, selected := p.found.Row, p.saml.admitted
	return organization.ProviderRoleGrantInput{Scope: organization.ProviderRoleGrantScope{
		TenantID: row.TenantID, OrganizationID: organization.ID(row.OrganizationID), ProviderID: organization.ID(row.ProviderID), UserID: selected.recipient.account.Account.UserID,
	}, MemberVersion: selected.recipient.member.Actor.Version, MappingVersion: row.MappingVersion,
		OriginalFlowStartedAt: p.roleSyncStartedAt(), AssertedAt: selected.roles.assertedAt, RoleIDs: selected.roles.roleIDs}
}

func (p *providerLoginCallbackPhase) prepareSAMLRoleUpdate(ctx context.Context) (*providerLoginRoleUpdateWire, error) {
	input, member := p.samlRoleGrantInput(), p.saml.admitted.recipient.member
	grants, err := organization.NewProviderRoleGrantSet(input)
	if err != nil {
		return nil, identity.ForbiddenError{}
	}
	generation := p.found.Row.ProviderVersion
	planned, err := p.service.router.organizations.PrepareProviderRoleGrantUpdate(ctx, grants, member, generation)
	if err != nil {
		return nil, err
	}
	return &providerLoginRoleUpdateWire{Grants: input, Member: member, Generation: generation,
		ExpectedOrganizationVersion: planned.ExpectedOrganizationVersion()}, nil
}

func (p *providerLoginCallbackPhase) restoreSAMLRoleUpdate(wire *providerLoginRoleUpdateWire) (organizationpg.ProviderRoleGrantUpdate, error) {
	var zero organizationpg.ProviderRoleGrantUpdate
	if p.saml.admitted.roles == nil || wire == nil {
		if p.saml.admitted.roles == nil && wire == nil {
			return zero, nil
		}
		return zero, identity.ForbiddenError{}
	}
	member := p.saml.admitted.recipient.member
	if wire.Generation != p.found.Row.ProviderVersion || !reflect.DeepEqual(wire.Grants, p.samlRoleGrantInput()) ||
		wire.Member.Version != member.Version || wire.Member.CredentialVersion != member.CredentialVersion || wire.Member.Actor != member.Actor {
		return zero, identity.ForbiddenError{}
	}
	grants, err := organization.NewProviderRoleGrantSet(wire.Grants)
	if err != nil {
		return zero, identity.ForbiddenError{}
	}
	return organizationpg.NewProviderRoleGrantUpdate(grants, wire.Member, wire.Generation, wire.ExpectedOrganizationVersion)
}

func (p *providerLoginCallbackPhase) UpdateSSOSAMLOrganization(ctx context.Context, work kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, record session.Session) error {
	if p.saml == nil || p.saml.admitted.roles == nil || p.execution == nil || owner != p || command != p.execution.command ||
		!equalProviderLoginSessionWithFields(record, p.execution.record, sessionpg.SSOSAMLSigninSessionFields) {
		return identity.ForbiddenError{}
	}
	return p.service.router.organizations.ApplySAMLProviderRoleGrantUpdate(ctx, work, p, command, p.execution.roleUpdate)
}
