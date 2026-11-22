package postgres

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

// The selected mailbox and original owner lease are held only in the existing
// encrypted preparation. Command fields bind their digests, never clear text.
type providerLoginJITWire struct {
	Email        identity.Identifier
	Owner        organization.CredentialAuthorityObservation
	PolicyDigest [32]byte
}

type providerLoginJITExecution struct {
	intent     kernel.SSOOIDCJITIntent
	owner      organization.CredentialAuthorityObservation
	membership organizationpg.ProviderJITMembership
}

func (p *providerLoginCallbackPhase) callbackRecipient(ctx context.Context, result providerLoginCallbackExchange) (providerLoginCallbackRecipient, *providerLoginJITWire, error) {
	recipient, err := p.service.resolveProviderLoginCallbackRecipient(ctx, p.original, result.Identity, p.policy.PolicyNamespace)
	if !errors.Is(err, errProviderLoginRecipientLinkUnavailable) {
		return recipient, nil, err
	}
	policy := p.jitPolicy
	if policy == nil || !result.providerEnabled || !policy.selectsMapping(result.mapping, p.transport) {
		return providerLoginCallbackRecipient{}, nil, errProviderLoginRecipientIneligible
	}
	mail, err := selectProviderLoginJITMailbox(policy.address, result.mapping, policy.MappingVersion, p.original.Proof.Domain, result.VerifiedOIDCClaims())
	if err != nil {
		return providerLoginCallbackRecipient{}, nil, errProviderLoginRecipientIneligible
	}
	provider, err := SSOOIDCAccountProviderNamespace(p.original.Proof.OrganizationID, p.original.ProviderID)
	if err != nil {
		return providerLoginCallbackRecipient{}, nil, err
	}
	row := p.found.Row
	query := kernel.ProviderSigninAccountQuery{TenantID: row.TenantID, Provider: provider, Issuer: result.Identity.Issuer(), Subject: result.Identity.Subject()}
	available, err := p.service.directory.SSOOIDCSubjectAvailable(ctx, query)
	if err != nil {
		return providerLoginCallbackRecipient{}, nil, providerError(ctx, err)
	}
	if !available {
		return providerLoginCallbackRecipient{}, nil, errProviderLoginRecipientIneligible
	}

	var ids [4]identity.SubjectID
	for i := range ids {
		ids[i], err = identity.NewSubjectID()
		if err != nil {
			return providerLoginCallbackRecipient{}, nil, err
		}
	}
	user := identity.UserID(ids[0])
	account := kernel.ProviderAccountAdmission{
		Account: identity.Account{TenantID: row.TenantID, UserID: user, ID: identity.AccountID(ids[1]), Provider: provider,
			Issuer: query.Issuer, Subject: query.Subject, Version: 1}, SocialLinkVersion: 1,
		Credential: kernel.CredentialAdmission{Credential: identity.CredentialRef{TenantID: row.TenantID, UserID: user,
			ID: identity.CredentialID(ids[2]), Kind: identity.CredentialProvider, Owner: "sso", Version: 1},
			UserAuthorityVersion: 1, IdentifierAuthorityVersion: 1, CredentialAuthorityVersion: 1},
	}
	canonical := mail.Canonical().Record()
	wire := &providerLoginJITWire{Owner: p.authority.organization, PolicyDigest: policy.digest,
		Email: identity.Identifier{ID: identity.IdentifierID(ids[3]), UserID: user, Kind: identity.IdentifierEmail,
			CanonicalValue: canonical.Value, DisplayValue: mail.Display(), Verified: true, Version: 1,
			NormalizationProfile: string(canonical.ProfileID), NormalizationVersion: canonical.ProfileVersion}}
	return providerLoginCallbackRecipient{account: account, member: wire.Owner, factorVersion: 1, policyVersion: 1}, wire, nil
}

func (p *providerLoginCallbackPhase) restoreProviderLoginJIT(wire *providerLoginJITWire, account kernel.ProviderAccountAdmission, until time.Time) (*providerLoginJITExecution, []identity.FeatureField, error) {
	if wire == nil {
		return nil, nil, nil
	}
	policy := p.jitPolicy
	if policy == nil || policy.MappingVersion != p.found.Row.MappingVersion || wire.PolicyDigest != policy.digest {
		return nil, nil, identity.ForbiddenError{}
	}
	current, original := p.authority.organization, wire.Owner
	ownerQuery := organization.CredentialAuthorityQuery{TenantID: current.TenantID, OrganizationID: current.OrganizationID}
	if original.Validate(ownerQuery, original.VerifiedAt) != nil || original.Version != current.Version || original.CredentialVersion != current.CredentialVersion ||
		until.After(original.ValidUntil) || wire.Email.NormalizationProfile != policy.normalizationProfile || wire.Email.NormalizationVersion != policy.normalizationVersion {
		return nil, nil, identity.ForbiddenError{}
	}
	provider, err := SSOOIDCAccountProviderNamespace(p.original.Proof.OrganizationID, p.original.ProviderID)
	_, domain, mail := strings.Cut(wire.Email.CanonicalValue, "@")
	if err != nil || account.Account.Provider != provider || account.Account.Issuer != p.original.Issuer || account.Account.TenantID != current.TenantID ||
		!mail || domain != p.original.Proof.Domain {
		return nil, nil, identity.ForbiddenError{}
	}
	intent := kernel.SSOOIDCJITIntent{Account: account, Email: wire.Email, ComparisonProfile: policy.comparisonProfile,
		JITPolicyVersion: policy.Version, MembershipPolicyVersion: policy.MembershipVersion, ValidUntil: until}
	identityField, err := kernel.SSOOIDCJITIntentField(intent)
	if err != nil {
		return nil, nil, err
	}
	membership, err := organizationpg.NewProviderJITMembership(organizationpg.ProviderJITMembershipInput{Owner: original, UserID: account.Account.UserID,
		MaximumMembers: policy.MaximumMembers, MaximumPerUser: policy.MaximumPerUser})
	if err != nil {
		return nil, nil, err
	}
	membershipField, err := membership.Field()
	if err != nil {
		return nil, nil, err
	}
	return &providerLoginJITExecution{intent: intent, owner: original, membership: membership}, []identity.FeatureField{identityField, membershipField}, nil
}

func (p *providerLoginCallbackPhase) applyProviderLoginJIT(ctx context.Context, work kernel.Work, command identity.Command) error {
	user, err := p.jitPolicy.directory.Apply(ctx, work, p, command, p.execution.jit.intent)
	if err != nil {
		return err
	}
	if err := mfapg.InitializeSSOOIDCJIT(ctx, work, p, command); err != nil {
		return err
	}
	scope := authoritypg.AuthorityScope{TenantID: authorization.TenantID(user.TenantID), SubjectID: authorization.SubjectID(user.ID), PolicyNamespace: p.policy.PolicyNamespace}
	_, err = authoritypg.InitializeAuthority(ctx, work, scope, p.service.config.Coordinator.MaximumDuration)
	return err
}
