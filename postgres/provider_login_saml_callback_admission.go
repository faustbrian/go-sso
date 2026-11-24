package postgres

import (
	"context"
	"crypto/hmac"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	"github.com/faustbrian/go-sso"
)

// These observations establish no replay reservation or session authority.
// The original callback's sole Work must fence each owner before issuing.
type samlCallbackAdmission struct {
	original                providerLoginStartInput
	authority               providerLoginCallbackAuthority
	flow                    session.PreAuthTransaction
	recipient               providerLoginCallbackRecipient
	grant                   kernel.CapabilityPlan
	evidence                SAMLVerifiedResponse
	roles                   *samlRoleSelection
	logoutSubject           *samlStoredLogoutSubject
	validatedAt, validUntil time.Time
}

func (samlCallbackAdmission) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.samlCallbackAdmission(redacted)"))
}

func (s *ProviderLoginService) admitSAMLCallback(ctx context.Context, found providerLoginCallbackLookup, r SAMLSigninCallbackRequest, verify SAMLResponseVerifier, policy sessionpg.IdentifierAdmissionConfig, roleSync *samlRoleSyncProfile) (samlCallbackAdmission, error) {
	if err := s.checkLinkedProviderRecipientContext(ctx); err != nil {
		return samlCallbackAdmission{}, err
	}
	if s.saml == nil || verify == nil || found.Row.Protocol != providerProtocolSAML || found.CompletedAt != nil ||
		found.Binding.Metadata.Input.Protocol != providerProtocolSAML || found.Binding.Metadata.Input.Link != nil ||
		found.Row != found.Binding.Metadata.Input.rowIdentity() || found.Binding.Metadata.Input.validate() != nil ||
		!providerID(string(r.ProviderID)) || string(r.ProviderID) != found.Row.ProviderID ||
		len(r.RelayState) != 43 || !hmac.Equal([]byte(r.RelayState), []byte(found.Binding.Metadata.Public.State)) ||
		len(r.SAMLResponse) == 0 || len(r.SAMLResponse) > 4<<20 || !validSAMLCallbackPolicy(s, policy) {
		return samlCallbackAdmission{}, sso.ErrForbidden
	}
	configured, selected := s.saml.profiles[r.ProviderID]
	acs, validACS := samlProviderCallbackURL(configured.TrustedOrigin, string(r.ProviderID))
	if !selected || !validACS || configured.TrustedOrigin != s.config.Origin ||
		r.ReceivedAssertionConsumerURL != acs || found.Binding.Metadata.Input.RedirectURI != acs ||
		string(configured.OrganizationID) != found.Row.OrganizationID || configured.ProviderVersion != found.Row.ProviderVersion ||
		configured.CredentialGeneration != found.Row.CredentialGeneration || configured.MappingVersion != found.Row.MappingVersion {
		return samlCallbackAdmission{}, sso.ErrForbidden
	}
	if found.ObservedAt.IsZero() {
		return samlCallbackAdmission{}, sso.ErrForbidden
	}
	deadline := earlierLoginTime(found.ObservedAt.Add(20*time.Second), found.Row.ExpiresAt)
	now := s.router.config.Clock.Now().UTC()
	if now.Before(found.ObservedAt) || !now.Before(deadline) {
		return samlCallbackAdmission{}, sso.ErrForbidden
	}
	ctx, cancel := context.WithTimeout(ctx, min(s.config.Coordinator.MaximumDuration, deadline.Sub(now)))
	defer cancel()
	flow, err := s.authenticateSAMLCallbackBrowser(ctx, found, r.Browser, acs)
	if err != nil {
		return samlCallbackAdmission{}, err
	}
	original, err := s.readProviderLoginCallbackOrigin(ctx, found, flow)
	if err != nil {
		return samlCallbackAdmission{}, err
	}
	if err := s.requireAcknowledgedSAMLStart(ctx, found, original, r.Browser); err != nil {
		return samlCallbackAdmission{}, err
	}
	authority, err := s.observeProviderLoginCallbackAuthority(ctx, found, original)
	if err != nil {
		return samlCallbackAdmission{}, err
	}
	lookup, err := sso.NewDomainRouteRequest(s.config.TenantID, configured.Domain, configured.ProviderID)
	if err != nil {
		return samlCallbackAdmission{}, sso.ErrForbidden
	}
	route, err := s.router.RouteSAML(ctx, lookup)
	if err != nil {
		return samlCallbackAdmission{}, err
	}
	profile, err := s.router.readProviderSAMLLoginProfile(ctx, route, configured)
	if err != nil {
		return samlCallbackAdmission{}, err
	}
	current, err := route.Bindings()
	selectedProfile := providerLoginProfile{protocol: providerProtocolSAML, saml: &profile,
		issuer: profile.configuration.EntityID, authorizationEndpoint: profile.configuration.RedirectEndpoint}
	if err != nil || !original.matchesSelectedRoute(current, selectedProfile) || profile.acsURL != acs || original.ProtocolRedirectURI != acs {
		return samlCallbackAdmission{}, sso.ErrForbidden
	}
	// A current route checks eligibility only. It cannot renew the original
	// lookup, proof, browser or callback window.
	authority.deadline = earlierLoginTime(authority.deadline, current.ValidUntil)
	now = s.router.config.Clock.Now().UTC()
	if !validProviderLoginCallbackMaterialInput(found, original, authority, now) {
		return samlCallbackAdmission{}, sso.ErrForbidden
	}
	grant, err := s.prepareProviderLoginCallbackGrant(ctx, found)
	if err != nil {
		return samlCallbackAdmission{}, err
	}
	certificates := make([][]byte, len(profile.configuration.SigningCertificates))
	for i, certificate := range profile.configuration.SigningCertificates {
		certificates[i] = append([]byte(nil), certificate...)
	}
	defer func() {
		for _, certificate := range certificates {
			clear(certificate)
		}
	}()
	now = s.router.config.Clock.Now().UTC()
	if !validProviderLoginCallbackMaterialInput(found, original, authority, now) {
		return samlCallbackAdmission{}, sso.ErrForbidden
	}
	input := SAMLResponseVerificationInput{SPEntityID: profile.spEntityID,
		IdentityProviderEntityID: profile.configuration.EntityID, AssertionConsumerURL: acs,
		SigningCertificates: certificates, SAMLResponse: r.SAMLResponse, RequestID: "_" + string(original.Command.CommandID),
		IssuedAt: original.Issued, ExpiresAt: original.Expires, Now: now}
	var evidence SAMLVerifiedResponse
	var roles *samlRoleSelection
	var logoutSubject *samlStoredLogoutSubject
	if roleSync != nil {
		if mapping, ok := roleSync.mappings[r.ProviderID]; ok {
			evidence, logoutSubject, roles, err = roleSync.verify(ctx, profile, input, mapping)
		} else {
			evidence, err = verify(ctx, input)
		}
	} else {
		evidence, err = verify(ctx, input)
	}
	if ctx.Err() != nil {
		return samlCallbackAdmission{}, ctx.Err()
	}
	if err != nil || !validSAMLCallbackEvidence(evidence, now, original.Expires) {
		return samlCallbackAdmission{}, sso.ErrForbidden
	}
	validatedAt := now
	deadline = earlierLoginTime(authority.deadline, evidence.ValidUntil)
	deadline = earlierLoginTime(deadline, grant.ExpiresAt)
	recipient, err := s.readLinkedProviderRecipient(ctx, original, evidence.ProviderSubject, deadline, policy.PolicyNamespace)
	if err != nil {
		return samlCallbackAdmission{}, err
	}
	deadline = earlierLoginTime(deadline, recipient.member.ValidUntil)
	flowBinding, err := flow.Bindings()
	if err != nil {
		return samlCallbackAdmission{}, sso.ErrForbidden
	}
	deadline = earlierLoginTime(deadline, flowBinding.Binding.ExpiresAt)
	now = s.router.config.Clock.Now().UTC()
	if now.Before(validatedAt) || !now.Before(deadline) || !validProviderLoginCallbackMaterialInput(found, original, authority, now) {
		return samlCallbackAdmission{}, sso.ErrForbidden
	}
	remember, err := session.NewRememberPolicy(original.Remember)
	if err != nil || s.requireProviderLoginBrowserForAction(flow, now, r.Browser, acs, remember, kernel.SSOSAMLSigninOperation().OperationID) != nil {
		return samlCallbackAdmission{}, sso.ErrForbidden
	}
	if err := ctx.Err(); err != nil {
		return samlCallbackAdmission{}, err
	}
	return samlCallbackAdmission{original: original, authority: authority, flow: flow, recipient: recipient,
		grant: grant, evidence: evidence, roles: roles, logoutSubject: logoutSubject, validatedAt: validatedAt, validUntil: deadline}, nil
}

func validSAMLCallbackPolicy(s *ProviderLoginService, p sessionpg.IdentifierAdmissionConfig) bool {
	scope := authoritypg.AuthorityScope{TenantID: authorization.TenantID(s.config.TenantID), SubjectID: "scope-validation", PolicyNamespace: p.PolicyNamespace}
	return p.GlobalAuthorityID == s.config.GlobalAuthorityID &&
		p.AuthenticationMethod == "sso-saml" && p.CredentialKind == identity.CredentialProvider && p.CredentialOwner == "sso" &&
		scope.Validate() == nil
}

func (s *ProviderLoginService) authenticateSAMLCallbackBrowser(ctx context.Context, found providerLoginCallbackLookup, browser ProviderLoginBrowser, acs string) (session.PreAuthTransaction, error) {
	input := found.Binding.Metadata.Input
	binding := input.Command
	flowID, err := identity.ParsePreAuthTransactionID(binding.AnonymousFlowID)
	if err != nil || binding.ValidateFor(kernel.SSOSAMLSigninStartOperation()) != nil || binding.ActorKind != authorization.SubjectServiceAccount ||
		binding.ActorID != s.config.ActorID || binding.CommandID != found.Row.StartCommandID || binding.TenantID != s.config.TenantID ||
		binding.PolicyID != s.config.PolicyID || binding.PolicyVersion != s.policyVersion || flowID != browser.FlowID ||
		browser.Origin != s.config.Origin || browser.Origin != input.BrowserOrigin || !browser.Network.IsValid() ||
		browser.Network.Is4In6() || browser.Network.Zone() != "" || !providerID(browser.Device) {
		return session.PreAuthTransaction{}, sso.ErrForbidden
	}
	if _, allowed := s.callbacks[input.SuccessCallback]; !allowed {
		return session.PreAuthTransaction{}, sso.ErrForbidden
	}
	if _, allowed := s.callbacks[input.ErrorCallback]; !allowed {
		return session.PreAuthTransaction{}, sso.ErrForbidden
	}
	remember, err := session.NewRememberPolicy(input.Remember)
	if err != nil {
		return session.PreAuthTransaction{}, sso.ErrForbidden
	}
	flow, err := sessionpg.ReadPreAuth(ctx, s.router.pool.Raw(), s.config.Session, binding.TenantID, flowID)
	if err != nil {
		return session.PreAuthTransaction{}, providerError(ctx, err)
	}
	var now time.Time
	if err := s.router.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return session.PreAuthTransaction{}, providerError(ctx, err)
	}
	if now.Before(found.ObservedAt) || !now.Before(found.ObservedAt.Add(20*time.Second)) || !now.Before(found.Row.ExpiresAt) ||
		s.requireProviderLoginBrowserForAction(flow, now.UTC(), browser, acs, remember, kernel.SSOSAMLSigninOperation().OperationID) != nil {
		return session.PreAuthTransaction{}, sso.ErrForbidden
	}
	return flow, nil
}

func (s *ProviderLoginService) requireAcknowledgedSAMLStart(ctx context.Context, found providerLoginCallbackLookup, original providerLoginStartInput, browser ProviderLoginBrowser) error {
	phase := &providerLoginPhase{service: s, browser: browser, protocol: providerProtocolSAML}
	coordinator, _, err := s.coordinator(phase)
	if err != nil {
		return providerError(ctx, err)
	}
	binding := identity.CommandBinding(original.Command)
	query := identity.RecoveryQuery{CommandID: binding.CommandID, TenantID: binding.TenantID, ActorID: binding.ActorID, ActorKind: binding.ActorKind,
		UserID: binding.UserID, AnonymousFlowID: binding.AnonymousFlowID, OperationID: binding.OperationID, RecordID: binding.RecordID}
	caller := phase.startCaller()
	caller.Request.Resource = authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(binding.AnonymousFlowID)}
	acknowledged, err := coordinator.QueryCommand(ctx, query, caller)
	if err != nil {
		return providerError(ctx, err)
	}
	if acknowledged.Validate() != nil || acknowledged.Binding != binding || acknowledged.Feature == nil ||
		*acknowledged.Feature != kernel.SSOSAMLSigninStartOperation() || acknowledged.Outcome != identity.CommitOutcomeCommitted ||
		binding.CommandID != found.Row.StartCommandID {
		return sso.ErrForbidden
	}
	return nil
}

func validSAMLCallbackEvidence(e SAMLVerifiedResponse, now, originalExpiry time.Time) bool {
	return !e.ValidUntil.After(originalExpiry) && validSAMLResponseEvidence(e, now)
}

func validSAMLResponseEvidence(e SAMLVerifiedResponse, now time.Time) bool {
	// The wire adapter owns XML/NCName validation. Here the native boundary
	// enforces its detached scalar contracts before hashing or account lookup.
	validText := func(value string, maximum int) bool {
		return len(value) > 0 && len(value) <= maximum && utf8.ValidString(value) && !strings.ContainsFunc(value, unicode.IsControl)
	}
	if !validText(e.ResponseID, 2048) || !validText(e.AssertionID, 2048) || e.ResponseID == e.AssertionID ||
		strings.ContainsFunc(e.ResponseID, unicode.IsSpace) || strings.ContainsFunc(e.AssertionID, unicode.IsSpace) ||
		!validText(e.ProviderSubject, 512) || strings.TrimSpace(e.ProviderSubject) == "" ||
		(e.SessionIndex != "" && !validText(e.SessionIndex, 2048)) ||
		(e.SubjectFormat != "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" && e.SubjectFormat != "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress") {
		return false
	}
	if !validSAMLReplayTime(e.AssertionExpiresAt) || !validSAMLReplayTime(e.ValidUntil) || !now.Before(e.ValidUntil) {
		return false
	}
	_, err := samlReplayRetainUntil(now, e.AssertionExpiresAt)
	return err == nil
}
