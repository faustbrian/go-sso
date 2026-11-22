package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"reflect"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/oauth"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
)

// This is the coordinator's existing encrypted preparation output. It owns
// only the session lookup and other tokenless projections, not the browser
// bearer or CSRF secret. Those remain local to the original SessionIssuer.
type providerLoginCallbackOutput struct {
	Schema     uint8
	Fields     []identity.FeatureField
	Risk       providerLoginStoredAdmission
	ObservedAt time.Time
	ValidUntil time.Time
	Terminal   []byte
	Tokens     providerLoginPreparedTokens
	RoleUpdate *providerLoginRoleUpdateWire `json:",omitempty"`
	JIT        *providerLoginJITWire        `json:",omitempty"`
	Link       *identity.AccountLinkChange  `json:",omitempty"`
}

const providerLoginCallbackCipherLimit = 192 << 10
const providerLoginCallbackPlainLimit = 128 << 10

func (p *providerLoginCallbackPhase) outputContext(generation uint64) (envelope.Context, error) {
	if p.oauth2 != nil {
		return p.callbackOutputContext(generation, "oauth2-callback-output-v1")
	}
	return p.callbackOutputContext(generation, "oidc-callback-output-v1")
}

func (p *providerLoginCallbackPhase) callbackOutputContext(generation uint64, purpose string) (envelope.Context, error) {
	f, ok := p.command.Feature()
	if !ok || generation == 0 {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	if p.oauth2 != nil {
		encoded, err := providerLoginPayloadEncode(struct {
			Original                  identity.FeatureCommandSpec
			StartProfile              [32]byte
			Generation                uint64
			Audience, PolicyNamespace string
			Profile                   oauth.OAuth2UserInfoProfile
		}{f, p.service.oauthDigest, generation, p.policy.Audience, p.policy.PolicyNamespace, p.oauth2.Profile})
		defer clear(encoded)
		if err != nil {
			return envelope.Context{}, identity.ForbiddenError{}
		}
		digest := sha256.Sum256(encoded)
		return envelope.NewContext(map[string]string{"owner": "sso/postgres", "purpose": purpose, "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
	}
	var roleMappingDigest *[32]byte
	if p.roleMapping != nil {
		roleMappingDigest = &p.roleMapping.digest
	}
	encoded, err := providerLoginPayloadEncode(struct {
		Original                  identity.FeatureCommandSpec
		StartProfile              [32]byte
		Generation                uint64
		Audience, PolicyNamespace string
		Metadata                  sso.OIDCStaticMetadataSpec
		Authentication            oauth.ClientAuthentication
		Algorithms, Claims        []string
		RoleMappingDigest         *[32]byte `json:",omitempty"`
	}{f, p.service.profileDigest, generation, p.policy.Audience, p.policy.PolicyNamespace, p.transport.metadata,
		p.transport.authentication, p.transport.algorithms, p.transport.claims, roleMappingDigest})
	defer clear(encoded)
	if err != nil {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	digest := sha256.Sum256(encoded)
	return envelope.NewContext(map[string]string{"owner": "sso/postgres", "purpose": purpose, "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}

func (p *providerLoginCallbackPhase) generateAccepted(ctx context.Context, generation uint64, admission risk.AuthenticationAdmission) ([]byte, error) {
	if p != nil && p.member != nil {
		return p.generateMemberAccepted(ctx, generation, admission)
	}
	if p == nil || p.issuer == nil || p.prepared != (session.PreparedIssuance{}) || generation == 0 {
		return nil, identity.ForbiddenError{}
	}
	aad, err := p.outputContext(generation)
	if err != nil {
		return nil, err
	}
	if p.oidc != nil {
		return p.generateOIDCAdapterAccepted(ctx, generation, admission, aad, p.prepareSigninAccepted)
	}
	var result providerLoginCallbackExchange
	if p.oauth2 != nil {
		if p.oauthInputRefused || p.oauthCallback.Denied() {
			return p.sealProviderLoginCallbackRefusal(ctx, generation)
		}
		if p.oauthAdapter != nil {
			return p.generateOAuth2AdapterAccepted(ctx, generation, admission, aad)
		}
		result, err = p.exchangeOAuth2Acknowledged(ctx, p.oauthCallback, *p.oauth2, admission)
	} else {
		result, err = p.exchangeAcknowledged(ctx, p.input, p.transport, admission)
	}
	defer result.Tokens.Destroy()
	if err != nil {
		if terminalProviderExchangeRefusal(ctx, err, p.oauth2 != nil) {
			return p.sealProviderLoginCallbackRefusal(ctx, generation)
		}
		return nil, err
	}
	return p.prepareSigninAccepted(ctx, generation, admission, aad, result)
}

func (p *providerLoginCallbackPhase) prepareSigninAccepted(ctx context.Context, generation uint64, admission risk.AuthenticationAdmission, aad envelope.Context, result providerLoginCallbackExchange) ([]byte, error) {
	recipient, jitWire, err := p.callbackRecipient(ctx, result)
	if err != nil {
		if terminalProviderRecipientRefusal(ctx, err, p.oauth2 != nil) {
			return p.sealProviderLoginCallbackRefusal(ctx, generation)
		}
		return nil, err
	}
	return p.sealAcceptedOutput(ctx, generation, admission, aad, recipient, jitWire, result.Identity.EvidenceExpiresAt(), result.ExchangeResult)
}

func terminalProviderExchangeRefusal(ctx context.Context, err error, oauth2 bool) bool {
	var disposition *oauth.Error
	return ctx.Err() == nil && errors.As(err, &disposition) && (disposition.Kind() == oauth.Refused || oauth2 && disposition.Kind() == oauth.InvalidProof)
}

func terminalProviderRecipientRefusal(ctx context.Context, err error, oauth2 bool) bool {
	var forbidden identity.ForbiddenError
	return ctx.Err() == nil && (errors.Is(err, errProviderLoginRecipientIneligible) || oauth2 && (errors.Is(err, sso.ErrForbidden) || errors.As(err, &forbidden)))
}

func (p *providerLoginCallbackPhase) sealAcceptedOutput(ctx context.Context, generation uint64, admission risk.AuthenticationAdmission, aad envelope.Context, recipient providerLoginCallbackRecipient, jitWire *providerLoginJITWire, proofExpires time.Time, result oauth.ExchangeResult) ([]byte, error) {
	now := p.service.router.config.Clock.Now().UTC().Truncate(time.Microsecond)
	if err := p.checkOriginal(now); err != nil {
		return nil, err
	}
	if err := admission.CheckAt(ctx, now); err != nil {
		return nil, err
	}
	flow, err := p.flow.Bindings()
	if err != nil || recipient.member.Version != p.authority.organization.Version {
		return nil, identity.ForbiddenError{}
	}
	until := earliestProviderLoginCallbackTime(p.authority.deadline, flow.Binding.ExpiresAt, recipient.member.ValidUntil, proofExpires).UTC().Truncate(time.Microsecond)
	if !now.Before(until) {
		return nil, identity.ForbiddenError{}
	}
	organizationVersion := recipient.member.Version
	var roleUpdate *providerLoginRoleUpdateWire
	var effectFields []identity.FeatureField
	if jitWire != nil {
		jit, fields, err := p.restoreProviderLoginJIT(jitWire, recipient.account, until)
		if err != nil {
			return nil, err
		}
		organizationVersion, effectFields = jit.membership.ExpectedOrganizationVersion(), fields
	} else {
		var roleField *identity.FeatureField
		roleUpdate, roleField, err = p.prepareProviderLoginRoleUpdate(ctx, result, recipient)
		if errors.Is(err, sso.ErrForbidden) {
			return p.sealProviderLoginCallbackRefusal(ctx, generation)
		}
		if err != nil {
			return nil, err
		}
		if roleField != nil {
			organizationVersion, effectFields = roleUpdate.ExpectedOrganizationVersion, []identity.FeatureField{*roleField}
		}
	}
	fields, command, err := p.prepareCallbackSession(recipient, now, until, organizationVersion, effectFields)
	if err != nil {
		return nil, err
	}
	tokens, err := p.service.prepareProviderLoginTokens(ctx, p.found, command, generation, result.Tokens)
	if err != nil {
		return nil, err
	}
	defer clear(tokens.Ciphertext)
	terminal, err := p.sealCallbackTerminal(ctx)
	if err != nil {
		return nil, err
	}
	defer clear(terminal)
	plain, err := providerLoginPayloadEncode(providerLoginCallbackOutput{Schema: 1, Fields: fields, Risk: providerLoginStoredAdmission(admission.Prepared()),
		ObservedAt: p.found.ObservedAt, ValidUntil: until, Terminal: terminal, Tokens: tokens, RoleUpdate: roleUpdate, JIT: jitWire})
	defer clear(plain)
	if err != nil || len(plain) > providerLoginCallbackPlainLimit {
		return nil, identity.UnavailableError{}
	}
	return p.service.payload.seal(ctx, aad, plain, providerLoginCallbackCipherLimit)
}

func (p *providerLoginCallbackPhase) sealCallbackTerminal(ctx context.Context) ([]byte, error) {
	if p.oauth2 != nil {
		return p.service.payload.sealProviderOAuth2LoginCallbackTerminal(ctx, p.found)
	}
	return p.service.payload.sealProviderLoginCallbackTerminal(ctx, p.found)
}

func (p *providerLoginCallbackPhase) openCallbackTerminal(ctx context.Context, wire []byte) (providerLoginStoredBinding, error) {
	if p.oauth2 != nil {
		return p.service.payload.openProviderOAuth2LoginCallbackTerminal(ctx, p.found.Row, wire)
	}
	return p.service.payload.openProviderLoginCallbackTerminal(ctx, p.found.Row, wire)
}

func earliestProviderLoginCallbackTime(first time.Time, rest ...time.Time) time.Time {
	for _, next := range rest {
		first = earlierLoginTime(first, next)
	}
	return first
}

func (p *providerLoginCallbackPhase) prepareCallbackSession(recipient providerLoginCallbackRecipient, now, until time.Time, organizationVersion uint64, effectFields []identity.FeatureField) ([]identity.FeatureField, identity.Command, error) {
	deny := func(err error) ([]identity.FeatureField, identity.Command, error) {
		return nil, identity.Command{}, err
	}
	id, err := identity.NewSubjectID()
	if err != nil {
		return deny(err)
	}
	family, err := identity.NewSubjectID()
	if err != nil {
		return deny(err)
	}
	account := recipient.account
	vector, err := p.callbackSessionAuthority(account, recipient.factorVersion, recipient.policyVersion, organizationVersion, string(id), string(family))
	if err != nil {
		return deny(err)
	}
	flow, err := p.flow.Bindings()
	if err != nil {
		return deny(err)
	}
	original, _ := p.command.Feature()
	method := "sso-oidc"
	if p.oauth2 != nil {
		method = "sso-oauth2"
	}
	proof := authentication.Proof{ID: authentication.ProofID(original.Binding.CommandID), Tenant: string(account.Account.TenantID), Subject: string(account.Account.UserID),
		Method: method, Assurance: authentication.AssuranceSingleFactor, Purpose: "session-issue", Audience: p.policy.Audience, IssuedAt: now, ExpiresAt: until}
	credential := account.Credential.Credential
	issuance := session.SSOOIDCIssuanceSpec{Credential: credential, Session: session.SessionSpec{
		SessionID: string(id), FamilyID: string(family), TenantID: account.Account.TenantID, UserID: account.Account.UserID, Audience: p.policy.Audience,
		Version: 1, FamilyVersion: 1, Remember: flow.Binding.Intent.Remember, Authority: vector, IssuedAt: now, LastActivityAt: now,
		Authentication: session.AuthenticationMetadata{Kind: session.AuthenticationVerified, Proof: proof, ProofVersion: p.found.Row.ProviderVersion,
			CredentialID: string(credential.ID), CredentialVersion: credential.Version},
	}}
	var prepared session.PreparedIssuance
	if p.oauth2 != nil {
		prepared, err = p.issuer.PrepareSSOOAuth2(original.Binding, session.SSOOAuth2IssuanceSpec(issuance))
	} else {
		prepared, err = p.issuer.PrepareSSOOIDC(original.Binding, issuance)
	}
	if err != nil {
		return deny(err)
	}
	record, ok := prepared.Session()
	if !ok {
		return deny(identity.ForbiddenError{})
	}
	fields, err := p.callbackAccountSessionFields(record, account)
	if err != nil {
		return deny(err)
	}
	fields = append(fields, effectFields...)
	command, err := p.callbackCommandWithOutput(fields)
	if err != nil {
		return deny(err)
	}
	p.prepared = prepared
	return fields, command, nil
}

func (p *providerLoginCallbackPhase) callbackAccountSessionFields(record session.Session, account kernel.ProviderAccountAdmission) ([]identity.FeatureField, error) {
	sessionFields, accountFields := sessionpg.SSOOIDCSigninSessionFields, kernel.SSOOIDCSigninAccountFields
	if p.oauth2 != nil {
		sessionFields, accountFields = sessionpg.SSOOAuth2SigninSessionFields, kernel.SSOOAuth2SigninAccountFields
	}
	fields, err := sessionFields(record)
	if err != nil {
		return nil, err
	}
	wantedAccount, err := accountFields(account)
	if err != nil {
		return nil, err
	}
	return append(fields, wantedAccount...), nil
}

func (p *providerLoginCallbackPhase) callbackCommandWithOutput(fields []identity.FeatureField) (identity.Command, error) {
	original, ok := p.command.Feature()
	if !ok || len(fields) < 1 || len(fields) > 128 {
		return identity.Command{}, identity.ForbiddenError{}
	}
	original.Fields = append(original.Fields, fields...)
	return identity.NewFeaturePreAuthCommand(original, p.browser.FlowCookie)
}

func (p *providerLoginCallbackPhase) callbackSessionAuthority(account kernel.ProviderAccountAdmission, factor, policy, orgVersion uint64, id, family string) (session.AuthoritySnapshot, error) {
	q, user := p.service.directoryQuery(), account.Account.UserID
	keys, err := kernel.KernelAuthorityKeys(q, user)
	if err != nil {
		return session.AuthoritySnapshot{}, err
	}
	sessionKeys, err := sessionpg.SessionAuthorityKeys(q.TenantID, user, family, id)
	if err != nil {
		return session.AuthoritySnapshot{}, err
	}
	policyScope := authoritypg.AuthorityScope{TenantID: authorization.TenantID(q.TenantID), SubjectID: authorization.SubjectID(user), PolicyNamespace: p.policy.PolicyNamespace}
	policyKey, err := policyScope.Key()
	if err != nil {
		return session.AuthoritySnapshot{}, err
	}
	factorKey, err := mfapg.FactorAuthorityKey(q.TenantID, user)
	if err != nil {
		return session.AuthoritySnapshot{}, err
	}
	orgKey, err := organization.OrganizationSessionScope(q.TenantID, organization.ID(p.found.Row.OrganizationID))
	if err != nil {
		return session.AuthoritySnapshot{}, err
	}
	bind := func(key string, version uint64) session.AuthorityBinding {
		return session.AuthorityBinding{ScopeKey: key, Version: version}
	}
	c := account.Credential
	return session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{
		Global: bind(keys.Global, p.original.GlobalVersion), Tenant: bind(keys.Tenant, p.original.TenantVersion), User: bind(keys.User, c.UserAuthorityVersion),
		Identifier: bind(keys.Identifier, c.IdentifierAuthorityVersion), Credential: bind(keys.Credential, c.CredentialAuthorityVersion),
		SessionFamily: bind(sessionKeys.Family, 1), Session: bind(sessionKeys.Session, 1), Authorization: bind(policyKey, policy),
		ActiveOrganizationID: p.found.Row.OrganizationID, Organization: session.OptionalAuthorityBinding{Present: true, Binding: bind(orgKey, orgVersion)},
		Factor: session.OptionalAuthorityBinding{Present: true, Binding: bind(factorKey, factor)},
	})
}

func (p *providerLoginCallbackPhase) restoreAccepted(ctx context.Context, generation uint64, wire []byte) error {
	digest := sha256.Sum256(wire)
	if p.execution != nil {
		if p.execution.generation == generation && p.execution.digest == digest {
			return nil
		}
		return identity.ForbiddenError{}
	}
	aad, err := p.outputContext(generation)
	if err != nil {
		return err
	}
	plain, err := p.service.payload.open(ctx, aad, wire, providerLoginCallbackCipherLimit, providerLoginCallbackPlainLimit)
	if err != nil {
		return err
	}
	defer clear(plain)
	var saved providerLoginCallbackOutput
	owned := false
	defer func() {
		if !owned {
			clear(saved.Terminal)
			clear(saved.Tokens.Ciphertext)
		}
	}()
	if providerLoginPayloadDecode(plain, &saved) != nil || saved.Schema != 1 || saved.ObservedAt.Before(p.found.Row.IssuedAt) || saved.ObservedAt.After(p.found.ObservedAt) ||
		!saved.ValidUntil.After(saved.ObservedAt) || saved.ValidUntil.After(saved.ObservedAt.Add(20*time.Second)) || saved.ValidUntil.After(p.found.Row.ExpiresAt) ||
		saved.Tokens.CallbackGeneration != generation || saved.Tokens.BindingWireDigest != p.found.BindingWireDigest {
		return identity.ForbiddenError{}
	}
	if p.member != nil {
		if err := p.restoreMemberAccepted(ctx, generation, digest, saved); err != nil {
			return err
		}
		owned = true
		return nil
	}
	if saved.Link != nil || p.oauth2 != nil && (saved.JIT != nil || saved.RoleUpdate != nil) {
		return identity.ForbiddenError{}
	}
	command, err := p.callbackCommandWithOutput(saved.Fields)
	if err != nil {
		return err
	}
	decodeSession, decodeAccount := sessionpg.SSOOIDCSigninSession, kernel.SSOOIDCSigninAccount
	if p.oauth2 != nil {
		decodeSession, decodeAccount = sessionpg.SSOOAuth2SigninSession, kernel.SSOOAuth2SigninAccount
	}
	record, err := decodeSession(command)
	if err != nil {
		return err
	}
	account, err := decodeAccount(command)
	if err != nil {
		return err
	}
	fields, err := p.callbackAccountSessionFields(record, account)
	if err != nil || account.Account != saved.Tokens.Account || account.SocialLinkVersion != saved.Tokens.SocialLinkVersion {
		return identity.ForbiddenError{}
	}
	jit, jitFields, err := p.restoreProviderLoginJIT(saved.JIT, account, saved.ValidUntil)
	if err != nil {
		return err
	}
	var roleUpdate organizationpg.ProviderRoleGrantUpdate
	organizationVersion := p.authority.organization.Version
	if jit != nil {
		if saved.RoleUpdate != nil {
			return identity.ForbiddenError{}
		}
		fields = append(fields, jitFields...)
		organizationVersion = jit.membership.ExpectedOrganizationVersion()
		vector, err := record.Bindings()
		if err != nil {
			return err
		}
		authority, err := vector.Authority.Bindings()
		if err != nil || authority.Authorization.Version != 1 || authority.Factor.Binding.Version != 1 {
			return identity.ForbiddenError{}
		}
	} else {
		var roleField *identity.FeatureField
		roleUpdate, roleField, err = p.restoreProviderLoginRoleUpdate(saved.RoleUpdate, account.Account.UserID)
		if err != nil {
			return err
		}
		if roleField != nil {
			fields = append(fields, *roleField)
			organizationVersion = roleUpdate.ExpectedOrganizationVersion()
		}
	}
	if !reflect.DeepEqual(fields, saved.Fields) {
		return identity.ForbiddenError{}
	}
	if err := p.checkRestoredSession(record, account, saved, organizationVersion); err != nil {
		return err
	}
	terminal, err := p.openCallbackTerminal(ctx, saved.Terminal)
	if err != nil || terminal.Metadata != p.found.Binding.Metadata {
		return identity.ForbiddenError{}
	}
	if err := p.service.validateProviderLoginTokens(ctx, saved.Tokens); err != nil {
		return err
	}
	scope, subject := p.riskScope()
	admission, err := p.service.custody.Restore(ctx, risk.PreparedAuthenticationAdmission(saved.Risk), scope, subject)
	if err != nil {
		return err
	}
	p.execution = &providerLoginCallbackExecution{command: command, record: record, admission: admission, tokens: saved.Tokens, terminal: saved.Terminal, roleUpdate: roleUpdate, jit: jit,
		generation: generation, digest: digest, validUntil: earlierLoginTime(saved.ValidUntil, p.authority.deadline)}
	owned = true
	return nil
}

func (p *providerLoginCallbackPhase) checkRestoredSession(record session.Session, account kernel.ProviderAccountAdmission, output providerLoginCallbackOutput, organizationVersion uint64) error {
	spec, err := record.Bindings()
	if err != nil {
		return err
	}
	flow, err := p.flow.Bindings()
	credential := account.Credential.Credential
	if err != nil || spec.TenantID != p.found.Row.TenantID || spec.UserID != account.Account.UserID || spec.Audience != p.policy.Audience ||
		spec.Authentication.ProofVersion != p.found.Row.ProviderVersion || spec.Authentication.CredentialID != string(credential.ID) || spec.Authentication.CredentialVersion != credential.Version ||
		spec.IssuedAt.Before(output.ObservedAt) || !spec.Authentication.Proof.ExpiresAt.Equal(output.ValidUntil) || output.ValidUntil.After(flow.Binding.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	remember, err := spec.Remember.Bindings()
	original, originalErr := flow.Binding.Intent.Remember.Bindings()
	if err != nil || originalErr != nil || remember != original {
		return identity.ForbiddenError{}
	}
	vector, err := spec.Authority.Bindings()
	if err != nil {
		return err
	}
	expected, err := p.callbackSessionAuthority(account, vector.Factor.Binding.Version, vector.Authorization.Version, organizationVersion, spec.SessionID, spec.FamilyID)
	if err != nil {
		return err
	}
	wanted, err := expected.Bindings()
	if err != nil || wanted != vector {
		return identity.ForbiddenError{}
	}
	return nil
}
