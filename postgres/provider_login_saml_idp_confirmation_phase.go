package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	organization "github.com/faustbrian/go-organization"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
)

type samlIDPConfirmationPhase struct {
	arrival      *ProviderSAMLIDPArrivalService
	effect       *sessionpg.SSOSAMLIDPConfirmationEffect
	issuer       *session.SessionIssuer
	audience     string
	remember     session.RememberPolicy
	pending      samlIDPPendingArrival
	original     samlIDPArrivalOrigin
	command      identity.Command
	grant        kernel.CapabilityPlan
	declaration  kernel.CommandPlan
	prepared     session.PreparedIssuance
	execution    identity.Command
	record       session.Session
	generation   uint64
	sealedDigest [32]byte
	acknowledged identity.CommandResult
	canDisclose  bool
}

var _ kernel.SSOSAMLIDPConfirmationContributor = (*samlIDPConfirmationPhase)(nil)
var _ session.IssueExecutor = (*samlIDPConfirmationPhase)(nil)

func samlIDPConfirmationDescriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.saml-idp-confirmation", Version: 1}
}

func (*samlIDPConfirmationPhase) Descriptor() kernel.ContributorDescriptor {
	return samlIDPConfirmationDescriptor()
}

func (*samlIDPConfirmationPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{kernel.SSOSAMLIDPConfirmationOperation()}
}

func (p *samlIDPConfirmationPhase) ValidateSSOSAMLIDPConfirmationConsumption(c identity.Command, grant kernel.CapabilityPlan) error {
	if c == (identity.Command{}) || (c != p.command && c != p.execution) || p.grant != grant {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *samlIDPConfirmationPhase) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if plan.Feature == nil || plan.Lifecycle == nil || plan.Capability == nil || plan.SubjectType != "sso_saml_confirmation" ||
		!exactSAMLIDPPendingConfirmationScope(*plan.Feature, *plan.Lifecycle) {
		return identity.ForbiddenError{}
	}
	return p.ValidateSSOSAMLIDPConfirmationConsumption(c, *plan.Capability)
}

func (p *samlIDPConfirmationPhase) ValidateFeaturePreparation(c identity.Command, plan kernel.CommandPlan) error {
	if c != p.command {
		return identity.ForbiddenError{}
	}
	return p.ValidateFeatureCommand(c, plan)
}

func (p *samlIDPConfirmationPhase) account() kernel.ProviderAccountAdmission {
	a := p.original.Account
	return kernel.ProviderAccountAdmission{Account: a.Account, SocialLinkVersion: a.LinkVersion, Credential: kernel.CredentialAdmission{
		Credential: a.Credential, UserAuthorityVersion: a.UserVersion, IdentifierAuthorityVersion: a.IdentifierVersion,
		CredentialAuthorityVersion: a.CredentialAuthorityVersion,
	}}
}

func (p *samlIDPConfirmationPhase) directory() kernel.DirectoryAuthorityAdmission {
	o := p.original
	return kernel.DirectoryAuthorityAdmission{Query: kernel.DirectoryAuthorityQuery{GlobalAuthorityID: o.GlobalAuthorityID, TenantID: o.Binding.TenantID},
		GlobalVersion: o.GlobalVersion, TenantVersion: o.TenantVersion}
}

func (p *samlIDPConfirmationPhase) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, c identity.Command) error {
	binding, feature, lifecycle, err := w.FeatureScope(p)
	original, ok := c.SAMLIDPConfirmationFeature()
	if err != nil || !ok || c != p.command || binding != original.Binding || !exactSAMLIDPPendingConfirmationScope(feature, lifecycle) {
		return identity.ForbiddenError{}
	}
	if err := w.RequireActiveDirectoryAuthority(ctx, p, p.directory()); err != nil {
		return err
	}
	if _, err := w.RequireActiveProviderAccount(ctx, p, p.account()); err != nil {
		return err
	}
	scope := authoritypg.AuthorityScope{TenantID: authorization.TenantID(binding.TenantID), SubjectID: authorization.SubjectID(binding.UserID),
		PolicyNamespace: p.arrival.admission.linked.namespace}
	if err := authoritypg.RequireAuthority(ctx, w, scope, p.original.PolicyVersion, p.arrival.admission.router.config.MaximumDuration); err != nil {
		return err
	}
	return p.requireProvider(ctx, w)
}

func (p *samlIDPConfirmationPhase) requireProvider(ctx context.Context, w kernel.Work) error {
	r := p.original.Route
	bound := sso.DomainRouteBinding{ProviderID: r.ProviderID, ProviderVersion: r.ProviderVersion, CredentialGeneration: r.CredentialGeneration,
		PolicyVersion: r.PolicyVersion, Proof: sso.DomainProofCheckpoint{Key: r.ProofKey, ProofVersion: r.ProofVersion}, ObservedAt: r.ObservedAt, ValidUntil: r.ValidUntil}
	owner := p.original.Member
	owner.Actor = organization.Member{}
	if err := p.arrival.admission.router.organizations.RequireCredentialAuthority(ctx, w, p, owner); err != nil {
		return err
	}
	return requireProviderLoginAdmissionRow(ctx, w, providerLoginSAMLAdmissionFenceSQL, bound, p.original.MappingVersion, p.grant.ExpiresAt)
}

type samlIDPConfirmationAdmission struct{ phase *samlIDPConfirmationPhase }

func (a samlIDPConfirmationAdmission) Check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	now := a.phase.arrival.admission.router.config.Clock.Now().UTC()
	if now.Before(a.phase.pending.IssuedAt) || !now.Before(a.phase.grant.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *samlIDPConfirmationPhase) PrepareFeatureAdmission(ctx context.Context, c identity.Command) (kernel.FeaturePreparationAdmission, error) {
	if p.command == (identity.Command{}) || p.command != c {
		return nil, identity.ForbiddenError{}
	}
	a := samlIDPConfirmationAdmission{p}
	return a, a.Check(ctx)
}

func (*samlIDPConfirmationPhase) GenerateFeaturePreparation(context.Context, identity.Command, uint64) ([]byte, error) {
	return nil, identity.ForbiddenError{}
}

func (a samlIDPConfirmationAdmission) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	if err := a.Check(ctx); err != nil {
		return nil, err
	}
	p := a.phase
	aad, err := p.outputAAD(generation)
	if err != nil {
		return nil, err
	}
	prepared, err := p.prepareSession()
	if err != nil {
		return nil, err
	}
	record, ok := prepared.Session()
	if !ok {
		return nil, identity.ForbiddenError{}
	}
	sessionFields, err := sessionpg.SSOSAMLIDPConfirmationSessionFields(record)
	if err != nil {
		return nil, err
	}
	accountFields, err := kernel.SSOSAMLIDPConfirmationAccountFields(p.account())
	if err != nil {
		return nil, err
	}
	plain, err := providerLoginPayloadEncode(append(sessionFields, accountFields...))
	defer clear(plain)
	if err != nil || len(plain) > providerLoginCallbackPlainLimit {
		return nil, identity.UnavailableError{}
	}
	wire, err := p.arrival.payload.seal(ctx, aad, plain, providerLoginCallbackCipherLimit)
	if err == nil {
		p.prepared = prepared
	}
	return wire, err
}

func (p *samlIDPConfirmationPhase) outputAAD(generation uint64) (envelope.Context, error) {
	original, ok := p.command.SAMLIDPConfirmationFeature()
	if !ok || generation == 0 {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	digest := sha256.Sum256(p.pending.Envelope)
	return envelope.NewContext(map[string]string{"owner": "sso/postgres", "purpose": "saml-idp-session-output-v1",
		"tenant": string(original.Binding.TenantID), "completion": string(original.Binding.CommandID), "pending": original.Binding.RecordID,
		"origin": hex.EncodeToString(digest[:]), "generation": strconv.FormatUint(generation, 10), "audience": p.audience,
		"remember": samlIDPConfirmationRemember(p.remember)})
}

func (p *samlIDPConfirmationPhase) RestoreFeatureAdmission(ctx context.Context, c identity.Command, generation uint64, wire []byte) (kernel.FeaturePreparationAdmission, error) {
	if _, _, err := p.RestoreFeaturePreparation(ctx, c, generation, wire); err != nil {
		return nil, err
	}
	a := samlIDPConfirmationAdmission{p}
	return a, a.Check(ctx)
}

func (p *samlIDPConfirmationPhase) RestoreFeaturePreparation(ctx context.Context, c identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	deny := func() (identity.Command, kernel.CommandPlan, error) {
		return identity.Command{}, kernel.CommandPlan{}, identity.ForbiddenError{}
	}
	original, ok := c.SAMLIDPConfirmationFeature()
	if !ok || c != p.command {
		return deny()
	}
	digest := sha256.Sum256(wire)
	if p.execution != (identity.Command{}) {
		if digest != p.sealedDigest || generation != p.generation {
			return deny()
		}
		return p.execution, p.declaration, nil
	}
	aad, err := p.outputAAD(generation)
	if err != nil {
		return deny()
	}
	plain, err := p.arrival.payload.open(ctx, aad, wire, providerLoginCallbackCipherLimit, providerLoginCallbackPlainLimit)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	defer clear(plain)
	var fields []identity.FeatureField
	if err := providerLoginPayloadDecode(plain, &fields); err != nil || len(fields) == 0 || len(fields)+len(original.Fields) > 128 {
		return deny()
	}
	original.Fields = append(original.Fields, fields...)
	browser, form, ok := c.SAMLIDPConfirmationCustody()
	if !ok {
		return deny()
	}
	restored, err := identity.NewFeatureSAMLIDPConfirmationCommand(original, browser, form)
	if err != nil {
		return deny()
	}
	record, err := sessionpg.SSOSAMLIDPConfirmationSession(restored)
	if err != nil {
		return deny()
	}
	admitted, err := kernel.SSOSAMLIDPConfirmationAccount(restored)
	if err != nil || admitted != p.account() || !p.matchesRecord(record) {
		return deny()
	}
	p.execution, p.record, p.generation, p.sealedDigest = restored, record, generation, digest
	return restored, p.declaration, nil
}

func (p *samlIDPConfirmationPhase) prepareSession() (session.PreparedIssuance, error) {
	id, err := identity.NewSubjectID()
	if err != nil {
		return session.PreparedIssuance{}, err
	}
	family, err := identity.NewSubjectID()
	if err != nil {
		return session.PreparedIssuance{}, err
	}
	authority, err := p.authority(string(id), string(family))
	if err != nil {
		return session.PreparedIssuance{}, err
	}
	feature, _ := p.command.SAMLIDPConfirmationFeature()
	b, credential := feature.Binding, p.original.Account.Credential
	now := p.arrival.admission.router.config.Clock.Now().UTC().Truncate(time.Microsecond)
	proof := auth.Proof{ID: auth.ProofID(b.CommandID), Tenant: string(b.TenantID), Subject: string(b.UserID), Method: "sso-saml",
		Assurance: auth.AssuranceSingleFactor, Purpose: "session-issue", Audience: p.audience, IssuedAt: now, ExpiresAt: p.grant.ExpiresAt}
	return p.issuer.PrepareSSOSAMLIDPConfirmation(b, session.SSOSAMLIssuanceSpec{Credential: credential, Session: session.SessionSpec{
		SessionID: string(id), FamilyID: string(family), TenantID: b.TenantID, UserID: b.UserID, Audience: p.audience, Version: 1, FamilyVersion: 1,
		Remember: p.remember, Authority: authority, IssuedAt: now, LastActivityAt: now,
		Authentication: session.AuthenticationMetadata{Kind: session.AuthenticationVerified, Proof: proof, ProofVersion: p.original.Route.ProviderVersion,
			CredentialID: string(credential.ID), CredentialVersion: credential.Version},
	}})
}

func (p *samlIDPConfirmationPhase) matchesRecord(record session.Session) bool {
	spec, err := record.Bindings()
	if err != nil || spec.Audience != p.audience || spec.Remember != p.remember || spec.IssuedAt.Before(p.pending.IssuedAt) ||
		!spec.IssuedAt.Before(p.grant.ExpiresAt) || !spec.Authentication.Proof.ExpiresAt.Equal(p.grant.ExpiresAt) ||
		spec.Authentication.ProofVersion != p.original.Route.ProviderVersion {
		return false
	}
	want, err := p.authority(spec.SessionID, spec.FamilyID)
	if err != nil {
		return false
	}
	bound, err := want.Bindings()
	actual, actualErr := spec.Authority.Bindings()
	return err == nil && actualErr == nil && bound == actual
}

func (p *samlIDPConfirmationPhase) authority(id, family string) (session.AuthoritySnapshot, error) {
	o := p.original
	q := p.directory().Query
	user := o.Binding.UserID
	keys, err := kernel.KernelAuthorityKeys(q, user)
	if err != nil {
		return session.AuthoritySnapshot{}, err
	}
	sessionKeys, err := sessionpg.SessionAuthorityKeys(q.TenantID, user, family, id)
	if err != nil {
		return session.AuthoritySnapshot{}, err
	}
	policy := authoritypg.AuthorityScope{TenantID: authorization.TenantID(q.TenantID), SubjectID: authorization.SubjectID(user),
		PolicyNamespace: p.arrival.admission.linked.namespace}
	policyKey, err := policy.Key()
	if err != nil {
		return session.AuthoritySnapshot{}, err
	}
	factorKey, err := mfapg.FactorAuthorityKey(q.TenantID, user)
	if err != nil {
		return session.AuthoritySnapshot{}, err
	}
	orgID := p.pending.Organization
	orgKey, err := organization.OrganizationSessionScope(q.TenantID, orgID)
	if err != nil {
		return session.AuthoritySnapshot{}, err
	}
	bind := func(key string, version uint64) session.AuthorityBinding {
		return session.AuthorityBinding{ScopeKey: key, Version: version}
	}
	account := o.Account
	return session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{
		Global: bind(keys.Global, o.GlobalVersion), Tenant: bind(keys.Tenant, o.TenantVersion), User: bind(keys.User, account.UserVersion),
		Identifier: bind(keys.Identifier, account.IdentifierVersion), Credential: bind(keys.Credential, account.CredentialAuthorityVersion),
		SessionFamily: bind(sessionKeys.Family, 1), Session: bind(sessionKeys.Session, 1), Authorization: bind(policyKey, o.PolicyVersion),
		ActiveOrganizationID: string(orgID), Organization: session.OptionalAuthorityBinding{Present: true, Binding: bind(orgKey, o.Member.Version)},
		Factor: session.OptionalAuthorityBinding{Present: true, Binding: bind(factorKey, o.FactorVersion)},
	})
}

func (p *samlIDPConfirmationPhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if p.execution == (identity.Command{}) || c != p.execution {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	wire, generation, err := w.FeaturePreparationOutput(p)
	defer clear(wire)
	if err != nil || generation != p.generation || sha256.Sum256(wire) != p.sealedDigest {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	if err := completeSAMLIDPPendingConfirmation(ctx, w, p, c, p.pending); err != nil {
		return identity.FeatureReceipt{}, err
	}
	binding, fp, gen, err := w.FeatureCommandIdentity(p)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	e := p.original.Evidence
	retained, err := samlReplayRetainUntil(p.pending.IssuedAt, e.AssertionExpiresAt)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := reserveSAMLIDPReplayInWork(ctx, w, p, samlReplayClaim{Tenant: binding.TenantID, CommandID: binding.CommandID,
		OrganizationID: string(p.pending.Organization), ProviderID: string(p.pending.Provider), IssuerDigest: sha256.Sum256([]byte(p.original.Issuer)),
		ResponseDigest: sha256.Sum256([]byte(e.ResponseID)), AssertionDigest: sha256.Sum256([]byte(e.AssertionID)), Fingerprint: fp, Generation: gen, RetainUntil: retained}); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return p.effect.Apply(ctx, w, p, c)
}

func (p *samlIDPConfirmationPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if p.execution == (identity.Command{}) || p.execution != c {
		return identity.ForbiddenError{}
	}
	if err := p.effect.CheckCurrent(ctx, w, p, c); err != nil {
		return err
	}
	return p.requireProvider(ctx, w)
}

const recoverSAMLIDPConfirmationPendingSQL = `SELECT user_id=$3 AND completed_at IS NULL AND completion_command_id IS NULL
FROM sso_providers.saml_idp_confirmations WHERE tenant_id=$1 AND confirmation_id=$2`

func (p *samlIDPConfirmationPhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	b, feature, lifecycle, err := w.FeatureScope(p)
	if err != nil || !exactSAMLIDPPendingConfirmationScope(feature, lifecycle) || b.RecordID == string(b.CommandID) {
		return kernel.RecoveryUnknown, identity.ForbiddenError{}
	}
	original, err := identity.ParseCommandID(b.RecordID)
	if err != nil {
		return kernel.RecoveryUnknown, identity.ForbiddenError{}
	}
	key, err := base64.RawURLEncoding.Strict().DecodeString(string(original))
	if err != nil || len(key) != 16 {
		return kernel.RecoveryUnknown, identity.ForbiddenError{}
	}
	// A missing, changed or completed pending record is not negative evidence.
	// Recovery proves absence only if the original linked-user record is still
	// pending, both replay members are absent and session issuance is absent.
	rows, err := w.Query(ctx, recoverSAMLIDPConfirmationPendingSQL, string(b.TenantID), key, string(b.UserID))
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	var pending bool
	if !rows.Next() {
		return kernel.RecoveryUnknown, rows.Err()
	}
	if err := rows.Scan(&pending); err != nil || rows.Next() || rows.Err() != nil || !pending {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	rows.Close()
	status, err := verifySAMLIDPReplayAbsentInRecovery(ctx, w, p)
	if err != nil || status != kernel.RecoveryNotCommitted {
		return kernel.RecoveryUnknown, err
	}
	status, err = p.effect.Recover(ctx, w, p)
	if err != nil || status != kernel.RecoveryNotCommitted {
		return kernel.RecoveryUnknown, err
	}
	return kernel.RecoveryNotCommitted, nil
}

func (p *samlIDPConfirmationPhase) ExecuteIssue(ctx context.Context, r session.IssueRequest) (session.IssueExecution, error) {
	command, record, ok := r.SSOSAMLIDPConfirmationCommand()
	if ctx.Err() != nil || !ok || !p.canDisclose || p.execution != command ||
		!equalProviderLoginSessionWithFields(record, p.record, sessionpg.SSOSAMLIDPConfirmationSessionFields) ||
		p.acknowledged.Outcome != identity.CommitOutcomeCommitted || p.acknowledged.Validate() != nil {
		return session.IssueExecution{}, identity.ForbiddenError{}
	}
	p.canDisclose = false
	return session.IssueExecution{Receipt: p.acknowledged, Session: p.record}, nil
}

func (*samlIDPConfirmationPhase) RecoverIssue(context.Context, session.IssueRequest) (session.IssueExecution, error) {
	return session.IssueExecution{}, identity.ForbiddenError{}
}
