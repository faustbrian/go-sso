package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"strconv"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	"github.com/faustbrian/go-sso/oidc"
	"github.com/jackc/pgx/v5"
)

// Resolve the original opaque session's credential association under the
// selected enabled installation. A provider path cannot choose another issuer,
// even for a user who also holds that provider's account.
const providerLogoutLinkedIssuerSQL = `WITH account AS MATERIALIZED (
 SELECT a.issuer,sha256(convert_to(a.issuer,'UTF8')) AS digest
 FROM identity.account_credentials m
 JOIN identity.accounts a ON (a.tenant_id,a.user_id,a.account_id)=(m.tenant_id,m.user_id,m.account_id)
 WHERE m.tenant_id=$1 AND m.credential_id=$6 AND m.user_id=$7 AND a.linked AND a.provider=$8 LIMIT 2`

const providerLogoutIssuerSQL = `) SELECT account.issuer,provider.issuer_digest FROM account
 CROSS JOIN LATERAL (SELECT p.issuer_digest FROM sso_providers.providers p
 WHERE p.tenant_id=$1 AND p.organization_id=$2 AND p.provider_id=$3
 AND p.enabled AND p.metadata_version=$4::numeric AND p.enablement_credential_generation=$5::numeric
 AND p.issuer_digest=account.digest`

type providerLogoutRows interface {
	Next() bool
	Scan(...any) error
	Err() error
	Close()
}

func (p *providerLogoutStartPhase) issuerQuery(configured StaticOIDCLoginProfile, inWork bool) (string, []any, error) {
	namespace, err := SSOOIDCAccountProviderNamespace(configured.OrganizationID, configured.ProviderID)
	if err != nil || p.session.Authentication.CredentialID == "" {
		return "", nil, identity.ForbiddenError{}
	}
	query := providerLogoutLinkedIssuerSQL
	if inWork {
		query += " FOR SHARE OF m,a"
	}
	query += providerLogoutIssuerSQL
	if p.service.login.router.protocolRegistry {
		query += " AND p.protocol='oidc'"
	}
	query += " LIMIT 2"
	if inWork {
		query += " FOR SHARE OF p"
	}
	query += ") provider LIMIT 2"
	return query, []any{string(p.session.TenantID), string(configured.OrganizationID), string(configured.ProviderID),
		strconv.FormatUint(configured.ProviderVersion, 10), strconv.FormatUint(configured.CredentialGeneration, 10),
		p.session.Authentication.CredentialID, string(p.session.UserID), namespace}, nil
}

func readProviderLogoutIssuer(rows providerLogoutRows) (string, error) {
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return "", err
		}
		return "", identity.ForbiddenError{}
	}
	var issuer string
	var digest []byte
	if err := rows.Scan(&issuer, &digest); err != nil {
		return "", identity.UnavailableError{}
	}
	if rows.Next() || rows.Err() != nil {
		return "", identity.UnavailableError{}
	}
	expected := sha256.Sum256([]byte(issuer))
	if !validProviderLoginCallback(issuer) || !bytes.Equal(digest, expected[:]) {
		return "", identity.ForbiddenError{}
	}
	return issuer, nil
}

func (p *providerLogoutStartPhase) readIssuer(ctx context.Context, configured StaticOIDCLoginProfile) (string, error) {
	query, args, err := p.issuerQuery(configured, false)
	if err != nil {
		return "", err
	}
	rows, err := p.service.login.router.pool.Raw().Query(ctx, query, args...)
	if err != nil {
		return "", err
	}
	return readProviderLogoutIssuer(rows)
}

func (p *providerLogoutStartPhase) requireIssuer(ctx context.Context, work kernel.Work) error {
	configured, _, _, err := p.selected()
	if err != nil || p.input == nil || p.input.Organization != string(configured.OrganizationID) || p.input.Provider != string(configured.ProviderID) {
		return identity.ForbiddenError{}
	}
	if err := work.RequireSSOOIDCLogoutScope(ctx, p, p.session.TenantID, p.session.UserID, p.session.SessionID, p.session.Version); err != nil {
		return err
	}
	query, args, err := p.issuerQuery(configured, true)
	if err != nil {
		return err
	}
	rows, err := work.Query(ctx, query, args...)
	if err != nil {
		return err
	}
	issuer, err := readProviderLogoutIssuer(rows)
	if err != nil {
		return err
	}
	if issuer != p.input.Issuer {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *providerLogoutStartPhase) mapped() (identity.Command, error) {
	if p.input == nil || p.inputDigest == ([32]byte{}) {
		return identity.Command{}, identity.ForbiddenError{}
	}
	fields, err := sessionpg.SSOOIDCLogoutFields(p.original, p.input.ValidUntil)
	if err != nil {
		return identity.Command{}, err
	}
	fields = append(fields, identity.FeatureField{Name: providerLogoutInputField, Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: p.inputDigest[:]}})
	return identity.NewFeatureSessionCommand(identity.FeatureCommandSpec{Binding: p.input.binding(), Operation: p.DescriptorOperation(), Fields: fields}, p.browser.Session)
}

func (p *providerLogoutStartPhase) lifecycle() kernel.LifecyclePlan {
	return kernel.LifecyclePlan{EventType: "session.revoked.v1", BeforeVersion: p.session.Version, AfterVersion: p.session.Version + 1}
}

func (p *providerLogoutStartPhase) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	want, err := p.mapped()
	if err != nil || p.historical {
		return identity.ForbiddenError{}
	}
	wantSpec, _ := want.Feature()
	actual, ok := c.Feature()
	cookie, carried := c.SessionToken()
	if !ok || !carried || cookie != p.browser.Session || actual.Binding != wantSpec.Binding || actual.Operation != wantSpec.Operation ||
		!equalProviderLogoutFields(actual.Fields, wantSpec.Fields) {
		return identity.ForbiddenError{}
	}
	if plan.SubjectType != "session" || plan.Feature == nil || *plan.Feature != p.registration() || plan.Lifecycle == nil || *plan.Lifecycle != p.lifecycle() {
		return identity.ForbiddenError{}
	}
	return nil
}

func equalProviderLogoutFields(a, b []identity.FeatureField) bool {
	if len(a) != len(b) {
		return false
	}
	for i, f := range a {
		g := b[i]
		if f.Name != g.Name || f.Value.Kind != g.Value.Kind || f.Value.Text != g.Value.Text ||
			f.Value.Uint64 != g.Value.Uint64 || f.Value.Int64 != g.Value.Int64 || f.Value.Bool != g.Value.Bool ||
			!f.Value.Time.Equal(g.Value.Time) || !bytes.Equal(f.Value.Bytes, g.Value.Bytes) {
			return false
		}
	}
	return true
}

func (p *providerLogoutStartPhase) plan(registry *kernel.ContributorRegistry) (kernel.CommandPlan, error) {
	b := p.input.binding()
	life, f := p.lifecycle(), p.registration()
	const action = "identity.sso.logout_oidc"
	const subject = "session"
	bldr, err := audit.NewBuilder(audit.BuilderConfig{IDGenerator: func() (string, error) { return "sso-oidc-logout-declaration", nil }})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	seed, err := bldr.Build(audit.RecordInput{Action: action, OccurredAt: p.input.StartedAt, Outcome: audit.OutcomeSucceeded, ReasonCode: "completed",
		Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: subject, ID: b.RecordID},
		Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID},
		Policy:  audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true},
		Attributes: map[string]string{"identity.profile": "identity.security.v1", "command.id": string(b.CommandID), "retention.class": "protected",
			"aggregate.type": subject, "aggregate.id": b.RecordID, "aggregate.before_version": strconv.FormatUint(life.BeforeVersion, 10), "aggregate.after_version": strconv.FormatUint(life.AfterVersion, 10)},
	})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, f.Operation, subject, seed)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	return kernel.CommandPlan{Contributors: registry.Descriptors(), SubjectType: subject, Feature: &f, Lifecycle: &life,
		Audits: []kernel.AuditPlan{{EventType: action, SchemaVersion: 1, BindingDigest: digest, RetentionClass: "protected",
			RetentionPolicyVersion: p.service.login.config.AuditRetentionPolicyVersion, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384}},
	}, nil
}

func (p *providerLogoutStartPhase) execute(ctx context.Context, c *kernel.Coordinator, registry *kernel.ContributorRegistry) (identity.CommandResult, error) {
	command, err := p.mapped()
	if err != nil {
		return identity.CommandResult{}, err
	}
	b := p.input.binding()
	declaration, err := p.plan(registry)
	if err != nil {
		return identity.CommandResult{}, err
	}
	return executeProviderLogoutCommand(ctx, c, b, command, declaration)
}

func executeProviderLogoutCommand(ctx context.Context, c *kernel.Coordinator, b identity.CommandBinding, command identity.Command, declaration kernel.CommandPlan) (identity.CommandResult, error) {
	plan, err := c.PrepareCommandPlan(b, command, declaration)
	if err != nil {
		return identity.CommandResult{}, err
	}
	reservation, existing, err := c.ReserveCommand(ctx, b, command, plan)
	// A newly acknowledged reservation also has an in-progress receipt. Only
	// the nonzero handle distinguishes ownership from an observed busy command.
	if err != nil || reservation == (kernel.Reservation{}) {
		return existing, err
	}
	work, err := c.Begin(ctx, reservation)
	if err != nil {
		return identity.CommandResult{}, err
	}
	defer c.Abort(work, identity.UnavailableError{})
	result, err := c.ApplyFeature(ctx, work, command)
	if err != nil {
		return c.Abort(work, err)
	}
	return c.Commit(work, result)
}

const providerLogoutInsertSQL = `INSERT INTO sso_providers.logout_transactions
 (tenant_id,state_key_version,state_digest,start_command_id,issued_at,expires_at,binding_envelope)
 VALUES ($1,$2,$3,$4,$5,$6,$7)`

const providerLogoutByStartSQL = `SELECT state_key_version,state_digest,issued_at,expires_at,binding_envelope,
 (completed_at IS NULL AND clock_timestamp() < expires_at)
 FROM sso_providers.logout_transactions WHERE tenant_id=$1 AND start_command_id=$2`

func (r providerLogoutRow) commandBytes() []byte {
	// The prepared request codec validated the canonical native command ID.
	raw, _ := base64.RawURLEncoding.DecodeString(string(r.StartCommandID))
	return raw
}

func (p *providerLogoutStartPhase) ApplyFeature(ctx context.Context, work kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	// The session owner locks directory, credential/account and organization
	// before provider locks. Reverse order would conflict with linked writers.
	receipt, err := p.service.effect.Apply(ctx, work, p, command, p.browser.CSRF, p.csrfKey)
	if err != nil {
		return receipt, err
	}
	if err = p.requireIssuer(ctx, work); err != nil || p.input.Remote == nil {
		return receipt, err
	}
	row := p.row(*p.input)
	n, err := work.Exec(ctx, providerLogoutInsertSQL, string(row.TenantID), int64(row.StateKeyVersion), row.StateDigest[:], row.commandBytes(), row.IssuedAt, row.ExpiresAt, p.input.Remote.Wire)
	if err != nil || n != 1 {
		return identity.FeatureReceipt{}, identity.UnavailableError{}
	}
	return receipt, nil
}

func (p *providerLogoutStartPhase) CheckFeatureCommit(ctx context.Context, work kernel.Work, command identity.Command) error {
	if err := p.requireIssuer(ctx, work); err != nil {
		return err
	}
	return p.service.effect.Check(ctx, work, p, command)
}

type providerLogoutRowScanner interface{ Scan(...any) error }

func (p *providerLogoutStartPhase) checkedRow(scan providerLogoutRowScanner) (bool, error) {
	row := p.row(*p.input)
	var version int64
	var digest, wire []byte
	var stored providerLogoutRow
	var pending bool
	if err := scan.Scan(&version, &digest, &stored.IssuedAt, &stored.ExpiresAt, &wire, &pending); err != nil {
		return false, err
	}
	defer clear(wire)
	if version != int64(row.StateKeyVersion) || !bytes.Equal(digest, row.StateDigest[:]) || !bytes.Equal(wire, p.input.Remote.Wire) ||
		!row.IssuedAt.Equal(stored.IssuedAt) || !row.ExpiresAt.Equal(stored.ExpiresAt) {
		return false, identity.UnavailableError{}
	}
	return pending, nil
}

func (p *providerLogoutStartPhase) RecoverParticipant(ctx context.Context, work kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	if p.input == nil {
		return kernel.RecoveryUnknown, identity.ForbiddenError{}
	}
	local, err := p.service.effect.Recover(ctx, work, p, p.original)
	if err != nil || p.input.Remote == nil || local == kernel.RecoveryUnknown {
		return local, err
	}
	row := p.row(*p.input)
	rows, err := work.Query(ctx, providerLogoutByStartSQL, string(row.TenantID), row.commandBytes())
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() == nil && local == kernel.RecoveryNotCommitted {
			return local, nil
		}
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	if _, err := p.checkedRow(rows); err != nil || rows.Next() || rows.Err() != nil || local != kernel.RecoveryCommitted {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	return local, nil
}

func (p *providerLogoutStartPhase) disclose(ctx context.Context, result identity.CommandResult) (oidc.LogoutStartResult, error) {
	if p.input.Remote == nil {
		return oidc.NewLogoutStartResult(oidc.OIDCLogoutLocalOnly, url.URL{}, result)
	}
	row := p.row(*p.input)
	pending, err := p.checkedRow(p.service.login.router.pool.Raw().QueryRow(ctx, providerLogoutByStartSQL, string(row.TenantID), row.commandBytes()))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return oidc.NewLogoutStartResult(oidc.OIDCLogoutUnknownReconciliation, url.URL{}, result)
		}
		return oidc.LogoutStartResult{}, providerError(ctx, err)
	}
	if !pending {
		return oidc.NewLogoutStartResult(oidc.OIDCLogoutLocalOnly, url.URL{}, result)
	}
	_, profile, selected, err := p.selected()
	if err != nil || !selected || !p.service.login.router.config.Clock.Now().Before(row.ExpiresAt) {
		return oidc.NewLogoutStartResult(oidc.OIDCLogoutLocalOnly, url.URL{}, result)
	}
	target, err := profile.Redirect(ctx, oidc.NewRPLogoutState(p.input.Remote.Raw))
	if err != nil {
		return oidc.LogoutStartResult{}, err
	}
	return oidc.NewLogoutStartResult(oidc.OIDCLogoutRedirect, target, result)
}
