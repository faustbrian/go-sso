package postgres

import (
	"context"
	"crypto/hmac"
	"encoding/base64"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-sso"
	"github.com/faustbrian/go-sso/oidc"
)

// ProviderLogoutCompleteRequest carries the selected route and bounded provider
// response. The transport supplies CallbackURI from its trusted origin and
// actual route, not from request query parameters or forwarding headers.
type ProviderLogoutCompleteRequest struct {
	ProviderID  string
	CallbackURI string
	RawQuery    string
}

func (ProviderLogoutCompleteRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("sso.postgres.ProviderLogoutCompleteRequest(redacted)"))
}

func (ProviderLogoutCompleteRequest) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}
func (ProviderLogoutCompleteRequest) MarshalText() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}

// ProviderLogoutRateContext attributes quota to the installed provider and
// original logout transaction, never to raw browser state. Lifetime is the
// original configured interval, not a validity grant or a refreshed deadline.
type ProviderLogoutRateContext struct {
	ProviderID    sso.ProviderID
	TransactionID string
	Lifetime      time.Duration
}

// CompleteRateSource authenticates pending callback custody without consuming
// it. Transport can meter this transaction before Complete repeats the checks.
// A late valid return may still be attributed so Complete can settle timeout.
func (s *ProviderLogoutService) CompleteRateSource(ctx context.Context, tenant identity.TenantID, request ProviderLogoutCompleteRequest) (out ProviderLogoutRateContext, err error) {
	if s == nil || s.login == nil || ctx == nil {
		return out, sso.ErrInvalidInput
	}
	if tenant != s.login.config.TenantID {
		return out, sso.ErrForbidden
	}
	ctx, cancel := context.WithTimeout(ctx, s.login.config.Coordinator.MaximumDuration)
	defer cancel()
	defer func() {
		if recover() != nil {
			out, err = ProviderLogoutRateContext{}, sso.ErrUnavailable
		}
	}()
	p, err := s.admitProviderLogoutCallback(ctx, request)
	if err != nil {
		return out, err
	}
	defer clear(p.wire)
	return ProviderLogoutRateContext{
		ProviderID: sso.ProviderID(p.bound.ProviderID), TransactionID: string(p.row.StartCommandID),
		Lifetime: p.row.ExpiresAt.Sub(p.row.IssuedAt),
	}, nil
}

// Complete consumes the original committed logout state without requiring a
// still-valid cookie. A refused, late, replayed or ambiguous callback never
// restores or mutates the already-revoked session. Only the request whose
// consumption is acknowledged can disclose the selected final target.
func (s *ProviderLogoutService) Complete(ctx context.Context, request ProviderLogoutCompleteRequest) (out oidc.LogoutCompleteResult, err error) {
	if s == nil || s.login == nil || ctx == nil {
		return out, sso.ErrInvalidInput
	}
	ctx, cancel := context.WithTimeout(ctx, s.login.config.Coordinator.MaximumDuration)
	defer cancel()
	defer func() {
		if recover() != nil {
			out, err = oidc.LogoutCompleteResult{}, sso.ErrUnavailable
		}
	}()
	p, err := s.admitProviderLogoutCallback(ctx, request)
	if err != nil {
		return out, err
	}
	defer clear(p.wire)
	b := p.binding()
	policy := s.login.config.Coordinator.AdmissionPolicy
	decision, err := policy.Authorization.Decide(ctx, authorization.DecisionContext{
		PolicyRevision: authorization.Revision(b.PolicyVersion), Request: authorization.Request{
			Tenant: authorization.TenantID(b.TenantID), Subject: authorization.Subject{Kind: b.ActorKind, ID: authorization.SubjectID(b.ActorID)},
			Action: authorization.Action(b.OperationID), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)},
		},
	})
	if err != nil {
		return out, providerError(ctx, err)
	}
	if decision.Outcome != authorization.Allow || decision.Revision != authorization.Revision(b.PolicyVersion) {
		return out, sso.ErrForbidden
	}
	c, registry, err := s.coordinator(p)
	if err != nil {
		return out, providerError(ctx, err)
	}
	command, err := p.command()
	if err != nil {
		return out, providerError(ctx, err)
	}
	plan, err := p.plan(registry)
	if err != nil {
		return out, providerError(ctx, err)
	}
	result, err := executeProviderLogoutCommand(ctx, c, b, command, plan)
	if result.Outcome == identity.CommitOutcomeUnknown || result.Outcome == identity.CommitOutcomeInProgress {
		return oidc.NewLogoutCompleteResult(oidc.OIDCLogoutUnknownReconciliation, url.URL{}, result)
	}
	if err != nil {
		return out, providerError(ctx, err)
	}
	if result.Outcome != identity.CommitOutcomeCommitted || result.Binding != b || p.terminal == "" {
		return out, sso.ErrForbidden
	}
	switch p.terminal {
	case providerLogoutTimeoutKind:
		return oidc.NewLogoutCompleteResult(oidc.OIDCLogoutTimeout, url.URL{}, result)
	case providerLogoutErrorKind:
		return oidc.NewLogoutCompleteResult(oidc.OIDCLogoutProviderError, url.URL{}, result)
	case providerLogoutCompleteKind:
		if _, allowed := s.finalRedirect[p.bound.FinalRedirect]; !allowed {
			return oidc.NewLogoutCompleteResult(oidc.OIDCLogoutProviderComplete, url.URL{}, result)
		}
		target, err := url.Parse(p.bound.FinalRedirect)
		if err != nil {
			return out, sso.ErrUnavailable
		}
		return oidc.NewLogoutCompleteResult(oidc.OIDCLogoutRedirect, *target, result)
	default:
		return out, sso.ErrUnavailable
	}
}

func (s *ProviderLogoutService) admitProviderLogoutCallback(ctx context.Context, request ProviderLogoutCompleteRequest) (*providerLogoutCompletePhase, error) {
	path := providerLogoutCallbackPath(request.ProviderID)
	if path == "" || request.CallbackURI != strings.TrimSuffix(s.login.config.Origin, "/")+path {
		return nil, sso.ErrForbidden
	}
	callback, err := oidc.ParseRPLogoutCallback(request.RawQuery)
	if err != nil {
		return nil, err
	}
	row, wire, err := s.pendingLogout(ctx, callback.State())
	if err != nil {
		return nil, providerError(ctx, err)
	}
	retained := false
	defer func() {
		if !retained {
			clear(wire)
		}
	}()
	bound, err := openProviderLogoutBinding(ctx, s.login.payload, row, wire)
	if err != nil || bound.ProviderID != request.ProviderID || bound.Protocol.CallbackURI != request.CallbackURI {
		return nil, sso.ErrForbidden
	}
	profile, err := oidc.NewRPLogoutProfile(bound.Protocol)
	if err != nil {
		return nil, sso.ErrForbidden
	}
	// pendingLogout already authenticated these exact state bytes against the
	// persisted keyed digest. Raw browser state is not stored in this row.
	outcome, err := callback.OutcomeFor(ctx, profile, callback.State(), request.CallbackURI)
	if err != nil {
		return nil, err
	}
	var kind string
	switch outcome {
	case oidc.OIDCLogoutProviderComplete:
		kind = providerLogoutCompleteKind
	case oidc.OIDCLogoutProviderError:
		kind = providerLogoutErrorKind
	default:
		return nil, sso.ErrForbidden
	}
	retained = true
	return &providerLogoutCompletePhase{service: s, row: row, bound: bound, wire: wire, requested: kind}, nil
}

const providerLogoutPendingSQL = `SELECT t.state_key_version,t.state_digest,t.start_command_id,t.issued_at,t.expires_at,t.binding_envelope
 FROM unnest($2::bigint[],$3::bytea[]) AS k(version,digest)
 JOIN sso_providers.logout_transactions t ON (t.tenant_id,t.state_key_version,t.state_digest)=($1,k.version,k.digest)
 JOIN identity.commands c ON (c.tenant_id,c.purpose,c.command_id)=(t.tenant_id,t.start_purpose,t.start_command_id)
 WHERE t.completed_at IS NULL AND c.state='committed' LIMIT 2`

func (s *ProviderLogoutService) pendingLogout(ctx context.Context, state oidc.RPLogoutState) (providerLogoutRow, []byte, error) {
	keys, tenant := s.login.payload.StateKeys, s.login.config.TenantID
	versions := make([]int64, 0, len(keys))
	for version := range keys {
		versions = append(versions, int64(version))
	}
	slices.Sort(versions)
	digests := make([][]byte, 0, len(versions))
	for _, version := range versions {
		digest := providerLogoutStateDigest(tenant, keys[uint32(version)], state)
		digests = append(digests, digest[:])
	}
	rows, err := s.login.router.pool.Raw().Query(ctx, providerLogoutPendingSQL, string(tenant), versions, digests)
	if err != nil {
		return providerLogoutRow{}, nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return providerLogoutRow{}, nil, err
		}
		return providerLogoutRow{}, nil, identity.ForbiddenError{}
	}
	row := providerLogoutRow{TenantID: tenant}
	var version int64
	var digest, command, wire []byte
	if err := rows.Scan(&version, &digest, &command, &row.IssuedAt, &row.ExpiresAt, &wire); err != nil {
		clear(wire)
		return providerLogoutRow{}, nil, err
	}
	if rows.Next() || rows.Err() != nil || version <= 0 || version > int64(^uint32(0)) {
		clear(wire)
		return providerLogoutRow{}, nil, identity.UnavailableError{}
	}
	row.StateKeyVersion = uint32(version)
	row.StartCommandID, err = identity.ParseCommandID(base64.RawURLEncoding.EncodeToString(command))
	want := providerLogoutStateDigest(tenant, keys[row.StateKeyVersion], state)
	if err != nil || want == ([32]byte{}) || !hmac.Equal(digest, want[:]) {
		clear(wire)
		return providerLogoutRow{}, nil, identity.ForbiddenError{}
	}
	row.StateDigest = want
	return row, wire, nil
}
