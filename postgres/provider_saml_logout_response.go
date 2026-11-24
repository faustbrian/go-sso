package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-sso"
	"github.com/faustbrian/go-sso/saml"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ProviderSAMLLogoutResponseRequest is the response-only decoded POST form for
// the exact trusted provider route. Pass all values to retain duplicate
// detection. The caller must not modify the slice during the call. This
// outbound profile sends no RelayState; transport must reject one here.
type ProviderSAMLLogoutResponseRequest struct {
	ProviderID   sso.ProviderID
	SAMLResponse []string
}

func (ProviderSAMLLogoutResponseRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("sso.postgres.ProviderSAMLLogoutResponseRequest(redacted)"))
}

func (ProviderSAMLLogoutResponseRequest) LogValue() slog.Value {
	return slog.StringValue("sso.postgres.ProviderSAMLLogoutResponseRequest(redacted)")
}

func (ProviderSAMLLogoutResponseRequest) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}

func (ProviderSAMLLogoutResponseRequest) MarshalText() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}

// SAMLLogoutResponseOutcome is the disposition of the provider response, not
// proof any session was revoked upstream. Empty means no session was selected.
type SAMLLogoutResponseOutcome string

const (
	SAMLLogoutResponseSettled         SAMLLogoutResponseOutcome = "settled"
	SAMLLogoutResponseProviderFailure SAMLLogoutResponseOutcome = "provider_failure"
	SAMLLogoutResponseReplayed        SAMLLogoutResponseOutcome = "replayed"
	SAMLLogoutResponseConflict        SAMLLogoutResponseOutcome = "conflict"
	SAMLLogoutResponseTimeout         SAMLLogoutResponseOutcome = "timeout"
	SAMLLogoutResponseUnavailable     SAMLLogoutResponseOutcome = "unavailable"
	SAMLLogoutResponseUnknown         SAMLLogoutResponseOutcome = "unknown"
)

// ProviderSAMLLogoutResponseResult preserves the exact original local receipt
// independent of the provider outcome. Status is populated only for a durable
// response or its exact replay. Unknown concerns the provider receipt only;
// retry the same signed response while it's still current to reconcile it.
type ProviderSAMLLogoutResponseResult struct {
	LocalRevocation saml.LocalRevocation
	Outcome         SAMLLogoutResponseOutcome
	Status          saml.LogoutPOSTStatus
	finalRedirect   *url.URL
}

// FinalRedirect returns the approved original application continuation only
// after a newly acknowledged full provider success. Replays and failures never
// disclose it, and no response field can select or override it.
func (r ProviderSAMLLogoutResponseResult) FinalRedirect() (url.URL, bool) {
	if r.Outcome != SAMLLogoutResponseSettled || r.finalRedirect == nil {
		return url.URL{}, false
	}
	return *r.finalRedirect, true
}

// SettleResponse authenticates one installed-provider LogoutResponse, reads
// the original request selected solely by its signed InResponseTo, and settles
// one immutable receipt. It never reads a session credential or mutates a
// session. Install SAMLLogoutResponseMigrationSource before using this method.
func (s *ProviderSAMLLogoutRedirectService) SettleResponse(ctx context.Context, input ProviderSAMLLogoutResponseRequest) (ProviderSAMLLogoutResponseResult, error) {
	return s.settleResponse(ctx, input, "")
}

// SettleResponseWithRelayState settles one signed POST response for the
// explicitly enabled original RelayState request. Pass all values so
// duplicates cannot be normalized into a valid handle. The handle cannot
// select request custody, a session or a continuation. Do not mutate input
// slices during the call.
func (s *ProviderSAMLLogoutRedirectService) SettleResponseWithRelayState(ctx context.Context, input ProviderSAMLLogoutResponseRequest, relayState []string) (ProviderSAMLLogoutResponseResult, error) {
	if s == nil || s.relayKeys == nil || len(relayState) != 1 || len(relayState[0]) != 43 {
		return ProviderSAMLLogoutResponseResult{}, sso.ErrInvalidInput
	}
	return s.settleResponse(ctx, input, relayState[0])
}

func (s *ProviderSAMLLogoutRedirectService) settleResponse(ctx context.Context, input ProviderSAMLLogoutResponseRequest, relayState string) (ProviderSAMLLogoutResponseResult, error) {
	var out ProviderSAMLLogoutResponseResult
	if s == nil || s.local == nil || ctx == nil || len(input.SAMLResponse) != 1 {
		return out, sso.ErrInvalidInput
	}
	profile, selected := s.profiles[input.ProviderID]
	if !selected || input.SAMLResponse[0] == "" {
		return out, sso.ErrInvalidInput
	}
	login := s.local.login
	router, tenant := login.router, login.config.TenantID
	ctx, cancel := context.WithTimeout(ctx, login.config.Coordinator.MaximumDuration)
	defer cancel()

	route, installed, err := router.loadExactSAMLLogoutProfile(ctx, tenant, profile.config)
	if err != nil {
		return out, providerError(ctx, err)
	}
	destination := profile.config.Provider.TrustedOrigin + "/saml2/" + string(input.ProviderID) + "/slo"
	post, err := saml.NewLogoutPOSTProfile(saml.LogoutPOSTConfig{
		SPEntityID: installed.spEntityID, IdentityProviderEntityID: installed.configuration.EntityID,
		SingleLogoutURL: destination, SigningCertificates: installed.configuration.SigningCertificates,
		MaximumAge: samlLogoutRequestLife, ClockSkew: 30 * time.Second,
	})
	if err != nil {
		return out, sso.ErrUnavailable
	}
	verified, err := post.Validate(ctx, saml.LogoutPOSTInput{SAMLResponse: input.SAMLResponse, Now: router.config.Clock.Now()})
	if err != nil {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		return out, sso.ErrInvalidInput
	}
	response, err := verified.Response()
	if err != nil {
		return out, sso.ErrInvalidInput
	}
	correlation, prefixed := strings.CutPrefix(response.InResponseTo, "_")
	start, err := identity.ParseCommandID(correlation)
	if !prefixed || err != nil {
		return out, sso.ErrInvalidInput
	}
	row, retained, found, err := login.readSAMLLogoutRequest(ctx, tenant, start)
	if err != nil {
		return out, providerError(ctx, err)
	}
	if !found || row.requestID() != response.InResponseTo || !matchesSAMLLogoutResponseRequest(row, retained, route, profile.config) ||
		response.IssuedAt.Before(row.IssuedAt.Truncate(time.Second)) {
		return out, sso.ErrInvalidInput
	}
	if retained.Relay != nil {
		defer clear(retained.Relay.Proof)
		if relayState == "" || subtle.ConstantTimeCompare([]byte(relayState), []byte(retained.Relay.Handle)) != 1 || !validSAMLLogoutRelayCustody(row, retained) {
			return out, sso.ErrInvalidInput
		}
	} else if relayState != "" {
		return out, sso.ErrInvalidInput
	}
	out.LocalRevocation = saml.LocalRevocation{SessionID: retained.Anchor.Session, Version: retained.SessionVersion, Committed: true}
	if out.LocalRevocation.Validate() != nil {
		return ProviderSAMLLogoutResponseResult{}, sso.ErrUnavailable
	}
	if retained.Relay != nil {
		return s.settleVerifiedSAMLLogoutRelayResponse(ctx, row, retained, route, response, input.SAMLResponse[0], out)
	}
	return s.settleVerifiedSAMLLogoutResponse(ctx, row, retained, route, response, input.SAMLResponse[0], out)
}

func matchesSAMLLogoutResponseRequest(row samlLogoutRequestRow, stored samlLogoutRequestBinding, route sso.DomainRouteBinding, profile ProviderSAMLLogoutRedirectProfile) bool {
	proof, anchor := route.Proof.Key, stored.Anchor
	return row.Tenant == proof.TenantID && row.Organization == string(proof.OrganizationID) && row.Provider == string(route.ProviderID) &&
		anchor.Tenant == string(row.Tenant) && anchor.Organization == row.Organization && anchor.Provider == row.Provider &&
		stored.Issuer == profile.IdentityProviderEntityID && stored.Endpoint == profile.Endpoint &&
		stored.ProviderVersion == route.ProviderVersion && stored.CredentialGeneration == route.CredentialGeneration &&
		stored.SessionVersion >= 2 && !row.ExpiresAt.After(anchor.ExpiresAt) &&
		stored.Subject.SessionIndex != "" && validSAMLLogoutStoredSubject(stored.Issuer, stored.Subject)
}

func (s *ProviderSAMLLogoutRedirectService) settleVerifiedSAMLLogoutResponse(ctx context.Context, row samlLogoutRequestRow, stored samlLogoutRequestBinding,
	route sso.DomainRouteBinding, response saml.LogoutPOSTResponseEvidence, wire string, out ProviderSAMLLogoutResponseResult,
) (ProviderSAMLLogoutResponseResult, error) {
	router := s.local.login.router
	messageCutoff := minSAMLLogoutTime(row.ExpiresAt, response.ValidUntil).UTC().Truncate(time.Microsecond)
	if !router.config.Clock.Now().Before(messageCutoff) {
		out.Outcome = SAMLLogoutResponseTimeout
		return out, nil
	}
	if err := router.requireSAMLLogoutRoute(ctx, route); err != nil {
		out.Outcome = SAMLLogoutResponseUnavailable
		return out, providerError(ctx, err)
	}
	cutoff := minSAMLLogoutTime(messageCutoff, route.ValidUntil)
	// The ID is scoped to the pinned issuer; a second signature cannot turn a
	// reused ID into a fresh response. Only a replay of the exact wire can read
	// the previous provider status. Raw wire and session data stay out of SQL.
	id := sha256.Sum256([]byte(stored.Issuer + "\x00" + response.ID))
	digest := sha256.Sum256([]byte(wire))
	outcome, err := router.writeSAMLLogoutResponse(ctx, row, route, response.Status, cutoff, id, digest)
	out.Outcome = outcome
	if err != nil {
		return out, err
	}
	if outcome != SAMLLogoutResponseSettled && outcome != SAMLLogoutResponseProviderFailure && outcome != SAMLLogoutResponseReplayed {
		return out, nil
	}
	out.Status = response.Status
	if outcome == SAMLLogoutResponseSettled && router.config.Clock.Now().Before(cutoff) && ctx.Err() == nil {
		if _, approved := s.local.finalRedirect[stored.FinalRedirect]; approved {
			out.finalRedirect, _ = url.Parse(stored.FinalRedirect) // Already validated by the current allowlist's constructor.
		}
	}
	return out, nil
}

const insertSAMLLogoutResponsePrefixSQL = `WITH eligible AS MATERIALIZED (
 SELECT r.tenant_id,r.request_id FROM sso_providers.saml_logout_requests r
 JOIN sso_providers.providers p USING(tenant_id,organization_id,provider_id)
 JOIN sso_providers.credentials c USING(tenant_id,organization_id,provider_id)
 WHERE r.tenant_id=$1 AND r.request_id=$2 AND p.organization_id=$3 AND p.provider_id=$4
 AND r.expires_at=$5 AND p.protocol='saml' AND p.enabled AND p.metadata_version=$6::numeric
 AND p.enablement_credential_generation=$7::numeric AND c.generation=$7::numeric`

const insertSAMLLogoutResponseSuffixSQL = `
 FOR NO KEY UPDATE OF r FOR SHARE OF p
), current_request AS MATERIALIZED (
 SELECT tenant_id,request_id FROM eligible WHERE clock_timestamp() < $8::timestamptz
), written AS (
 INSERT INTO sso_providers.saml_logout_responses
 (tenant_id,request_id,response_id_digest,response_digest,status_code,status_subcode,settled_at)
 SELECT tenant_id,request_id,$9,$10,$11,$12,clock_timestamp() FROM current_request
 ON CONFLICT DO NOTHING RETURNING 1
)
SELECT EXISTS(SELECT FROM current_request), EXISTS(SELECT FROM written)`

const insertSAMLLogoutResponseSQL = insertSAMLLogoutResponsePrefixSQL + insertSAMLLogoutResponseSuffixSQL

const insertSAMLLogoutRelayResponseSQL = insertSAMLLogoutResponsePrefixSQL + `
 AND sha256(r.request_envelope)=$13` + insertSAMLLogoutResponseSuffixSQL

const readSAMLLogoutResponseSQL = `SELECT response_digest,status_code,status_subcode
 FROM sso_providers.saml_logout_responses WHERE tenant_id=$1 AND request_id=$2`

func (r *ProviderRouter) writeSAMLLogoutResponse(ctx context.Context, row samlLogoutRequestRow, route sso.DomainRouteBinding,
	status saml.LogoutPOSTStatus, cutoff time.Time, id, digest [sha256.Size]byte,
) (SAMLLogoutResponseOutcome, error) {
	budget := cutoff.Sub(r.config.Clock.Now())
	if budget <= 0 {
		return SAMLLogoutResponseTimeout, nil
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	var outcome SAMLLogoutResponseOutcome
	var committing bool
	err := pgx.BeginFunc(ctx, r.pool.Raw(), func(tx pgx.Tx) error {
		var eligible, written bool
		err := tx.QueryRow(ctx, insertSAMLLogoutResponseSQL, string(row.Tenant), row.requestID(), row.Organization, row.Provider,
			row.ExpiresAt, strconv.FormatUint(route.ProviderVersion, 10), strconv.FormatUint(route.CredentialGeneration, 10), cutoff,
			id[:], digest[:], string(status.Code), string(status.Subcode)).Scan(&eligible, &written)
		if err != nil {
			return err
		}
		if !eligible {
			return sso.ErrUnavailable
		}
		if !written {
			return settleSAMLLogoutReplay(ctx, tx, row, digest, status, &outcome)
		}
		// A uniqueness wait across two different requests can outlast the
		// timestamp sampled after locking this request. Roll back before commit.
		if !r.config.Clock.Now().Before(cutoff) || ctx.Err() != nil {
			return context.DeadlineExceeded
		}
		outcome = SAMLLogoutResponseSettled
		if status.Code != saml.LogoutStatusSuccess || status.Subcode != "" {
			outcome = SAMLLogoutResponseProviderFailure
		}
		committing = true
		return nil
	})
	if err == nil {
		return outcome, nil
	}
	if errors.Is(err, sso.ErrConflict) {
		return SAMLLogoutResponseConflict, sso.ErrConflict
	}
	var serverError *pgconn.PgError
	if committing && !errors.Is(err, pgx.ErrTxCommitRollback) && !errors.As(err, &serverError) {
		return SAMLLogoutResponseUnknown, sso.ErrUnavailable
	}
	if !r.config.Clock.Now().Before(cutoff) {
		return SAMLLogoutResponseTimeout, nil
	}
	return SAMLLogoutResponseUnavailable, providerError(ctx, err)
}

func settleSAMLLogoutReplay(ctx context.Context, tx pgx.Tx, row samlLogoutRequestRow, digest [sha256.Size]byte, status saml.LogoutPOSTStatus, outcome *SAMLLogoutResponseOutcome) error {
	var original []byte
	var code, subcode string
	err := tx.QueryRow(ctx, readSAMLLogoutResponseSQL, string(row.Tenant), row.requestID()).Scan(&original, &code, &subcode)
	if errors.Is(err, pgx.ErrNoRows) {
		// The same signed ID belongs to another request.
		return sso.ErrConflict
	}
	if err != nil {
		return err
	}
	if !bytes.Equal(original, digest[:]) || code != string(status.Code) || subcode != string(status.Subcode) {
		return sso.ErrConflict
	}
	*outcome = SAMLLogoutResponseReplayed
	return nil
}
