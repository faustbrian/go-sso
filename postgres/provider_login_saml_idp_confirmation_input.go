package postgres

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"math"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	"github.com/faustbrian/go-sso"
	"github.com/jackc/pgx/v5"
)

// SAMLIDPConfirmationRequest carries the pending identifier and both original
// browser values. Tenant and provider come from the trusted route; Origin
// must be the actual request origin validated by the transport, never a form
// field or a value guessed from Host. Neither value is a session credential.
type SAMLIDPConfirmationRequest struct {
	TenantID      identity.TenantID
	ProviderID    sso.ProviderID
	PendingID     identity.CommandID
	Origin        string
	Browser, Form auth.BearerCredential
}

func (SAMLIDPConfirmationRequest) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprint(f, "sso.postgres.SAMLIDPConfirmationRequest(redacted)")
}

func (SAMLIDPConfirmationRequest) LogValue() slog.Value {
	return slog.StringValue("sso.postgres.SAMLIDPConfirmationRequest(redacted)")
}

func (SAMLIDPConfirmationRequest) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}
func (SAMLIDPConfirmationRequest) MarshalText() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}

// This observation authenticates original custody but takes no durable lock.
// The protected Work must match and clear that exact pending row at Apply.
const readSAMLIDPPendingConfirmationSQL = `SELECT organization_id,provider_id,user_id,binding_envelope,confirmation_key_version,browser_digest,form_digest,issued_at,expires_at
FROM sso_providers.saml_idp_confirmations WHERE tenant_id=$1 AND confirmation_id=$2 AND completed_at IS NULL
 AND issued_at<=statement_timestamp() AND expires_at>statement_timestamp()`

func (s *ProviderSAMLIDPArrivalService) readPendingConfirmation(ctx context.Context, req SAMLIDPConfirmationRequest) (pending samlIDPPendingArrival, original samlIDPArrivalOrigin, err error) {
	if ctx == nil || s == nil || s.admission == nil {
		return pending, original, sso.ErrInvalidInput
	}
	selected, exists := s.admission.profiles[req.ProviderID]
	if !exists || req.TenantID != s.admission.tenant || req.Origin != selected.profile.Provider.TrustedOrigin {
		return pending, original, sso.ErrForbidden
	}
	id, err := identity.ParseCommandID(string(req.PendingID))
	if err != nil {
		return pending, original, sso.ErrForbidden
	}
	key, err := base64.RawURLEncoding.Strict().DecodeString(string(id))
	if err != nil || len(key) != 16 {
		return pending, original, sso.ErrForbidden
	}
	var row samlIDPPendingArrivalRow
	var version int64
	err = s.admission.router.pool.Raw().QueryRow(ctx, readSAMLIDPPendingConfirmationSQL, string(req.TenantID), key).
		Scan(&row.Organization, &row.Provider, &row.User, &row.Envelope, &version, &row.BrowserDigest, &row.FormDigest, &row.IssuedAt, &row.ExpiresAt)
	defer func() {
		if err != nil {
			clear(row.Envelope)
			clear(original.Proof)
			pending, original = samlIDPPendingArrival{}, samlIDPArrivalOrigin{}
		}
	}()
	if errors.Is(err, pgx.ErrNoRows) {
		return pending, original, sso.ErrForbidden
	}
	if err != nil {
		return pending, original, samlIDPPendingArrivalFailure(ctx)
	}
	if row.Provider != string(req.ProviderID) || row.Organization != string(selected.profile.Provider.OrganizationID) ||
		row.User == "" || version <= 0 || version > math.MaxUint32 || len(row.BrowserDigest) != 32 || len(row.FormDigest) != 32 ||
		!validSAMLReplayTime(row.IssuedAt) || !validSAMLReplayTime(row.ExpiresAt) || !row.IssuedAt.Before(row.ExpiresAt) {
		return pending, original, sso.ErrForbidden
	}
	pending = samlIDPPendingArrival{Binding: identity.CommandBinding{TenantID: req.TenantID, UserID: identity.UserID(row.User), CommandID: id},
		Organization: organization.ID(row.Organization), Provider: req.ProviderID, Envelope: row.Envelope, KeyVersion: uint32(version),
		BrowserDigest: [32]byte(row.BrowserDigest), FormDigest: [32]byte(row.FormDigest), IssuedAt: row.IssuedAt.UTC(), ExpiresAt: row.ExpiresAt.UTC()}
	if !authenticateSAMLIDPBrowserPair(pending, s.config.ConfirmationKeys[pending.KeyVersion], req.Browser, req.Form) {
		return pending, original, sso.ErrForbidden
	}
	aad, err := samlIDPArrivalAAD(pending)
	if err != nil {
		return pending, original, sso.ErrForbidden
	}
	plain, err := s.payload.open(ctx, aad, pending.Envelope, 65536, 32768)
	if err != nil {
		return pending, original, err
	}
	defer clear(plain)
	original, err = decodeSAMLIDPArrivalOrigin(plain, s.admission.verifyLogoutSubject != nil)
	if err != nil || !s.matchesSAMLIDPConfirmationOrigin(pending, original, selected) {
		return pending, original, sso.ErrForbidden
	}
	pending.Binding = original.Binding
	return pending, original, nil
}

func (s *ProviderSAMLIDPArrivalService) matchesSAMLIDPConfirmationOrigin(pending samlIDPPendingArrival, original samlIDPArrivalOrigin, selected staticSAMLIDPAdmissionSelection) bool {
	b, route, grant, profile := original.Binding, original.Route, kernel.CapabilityPlan(original.Grant), selected.profile.Provider
	now := s.admission.router.config.Clock.Now().UTC()
	if !validSAMLIDPArrivalOriginVersion(original, s.admission.verifyLogoutSubject != nil) || b.ValidateFor(kernel.SSOSAMLIDPArrivalOperation()) != nil || b.CommandID != pending.Binding.CommandID || b.RecordID != string(b.CommandID) ||
		b.TenantID != pending.Binding.TenantID || b.UserID != pending.Binding.UserID || b.ActorKind != authorization.SubjectServiceAccount ||
		b.ActorID != s.config.ActorID || b.PolicyID != s.config.PolicyID || b.PolicyVersion != s.config.PolicyVersion || b.CorrelationID != string(b.CommandID) {
		return false
	}
	if original.ExternalOrigin != profile.TrustedOrigin || route.ProviderID != pending.Provider || route.ProofKey.TenantID != b.TenantID || route.ProofKey.OrganizationID != pending.Organization ||
		route.ProofKey.Domain != profile.Domain || route.ProofVersion == 0 || route.ProofKey.ProofVersion != route.ProofVersion || route.ProofKey.Revoked ||
		route.ProviderVersion != profile.ProviderVersion || route.CredentialGeneration != profile.CredentialGeneration || original.MappingVersion != profile.MappingVersion ||
		pending.ExpiresAt.After(route.ValidUntil) || pending.ExpiresAt.After(route.ProofKey.ExpiresAt) || pending.ExpiresAt.After(original.Evidence.ValidUntil) ||
		now.Before(pending.IssuedAt) || !now.Before(pending.ExpiresAt) || !validSAMLResponseEvidence(SAMLVerifiedResponse(original.Evidence), pending.IssuedAt) {
		return false
	}
	if grant.Purpose != "identity.sso.saml-idp-init" || grant.MaxUses != 1 || grant.ReplayKeyVersion == 0 || grant.ProofFingerprint == ([32]byte{}) ||
		grant.ExpiresAt.After(pending.ExpiresAt) || !now.Before(grant.ExpiresAt) || len(original.Proof) == 0 || original.GlobalAuthorityID != s.config.GlobalAuthorityID ||
		original.GlobalVersion == 0 || original.TenantVersion == 0 || original.FactorVersion == 0 || original.PolicyVersion == 0 {
		return false
	}
	account := original.Account
	if account.Account.Validate(b.TenantID, b.UserID) != nil || account.Credential.Validate(b.TenantID, b.UserID) != nil ||
		account.Account.Issuer != original.Issuer || account.Account.Subject != original.Evidence.ProviderSubject ||
		account.LinkVersion == 0 || account.UserVersion == 0 || account.IdentifierVersion == 0 || account.CredentialAuthorityVersion == 0 {
		return false
	}
	return original.Member.Validate(organization.CredentialAuthorityQuery{TenantID: b.TenantID, OrganizationID: pending.Organization, ActorID: b.UserID}, now) == nil
}

// Both independently issued values must match their original role, tenant,
// provider and arrival. The submitted form value cannot stand in for a cookie.
func authenticateSAMLIDPBrowserPair(pending samlIDPPendingArrival, key [32]byte, browser, form auth.BearerCredential) bool {
	if key == ([32]byte{}) || pending.KeyVersion == 0 || len(browser.Token()) != 43 || len(form.Token()) != 43 {
		return false
	}
	var b, f [32]byte
	defer clear(b[:])
	defer clear(f[:])
	encoding := base64.RawURLEncoding.Strict()
	bn, bErr := encoding.Decode(b[:], []byte(browser.Token()))
	fn, fErr := encoding.Decode(f[:], []byte(form.Token()))
	if bErr != nil || fErr != nil || bn != len(b) || fn != len(f) {
		return false
	}
	browserDigest, formDigest := samlIDPBrowserCommitments(key, pending.KeyVersion, pending.Binding, pending.Provider, b[:], f[:])
	return (subtle.ConstantTimeCompare(browserDigest[:], pending.BrowserDigest[:]) &
		subtle.ConstantTimeCompare(formDigest[:], pending.FormDigest[:]) &
		(1 ^ subtle.ConstantTimeCompare(b[:], f[:]))) == 1
}
