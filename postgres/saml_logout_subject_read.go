package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"math"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/jackc/pgx/v5"
)

const readSAMLLogoutSubjectSQL = `SELECT tenant_id::text,organization_id,provider_id,user_id::text,session_id,family_id,
 issuance_command_id,issuance_purpose,issued_at,expires_at,match_key_version,subject_digest,session_index_digest,subject_envelope
 FROM sso_providers.saml_logout_subjects WHERE tenant_id=$1 AND session_id=$2`

type samlLogoutSubjectRow struct {
	anchor        samlLogoutIssuanceAnchor
	command       []byte
	keyVersion    int64
	subjectDigest []byte
	indexDigest   []byte
	wire          []byte
}

// This exact-session lookup authenticates original custody only. The caller
// must still establish current session/user/family/provider authority and expiry.
func (c *SAMLLogoutSubjectCustody) read(ctx context.Context, pool *database.Pool, crypto *envelope.Service, tenant identity.TenantID, sessionID string) (samlLogoutIssuanceAnchor, samlLogoutIssuerScope, samlStoredLogoutSubject, bool, error) {
	fail := func(err error) (samlLogoutIssuanceAnchor, samlLogoutIssuerScope, samlStoredLogoutSubject, bool, error) {
		return samlLogoutIssuanceAnchor{}, samlLogoutIssuerScope{}, samlStoredLogoutSubject{}, false, err
	}
	if err := providerLoginPayloadContext(ctx); err != nil {
		return fail(err)
	}
	if c == nil || pool == nil || pool.Raw() == nil || crypto == nil || !providerLoginPayloadTenant(tenant) || !providerID(sessionID) {
		return fail(identity.ForbiddenError{})
	}
	var row samlLogoutSubjectRow
	defer func() {
		clear(row.command)
		clear(row.subjectDigest)
		clear(row.indexDigest)
		clear(row.wire)
	}()
	a := &row.anchor
	err := pool.Raw().QueryRow(ctx, readSAMLLogoutSubjectSQL, string(tenant), sessionID).Scan(
		&a.Tenant, &a.Organization, &a.Provider, &a.User, &a.Session, &a.Family, &row.command, &a.Purpose,
		&a.IssuedAt, &a.ExpiresAt, &row.keyVersion, &row.subjectDigest, &row.indexDigest, &row.wire)
	if errors.Is(err, pgx.ErrNoRows) {
		return fail(nil)
	}
	if err != nil {
		return fail(providerError(ctx, err))
	}
	anchor, scope, subject, err := c.openRow(ctx, crypto, tenant, sessionID, row)
	if err != nil {
		return fail(err)
	}
	return anchor, scope, subject, true, nil
}

func (c *SAMLLogoutSubjectCustody) openRow(ctx context.Context, crypto *envelope.Service, tenant identity.TenantID, sessionID string, row samlLogoutSubjectRow) (samlLogoutIssuanceAnchor, samlLogoutIssuerScope, samlStoredLogoutSubject, error) {
	fail := func(err error) (samlLogoutIssuanceAnchor, samlLogoutIssuerScope, samlStoredLogoutSubject, error) {
		return samlLogoutIssuanceAnchor{}, samlLogoutIssuerScope{}, samlStoredLogoutSubject{}, err
	}
	if err := providerLoginPayloadContext(ctx); err != nil {
		return fail(err)
	}
	anchor := row.anchor
	if c == nil || crypto == nil || !providerLoginPayloadTenant(tenant) || anchor.Tenant != string(tenant) || anchor.Session != sessionID {
		return fail(identity.ForbiddenError{})
	}
	if !providerID(anchor.Organization) || !providerID(anchor.Provider) || !providerID(anchor.Session) || !providerID(anchor.Family) ||
		(identity.User{ID: identity.UserID(anchor.User), TenantID: tenant, Status: identity.StatusActive, Version: 1}).Validate(tenant) != nil ||
		len(row.command) != 16 || (anchor.Purpose != "identity.sso.saml-acs" && anchor.Purpose != "identity.sso.saml-idp-init") {
		return fail(identity.ForbiddenError{})
	}
	if !validSAMLLogoutRowTime(anchor.IssuedAt) || !validSAMLLogoutRowTime(anchor.ExpiresAt) || !anchor.ExpiresAt.After(anchor.IssuedAt) {
		return fail(identity.ForbiddenError{})
	}
	if row.keyVersion < 1 || row.keyVersion > math.MaxUint32 || c.config.MatchKeys[uint32(row.keyVersion)] == ([32]byte{}) ||
		len(row.subjectDigest) != 32 || (row.indexDigest != nil && len(row.indexDigest) != 32) {
		return fail(identity.ForbiddenError{})
	}
	// The writer serializes the original 16-byte command as base64url and UTC
	// microseconds before sealing. PostgreSQL may return a different time zone.
	anchor.Command = base64.RawURLEncoding.EncodeToString(row.command)
	anchor.IssuedAt = anchor.IssuedAt.UTC().Truncate(time.Microsecond)
	anchor.ExpiresAt = anchor.ExpiresAt.UTC().Truncate(time.Microsecond)
	prepared := samlPreparedLogoutSubject{KeyVersion: uint32(row.keyVersion), Envelope: row.wire}
	copy(prepared.Subject[:], row.subjectDigest)
	if row.indexDigest != nil {
		prepared.Index = new([32]byte)
		copy(prepared.Index[:], row.indexDigest)
	}
	aad, err := samlLogoutSubjectAAD(anchor, prepared)
	if err != nil {
		return fail(err)
	}
	payload := providerLoginPayloadConfig{Envelope: crypto, KeyReference: c.config.KeyReference}
	plain, err := payload.open(ctx, aad, row.wire, samlLogoutSubjectEnvelopeLimit, providerLoginCallbackPlainLimit)
	if err != nil {
		return fail(err)
	}
	defer clear(plain)
	var stored struct {
		Issuer  string
		Subject samlStoredLogoutSubject
	}
	if providerLoginPayloadDecode(plain, &stored) != nil {
		return fail(identity.ForbiddenError{})
	}
	// Only the writer's original shape is accepted: JSON's case aliases,
	// duplicate fields and lossy text replacement cannot select a subject.
	canonical, err := providerLoginPayloadEncode(stored)
	defer clear(canonical)
	if err != nil || !bytes.Equal(plain, canonical) || !validSAMLLogoutStoredSubject(stored.Issuer, stored.Subject) {
		return fail(identity.ForbiddenError{})
	}
	scope := samlLogoutIssuerScope{anchor.Organization, anchor.Provider, stored.Issuer}
	if err := c.validatePrepared(&prepared, anchor, scope, &stored.Subject); err != nil {
		return fail(err)
	}
	return anchor, scope, stored.Subject, nil
}

func validSAMLLogoutRowTime(value time.Time) bool {
	return !value.IsZero() && value.Unix() > 0 && value.Year() <= 9999 && value.Nanosecond()%1000 == 0
}

func validSAMLLogoutStoredSubject(issuer string, subject samlStoredLogoutSubject) bool {
	validText := func(value string, maximum int) bool {
		return value != "" && len(value) <= maximum && utf8.ValidString(value) && !strings.ContainsFunc(value, func(r rune) bool {
			return unicode.IsControl(r) || r == 0xfffe || r == 0xffff
		})
	}
	if !providerLoginPayloadText(issuer, 2048) || !validText(subject.ProviderSubject, 512) || strings.TrimSpace(subject.ProviderSubject) == "" ||
		(subject.SubjectFormat != "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" && subject.SubjectFormat != "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress") ||
		(subject.NameQualifier != "" && subject.NameQualifier != issuer) ||
		(subject.SessionIndex != "" && !validText(subject.SessionIndex, 2048)) {
		return false
	}
	return validSAMLLogoutSubject(SAMLLogoutSubject(subject), SAMLVerifiedResponse{ProviderSubject: subject.ProviderSubject, SubjectFormat: subject.SubjectFormat, SessionIndex: subject.SessionIndex})
}
