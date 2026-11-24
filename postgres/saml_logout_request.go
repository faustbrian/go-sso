package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/jackc/pgx/v5"
)

const (
	samlLogoutRequestLife         = 5 * time.Minute
	samlLogoutRequestWireMaximum  = 64 << 10
	samlLogoutRequestPlainMaximum = 32 << 10
)

type samlLogoutRequestRow struct {
	Tenant                 identity.TenantID
	Command                identity.CommandID
	Organization, Provider string
	IssuedAt, ExpiresAt    time.Time
}

// Only signed InResponseTo will select this custody. The issuer, original
// NameID/index, approved continuation and exact local session all come from
// the sealed request, never from a subsequent provider response.
type samlLogoutRequestBinding struct {
	Anchor                                                samlLogoutIssuanceAnchor
	Subject                                               samlStoredLogoutSubject
	Issuer, Endpoint, FinalRedirect, Redirect             string
	SessionVersion, ProviderVersion, CredentialGeneration uint64
}

func (r samlLogoutRequestRow) requestID() string {
	return "_" + string(r.Command)
}

func (r samlLogoutRequestRow) aad() (envelope.Context, error) {
	if _, err := identity.ParseCommandID(string(r.Command)); err != nil || !providerLoginPayloadTenant(r.Tenant) ||
		!providerID(r.Organization) || !providerID(r.Provider) ||
		!validSAMLLogoutRowTime(r.IssuedAt) || !validSAMLLogoutRowTime(r.ExpiresAt) ||
		!r.ExpiresAt.After(r.IssuedAt) || r.ExpiresAt.After(r.IssuedAt.Add(samlLogoutRequestLife)) {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	r.IssuedAt, r.ExpiresAt = r.IssuedAt.UTC(), r.ExpiresAt.UTC()
	wire, err := providerLoginPayloadEncode(r)
	defer clear(wire)
	if err != nil {
		return envelope.Context{}, identity.UnavailableError{}
	}
	digest := sha256.Sum256(wire)
	return envelope.NewContext(map[string]string{
		"owner": "sso/postgres", "purpose": "saml-logout-request-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:]),
	})
}

func minSAMLLogoutTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

const selectSAMLLogoutRequestSQL = `SELECT organization_id,provider_id,request_id,issued_at,expires_at,request_envelope
 FROM sso_providers.saml_logout_requests WHERE tenant_id=$1 AND start_command_id=$2`

func (s *ProviderLoginService) readSAMLLogoutRequest(ctx context.Context, tenant identity.TenantID, start identity.CommandID) (samlLogoutRequestRow, samlLogoutRequestBinding, bool, error) {
	command, err := base64.RawURLEncoding.Strict().DecodeString(string(start))
	if err != nil || len(command) != 16 {
		return samlLogoutRequestRow{}, samlLogoutRequestBinding{}, false, identity.ForbiddenError{}
	}
	row := samlLogoutRequestRow{Tenant: tenant, Command: start}
	var id string
	var wire []byte
	err = s.router.pool.Raw().QueryRow(ctx, selectSAMLLogoutRequestSQL, string(row.Tenant), command).Scan(
		&row.Organization, &row.Provider, &id, &row.IssuedAt, &row.ExpiresAt, &wire)
	defer clear(wire)
	if errors.Is(err, pgx.ErrNoRows) {
		return samlLogoutRequestRow{}, samlLogoutRequestBinding{}, false, nil
	}
	if err != nil {
		return samlLogoutRequestRow{}, samlLogoutRequestBinding{}, false, err
	}
	if row.requestID() != id {
		return samlLogoutRequestRow{}, samlLogoutRequestBinding{}, false, identity.ForbiddenError{}
	}
	aad, err := row.aad()
	if err != nil {
		return samlLogoutRequestRow{}, samlLogoutRequestBinding{}, false, err
	}
	plain, err := s.payload.open(ctx, aad, wire, samlLogoutRequestWireMaximum, samlLogoutRequestPlainMaximum)
	defer clear(plain)
	if err != nil {
		return samlLogoutRequestRow{}, samlLogoutRequestBinding{}, false, err
	}
	var payload samlLogoutRequestBinding
	if providerLoginPayloadDecode(plain, &payload) != nil {
		return samlLogoutRequestRow{}, samlLogoutRequestBinding{}, false, identity.ForbiddenError{}
	}
	encoded, err := providerLoginPayloadEncode(payload)
	defer clear(encoded)
	if err != nil || !bytes.Equal(encoded, plain) {
		return samlLogoutRequestRow{}, samlLogoutRequestBinding{}, false, identity.ForbiddenError{}
	}
	return row, payload, true, nil
}

// The provider fence and the committed native command are part of the insert,
// not just the earlier observations used to open the signing credential.
const insertSAMLLogoutRequestSQL = `INSERT INTO sso_providers.saml_logout_requests
 (tenant_id,organization_id,provider_id,request_id,start_command_id,issued_at,expires_at,request_envelope)
 SELECT $1::identity.directory_id,$2,$3,$4,$5,$6,$7,$8 FROM sso_providers.providers p
 WHERE p.tenant_id=$1::text AND p.organization_id=$2 AND p.provider_id=$3 AND p.protocol='saml' AND p.enabled
 AND p.metadata_version=$9::numeric AND p.enablement_credential_generation=$10::numeric
 AND clock_timestamp() < $7
 AND EXISTS (SELECT 1 FROM identity.commands c WHERE c.command_id=$5 AND c.tenant_id=$1::identity.directory_id
   AND c.purpose='identity.sso.saml-logout-start' AND c.state='committed')
 FOR SHARE OF p
 ON CONFLICT (tenant_id,start_command_id) DO NOTHING`

func (s *ProviderLoginService) insertSAMLLogoutRequest(ctx context.Context, row samlLogoutRequestRow, payload samlLogoutRequestBinding) (bool, error) {
	aad, err := row.aad()
	if err != nil {
		return false, err
	}
	command, err := base64.RawURLEncoding.Strict().DecodeString(string(row.Command))
	if err != nil || len(command) != 16 {
		return false, identity.ForbiddenError{}
	}
	plain, err := providerLoginPayloadEncode(payload)
	defer clear(plain)
	if err != nil || len(plain) > samlLogoutRequestPlainMaximum {
		return false, identity.UnavailableError{}
	}
	wire, err := s.payload.seal(ctx, aad, plain, samlLogoutRequestWireMaximum)
	defer clear(wire)
	if err != nil {
		return false, err
	}
	tag, err := s.router.pool.Raw().Exec(ctx, insertSAMLLogoutRequestSQL, string(row.Tenant), row.Organization, row.Provider, row.requestID(), command,
		row.IssuedAt, row.ExpiresAt, wire, strconv.FormatUint(payload.ProviderVersion, 10), strconv.FormatUint(payload.CredentialGeneration, 10))
	return tag.RowsAffected() == 1, err
}
