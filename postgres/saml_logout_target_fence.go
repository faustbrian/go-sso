package postgres

import (
	"context"
	"slices"
	"strings"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// Both readers use this exact indexed predicate and one MVCC snapshot across
// retained keys. Work only accepts scalars, so tuples are bounded JSON text.
const samlIDPLogoutCandidatePrefixSQL = `
 FROM jsonb_to_recordset($4::jsonb) AS match(version bigint,subject text,index text)
 CROSS JOIN LATERAL (
 SELECT * FROM sso_providers.saml_logout_subjects
 WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3
 AND match_key_version=match.version AND subject_digest=decode(match.subject,'hex')`

const samlIDPLogoutCandidateSuffixSQL = `
 AND issued_at<=$5 AND expires_at>$5 LIMIT $6
 ) candidate LIMIT $6`

// Epoch microseconds avoid session TimeZone/DateStyle-dependent fingerprints.
// Hash the envelope on the server so the 128-row fence fits Work's 1 MiB budget
// even when every authenticated envelope reaches its 64 KiB storage limit.
const samlIDPLogoutRowDigestSQL = `sha256(convert_to(jsonb_build_array(
 tenant_id::text,organization_id,provider_id,user_id::text,session_id,family_id,
 encode(issuance_command_id,'hex'),issuance_purpose,
 (extract(epoch FROM issued_at)*1000000)::bigint,(extract(epoch FROM expires_at)*1000000)::bigint,
 match_key_version,encode(subject_digest,'hex'),encode(session_index_digest,'hex'),
 encode(sha256(subject_envelope),'hex'))::text,'UTF8'))`

const samlIDPLogoutLookupProjectionSQL = `SELECT tenant_id::text,organization_id,provider_id,user_id::text,session_id,family_id,
 issuance_command_id,issuance_purpose,issued_at,expires_at,match_key_version,subject_digest,session_index_digest,subject_envelope,` + samlIDPLogoutRowDigestSQL

const samlIDPLogoutFenceProjectionSQL = `SELECT session_id,` + samlIDPLogoutRowDigestSQL
const samlIDPLogoutExactIndexSQL = ` AND session_index_digest=decode(match.index,'hex')`

const lookupSAMLLogoutTargetsSQL = samlIDPLogoutLookupProjectionSQL + samlIDPLogoutCandidatePrefixSQL + samlIDPLogoutCandidateSuffixSQL
const lookupSAMLLogoutTargetsWithIndexSQL = samlIDPLogoutLookupProjectionSQL + samlIDPLogoutCandidatePrefixSQL + samlIDPLogoutExactIndexSQL + samlIDPLogoutCandidateSuffixSQL
const fenceSAMLLogoutTargetsSQL = samlIDPLogoutFenceProjectionSQL + samlIDPLogoutCandidatePrefixSQL + samlIDPLogoutCandidateSuffixSQL
const fenceSAMLLogoutTargetsWithIndexSQL = samlIDPLogoutFenceProjectionSQL + samlIDPLogoutCandidatePrefixSQL + samlIDPLogoutExactIndexSQL + samlIDPLogoutCandidateSuffixSQL

func (p samlIDPLogoutProbe) fenceSQL() string {
	if p.withIndex {
		return fenceSAMLLogoutTargetsWithIndexSQL
	}
	return fenceSAMLLogoutTargetsSQL
}

// requireInWork fences the complete authenticated lookup, including inactive
// sessions not selected for revocation. The caller owns exact feature authority
// and provider/domain locks. This helper performs no writes or decryption.
func (p samlIDPLogoutProbe) requireInWork(ctx context.Context, w kernel.Work, expected []samlIDPLogoutMatch) error {
	if err := providerLoginPayloadContext(ctx); err != nil {
		return err
	}
	if !p.valid() || len(expected) > samlLogoutTargetLimit {
		return identity.ForbiddenError{}
	}
	binding, err := w.Scope()
	if err != nil {
		return err
	}
	if string(binding.TenantID) != p.tenant {
		return identity.ForbiddenError{}
	}
	for n, match := range expected {
		a := match.Anchor
		if a.Tenant != p.tenant || a.Organization != p.organization || a.Provider != p.provider || !providerID(a.Session) ||
			match.RowDigest == ([32]byte{}) || n > 0 && expected[n-1].Anchor.Session >= a.Session {
			return identity.ForbiddenError{}
		}
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	rows, err := w.Query(ctx, p.fenceSQL(), p.bindings(now)...)
	if err != nil {
		return err
	}
	defer rows.Close()
	type rowFingerprint struct {
		session string
		digest  [32]byte
	}
	var current []rowFingerprint
	for rows.Next() {
		if len(current) == samlLogoutTargetLimit {
			return identity.ForbiddenError{}
		}
		var session string
		var digest []byte
		if err := rows.Scan(&session, &digest); err != nil {
			return err
		}
		if len(digest) != 32 {
			return identity.ForbiddenError{}
		}
		current = append(current, rowFingerprint{session, [32]byte(digest)})
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(current) != len(expected) {
		return identity.ForbiddenError{}
	}
	slices.SortFunc(current, func(a, b rowFingerprint) int { return strings.Compare(a.session, b.session) })
	for n, row := range current {
		if row.session != expected[n].Anchor.Session || row.digest != expected[n].RowDigest {
			return identity.ForbiddenError{}
		}
	}
	return nil
}
