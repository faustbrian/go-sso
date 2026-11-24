package postgres

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso/saml"
)

// Identity's bounded SAML logout command accepts at most 128 correlations.
// Read one extra row to reject an incomplete selection rather than truncate it.
const samlLogoutTargetLimit = 128

type samlIDPLogoutMatch struct {
	Anchor    samlLogoutIssuanceAnchor
	RowDigest [32]byte
}

type samlIDPLogoutProbeMAC struct {
	Version int64  `json:"version"`
	Subject string `json:"subject"`
	Index   string `json:"index,omitempty"`
}

// A prepared probe retains only scoped keyed digests, never the signed subject
// or XML. The same scalar JSON representation is accepted by kernel.Work.
type samlIDPLogoutProbe struct {
	tenant, organization, provider string
	macs                           string
	withIndex                      bool
}

func (c *SAMLLogoutSubjectCustody) prepareIDPLogoutProbe(tenant identity.TenantID, scope samlLogoutIssuerScope, request saml.LogoutPOSTRequestEvidence) (samlIDPLogoutProbe, error) {
	if c == nil || !providerLoginPayloadTenant(tenant) || !providerID(scope.organization) || !providerID(scope.provider) ||
		len(c.config.MatchKeys) == 0 || len(c.config.MatchKeys) > 32 {
		return samlIDPLogoutProbe{}, identity.ForbiddenError{}
	}
	subject := samlStoredLogoutSubject{
		ProviderSubject: request.ProviderSubject, SubjectFormat: request.SubjectFormat,
		NameQualifier: request.NameQualifier, SPNameQualifier: request.SPNameQualifier, SessionIndex: request.SessionIndex,
	}
	if !validSAMLLogoutStoredSubject(scope.issuer, subject) {
		return samlIDPLogoutProbe{}, identity.ForbiddenError{}
	}
	anchor := samlLogoutIssuanceAnchor{Tenant: string(tenant), Organization: scope.organization, Provider: scope.provider}
	macs := make([]samlIDPLogoutProbeMAC, 0, len(c.config.MatchKeys))
	for _, version := range slices.Sorted(maps.Keys(c.config.MatchKeys)) {
		prepared, err := c.matches(version, anchor, scope, &subject)
		if err != nil {
			return samlIDPLogoutProbe{}, err
		}
		mac := samlIDPLogoutProbeMAC{Version: int64(version), Subject: hex.EncodeToString(prepared.Subject[:])}
		if prepared.Index != nil {
			mac.Index = hex.EncodeToString(prepared.Index[:])
		}
		macs = append(macs, mac)
	}
	wire, err := json.Marshal(macs)
	if err != nil {
		return samlIDPLogoutProbe{}, identity.UnavailableError{}
	}
	return samlIDPLogoutProbe{tenant: string(tenant), organization: scope.organization, provider: scope.provider, macs: string(wire), withIndex: request.SessionIndex != ""}, nil
}

func (p samlIDPLogoutProbe) bindings(now time.Time) []any {
	return []any{p.tenant, p.organization, p.provider, p.macs, now, int64(samlLogoutTargetLimit + 1)}
}

func (p samlIDPLogoutProbe) lookupSQL() string {
	if p.withIndex {
		return lookupSAMLLogoutTargetsWithIndexSQL
	}
	return lookupSAMLLogoutTargetsSQL
}

func (p samlIDPLogoutProbe) valid() bool {
	return providerLoginPayloadTenant(identity.TenantID(p.tenant)) && providerID(p.organization) && providerID(p.provider) && p.macs != ""
}

// lookup authenticates original login custody, not current session authority.
// Rows are released before any sealed value is opened. The subject is checked
// again against the prepared MACs without retaining its plaintext in the probe.
func (p samlIDPLogoutProbe) lookup(ctx context.Context, pool *database.Pool, crypto *envelope.Service, c *SAMLLogoutSubjectCustody, now time.Time) ([]samlIDPLogoutMatch, error) {
	if err := providerLoginPayloadContext(ctx); err != nil {
		return nil, err
	}
	if !p.valid() || c == nil || pool == nil || pool.Raw() == nil || crypto == nil || now.IsZero() || now.Unix() <= 0 || now.Year() > 9999 {
		return nil, identity.ForbiddenError{}
	}
	rows, err := pool.Raw().Query(ctx, p.lookupSQL(), p.bindings(now)...)
	if err != nil {
		return nil, providerError(ctx, err)
	}
	defer rows.Close()
	var retained []samlLogoutSubjectRow
	var fingerprints [][32]byte
	defer func() {
		for _, row := range retained {
			clear(row.command)
			clear(row.subjectDigest)
			clear(row.indexDigest)
			clear(row.wire)
		}
	}()
	for rows.Next() {
		if len(retained) == samlLogoutTargetLimit {
			return nil, identity.ForbiddenError{}
		}
		retained = append(retained, samlLogoutSubjectRow{})
		row := &retained[len(retained)-1]
		a := &row.anchor
		var digest []byte
		if err := rows.Scan(&a.Tenant, &a.Organization, &a.Provider, &a.User, &a.Session, &a.Family,
			&row.command, &a.Purpose, &a.IssuedAt, &a.ExpiresAt, &row.keyVersion, &row.subjectDigest, &row.indexDigest, &row.wire, &digest); err != nil {
			return nil, providerError(ctx, err)
		}
		if len(digest) != 32 {
			return nil, identity.ForbiddenError{}
		}
		fingerprints = append(fingerprints, [32]byte(digest))
	}
	if err := rows.Err(); err != nil {
		return nil, providerError(ctx, err)
	}
	// Key providers may perform I/O. Release the database connection before
	// opening any sealed row, and reject overflow before that work begins.
	rows.Close()
	var matches []samlIDPLogoutMatch
	for n, row := range retained {
		anchor, scope, subject, err := c.openRow(ctx, crypto, identity.TenantID(p.tenant), row.anchor.Session, row)
		if err != nil {
			return nil, err
		}
		if !p.withIndex {
			subject.SessionIndex = ""
		}
		request := saml.LogoutPOSTRequestEvidence{ProviderSubject: subject.ProviderSubject, SubjectFormat: subject.SubjectFormat,
			NameQualifier: subject.NameQualifier, SPNameQualifier: subject.SPNameQualifier, SessionIndex: subject.SessionIndex}
		openedProbe, err := c.prepareIDPLogoutProbe(identity.TenantID(p.tenant), scope, request)
		if err != nil || openedProbe != p || anchor.IssuedAt.After(now) || !anchor.ExpiresAt.After(now) ||
			(len(matches) > 0 && anchor.User != matches[0].Anchor.User) {
			return nil, identity.ForbiddenError{}
		}
		matches = append(matches, samlIDPLogoutMatch{Anchor: anchor, RowDigest: fingerprints[n]})
	}
	if err := providerLoginPayloadContext(ctx); err != nil {
		return nil, err
	}
	slices.SortFunc(matches, func(a, b samlIDPLogoutMatch) int { return strings.Compare(a.Anchor.Session, b.Anchor.Session) })
	for n := 1; n < len(matches); n++ {
		if matches[n-1].Anchor.Session == matches[n].Anchor.Session {
			return nil, identity.ForbiddenError{}
		}
	}
	return matches, nil
}

// lookupTargets preserves the original authenticated-anchor lookup contract.
func (c *SAMLLogoutSubjectCustody) lookupTargets(ctx context.Context, pool *database.Pool, crypto *envelope.Service, tenant identity.TenantID, scope samlLogoutIssuerScope, request saml.LogoutPOSTRequestEvidence, now time.Time) ([]samlLogoutIssuanceAnchor, error) {
	probe, err := c.prepareIDPLogoutProbe(tenant, scope, request)
	if err != nil {
		return nil, err
	}
	matches, err := probe.lookup(ctx, pool, crypto, c, now)
	if err != nil {
		return nil, err
	}
	var anchors []samlLogoutIssuanceAnchor
	for _, match := range matches {
		anchors = append(anchors, match.Anchor)
	}
	return anchors, nil
}
