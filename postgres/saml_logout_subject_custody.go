package postgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log/slog"
	"maps"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
)

const samlLogoutSubjectEnvelopeLimit = 65536

// SAMLLogoutSubjectCustodyConfig selects one encryption key reference and a
// bounded set of purpose-specific subject match keys shared by the SAML owners.
// Keep retained versions until their original session correlation expires.
type SAMLLogoutSubjectCustodyConfig struct {
	KeyReference    string
	CurrentMatchKey uint32
	MatchKeys       map[uint32][32]byte
}

func (SAMLLogoutSubjectCustodyConfig) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprint(f, "sso.postgres.SAMLLogoutSubjectCustodyConfig(redacted)")
}

func (SAMLLogoutSubjectCustodyConfig) LogValue() slog.Value {
	return slog.StringValue("sso.postgres.SAMLLogoutSubjectCustodyConfig(redacted)")
}

func (SAMLLogoutSubjectCustodyConfig) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}

func (SAMLLogoutSubjectCustodyConfig) MarshalText() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}

// SAMLLogoutSubjectCustody is an immutable policy for retaining original
// signed subject context. It does not grant or create session authority.
type SAMLLogoutSubjectCustody struct {
	config SAMLLogoutSubjectCustodyConfig
}

// NewSAMLLogoutSubjectCustody validates and snapshots the caller's retained
// keys. It never performs I/O or installs a migration. Configure the same
// subject custody policy for every selected writer and lookup on a provider.
func NewSAMLLogoutSubjectCustody(c SAMLLogoutSubjectCustodyConfig) (*SAMLLogoutSubjectCustody, error) {
	if !providerID(c.KeyReference) || c.CurrentMatchKey == 0 || len(c.MatchKeys) == 0 || len(c.MatchKeys) > 32 || c.MatchKeys[c.CurrentMatchKey] == ([32]byte{}) {
		return nil, sso.ErrInvalidInput
	}
	seen := make(map[[32]byte]bool, len(c.MatchKeys))
	for version, key := range c.MatchKeys {
		if version == 0 || key == ([32]byte{}) || seen[key] {
			return nil, sso.ErrInvalidInput
		}
		seen[key] = true
	}
	c.MatchKeys = maps.Clone(c.MatchKeys)
	return &SAMLLogoutSubjectCustody{config: c}, nil
}

func (SAMLLogoutSubjectCustody) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprint(f, "sso.postgres.SAMLLogoutSubjectCustody(redacted)")
}

func (SAMLLogoutSubjectCustody) LogValue() slog.Value {
	return slog.StringValue("sso.postgres.SAMLLogoutSubjectCustody(redacted)")
}

func (SAMLLogoutSubjectCustody) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}

func (SAMLLogoutSubjectCustody) MarshalText() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}

type samlLogoutIssuerScope struct{ organization, provider, issuer string }

type samlLogoutIssuanceAnchor struct {
	Tenant, Organization, Provider, User, Session, Family string
	Purpose, Command                                      string
	IssuedAt, ExpiresAt                                   time.Time
}

// Only private authenticated preparation may serialize this. It contains no
// plaintext provider subject and no bearer/session or signing key material.
type samlPreparedLogoutSubject struct {
	KeyVersion uint32
	Subject    [32]byte
	Index      *[32]byte `json:",omitempty"`
	Envelope   []byte
}

func samlLogoutSubjectAnchor(b identity.CommandBinding, s session.Session, scope samlLogoutIssuerScope) (samlLogoutIssuanceAnchor, error) {
	op := kernel.SSOSAMLSigninOperation()
	if b.OperationID == kernel.SSOSAMLIDPConfirmationOperation().OperationID {
		op = kernel.SSOSAMLIDPConfirmationOperation()
	}
	record, err := s.Bindings()
	if err != nil || b.ValidateFor(op) != nil || record.TenantID != b.TenantID || record.Version != 1 ||
		b.UserID != "" && record.UserID != b.UserID || string(record.Authentication.Proof.ID) != string(b.CommandID) ||
		record.Authentication.Proof.Method != "sso-saml" || !providerID(scope.provider) || !providerID(scope.organization) || len(scope.issuer) == 0 || len(scope.issuer) > 2048 {
		return samlLogoutIssuanceAnchor{}, identity.ForbiddenError{}
	}
	authority, err := record.Authority.Bindings()
	if err != nil || !authority.Organization.Present || authority.ActiveOrganizationID != scope.organization {
		return samlLogoutIssuanceAnchor{}, identity.ForbiddenError{}
	}
	lifetime, err := s.Lifetime(record.LastActivityAt)
	if err != nil || !lifetime.AbsoluteExpiresAt.After(record.IssuedAt) {
		return samlLogoutIssuanceAnchor{}, identity.ForbiddenError{}
	}
	return samlLogoutIssuanceAnchor{
		Tenant: string(record.TenantID), Organization: scope.organization, Provider: scope.provider, User: string(record.UserID),
		Session: record.SessionID, Family: record.FamilyID, Purpose: op.OperationID, Command: string(b.CommandID),
		IssuedAt: record.IssuedAt.UTC().Truncate(time.Microsecond), ExpiresAt: lifetime.AbsoluteExpiresAt.UTC().Truncate(time.Microsecond),
	}, nil
}

func samlLogoutMatchDigest(key [32]byte, parts ...string) [32]byte {
	h := hmac.New(sha256.New, key[:])
	var size [binary.MaxVarintLen64]byte
	for _, part := range parts {
		n := binary.PutUvarint(size[:], uint64(len(part)))
		_, _ = h.Write(size[:n])
		_, _ = h.Write([]byte(part))
	}
	var digest [32]byte
	_ = h.Sum(digest[:0])
	return digest
}

func (c *SAMLLogoutSubjectCustody) matches(version uint32, anchor samlLogoutIssuanceAnchor, scope samlLogoutIssuerScope, subject *samlStoredLogoutSubject) (samlPreparedLogoutSubject, error) {
	if c == nil || subject == nil {
		return samlPreparedLogoutSubject{}, identity.ForbiddenError{}
	}
	key := c.config.MatchKeys[version]
	if key == ([32]byte{}) {
		return samlPreparedLogoutSubject{}, identity.ForbiddenError{}
	}
	out := samlPreparedLogoutSubject{KeyVersion: version}
	out.Subject = samlLogoutMatchDigest(key, "saml-logout-subject-v1", anchor.Tenant, anchor.Organization, anchor.Provider, scope.issuer,
		subject.ProviderSubject, subject.SubjectFormat, subject.NameQualifier, subject.SPNameQualifier)
	if subject.SessionIndex != "" {
		index := samlLogoutMatchDigest(key, "saml-logout-session-index-v1", anchor.Tenant, anchor.Organization, anchor.Provider, scope.issuer, subject.SessionIndex)
		out.Index = &index
	}
	return out, nil
}

func (c *SAMLLogoutSubjectCustody) prepare(ctx context.Context, crypto *envelope.Service, anchor samlLogoutIssuanceAnchor, scope samlLogoutIssuerScope, subject *samlStoredLogoutSubject) (*samlPreparedLogoutSubject, error) {
	if ctx == nil || c == nil || crypto == nil {
		return nil, identity.ForbiddenError{}
	}
	out, err := c.matches(c.config.CurrentMatchKey, anchor, scope, subject)
	if err != nil {
		return nil, err
	}
	aad, err := samlLogoutSubjectAAD(anchor, out)
	if err != nil {
		return nil, err
	}
	plain, err := providerLoginPayloadEncode(struct {
		Issuer  string
		Subject samlStoredLogoutSubject
	}{scope.issuer, *subject})
	defer clear(plain)
	if err != nil || len(plain) > providerLoginCallbackPlainLimit {
		return nil, identity.UnavailableError{}
	}
	payload := providerLoginPayloadConfig{Envelope: crypto, KeyReference: c.config.KeyReference}
	out.Envelope, err = payload.seal(ctx, aad, plain, samlLogoutSubjectEnvelopeLimit)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func samlLogoutSubjectAAD(anchor samlLogoutIssuanceAnchor, subject samlPreparedLogoutSubject) (envelope.Context, error) {
	subject.Envelope = nil
	wire, err := providerLoginPayloadEncode(struct {
		Anchor  samlLogoutIssuanceAnchor
		Subject samlPreparedLogoutSubject
	}{anchor, subject})
	defer clear(wire)
	if err != nil {
		return envelope.Context{}, identity.UnavailableError{}
	}
	digest := sha256.Sum256(wire)
	return envelope.NewContext(map[string]string{"owner": "sso/postgres", "purpose": "saml-logout-subject-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}

func (c *SAMLLogoutSubjectCustody) validatePrepared(prepared *samlPreparedLogoutSubject, anchor samlLogoutIssuanceAnchor, scope samlLogoutIssuerScope, subject *samlStoredLogoutSubject) error {
	if prepared == nil || len(prepared.Envelope) == 0 || len(prepared.Envelope) > samlLogoutSubjectEnvelopeLimit {
		return identity.ForbiddenError{}
	}
	want, err := c.matches(prepared.KeyVersion, anchor, scope, subject)
	if err != nil || !hmac.Equal(prepared.Subject[:], want.Subject[:]) || (prepared.Index == nil) != (want.Index == nil) ||
		want.Index != nil && !hmac.Equal(prepared.Index[:], want.Index[:]) {
		return identity.ForbiddenError{}
	}
	return nil
}

const insertSAMLLogoutSubjectSQL = `INSERT INTO sso_providers.saml_logout_subjects
 (tenant_id,organization_id,provider_id,user_id,session_id,family_id,issuance_command_id,issuance_purpose,
 issued_at,expires_at,match_key_version,subject_digest,session_index_digest,subject_envelope)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`

const samlLogoutSubjectExistsSQL = `SELECT EXISTS(SELECT 1 FROM sso_providers.saml_logout_subjects
 WHERE tenant_id=$1 AND issuance_command_id=$2)`

func persistSAMLLogoutSubject(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, anchor samlLogoutIssuanceAnchor, prepared *samlPreparedLogoutSubject) error {
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return err
	}
	b, _, _, err := w.FeatureScope(owner)
	if err != nil || prepared == nil || string(b.TenantID) != anchor.Tenant || b.OperationID != anchor.Purpose || string(b.CommandID) != anchor.Command {
		return identity.ForbiddenError{}
	}
	// SP ACS is still an anonymous-flow command. Its exact linked user is
	// carried by the account proof already fenced by the session effect.
	user := b.UserID
	if b.OperationID == kernel.SSOSAMLSigninOperation().OperationID {
		account, err := kernel.SSOSAMLSigninAccount(command)
		if err != nil || account.Account.TenantID != b.TenantID {
			return identity.ForbiddenError{}
		}
		user = account.Account.UserID
	}
	if user == "" || string(user) != anchor.User {
		return identity.ForbiddenError{}
	}
	commandID, err := base64.RawURLEncoding.Strict().DecodeString(anchor.Command)
	if err != nil || len(commandID) != 16 {
		return identity.ForbiddenError{}
	}
	var index []byte
	if prepared.Index != nil {
		index = prepared.Index[:]
	}
	n, err := w.Exec(ctx, insertSAMLLogoutSubjectSQL, anchor.Tenant, anchor.Organization, anchor.Provider, anchor.User, anchor.Session, anchor.Family,
		commandID, anchor.Purpose, anchor.IssuedAt, anchor.ExpiresAt, int64(prepared.KeyVersion), prepared.Subject[:], index, prepared.Envelope)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.UnavailableError{}
	}
	return nil
}

// Only the original owning Work may vote. Any row contradicts an inferred
// rollback; it is never enough to prove a successful session without its journal.
func recoverSAMLLogoutSubjectAbsence(ctx context.Context, w kernel.RecoveryWork, owner kernel.FeatureExecutionContributor) (kernel.RecoveryStatus, error) {
	b, f, _, err := w.FeatureScope(owner)
	if err != nil || (f.Operation != kernel.SSOSAMLSigninOperation() && f.Operation != kernel.SSOSAMLIDPConfirmationOperation()) {
		return kernel.RecoveryUnknown, identity.ForbiddenError{}
	}
	command, err := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if err != nil || len(command) != 16 {
		return kernel.RecoveryUnknown, identity.ForbiddenError{}
	}
	rows, err := w.Query(ctx, samlLogoutSubjectExistsSQL, string(b.TenantID), command)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	var exists bool
	if !rows.Next() || rows.Scan(&exists) != nil || rows.Next() || rows.Err() != nil || exists {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	return kernel.RecoveryNotCommitted, nil
}
