// Package postgres persists encrypted SSO challenge custody and composes the
// existing organization-owned evidence transition. It is not a proof store,
// command journal, transaction coordinator or provider implementation.
package postgres

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	sso "github.com/faustbrian/go-sso"
	"github.com/jackc/pgx/v5"
)

// Config selects borrowed primary pool and envelope custody; retain decrypting
// keys while challenges or original command recovery remain supported. Apply
// DomainChallengeMigrationSource before enabling callers. No background work.
type Config struct {
	MaximumDuration time.Duration
	Envelope        *envelope.Service
	KeyReference    string
}

// Store owns encrypted challenge data and original safe recovery bindings only.
// Organization owns uniqueness, proof/lifecycle and every durable command result.
// Store is safe for concurrent use; the caller closes its borrowed pool.
type Store struct {
	pool   *database.Pool
	config Config
}

var _ sso.DomainChallengeStore = (*Store)(nil)

func NewStore(pool *database.Pool, c Config) (*Store, error) {
	if pool == nil || c.Envelope == nil || c.KeyReference == "" || len(c.KeyReference) > 256 || c.MaximumDuration <= 0 || c.MaximumDuration > time.Minute {
		return nil, sso.ErrInvalidInput
	}
	return &Store{pool: pool, config: c}, nil
}
func (Store) Format(s fmt.State, _ rune)   { _, _ = s.Write([]byte("sso.postgres.Store(redacted)")) }
func (Store) MarshalJSON() ([]byte, error) { return nil, sso.ErrSensitiveSerialization }
func (Store) MarshalText() ([]byte, error) { return nil, sso.ErrSensitiveSerialization }
func (Config) Format(s fmt.State, _ rune)  { _, _ = s.Write([]byte("sso.postgres.Config(redacted)")) }

func storeError(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return sso.ErrForbidden
	}
	for _, known := range []error{sso.ErrInvalidInput, sso.ErrForbidden, sso.ErrConflict, sso.ErrUnavailable, context.Canceled, context.DeadlineExceeded} {
		if errors.Is(err, known) {
			return known
		}
	}
	return sso.ErrUnavailable
}

func challengeContext(r sso.ChallengeRecord) (envelope.Context, error) {
	return envelope.NewContext(map[string]string{"owner": "sso/domain-challenge", "tenant": string(r.Claim.TenantID), "organization": string(r.Claim.OrganizationID), "claim": string(r.Claim.ID), "claim-version": "1", "domain": r.Claim.Domain, "actor": string(r.ActorID), "command": string(r.CommandID), "method": "dns-txt", "purpose": r.Purpose, "digest": r.ChallengeDigest, "issued": r.IssuedAt.UTC().Format(time.RFC3339Nano), "expires": r.ExpiresAt.UTC().Format(time.RFC3339Nano)})
}

func (s *Store) CreateDomainChallenge(ctx context.Context, r sso.ChallengeRecord) (sso.ChallengeRecord, error) {
	if s == nil || ctx == nil || r.Validate() != nil || len(r.Capability) == 0 || len(r.Capability) > 16<<10 || len(r.NetworkDigest) != 64 || r.CorrelationID == "" || len(r.CorrelationID) > 128 {
		return sso.ChallengeRecord{}, sso.ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	aad, e := challengeContext(r)
	if e != nil {
		return sso.ChallengeRecord{}, sso.ErrInvalidInput
	}
	plain := []byte(r.Capability)
	defer clear(plain)
	sealed, e := s.config.Envelope.Encrypt(bounded, envelope.EncryptRequest{Plaintext: plain, KeyReference: s.config.KeyReference, Context: aad})
	if e != nil {
		return sso.ChallengeRecord{}, storeError(bounded, e)
	}
	wire, e := sealed.MarshalBinary()
	if e != nil {
		return sso.ChallengeRecord{}, sso.ErrUnavailable
	}
	digest, e := hex.DecodeString(r.ChallengeDigest)
	if e != nil {
		return sso.ChallengeRecord{}, sso.ErrInvalidInput
	}
	network, e := hex.DecodeString(r.NetworkDigest)
	if e != nil {
		return sso.ChallengeRecord{}, sso.ErrInvalidInput
	}
	_, e = s.pool.Raw().Exec(bounded, `INSERT INTO sso.domain_challenges(tenant_id,organization_id,claim_id,actor_id,command_id,canonical_domain,challenge_digest,capability_envelope,network_digest,correlation_id,issued_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT DO NOTHING`, string(r.Claim.TenantID), string(r.Claim.OrganizationID), string(r.Claim.ID), string(r.ActorID), string(r.CommandID), r.Claim.Domain, digest, wire, network, r.CorrelationID, r.IssuedAt, r.ExpiresAt)
	if e != nil {
		return sso.ChallengeRecord{}, storeError(bounded, e)
	}
	state, e := s.LoadDomainChallenge(bounded, r.Key())
	if e != nil {
		return sso.ChallengeRecord{}, e
	}
	saved := state.Challenge
	if saved.Claim != r.Claim || saved.ActorID != r.ActorID || saved.CommandID != r.CommandID || saved.Method != r.Method || saved.Purpose != r.Purpose || saved.CorrelationID != r.CorrelationID || saved.NetworkDigest != r.NetworkDigest {
		return sso.ChallengeRecord{}, sso.ErrConflict
	}
	return saved, nil
}

func (s *Store) LoadDomainChallenge(ctx context.Context, key sso.DomainChallengeKey) (sso.DomainChallengeState, error) {
	if s == nil || ctx == nil || len(key.TenantID) < 1 || len(key.TenantID) > 128 || len(key.OrganizationID) < 1 || len(key.OrganizationID) > 128 || len(key.ClaimID) < 1 || len(key.ClaimID) > 128 {
		return sso.DomainChallengeState{}, sso.ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	r := sso.ChallengeRecord{Claim: organization.DomainClaim{TenantID: key.TenantID, OrganizationID: key.OrganizationID, ID: key.ClaimID, Version: 1, State: organization.DomainRequested}, Method: sso.DomainProofDNS, Purpose: "identity.sso.domain-verify"}
	var actor, command string
	var digest, wire, network, recovery []byte
	e := s.pool.Raw().QueryRow(bounded, `SELECT actor_id::text,command_id,canonical_domain,challenge_digest,capability_envelope,network_digest,correlation_id,issued_at,expires_at,recovery FROM sso.domain_challenges WHERE tenant_id=$1 AND organization_id=$2 AND claim_id=$3`, string(key.TenantID), string(key.OrganizationID), string(key.ClaimID)).Scan(&actor, &command, &r.Claim.Domain, &digest, &wire, &network, &r.CorrelationID, &r.IssuedAt, &r.ExpiresAt, &recovery)
	if e != nil {
		return sso.DomainChallengeState{}, storeError(bounded, e)
	}
	r.ActorID = identity.UserID(actor)
	r.CommandID = identity.CommandID(command)
	r.IssuedAt = r.IssuedAt.UTC().Truncate(time.Microsecond)
	r.ExpiresAt = r.ExpiresAt.UTC().Truncate(time.Microsecond)
	r.ChallengeDigest = hex.EncodeToString(digest)
	r.NetworkDigest = hex.EncodeToString(network)
	if r.Validate() != nil || len(wire) > 64<<10 || len(recovery) > 4096 {
		return sso.DomainChallengeState{}, sso.ErrUnavailable
	}
	sealed, e := envelope.ParseEnvelope(wire)
	if e != nil {
		return sso.DomainChallengeState{}, sso.ErrUnavailable
	}
	aad, e := challengeContext(r)
	if e != nil {
		return sso.DomainChallengeState{}, sso.ErrUnavailable
	}
	plain, e := s.config.Envelope.Decrypt(bounded, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	if e != nil {
		return sso.DomainChallengeState{}, storeError(bounded, e)
	}
	defer clear(plain)
	if len(plain) == 0 || len(plain) > 16<<10 {
		return sso.DomainChallengeState{}, sso.ErrUnavailable
	}
	r.Capability = string(plain)
	state := sso.DomainChallengeState{Challenge: r}
	if len(recovery) > 0 {
		if e = json.Unmarshal(recovery, &state.Recovery); e != nil || !validRecovery(r, state.Recovery) {
			return sso.DomainChallengeState{}, sso.ErrUnavailable
		}
	}
	return state, nil
}

func validRecovery(r sso.ChallengeRecord, b identity.CommandBinding) bool {
	return b.ValidateFor(organization.ApplyDomainProof.Descriptor()) == nil && b.CommandID == r.CommandID && b.TenantID == r.Claim.TenantID && b.ActorID == identity.ActorID(r.ActorID) && b.UserID == r.ActorID && b.RecordID == string(r.Claim.OrganizationID) && b.CorrelationID == r.CorrelationID
}

func (s *Store) SaveDomainRecovery(ctx context.Context, key sso.DomainChallengeKey, b identity.CommandBinding) error {
	if s == nil || ctx == nil {
		return sso.ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	state, e := s.LoadDomainChallenge(bounded, key)
	if e != nil {
		return e
	}
	if !validRecovery(state.Challenge, b) {
		return sso.ErrInvalidInput
	}
	wire, e := json.Marshal(b)
	if e != nil || len(wire) > 4096 {
		return sso.ErrInvalidInput
	}
	updated, e := s.pool.Raw().Exec(bounded, `UPDATE sso.domain_challenges SET recovery=$4::jsonb WHERE tenant_id=$1 AND organization_id=$2 AND claim_id=$3 AND (recovery IS NULL OR recovery=$4::jsonb)`, string(key.TenantID), string(key.OrganizationID), string(key.ClaimID), wire)
	if e != nil {
		return storeError(bounded, e)
	}
	if updated.RowsAffected() != 1 {
		return sso.ErrConflict
	}
	return nil
}

// DomainEvidenceFactory binds the existing native organization facade. It owns
// no coordinator/transaction and cannot replace its trusted observer or grant.
type DomainEvidenceFactory struct{ service *organizationpg.Service }

var _ sso.DomainEvidenceFactory = (*DomainEvidenceFactory)(nil)

func NewDomainEvidenceFactory(service *organizationpg.Service) (*DomainEvidenceFactory, error) {
	if service == nil {
		return nil, sso.ErrInvalidInput
	}
	return &DomainEvidenceFactory{service: service}, nil
}
func (f *DomainEvidenceFactory) DomainEvidence(authentication organization.Authentication, network string, recovery identity.CommandBinding) (sso.DomainEvidenceAuthority, error) {
	if f == nil || f.service == nil {
		return nil, sso.ErrInvalidInput
	}
	if recovery == (identity.CommandBinding{}) {
		return f.service.DomainEvidence(authentication, network)
	}
	return f.service.DomainEvidence(authentication, network, organizationpg.Recovery{Binding: recovery})
}

// DomainChallengeMigrationSource creates only new SSO-owned objects. Apply it
// before enabling the DNS profile; existing organization/identity tables are not
// altered or locked. Rollback disables code but retains challenge/recovery data.
// Cleanup/deletion and additional SSO profiles are deliberately not selected.
type DomainChallengeMigrationSource struct{ Version migrations.Version }

func (s DomainChallengeMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, sso.ErrInvalidInput
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	m, e := migrations.NewMigration(s.Version, "sso_domain_challenges", migrations.TransactionModeDefault, domainChallengeSQL, "")
	if e != nil {
		return nil, sso.ErrUnavailable
	}
	return []migrations.Migration{m}, nil
}

const domainChallengeSQL = `CREATE SCHEMA sso;
CREATE TABLE sso.domain_challenges(
 tenant_id text COLLATE "C" NOT NULL CHECK(octet_length(tenant_id) BETWEEN 1 AND 128),
 organization_id text COLLATE "C" NOT NULL CHECK(octet_length(organization_id) BETWEEN 1 AND 128),
 claim_id text COLLATE "C" NOT NULL CHECK(octet_length(claim_id) BETWEEN 1 AND 128),
 actor_id text COLLATE "C" NOT NULL CHECK(octet_length(actor_id) BETWEEN 1 AND 128),
 command_id text COLLATE "C" NOT NULL UNIQUE CHECK(octet_length(command_id)=22),
 canonical_domain text COLLATE "C" NOT NULL CHECK(octet_length(canonical_domain) BETWEEN 3 AND 253),
 challenge_digest bytea NOT NULL CHECK(octet_length(challenge_digest)=32),
 capability_envelope bytea NOT NULL CHECK(octet_length(capability_envelope) BETWEEN 1 AND 65536),
 network_digest bytea NOT NULL CHECK(octet_length(network_digest)=32),
 correlation_id text NOT NULL CHECK(octet_length(correlation_id) BETWEEN 1 AND 128),
 issued_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL CHECK(expires_at>issued_at AND expires_at<=issued_at+interval '24 hours'),
 recovery jsonb CHECK(recovery IS NULL OR octet_length(recovery::text)<=4096),
 PRIMARY KEY(tenant_id,organization_id,claim_id)
);`
