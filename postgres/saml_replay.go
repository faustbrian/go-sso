package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	samlACSOperation = "identity.sso.saml-acs"
	// REFERENCE_CONFIGURATION.md saml.replay_ttl: retain the raw assertion
	// expiry plus the reconciliation buffer, within this lifetime band.
	samlReplayBuffer  = 5 * time.Minute
	samlReplayMinimum = 10 * time.Minute
	samlReplayMaximum = 24 * time.Hour
)

// The authenticated preparation supplies the scope, ID digests and original
// retention cutoff. The coordinator must supply and check its own command
// fingerprint and generation before insertion. This is not protocol evidence
// or permission by itself, and raw SAML IDs never enter storage.
type samlReplayClaim struct {
	Tenant          identity.TenantID
	OrganizationID  string
	ProviderID      string
	IssuerDigest    [32]byte
	ResponseDigest  [32]byte
	AssertionDigest [32]byte
	Fingerprint     [32]byte
	CommandID       identity.CommandID
	Generation      uint64
	RetainUntil     time.Time
}

type samlReplayExec func(context.Context, string, ...any) (int64, error)
type samlReplayLookup func(context.Context, string, ...any) (bool, error)

// The entire pair is one plain INSERT. A conflict aborts both rows, not just
// the existing member. Do not add ON CONFLICT DO NOTHING: a second caller
// must never retain half a pair. Digest order is stable across roles so
// overlapping pairs do not invert the primary-key acquisition order.
const insertSAMLReplayPairSQL = `INSERT INTO sso_providers.saml_replay_members
 (tenant_id,organization_id,provider_id,issuer_digest,member_digest,member_kind,
 callback_command_id,execution_fingerprint,execution_generation,retain_until)
SELECT $1,$2,$3,$4,m.digest,m.kind,$5,$6,$7::text::identity.version,$8::timestamptz
FROM (VALUES ($9::bytea,1::smallint),($10::bytea,2::smallint)) AS m(digest,kind)
ORDER BY m.digest`

// Recovery must vote for the complete original pair, including the original
// cutoff. An absent or different member cannot prove commit. This read does
// not reclaim even an expired record, renew its lifetime or issue a session.
const observeSAMLReplayPairSQL = `SELECT count(*)=2
FROM sso_providers.saml_replay_members
WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND issuer_digest=$4
 AND callback_command_id=$5 AND execution_fingerprint=$6
 AND execution_generation=$7::text::identity.version AND retain_until=$8::timestamptz
 AND ((member_kind=1 AND member_digest=$9) OR (member_kind=2 AND member_digest=$10))`

// Derive once from the trusted original validation instant and the assertion's
// raw expiry, not from the earlier usable proof/certificate cutoff or a retry.
// Round up to PostgreSQL precision so serialization cannot shorten protection.
// An assertion outside the retention budget is not eligible for this profile.
func samlReplayRetainUntil(validatedAt, assertionExpiresAt time.Time) (time.Time, error) {
	if !validSAMLReplayTime(validatedAt) || !validSAMLReplayTime(assertionExpiresAt) {
		return time.Time{}, identity.InvalidInputError{Field: "saml_replay"}
	}
	expires := assertionExpiresAt.Add(samlReplayBuffer)
	if floor := validatedAt.Add(samlReplayMinimum); floor.After(expires) {
		expires = floor
	}
	expires = expires.UTC()
	if rounded := expires.Truncate(time.Microsecond); !rounded.Equal(expires) {
		expires = rounded.Add(time.Microsecond)
	}
	if !validSAMLReplayTime(expires) || expires.After(validatedAt.Add(samlReplayMaximum)) {
		return time.Time{}, identity.InvalidInputError{Field: "saml_replay"}
	}
	return expires, nil
}

func validSAMLReplayTime(value time.Time) bool {
	return !value.IsZero() && value.UTC().Year() >= 1 && value.UTC().Year() <= 9999
}

func (claim samlReplayClaim) bindings() ([]any, error) {
	if !providerID(string(claim.Tenant)) || !providerID(claim.OrganizationID) || !providerID(claim.ProviderID) ||
		claim.IssuerDigest == ([32]byte{}) || claim.ResponseDigest == ([32]byte{}) || claim.AssertionDigest == ([32]byte{}) ||
		claim.ResponseDigest == claim.AssertionDigest || claim.Fingerprint == ([32]byte{}) || claim.Generation == 0 ||
		!validSAMLReplayTime(claim.RetainUntil) || claim.RetainUntil.Nanosecond()%1000 != 0 {
		return nil, identity.InvalidInputError{Field: "saml_replay"}
	}
	if _, err := identity.ParseCommandID(string(claim.CommandID)); err != nil {
		return nil, identity.InvalidInputError{Field: "saml_replay"}
	}
	command, err := base64.RawURLEncoding.Strict().DecodeString(string(claim.CommandID))
	if err != nil || len(command) != 16 {
		return nil, identity.InvalidInputError{Field: "saml_replay"}
	}
	return []any{string(claim.Tenant), claim.OrganizationID, claim.ProviderID, claim.IssuerDigest[:],
		command, claim.Fingerprint[:], strconv.FormatUint(claim.Generation, 10), claim.RetainUntil.UTC(),
		claim.ResponseDigest[:], claim.AssertionDigest[:]}, nil
}

// Call only after current provider and browser admission and authenticated
// preparation on the exact SAML callback. The already open Work is the sole
// owner of rollback, commit and unknown-acknowledgement recovery.
func reserveSAMLReplayInWork(ctx context.Context, w kernel.Work, participant kernel.FeatureExecutionContributor, claim samlReplayClaim) error {
	binding, feature, _, err := w.FeatureScope(participant)
	if err != nil || feature.Operation.Owner != "sso/saml" || binding.OperationID != samlACSOperation ||
		binding.TenantID != claim.Tenant || binding.CommandID != claim.CommandID {
		return identity.ForbiddenError{}
	}
	_, fingerprint, generation, err := w.FeatureCommandIdentity(participant)
	if err != nil || fingerprint != claim.Fingerprint || generation != claim.Generation {
		return identity.ForbiddenError{}
	}
	return insertSAMLReplayPair(ctx, w.Exec, claim)
}

func insertSAMLReplayPair(ctx context.Context, exec samlReplayExec, claim samlReplayClaim) error {
	if ctx == nil || exec == nil {
		return identity.InvalidInputError{Field: "saml_replay"}
	}
	args, err := claim.bindings()
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	rows, err := exec(ctx, insertSAMLReplayPairSQL, args...)
	if err != nil {
		return samlReplayWriteFailure(ctx, err)
	}
	if rows != 2 {
		return identity.UnavailableError{}
	}
	return nil
}

func samlReplayWriteFailure(ctx context.Context, err error) error {
	if cancelled := ctx.Err(); cancelled != nil {
		return cancelled
	}
	// Only raw driver callers can observe the constraint name. The bounded
	// Work deliberately hides native diagnostics and already poisons the
	// transaction on a SQL error. Do not undo or reinterpret that failure.
	var native *pgconn.PgError
	if errors.As(err, &native) && native.Code == "23505" && native.TableName == "saml_replay_members" &&
		(native.ConstraintName == "saml_replay_member_scope_pkey" || native.ConstraintName == "saml_replay_command_member_key") {
		return identity.ConflictError{}
	}
	return identity.UnavailableError{}
}

// This is only a vote from the same exact fully bound prepared command during
// its owned recovery. Do not use it to create authority outside the kernel.
func observeSAMLReplayInRecovery(ctx context.Context, w kernel.RecoveryWork, participant kernel.FeatureExecutionContributor, claim samlReplayClaim) (bool, error) {
	binding, feature, _, err := w.FeatureScope(participant)
	if err != nil || feature.Operation.Owner != "sso/saml" || binding.OperationID != samlACSOperation ||
		binding.TenantID != claim.Tenant || binding.CommandID != claim.CommandID {
		return false, identity.ForbiddenError{}
	}
	return observeSAMLReplayPair(ctx, func(ctx context.Context, sql string, args ...any) (bool, error) {
		rows, err := w.Query(ctx, sql, args...)
		if err != nil {
			return false, err
		}
		defer rows.Close()
		var exact bool
		if !rows.Next() || rows.Scan(&exact) != nil || rows.Next() || rows.Err() != nil {
			return false, identity.UnavailableError{}
		}
		return exact, nil
	}, claim)
}

// The native negative recovery vote cannot ignore a partial or contradictory
// replay set. The existing command index bounds this lookup to two members.
const samlReplayCommandExistsSQL = `SELECT EXISTS(SELECT 1 FROM sso_providers.saml_replay_members
 WHERE tenant_id=$1 AND callback_command_id=$2)`

func verifySAMLReplayAbsentInRecovery(ctx context.Context, w kernel.RecoveryWork, participant kernel.FeatureExecutionContributor) (kernel.RecoveryStatus, error) {
	binding, feature, _, err := w.FeatureScope(participant)
	if err != nil || feature.Operation != kernel.SSOSAMLSigninOperation() {
		return kernel.RecoveryUnknown, identity.ForbiddenError{}
	}
	command, err := base64.RawURLEncoding.Strict().DecodeString(string(binding.CommandID))
	if err != nil || len(command) != 16 {
		return kernel.RecoveryUnknown, identity.ForbiddenError{}
	}
	rows, err := w.Query(ctx, samlReplayCommandExistsSQL, string(binding.TenantID), command)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	var exists bool
	if !rows.Next() || rows.Scan(&exists) != nil || rows.Next() || rows.Err() != nil {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	if exists {
		return kernel.RecoveryUnknown, nil
	}
	return kernel.RecoveryNotCommitted, nil
}

func observeSAMLReplayPair(ctx context.Context, lookup samlReplayLookup, claim samlReplayClaim) (bool, error) {
	if ctx == nil || lookup == nil {
		return false, identity.InvalidInputError{Field: "saml_replay"}
	}
	args, err := claim.bindings()
	if err != nil {
		return false, err
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	exact, err := lookup(ctx, observeSAMLReplayPairSQL, args...)
	if err != nil {
		if cancelled := ctx.Err(); cancelled != nil {
			return false, cancelled
		}
		return false, identity.UnavailableError{}
	}
	return exact, nil
}
