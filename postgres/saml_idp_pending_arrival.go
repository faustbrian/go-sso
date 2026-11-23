package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	"github.com/faustbrian/go-sso"
)

// This is original encrypted confirmation custody, not browser possession,
// permission to decrypt, an SP login transaction or a prospective session.
type samlIDPPendingArrival struct {
	Binding                   identity.CommandBinding
	Organization              organization.ID
	Provider                  sso.ProviderID
	Envelope                  []byte
	KeyVersion                uint32
	BrowserDigest, FormDigest [32]byte
	IssuedAt, ExpiresAt       time.Time
}

func samlIDPPendingArrivalOperation() identity.FeatureOperation {
	return kernel.SSOSAMLIDPArrivalOperation()
}

func exactSAMLIDPPendingArrivalScope(feature kernel.FeatureRegistration, lifecycle kernel.LifecyclePlan) bool {
	return feature.Operation == samlIDPPendingArrivalOperation() &&
		feature.Contributor == (kernel.ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.saml-idp-arrival", Version: 1}) &&
		lifecycle == (kernel.LifecyclePlan{EventType: "sso.saml_confirmation.created.v1", BeforeVersion: 0, AfterVersion: 1})
}

func (a samlIDPPendingArrival) bindings() ([]any, error) {
	if a.Binding.ValidateFor(samlIDPPendingArrivalOperation()) != nil || a.Binding.RecordID != string(a.Binding.CommandID) ||
		!providerID(string(a.Organization)) || !providerID(string(a.Provider)) || len(a.Envelope) == 0 || len(a.Envelope) > 65536 ||
		a.KeyVersion == 0 || a.BrowserDigest == ([32]byte{}) || a.FormDigest == ([32]byte{}) || a.BrowserDigest == a.FormDigest ||
		!validSAMLReplayTime(a.IssuedAt) || !validSAMLReplayTime(a.ExpiresAt) ||
		a.IssuedAt.Nanosecond()%1000 != 0 || a.ExpiresAt.Nanosecond()%1000 != 0 ||
		!a.ExpiresAt.After(a.IssuedAt) || a.ExpiresAt.After(a.IssuedAt.Add(5*time.Minute)) {
		return nil, identity.InvalidInputError{Field: "saml_idp_pending_arrival"}
	}
	// ValidateFor establishes canonical, nonzero command identity before decode.
	command, err := base64.RawURLEncoding.Strict().DecodeString(string(a.Binding.CommandID))
	if err != nil || len(command) != 16 {
		return nil, identity.InvalidInputError{Field: "saml_idp_pending_arrival"}
	}
	return []any{string(a.Binding.TenantID), command, string(a.Organization), string(a.Provider), string(a.Binding.UserID),
		a.Envelope, int64(a.KeyVersion), a.BrowserDigest[:], a.FormDigest[:], a.IssuedAt.UTC(), a.ExpiresAt.UTC()}, nil
}

// After process loss the original binding alone permits only an absence vote.
// Do not accept partial custody as a substitute for the full expected arrival.
func (a samlIDPPendingArrival) recoveryBindings() ([]any, bool, error) {
	originOnly := a.Organization == "" && a.Provider == "" && a.Envelope == nil && a.KeyVersion == 0 &&
		a.BrowserDigest == ([32]byte{}) && a.FormDigest == ([32]byte{}) &&
		a.IssuedAt == (time.Time{}) && a.ExpiresAt == (time.Time{})
	if !originOnly {
		args, err := a.bindings()
		if err != nil {
			return nil, false, err
		}
		return args[:2], false, nil
	}
	if a.Binding.ValidateFor(samlIDPPendingArrivalOperation()) != nil || a.Binding.RecordID != string(a.Binding.CommandID) {
		return nil, false, identity.InvalidInputError{Field: "saml_idp_pending_arrival"}
	}
	command, err := base64.RawURLEncoding.Strict().DecodeString(string(a.Binding.CommandID))
	if err != nil || len(command) != 16 {
		return nil, false, identity.InvalidInputError{Field: "saml_idp_pending_arrival"}
	}
	return []any{string(a.Binding.TenantID), command}, true, nil
}

// SAMLIDPConfirmationMigrationSource fixes the five-minute original lifetime.
// Check the SQL clock in Apply so time spent awaiting Work cannot renew it.
// A conflict must abort this command; there is no upsert or partial success.
const insertSAMLIDPPendingArrivalSQL = `INSERT INTO sso_providers.saml_idp_confirmations
 (tenant_id,confirmation_id,organization_id,provider_id,user_id,binding_envelope,
 confirmation_key_version,browser_digest,form_digest,issued_at,expires_at)
SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10::timestamptz,$11::timestamptz
WHERE clock_timestamp()>=$10::timestamptz AND clock_timestamp()<$11::timestamptz`

func insertSAMLIDPPendingArrival(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, a samlIDPPendingArrival) error {
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return err
	}
	binding, feature, lifecycle, err := w.FeatureScope(owner)
	if err != nil || binding != a.Binding || !exactSAMLIDPPendingArrivalScope(feature, lifecycle) {
		return identity.ForbiddenError{}
	}
	return writeSAMLIDPPendingArrival(ctx, w.Exec, a)
}

func writeSAMLIDPPendingArrival(ctx context.Context, exec samlReplayExec, a samlIDPPendingArrival) error {
	if ctx == nil || exec == nil {
		return identity.InvalidInputError{Field: "saml_idp_pending_arrival"}
	}
	args, err := a.bindings()
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	count, err := exec(ctx, insertSAMLIDPPendingArrivalSQL, args...)
	if err != nil {
		return samlIDPPendingArrivalFailure(ctx)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if count == 0 {
		return identity.ForbiddenError{}
	}
	if count != 1 {
		return identity.UnavailableError{}
	}
	return nil
}

// Scope predicates belong in classification, not WHERE: an existing but
// conflicting primary key must remain Unknown rather than prove absence.
const observeSAMLIDPPendingArrivalSQL = `SELECT organization_id,provider_id,user_id,
 binding_envelope,confirmation_key_version,browser_digest,form_digest,
 issued_at,expires_at,completed_at,completion_command_id
FROM sso_providers.saml_idp_confirmations WHERE tenant_id=$1 AND confirmation_id=$2`

type samlIDPPendingArrivalRow struct {
	Organization, Provider, User string
	Envelope                     []byte
	KeyVersion                   *int64
	BrowserDigest, FormDigest    []byte
	IssuedAt, ExpiresAt          time.Time
	CompletedAt                  *time.Time
	CompletionCommand            []byte
}

// Recovery is only a participant vote under the kernel's original fenced
// command. Exact terminal erasure retains arrival evidence but never restores
// the encrypted binding or discloses browser/form possession material.
func observeSAMLIDPPendingArrival(ctx context.Context, w kernel.RecoveryWork, owner kernel.FeatureExecutionContributor, a samlIDPPendingArrival) (kernel.RecoveryStatus, error) {
	if ctx == nil {
		return kernel.RecoveryUnknown, identity.InvalidInputError{Field: "saml_idp_pending_arrival"}
	}
	binding, feature, lifecycle, err := w.FeatureScope(owner)
	if err != nil || binding != a.Binding || !exactSAMLIDPPendingArrivalScope(feature, lifecycle) {
		return kernel.RecoveryUnknown, identity.ForbiddenError{}
	}
	args, originOnly, err := a.recoveryBindings()
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	if err := ctx.Err(); err != nil {
		return kernel.RecoveryUnknown, err
	}
	rows, err := w.Query(ctx, observeSAMLIDPPendingArrivalSQL, args...)
	if err != nil {
		return kernel.RecoveryUnknown, samlIDPPendingArrivalFailure(ctx)
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil || ctx.Err() != nil {
			return kernel.RecoveryUnknown, samlIDPPendingArrivalFailure(ctx)
		}
		return kernel.RecoveryNotCommitted, nil
	}
	if originOnly {
		rows.Close()
		if rows.Err() != nil || ctx.Err() != nil {
			return kernel.RecoveryUnknown, samlIDPPendingArrivalFailure(ctx)
		}
		return kernel.RecoveryUnknown, nil
	}
	var row samlIDPPendingArrivalRow
	err = rows.Scan(&row.Organization, &row.Provider, &row.User, &row.Envelope, &row.KeyVersion,
		&row.BrowserDigest, &row.FormDigest, &row.IssuedAt, &row.ExpiresAt, &row.CompletedAt, &row.CompletionCommand)
	if err != nil || rows.Next() || rows.Err() != nil || ctx.Err() != nil {
		return kernel.RecoveryUnknown, samlIDPPendingArrivalFailure(ctx)
	}
	return classifySAMLIDPPendingArrivalRow(a, row), nil
}

func classifySAMLIDPPendingArrivalRow(a samlIDPPendingArrival, row samlIDPPendingArrivalRow) kernel.RecoveryStatus {
	if row.Organization != string(a.Organization) || row.Provider != string(a.Provider) || row.User != string(a.Binding.UserID) ||
		!row.IssuedAt.Equal(a.IssuedAt) || !row.ExpiresAt.Equal(a.ExpiresAt) {
		return kernel.RecoveryUnknown
	}
	if row.CompletedAt == nil {
		if row.CompletionCommand != nil || row.KeyVersion == nil || *row.KeyVersion != int64(a.KeyVersion) ||
			!bytes.Equal(row.Envelope, a.Envelope) || !bytes.Equal(row.BrowserDigest, a.BrowserDigest[:]) || !bytes.Equal(row.FormDigest, a.FormDigest[:]) {
			return kernel.RecoveryUnknown
		}
		return kernel.RecoveryCommitted
	}
	command, err := base64.RawURLEncoding.Strict().DecodeString(string(a.Binding.CommandID))
	var zeroCommand [16]byte
	if err != nil || len(row.CompletionCommand) != 16 || bytes.Equal(row.CompletionCommand, zeroCommand[:]) || bytes.Equal(row.CompletionCommand, command) ||
		!validSAMLReplayTime(*row.CompletedAt) || row.CompletedAt.Nanosecond()%1000 != 0 ||
		row.CompletedAt.Before(a.IssuedAt) || !row.CompletedAt.Before(a.ExpiresAt) ||
		row.Envelope != nil || row.KeyVersion != nil || row.BrowserDigest != nil || row.FormDigest != nil {
		return kernel.RecoveryUnknown
	}
	return kernel.RecoveryCommitted
}

func samlIDPPendingArrivalFailure(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return identity.UnavailableError{}
}
