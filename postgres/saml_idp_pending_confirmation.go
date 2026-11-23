package postgres

import (
	"context"
	"encoding/base64"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func exactSAMLIDPPendingConfirmationScope(feature kernel.FeatureRegistration, lifecycle kernel.LifecyclePlan) bool {
	return feature.Operation == kernel.SSOSAMLIDPConfirmationOperation() &&
		feature.Contributor == (kernel.ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.saml-idp-confirmation", Version: 1}) &&
		lifecycle == (kernel.LifecyclePlan{EventType: "session.created.v1", BeforeVersion: 1, AfterVersion: 2})
}

// Read the clock only after locking the exact pending identity: UPDATE target
// expressions alone can be evaluated before waiting for a row lock. One instant
// then fences both the original cutoff and the retained completion timestamp.
const completeSAMLIDPPendingConfirmationSQL = `WITH locked_pending AS MATERIALIZED (
 SELECT tenant_id,confirmation_id FROM sso_providers.saml_idp_confirmations
 WHERE tenant_id=$1 AND confirmation_id=$2 FOR UPDATE
), completion AS MATERIALIZED (
 SELECT tenant_id,confirmation_id,clock_timestamp() AS completed_at FROM locked_pending
)
UPDATE sso_providers.saml_idp_confirmations AS pending
SET completion_command_id=$12,completed_at=completion.completed_at,
 binding_envelope=NULL,confirmation_key_version=NULL,browser_digest=NULL,form_digest=NULL
FROM completion
WHERE pending.tenant_id=completion.tenant_id AND pending.confirmation_id=completion.confirmation_id
 AND pending.tenant_id=$1 AND pending.confirmation_id=$2 AND pending.organization_id=$3 AND pending.provider_id=$4 AND pending.user_id=$5
 AND pending.binding_envelope=$6 AND pending.confirmation_key_version=$7 AND pending.browser_digest=$8 AND pending.form_digest=$9
 AND pending.issued_at=$10::timestamptz AND pending.expires_at=$11::timestamptz
 AND pending.completed_at IS NULL AND pending.completion_command_id IS NULL
 AND completion.completed_at>=$10::timestamptz AND completion.completed_at<$11::timestamptz`

func completeSAMLIDPPendingConfirmation(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, a samlIDPPendingArrival) error {
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return err
	}
	binding, feature, lifecycle, err := w.FeatureScope(owner)
	if err != nil || !exactSAMLIDPPendingConfirmationScope(feature, lifecycle) {
		return identity.ForbiddenError{}
	}
	consumed, err := w.SSOSAMLIDPConfirmationConsumption(owner)
	if err != nil || consumed.Command != binding {
		return identity.ForbiddenError{}
	}
	return writeSAMLIDPPendingConfirmation(ctx, w.Exec, binding, a)
}

func writeSAMLIDPPendingConfirmation(ctx context.Context, exec samlReplayExec, binding identity.CommandBinding, a samlIDPPendingArrival) error {
	if ctx == nil || exec == nil {
		return identity.InvalidInputError{Field: "saml_idp_pending_confirmation"}
	}
	if binding.ValidateFor(kernel.SSOSAMLIDPConfirmationOperation()) != nil || binding.ActorKind != authorization.SubjectServiceAccount ||
		binding.TenantID != a.Binding.TenantID || binding.UserID != a.Binding.UserID ||
		binding.RecordID != string(a.Binding.CommandID) || binding.CommandID == a.Binding.CommandID {
		return identity.ForbiddenError{}
	}
	args, err := a.bindings()
	if err != nil {
		return err
	}
	// ValidateFor establishes canonical, nonzero command identity before decode.
	completion, err := base64.RawURLEncoding.Strict().DecodeString(string(binding.CommandID))
	if err != nil || len(completion) != 16 {
		return identity.ForbiddenError{}
	}
	args = append(args, completion)
	if err := ctx.Err(); err != nil {
		return err
	}
	count, err := exec(ctx, completeSAMLIDPPendingConfirmationSQL, args...)
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
