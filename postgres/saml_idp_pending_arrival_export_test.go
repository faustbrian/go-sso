package postgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

const SAMLIDPInsertPendingForTest = insertSAMLIDPPendingArrivalSQL
const SAMLIDPObservePendingForTest = observeSAMLIDPPendingArrivalSQL

// ReserveSAMLIDPArrivalWithoutApplyingForTest models interruption between the
// existing reservation and Apply without publishing a production fault seam.
func ReserveSAMLIDPArrivalWithoutApplyingForTest(ctx context.Context, s *ProviderSAMLIDPArrivalService, request SAMLIDPAdmissionRequest) (identity.RecoveryQuery, kernel.CapabilityPlan, error) {
	var q identity.RecoveryQuery
	a, err := s.admission.VerifyLinkedRecipient(ctx, request)
	if err != nil {
		return q, kernel.CapabilityPlan{}, err
	}
	p, _, err := s.prepareArrival(ctx, a)
	if err != nil {
		return q, kernel.CapabilityPlan{}, err
	}
	defer clear(p.pending.Envelope)
	c, registry, err := s.coordinator(p)
	if err != nil {
		return q, kernel.CapabilityPlan{}, err
	}
	declaration, err := p.plan(registry)
	if err != nil {
		return q, kernel.CapabilityPlan{}, err
	}
	b := p.pending.Binding
	plan, err := c.PrepareCommandPlan(b, p.command, declaration)
	if err != nil {
		return q, kernel.CapabilityPlan{}, err
	}
	r, _, err := c.ReserveCommand(ctx, b, p.command, plan)
	if err == nil && r == (kernel.Reservation{}) {
		err = identity.UnavailableError{}
	}
	return identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind,
		OperationID: b.OperationID, RecordID: b.RecordID}, declaration.CapabilityIssuance.Grants[0], err
}
