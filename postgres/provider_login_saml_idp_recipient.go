package postgres

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	"github.com/faustbrian/go-sso"
)

type samlIDPLinkedRecipientSelection struct {
	namespace string
	directory *kernel.Repository
}

// WithLinkedRecipientPolicy selects the configured linked-member authorization
// namespace for this native SAML admission. The original service is unchanged.
// The account and policy repositories read the router's same primary. There is
// no request-selected namespace, SP start, JIT account or session authority.
func (s *ProviderSAMLIDPAdmissionService) WithLinkedRecipientPolicy(namespace string) (*ProviderSAMLIDPAdmissionService, error) {
	if s == nil || s.router == nil || (s.verify == nil && s.verifyLogoutSubject == nil) || len(s.profiles) == 0 {
		return nil, sso.ErrInvalidInput
	}
	scope := authoritypg.AuthorityScope{TenantID: authorization.TenantID(s.tenant), SubjectID: "scope-validation", PolicyNamespace: namespace}
	if scope.Validate() != nil {
		return nil, sso.ErrInvalidInput
	}
	directory, err := kernel.NewRepository(s.router.pool, kernel.Config{MaximumDuration: s.router.config.MaximumDuration})
	if err != nil {
		return nil, sso.ErrInvalidInput
	}
	selected := *s
	selected.linked = &samlIDPLinkedRecipientSelection{namespace: namespace, directory: directory}
	return &selected, nil
}

// ProviderSAMLIDPLinkedAdmission keeps the verified response and original
// current linked-recipient observation together for native pending custody.
// The zero value has no evidence. This contains no browser confirmation,
// durable replay reservation, session authority or permission to provision.
type ProviderSAMLIDPLinkedAdmission struct {
	admission ProviderSAMLIDPAdmission
	recipient providerLoginCallbackRecipient
}

// LinkedUser returns the linked directory user observed by this admission, or
// empty for zero evidence. Use only in trusted native composition; this value
// is not a continuing authority lease or a public enumeration response.
func (a ProviderSAMLIDPLinkedAdmission) LinkedUser() identity.UserID {
	return a.recipient.account.Account.UserID
}

// Evidence returns the original wire observation and cutoff without renewal.
func (a ProviderSAMLIDPLinkedAdmission) Evidence() (SAMLVerifiedResponse, error) {
	return a.admission.Evidence()
}

func (ProviderSAMLIDPLinkedAdmission) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprint(f, "sso.postgres.ProviderSAMLIDPLinkedAdmission(redacted)")
}
func (ProviderSAMLIDPLinkedAdmission) LogValue() slog.Value {
	return slog.StringValue("sso.postgres.ProviderSAMLIDPLinkedAdmission(redacted)")
}
func (ProviderSAMLIDPLinkedAdmission) MarshalJSON() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}
func (ProviderSAMLIDPLinkedAdmission) MarshalText() ([]byte, error) {
	return nil, sso.ErrSensitiveSerialization
}

// VerifyLinkedRecipient verifies the installed IdP's unsolicited response and
// resolves only an eligible existing link. It uses the authenticated issuer
// and signed subject, the selected domain/provider, and the current primary
// account, membership, factor and policy evidence. It rereads the original
// provider and domain after recipient reads. Confirmation and its native Work
// must still fence current authority; this method performs no mutations.
func (s *ProviderSAMLIDPAdmissionService) VerifyLinkedRecipient(ctx context.Context, request SAMLIDPAdmissionRequest) (out ProviderSAMLIDPLinkedAdmission, err error) {
	if ctx == nil || s == nil || s.router == nil || s.linked == nil {
		return out, sso.ErrInvalidInput
	}
	router := s.router
	ctx, cancel := context.WithTimeout(ctx, router.config.MaximumDuration)
	defer cancel()
	defer func() {
		if recover() != nil {
			out, err = ProviderSAMLIDPLinkedAdmission{}, providerError(ctx, sso.ErrUnavailable)
		}
	}()
	admission, err := s.Verify(ctx, request)
	if err != nil {
		return out, err
	}
	checkpoint := admission.route.Proof
	key := checkpoint.Key
	recipient, err := router.readLinkedRecipient(ctx, s.linked.directory, linkedRecipientRequest{
		tenant: key.TenantID, organization: key.OrganizationID, provider: admission.route.ProviderID,
		protocol: providerProtocolSAML, issuer: admission.issuer, subject: admission.wire.ProviderSubject,
		policyNamespace: s.linked.namespace, observedAt: admission.verifiedAt, deadline: admission.validUntil,
		maximumDuration: router.config.MaximumDuration,
	})
	if err != nil {
		return out, err
	}
	proof, err := router.organizations.GetDomainProof(ctx, key)
	if err != nil {
		return out, providerError(ctx, err)
	}
	if organization.DomainProofKey(proof) != key || proof.ProofVersion != checkpoint.ProofVersion || proof.Revoked {
		return out, sso.ErrForbidden
	}
	if err := router.requireCurrentRoute(ctx, admission.route); err != nil {
		return out, err
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	now := router.config.Clock.Now().UTC()
	cutoff := earlierLoginTime(admission.validUntil, recipient.member.ValidUntil)
	if now.Before(admission.verifiedAt) || now.Before(proof.ObservedAt) || !now.Before(cutoff) || !now.Before(proof.ExpiresAt) {
		return out, sso.ErrForbidden
	}
	admission.validUntil = cutoff
	return ProviderSAMLIDPLinkedAdmission{admission: admission, recipient: recipient}, nil
}
