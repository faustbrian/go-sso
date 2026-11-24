package postgres

import (
	"context"
	"encoding/json"

	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
)

// prepareSAMLIDPPins keeps the installed SAML identity, route and mapping.
// Only the authenticated pin set changes; no SP key participates in the
// mutation. The caller already observed the exact disabled provider revision.
func (p *ProviderCredentialsContributor) prepareSAMLIDPPins(ctx context.Context, current providerSAMLConfiguration) (err error) {
	if !p.replacesSAMLIDPPins() {
		return sso.ErrInvalidInput
	}
	s := p.service.base
	if s.samlValidator == nil {
		return sso.ErrForbidden
	}
	defer func() {
		if recover() != nil {
			err = sso.ErrUnavailable
		}
	}()

	reference := p.request.CredentialReference
	binding := reference.Context()
	aad, err := binding.EncryptionContext()
	if err != nil || binding.Protocol != providerProtocolSAML || binding.ProviderVersion != p.request.ExpectedVersion {
		return sso.ErrForbidden
	}
	sealed := reference.EncryptedEnvelope()
	if sealed.KeyReference() != p.service.profile.IngressKeyID {
		return sso.ErrForbidden
	}
	plain, err := s.config.Envelope.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	defer clear(plain)
	if err != nil {
		return providerError(ctx, sso.ErrForbidden)
	}
	certificates, err := sso.DecodeSAMLIDPSigningCertificates(plain)
	if err != nil {
		return sso.ErrInvalidInput
	}
	current.IdP.SigningCertificates = certificates
	// Snapshot the authenticated values before lending the slices to the
	// composition port; it cannot change the bytes selected for persistence.
	metadata, err := json.Marshal(current)
	defer func() { clear(metadata) }()
	if err != nil || len(metadata) > providerConfigurationMaximumBytes {
		return sso.ErrInvalidInput
	}
	validationErr := s.samlValidator(ctx, current.IdP.EntityID, current.IdP.RedirectEndpoint, certificates)
	if err := ctx.Err(); err != nil {
		return err
	}
	if validationErr != nil {
		return sso.ErrInvalidInput
	}
	clear(p.metadata)
	p.metadata, metadata = metadata, nil
	return nil
}
