package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"github.com/faustbrian/go-sso"
)

// WithSAMLSigningCredentialValidator selects the optional wire validator on a
// copy of a SAML-registration-enabled service. Only trusted composition sets
// the validator. The local callback borrows decrypted material outside Work,
// which the envelope owner clears immediately afterward. It neither enables
// providers nor changes OIDC or OAuth 2.0 credential handling.
func (s *ProviderService) WithSAMLSigningCredentialValidator(validate sso.SAMLSigningCredentialValidator) (*ProviderService, error) {
	if s == nil || s.pool == nil || s.samlOrigin == "" || s.samlValidator == nil || validate == nil {
		return nil, sso.ErrInvalidInput
	}
	selected := *s
	selected.samlSigningValidator = validate
	return &selected, nil
}

func (s *ProviderService) readProviderSAMLConfiguration(plain []byte, mappingVersion uint64, pending int) (providerSAMLConfiguration, error) {
	var stored providerSAMLConfiguration
	if json.Unmarshal(plain, &stored) != nil || stored.Mapping.Version != mappingVersion || len(stored.Domains) != pending {
		return providerSAMLConfiguration{}, sso.ErrUnavailable
	}
	if s.samlOrigin == "" || stored.Origin != s.samlOrigin {
		return providerSAMLConfiguration{}, sso.ErrForbidden
	}
	encoded, err := json.Marshal(stored)
	defer clear(encoded)
	if err != nil || !bytes.Equal(encoded, plain) {
		return providerSAMLConfiguration{}, sso.ErrUnavailable
	}
	return stored, nil
}

func (s *ProviderService) validateSAMLSigningExpiry(ctx context.Context, tenant, organization, provider string, wire, contextWire []byte, generation, installed uint64, at time.Time) (validUntil time.Time, err error) {
	if s.samlSigningValidator == nil {
		return time.Time{}, sso.ErrForbidden
	}
	defer func() {
		if recover() != nil {
			validUntil, err = time.Time{}, sso.ErrUnavailable
		}
	}()
	err = withAuthenticatedProtocolProviderCredential(ctx, s.config.Envelope, providerProtocolSAML, tenant, organization, provider, wire, contextWire,
		generation, installed, func(ctx context.Context, plain []byte) error {
			expiry, err := checkedSAMLSigningExpiry(ctx, s.samlSigningValidator, plain, at)
			if err != nil {
				return err
			}
			if !s.config.Clock.Now().Before(expiry) {
				return sso.ErrForbidden
			}
			validUntil = expiry
			return nil
		})
	if err != nil {
		return time.Time{}, err
	}
	return validUntil, nil
}

func checkedSAMLSigningExpiry(ctx context.Context, validate sso.SAMLSigningCredentialValidator, plain []byte, at time.Time) (validUntil time.Time, err error) {
	if validate == nil {
		return time.Time{}, sso.ErrForbidden
	}
	defer func() {
		if recover() != nil {
			validUntil, err = time.Time{}, sso.ErrUnavailable
		}
	}()
	expiry, validationErr := validate(ctx, plain, at)
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	expiry = expiry.UTC().Truncate(time.Microsecond)
	if validationErr != nil || !at.Before(expiry) {
		return time.Time{}, sso.ErrForbidden
	}
	return expiry, nil
}
