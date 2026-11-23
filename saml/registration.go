package saml

import "context"

// ValidateRegistration checks the selected exact IdP entity URI, HTTPS Redirect
// endpoint (including reserved binding query fields), and 1..5 distinct pinned
// DER signing certificates against the response signing profile. It checks
// certificate lifetime shape, not current validity or trust chains. It does not
// fetch metadata, establish provider authority, or create state or sessions.
// Inputs are borrowed synchronously without modification or retention; callers
// must not mutate them concurrently. Invalid input, including a nil context,
// returns ErrInvalidInput; cancellation returns the context error. Errors never
// contain configuration or certificate data.
func ValidateRegistration(ctx context.Context, entityID, redirectEndpoint string, signingCertificates [][]byte) error {
	if ctx == nil {
		return ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !samlIdPEntityID(entityID) {
		return ErrInvalidInput
	}
	endpoint, ok := samlHTTPSURL(redirectEndpoint, maximumEndpointBytes, true)
	if !ok || !validFixedRedirectQuery(endpoint.RawQuery) {
		return ErrInvalidInput
	}
	if _, err := parsePinnedSigningCertificates(signingCertificates); err != nil {
		return err
	}
	return ctx.Err()
}
