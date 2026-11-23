package saml

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// IDPInitiatedPOSTResponseConfig selects one explicitly approved IdP and its
// separate unsolicited POST destination. ExternalOrigin is the configured
// external HTTPS origin, not a value taken from a request. ProviderID is a
// canonical installed path segment. MaximumAge explicitly selects 1s–5m;
// ClockSkew selects the existing 0–5m tolerance for remote timestamps, and
// never extends the maximum age cutoff from either signed IssueInstant.
type IDPInitiatedPOSTResponseConfig struct {
	SPEntityID, IdentityProviderEntityID string
	ExternalOrigin, ProviderID           string
	SigningCertificates                  [][]byte
	ClockSkew, MaximumAge                time.Duration
}

// IDPInitiatedPOSTResponseProfile verifies unsolicited signed POST messages.
// Its zero value denies. It owns only approved static verification inputs,
// is safe for concurrent use and does not authorize endpoint exposure or login.
type IDPInitiatedPOSTResponseProfile struct {
	verifier   POSTResponseProfile
	maximumAge time.Duration
}

// NewIDPInitiatedPOSTResponseProfile derives the exact non-default ACS from
// the external origin and provider path segment, and snapshots the approved
// signing keys. It neither mounts that route nor enables its provider.
func NewIDPInitiatedPOSTResponseProfile(config IDPInitiatedPOSTResponseConfig) (IDPInitiatedPOSTResponseProfile, error) {
	origin, ok := samlHTTPSURL(config.ExternalOrigin, maximumEndpointBytes, false)
	if !ok || config.ExternalOrigin != "https://"+origin.Host || strings.HasSuffix(origin.Host, ":") ||
		!validIDPInitiatedProviderSegment(config.ProviderID) || config.MaximumAge < time.Second || config.MaximumAge > 5*time.Minute {
		return IDPInitiatedPOSTResponseProfile{}, ErrInvalidInput
	}
	if port := origin.Port(); port != "" {
		value, err := strconv.ParseUint(port, 10, 16)
		if err != nil || value == 0 || strconv.FormatUint(value, 10) != port {
			return IDPInitiatedPOSTResponseProfile{}, ErrInvalidInput
		}
	}
	verifier, err := NewPOSTResponseProfile(POSTResponseConfig{
		SPEntityID: config.SPEntityID, IdentityProviderEntityID: config.IdentityProviderEntityID,
		AssertionConsumerURL: config.ExternalOrigin + "/saml2/" + config.ProviderID + "/idp-init",
		SigningCertificates:  config.SigningCertificates,
		ClockSkew:            config.ClockSkew,
	})
	if err != nil {
		return IDPInitiatedPOSTResponseProfile{}, err
	}
	return IDPInitiatedPOSTResponseProfile{verifier: verifier, maximumAge: config.MaximumAge}, nil
}

func validIDPInitiatedProviderSegment(id string) bool {
	return len(id) > 0 && len(id) <= 128 && id != "." && id != ".." &&
		url.PathEscape(id) == id && !strings.ContainsAny(id, "%?#\\/{}")
}

// IDPInitiatedPOSTResponseInput carries just the encoded SAMLResponse form value
// and trusted current time. The transport must bound and select the actual
// POST route, resolve current provider authority and preserve browser intent.
// RelayState and SP request context have no place in this API.
type IDPInitiatedPOSTResponseInput struct {
	SAMLResponse string
	Now          time.Time
}

// VerifiedIDPInitiatedPOSTResponse is distinct from SP-initiated evidence.
// It is not browser confirmation, a replay reservation or a session grant.
type VerifiedIDPInitiatedPOSTResponse struct{ verified POSTResponseEvidence }

// Validate checks both signed objects without inventing request correlation.
func (p IDPInitiatedPOSTResponseProfile) Validate(ctx context.Context, input IDPInitiatedPOSTResponseInput) (VerifiedIDPInitiatedPOSTResponse, error) {
	if ctx == nil || len(p.verifier.signing) == 0 || p.maximumAge == 0 || !validSAMLTime(input.Now) {
		return VerifiedIDPInitiatedPOSTResponse{}, ErrInvalidInput
	}
	evidence, err := p.verifier.validatePOSTResponse(ctx, input.SAMLResponse, postResponseBinding{
		now: input.Now, maximumUnsolicitedAge: p.maximumAge,
	})
	return VerifiedIDPInitiatedPOSTResponse{verified: evidence}, err
}

// Evidence explicitly returns the verified identity fields and replay set.
// The native owner must reserve both IDs atomically before issuing authority.
func (v VerifiedIDPInitiatedPOSTResponse) Evidence() (POSTResponseEvidence, error) {
	if v.verified.AssertionID == "" {
		return POSTResponseEvidence{}, ErrInvalidInput
	}
	return v.verified, nil
}

func (IDPInitiatedPOSTResponseInput) Format(s fmt.State, _ rune) {
	_, _ = fmt.Fprint(s, "saml.IDPInitiatedPOSTResponseInput(redacted)")
}
func (IDPInitiatedPOSTResponseInput) LogValue() slog.Value {
	return slog.StringValue("saml.IDPInitiatedPOSTResponseInput(redacted)")
}
func (IDPInitiatedPOSTResponseInput) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (IDPInitiatedPOSTResponseInput) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

func (VerifiedIDPInitiatedPOSTResponse) Format(s fmt.State, _ rune) {
	_, _ = fmt.Fprint(s, "saml.VerifiedIDPInitiatedPOSTResponse(redacted)")
}
func (VerifiedIDPInitiatedPOSTResponse) LogValue() slog.Value {
	return slog.StringValue("saml.VerifiedIDPInitiatedPOSTResponse(redacted)")
}
func (VerifiedIDPInitiatedPOSTResponse) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (VerifiedIDPInitiatedPOSTResponse) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
