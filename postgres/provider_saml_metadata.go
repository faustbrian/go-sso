package postgres

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"time"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	"github.com/faustbrian/go-sso"
)

// SAMLPublicCertificateProjector validates the installed SP signing bundle
// and selects its public DER certificate and original exclusive expiry. The
// bundle is borrowed synchronously; implementations do not retain its bytes,
// log it, or perform I/O. The selected SAML wire adapter owns that format.
type SAMLPublicCertificateProjector func(context.Context, []byte, time.Time) ([]byte, time.Time, error)

// SAMLSPMetadata is a detached, short-lived observation of the current
// SP-initiated provider. SigningCertificate is one owned public DER certificate,
// never IdP trust or a signing key. ValidUntil is exclusive and must not be
// extended by renderers or caches. The zero value conveys no metadata.
type SAMLSPMetadata struct {
	EntityID, AssertionConsumerURL string
	SigningCertificate             []byte
	ValidUntil                     time.Time
}

// ProviderSAMLMetadataService borrows an existing selected SAML start owner.
// It performs only bounded primary reads, not registration, certificate
// rotation, browser admission, signing, or authentication.
type ProviderSAMLMetadataService struct {
	start   *ProviderLoginService
	project SAMLPublicCertificateProjector
}

// NewProviderSAMLMetadataService enables public-only projection for the same
// installed profiles as the native SP-initiated login. The constructor calls
// neither the database nor the projector. The zero value denies reads.
func NewProviderSAMLMetadataService(start *ProviderLoginService, project SAMLPublicCertificateProjector) (*ProviderSAMLMetadataService, error) {
	if start == nil || start.saml == nil || start.router == nil || project == nil {
		return nil, sso.ErrInvalidInput
	}
	return &ProviderSAMLMetadataService{start: start, project: project}, nil
}

// Read observes the selected provider, verified domain and exact active SP
// signer on the primary. Unknown and retired routes deny without returning
// metadata. No bytes are retained by the service, and no observation is cached
// or renewed. Read is concurrent-safe if its borrowed dependencies are.
func (s *ProviderSAMLMetadataService) Read(ctx context.Context, tenant identity.TenantID, provider sso.ProviderID) (out SAMLSPMetadata, err error) {
	if s == nil || s.start == nil || s.project == nil || ctx == nil {
		return SAMLSPMetadata{}, sso.ErrInvalidInput
	}
	selected, ok := s.start.saml.profiles[provider]
	if !ok || tenant != s.start.config.TenantID {
		return SAMLSPMetadata{}, sso.ErrForbidden
	}
	router := s.start.router
	ctx, cancel := context.WithTimeout(ctx, router.config.MaximumDuration)
	defer cancel()
	defer func() {
		if recover() != nil {
			out, err = SAMLSPMetadata{}, sso.ErrUnavailable
		}
	}()
	request, err := sso.NewDomainRouteRequest(tenant, selected.Domain, provider)
	if err != nil {
		return SAMLSPMetadata{}, sso.ErrForbidden
	}
	route, err := router.RouteSAML(ctx, request)
	if err != nil {
		return SAMLSPMetadata{}, err
	}
	profile, err := router.readProviderSAMLLoginProfile(ctx, route, selected)
	if err != nil {
		return SAMLSPMetadata{}, err
	}
	binding, err := route.Bindings()
	if err != nil {
		return SAMLSPMetadata{}, sso.ErrUnavailable
	}

	cutoff := binding.ValidUntil
	var publicCertificate []byte
	err = router.withRouteCredential(ctx, binding, providerProtocolSAML, func(ctx context.Context, plain []byte) error {
		now := router.config.Clock.Now().UTC()
		if now.Before(binding.ObservedAt) || !now.Before(cutoff) {
			return sso.ErrForbidden
		}
		der, validUntil, err := s.project(ctx, plain, now)
		if canceled := ctx.Err(); canceled != nil {
			return canceled
		}
		if err != nil || !validProjectedSAMLSPCertificate(der, now, validUntil) {
			return sso.ErrForbidden
		}
		cutoff = earlierLoginTime(cutoff, validUntil)
		publicCertificate = bytes.Clone(der)
		return nil
	})
	if err != nil {
		return SAMLSPMetadata{}, err
	}

	// Projection is outside SQL. Do not disclose a certificate from an
	// installation or domain proof that changed during the borrowed call.
	proof, err := router.organizations.GetDomainProof(ctx, binding.Proof.Key)
	if err != nil {
		return SAMLSPMetadata{}, providerError(ctx, err)
	}
	if organization.DomainProofKey(proof) != binding.Proof.Key || proof.ProofVersion != binding.Proof.ProofVersion || proof.Revoked {
		return SAMLSPMetadata{}, sso.ErrForbidden
	}
	if err := router.requireCurrentRoute(ctx, binding); err != nil {
		return SAMLSPMetadata{}, err
	}
	if err := ctx.Err(); err != nil {
		return SAMLSPMetadata{}, err
	}
	now := router.config.Clock.Now().UTC()
	if now.Before(binding.ObservedAt) || now.Before(proof.ObservedAt) || !now.Before(cutoff) || !now.Before(proof.ExpiresAt) {
		return SAMLSPMetadata{}, sso.ErrForbidden
	}
	return SAMLSPMetadata{EntityID: profile.spEntityID, AssertionConsumerURL: profile.acsURL, SigningCertificate: publicCertificate, ValidUntil: cutoff}, nil
}

func validProjectedSAMLSPCertificate(der []byte, now, cutoff time.Time) bool {
	// Reference saml.certificate_bytes bounds DER before parsing. Only an
	// exact X.509 certificate may cross this public boundary, even if the
	// trusted adapter accidentally returns its original plaintext bundle.
	if len(der) == 0 || len(der) > 64*1024 || !now.Before(cutoff) {
		return false
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil || !bytes.Equal(certificate.Raw, der) || now.Before(certificate.NotBefore) || !certificate.NotAfter.Equal(cutoff) ||
		certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return false
	}
	key, ok := certificate.PublicKey.(*rsa.PublicKey)
	return ok && key.N.BitLen() >= 2048 && key.N.BitLen() <= 4096
}
