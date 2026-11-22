//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"

	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

// This fixture uses authenticated AES-GCM wrapping with an encrypted key-provider
// payload whose metadata makes the opaque wrapped data key exactly 6000 bytes.
// Envelope v2 supports such provider-owned blobs; no envelope format is mocked.
type providerLargeWrappedKey struct{ wrapping cipher.AEAD }

func (p providerLargeWrappedKey) GenerateDataKey(ctx context.Context, reference string, aad envelope.Context) (envelope.DataKey, error) {
	if err := ctx.Err(); err != nil {
		return envelope.DataKey{}, err
	}
	raw := make([]byte, envelope.DataKeySize)
	if _, err := rand.Read(raw); err != nil {
		return envelope.DataKey{}, err
	}
	payload := make([]byte, 6000-p.wrapping.NonceSize()-p.wrapping.Overhead())
	copy(payload, raw)
	defer clear(payload)
	nonce := make([]byte, p.wrapping.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		clear(raw)
		return envelope.DataKey{}, err
	}
	wrapped := p.wrapping.Seal(nonce, nonce, payload, append([]byte(reference), aad.AdditionalData()...))
	key, err := envelope.NewDataKey(raw, wrapped, reference)
	if err != nil {
		clear(raw)
	}
	return key, err
}

func (p providerLargeWrappedKey) DecryptDataKey(ctx context.Context, reference string, wrapped []byte, aad envelope.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(wrapped) != 6000 {
		return nil, envelope.ErrInvalidRequest
	}
	nonce := wrapped[:p.wrapping.NonceSize()]
	payload, err := p.wrapping.Open(nil, nonce, wrapped[len(nonce):], append([]byte(reference), aad.AdditionalData()...))
	if err != nil {
		return nil, err
	}
	defer clear(payload)
	return append([]byte(nil), payload[:envelope.DataKeySize]...), nil
}

func TestNativeProviderUpdateReadsCommittedLargeWrappedKeySuccessor(t *testing.T) {
	f, _, config := newProviderFixture(t)
	block, err := aes.NewCipher(bytes.Repeat([]byte{0x6a}, 32))
	if err != nil {
		t.Fatal(err)
	}
	wrapping, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	config.Envelope, err = envelope.NewService(providerLargeWrappedKey{wrapping: wrapping})
	if err != nil {
		t.Fatal(err)
	}
	service, err := ssopg.NewProviderService(f.pool, config, f.auth("org-test-basic", "owner"), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	service = withProviderUpdateOwner(t, service)
	registration := providerRequest(t, "https://wrapped-key.example.com", "wrapped-key-registration")
	registration.Domains = make([]string, 128)
	for i := range registration.Domains {
		registration.Domains[i] = fmt.Sprintf("%03d.%s.%s.com", i, strings.Repeat("a", 60), strings.Repeat("b", 60))
	}
	created, err := service.ProviderRegisterOidc(f.ctx, registration)
	if err != nil {
		t.Fatal("real wrapped-key registration", err)
	}
	service, err = service.ForOrganization(registration.OrganizationID)
	if err != nil {
		t.Fatal(err)
	}
	request := providerUpdateRequest(t, registration, created.Provider.ID, 1, "wrapped-key-first-update")
	endpoint := "https://endpoint.example.com/?" + strings.Repeat("&", 1760)
	metadata, err := sso.NewOIDCStaticMetadata(sso.OIDCStaticMetadataSpec{Issuer: registration.Issuer, AuthorizationEndpoint: endpoint, TokenEndpoint: endpoint, JWKSURI: endpoint})
	if err != nil {
		t.Fatal(err)
	}
	request.Configuration, err = sso.NewStaticOIDCProviderConfiguration(metadata)
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.ProviderUpdate(f.ctx, request)
	if err != nil || first.Provider.Version != 2 {
		t.Fatal("large wrapped-key successor did not commit", err)
	}
	var wireBytes int
	if err = f.pool.Raw().QueryRow(f.ctx, `SELECT octet_length(metadata_configuration_envelope) FROM sso_providers.providers WHERE provider_id=$1`, created.Provider.ID).Scan(&wireBytes); err != nil || wireBytes <= 49152+4096 || wireBytes > 65536 {
		t.Fatal("fixture did not exercise supported stored wire above legacy read bound", wireBytes, err)
	}
	next, err := service.ProviderUpdate(f.ctx, providerUpdateRequest(t, registration, created.Provider.ID, 2, "wrapped-key-next-update"))
	if err != nil || next.Provider.Version != 3 || next.Provider.MappingVersion != 3 {
		t.Fatal("committed supported stored envelope became unreadable to next update", wireBytes, err)
	}
}
