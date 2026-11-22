//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

// This configured provider retains the installed provider's original key and
// emits real authenticated 10KiB wrapped-key blobs for the newly selected key.
// The envelope format and both encryption layers are exercised unchanged.
type credentialLargeWrappedKeys struct {
	legacy   envelope.KeyProvider
	wrapping cipher.AEAD
	current  string
}

func (p credentialLargeWrappedKeys) GenerateDataKey(ctx context.Context, reference string, aad envelope.Context) (envelope.DataKey, error) {
	if reference != p.current {
		return p.legacy.GenerateDataKey(ctx, reference, aad)
	}
	if err := ctx.Err(); err != nil {
		return envelope.DataKey{}, err
	}
	raw := make([]byte, envelope.DataKeySize)
	if _, err := rand.Read(raw); err != nil {
		return envelope.DataKey{}, err
	}
	payload := make([]byte, 10<<10-p.wrapping.NonceSize()-p.wrapping.Overhead())
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

func (p credentialLargeWrappedKeys) DecryptDataKey(ctx context.Context, reference string, wrapped []byte, aad envelope.Context) ([]byte, error) {
	if reference != p.current {
		return p.legacy.DecryptDataKey(ctx, reference, wrapped, aad)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(wrapped) != 10<<10 {
		return nil, envelope.ErrInvalidRequest
	}
	nonce := wrapped[:p.wrapping.NonceSize()]
	payload, err := p.wrapping.Open(nil, nonce, wrapped[len(nonce):], append([]byte(reference), aad.AdditionalData()...))
	if err != nil {
		return nil, err
	}
	defer clear(payload)
	return bytes.Clone(payload[:envelope.DataKeySize]), nil
}

func TestNativeProviderCredentialsSupportedLargeWrappingExecutesAndReplays(t *testing.T) {
	f, legacy, config := newProviderFixture(t)
	registration := providerRequest(t, "https://credentials-large-wrapping.example.com", "credential-large-wrapping-registration")
	created, err := legacy.ProviderRegisterOidc(f.ctx, registration)
	if err != nil {
		t.Fatal("installed provider fixture", err)
	}
	installProviderCredentials(t, f)
	var originalMetadata []byte
	if err = f.pool.Raw().QueryRow(f.ctx, `SELECT configuration_envelope FROM sso_providers.providers WHERE provider_id=$1`, created.Provider.ID).Scan(&originalMetadata); err != nil {
		t.Fatal(err)
	}
	oldKeys, err := keyring.New(map[string][]byte{config.KeyReference: bytes.Repeat([]byte{0x94}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	wrappingKey := make([]byte, 32)
	if _, err = rand.Read(wrappingKey); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(wrappingKey)
	clear(wrappingKey)
	if err != nil {
		t.Fatal(err)
	}
	wrapping, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	config.KeyReference = "credential-wrapping-successor"
	config.Envelope, err = envelope.NewService(credentialLargeWrappedKeys{legacy: oldKeys, wrapping: wrapping, current: config.KeyReference})
	if err != nil {
		t.Fatal(err)
	}
	base, err := ssopg.NewProviderService(f.pool, config, f.auth("org-test-basic", "owner"), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	base, err = base.ForOrganization(registration.OrganizationID)
	if err != nil {
		t.Fatal(err)
	}
	service, err := ssopg.NewProviderCredentialsService(base, ssopg.ProviderCredentialsConfig{Authorization: credentialPolicyOwner{policy: fixturePolicy{}, until: time.Now().UTC().Add(time.Hour)}, IngressKeyID: config.KeyReference, MaximumReferenceLifetime: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	request := nativeCredentialRequest(t, f, config, created.Provider.ID, 1, 1)
	credentialWire, err := request.CredentialReference.EncryptedEnvelope().MarshalBinary()
	if err != nil || len(credentialWire) <= 8192 || len(credentialWire) > 32768 {
		t.Fatal("fixture did not produce supported large reference", len(credentialWire), err)
	}
	first, operationErr := service.ProviderCredentialsRotate(f.ctx, request)
	var requestWireBytes int
	if err = f.pool.Raw().QueryRow(f.ctx, `SELECT octet_length(request_preparation_ciphertext) FROM identity.request_key_mappings WHERE route_id='identity.sso.provider.credentials-rotate'`).Scan(&requestWireBytes); err != nil || requestWireBytes <= 8192 {
		t.Fatal("fixture did not retain the actual large native mapping", requestWireBytes, err)
	}
	if operationErr != nil || first.Completion.Outcome != identity.CommitOutcomeCommitted || !first.Active || first.Version != 2 {
		t.Fatalf("supported large wrapping stranded native custody: mapping_bytes=%d reference_bytes=%d outcome=%v error=%v", requestWireBytes, len(credentialWire), first.Completion.Outcome, operationErr)
	}
	retry, err := service.ProviderCredentialsRotate(f.ctx, request)
	if err != nil || retry.Completion.Binding != first.Completion.Binding || retry.Completion.AuditEventID != first.Completion.AuditEventID || retry.Version != first.Version || !retry.Active {
		t.Fatal("large wrapped-key original retry unreadable or changed", err)
	}
	var version string
	var enabled bool
	var afterMetadata []byte
	var credentials, effects, audits, events int
	if err = f.pool.Raw().QueryRow(f.ctx, `SELECT metadata_version::text,enabled,configuration_envelope,(SELECT count(*) FROM sso_providers.credentials),(SELECT count(*) FROM sso_providers.credential_effects),(SELECT count(*) FROM audit.records WHERE action='identity.sso.provider.credentials-rotate' AND outcome=1),(SELECT count(*) FROM outbox_messages WHERE topic='sso.provider_credentials_rotated.v1') FROM sso_providers.providers WHERE provider_id=$1`, created.Provider.ID).Scan(&version, &enabled, &afterMetadata, &credentials, &effects, &audits, &events); err != nil || version != "2" || enabled || !bytes.Equal(originalMetadata, afterMetadata) || credentials != 1 || effects != 1 || audits != 1 || events != 1 {
		t.Fatal("large-wrapped retry changed disabled metadata or repeated effects", version, credentials, effects, audits, events, err)
	}
}
