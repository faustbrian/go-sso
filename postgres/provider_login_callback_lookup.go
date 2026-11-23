package postgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"slices"
	"strconv"
	"time"

	"github.com/faustbrian/go-sso"
)

// A pending result is only a candidate for browser and current-authority
// checks, never permission to reserve state or release protocol custody.
// CompletedAt retains terminal correlation for exact callback recovery even
// after expiry; terminal results deliberately carry no execution proof.
type providerLoginCallbackLookup struct {
	Row               providerLoginRowIdentity
	Binding           providerLoginStoredBinding
	BindingWireDigest [32]byte
	ObservedAt        time.Time
	CompletedAt       *time.Time
}

func (providerLoginCallbackLookup) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.providerLoginCallbackLookup(redacted)")
}

// The retained key set is bounded before hashing or I/O. Joining those exact
// primary keys keeps the query independent of callback-supplied provider or
// issuer claims. Two matches are sufficient to reject cross-version ambiguity.
const providerLoginCallbackLookupSQL = `SELECT l.tenant_id,l.organization_id,l.provider_id,
 l.provider_version::text,l.credential_generation::text,l.mapping_version::text,
 l.start_command_id,l.callback_command_id,l.protocol,l.state_key_version,l.state_digest,
 l.pkce_key_version,l.pkce_commitment,l.binding_envelope,l.issued_at,l.expires_at,
 l.completed_at,statement_timestamp()
 FROM unnest($2::bigint[],$3::bytea[]) AS wanted(state_key_version,state_digest)
 JOIN sso_providers.login_transactions l
 ON l.tenant_id=$1 AND l.state_key_version=wanted.state_key_version AND l.state_digest=wanted.state_digest
 LIMIT 2`

func (s *ProviderLoginService) lookupProviderLoginCallback(ctx context.Context, state string) (providerLoginCallbackLookup, error) {
	return s.lookupProviderLoginCallbackForProtocol(ctx, state, "")
}

func (s *ProviderLoginService) lookupProviderOAuth2LoginCallback(ctx context.Context, state string) (providerLoginCallbackLookup, error) {
	return s.lookupProviderLoginCallbackForProtocol(ctx, state, providerProtocolOAuth2)
}

func (s *ProviderLoginService) lookupProviderSAMLLoginCallback(ctx context.Context, state string) (providerLoginCallbackLookup, error) {
	if s == nil || s.saml == nil {
		return providerLoginCallbackLookup{}, sso.ErrForbidden
	}
	return s.lookupProviderLoginCallbackForProtocol(ctx, state, providerProtocolSAML)
}

// Only the native callback owner chooses the original start discriminator.
// Neither provider nor issuer supplied by a callback can select this domain.
func (s *ProviderLoginService) lookupProviderLoginCallbackForProtocol(ctx context.Context, state, discriminator string) (providerLoginCallbackLookup, error) {
	deny := func() (providerLoginCallbackLookup, error) {
		return providerLoginCallbackLookup{}, sso.ErrForbidden
	}
	expectedProtocol, _ := providerLoginCryptoProtocol(discriminator)
	if expectedProtocol == "" || s == nil || ctx == nil || !providerLoginPayloadTenant(s.config.TenantID) ||
		len(state) != 43 || len(s.payload.StateKeys) < 1 || len(s.payload.StateKeys) > 32 {
		return deny()
	}
	for version, key := range s.payload.StateKeys {
		if version == 0 || key == ([32]byte{}) {
			return deny()
		}
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(state)
	defer clear(raw)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != state {
		return deny()
	}
	if s.router == nil || s.router.pool == nil || s.router.pool.Raw() == nil || !s.payload.readyFor(discriminator) {
		return deny()
	}
	if err := ctx.Err(); err != nil {
		return providerLoginCallbackLookup{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, s.config.Coordinator.MaximumDuration)
	defer cancel()

	versions := make([]int64, 0, len(s.payload.StateKeys))
	for version := range s.payload.StateKeys {
		versions = append(versions, int64(version))
	}
	slices.Sort(versions)
	digests := make([][]byte, 0, len(versions))
	defer func() {
		for _, digest := range digests {
			clear(digest)
		}
	}()
	for _, version := range versions {
		digest, err := providerLoginProtocolStateDigest(s.payload.StateKeys[uint32(version)], uint32(version), s.config.TenantID, discriminator, raw)
		if err != nil {
			return deny()
		}
		digests = append(digests, digest[:])
	}
	rows, err := s.router.pool.Raw().Query(ctx, providerLoginCallbackLookupSQL, string(s.config.TenantID), versions, digests)
	if err != nil {
		return providerLoginCallbackLookup{}, storeError(ctx, err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return providerLoginCallbackLookup{}, storeError(ctx, err)
		}
		return deny()
	}
	var found providerLoginCallbackLookup
	var providerVersion, generation, mapping, callback, protocol string
	var stateKey int64
	var pkceKey *int64
	var stateDigest, pkceCommitment, wire []byte
	defer func() {
		clear(stateDigest)
		clear(pkceCommitment)
		clear(wire)
	}()
	row := &found.Row
	err = rows.Scan(&row.TenantID, &row.OrganizationID, &row.ProviderID,
		&providerVersion, &generation, &mapping, &row.StartCommandID, &callback, &protocol,
		&stateKey, &stateDigest, &pkceKey, &pkceCommitment, &wire, &row.IssuedAt, &row.ExpiresAt,
		&found.CompletedAt, &found.ObservedAt)
	if err != nil {
		if ctx.Err() != nil {
			return providerLoginCallbackLookup{}, ctx.Err()
		}
		return deny()
	}
	if rows.Next() {
		return deny()
	}
	if err := rows.Err(); err != nil {
		return providerLoginCallbackLookup{}, storeError(ctx, err)
	}
	rows.Close()

	for _, field := range []struct {
		text  string
		value *uint64
	}{{providerVersion, &row.ProviderVersion}, {generation, &row.CredentialGeneration}, {mapping, &row.MappingVersion}} {
		*field.value, err = strconv.ParseUint(field.text, 10, 64)
		if err != nil {
			return deny()
		}
	}
	row.IssuedAt, row.ExpiresAt = row.IssuedAt.UTC(), row.ExpiresAt.UTC()
	found.ObservedAt = found.ObservedAt.UTC()
	if row.TenantID != s.config.TenantID || protocol != expectedProtocol ||
		stateKey < 1 || stateKey > 4294967295 || len(stateDigest) != 32 || found.ObservedAt.Before(row.IssuedAt) {
		return deny()
	}
	var verifierKey uint32
	if discriminator == providerProtocolSAML {
		if pkceKey != nil || pkceCommitment != nil {
			return deny()
		}
	} else {
		if pkceKey == nil || *pkceKey < 1 || *pkceKey > 4294967295 || len(pkceCommitment) != 32 {
			return deny()
		}
		verifierKey = uint32(*pkceKey)
	}
	// SQL retains the explicit protocol; published OIDC envelope identities
	// retain their original omitted discriminator, while OAuth is explicit.
	row.Protocol = discriminator
	if found.CompletedAt == nil {
		if !found.ObservedAt.Before(row.ExpiresAt) {
			return deny()
		}
	} else {
		completed := found.CompletedAt.UTC()
		if completed.Before(row.IssuedAt) || !completed.Before(row.ExpiresAt) || completed.After(found.ObservedAt) {
			return deny()
		}
		found.CompletedAt = &completed
	}
	var stored providerLoginStoredBinding
	if found.CompletedAt == nil {
		stored, err = s.payload.openCommittedBinding(ctx, *row, wire)
	} else {
		stored, err = s.payload.openProviderLoginProtocolCallbackTerminal(ctx, *row, wire, discriminator)
	}
	if err != nil {
		return providerLoginCallbackLookup{}, providerError(ctx, err)
	}
	metadata := stored.Metadata
	if metadata.StateKey != uint32(stateKey) || metadata.PKCEKey != verifierKey ||
		string(metadata.CallbackCommand) != callback || !hmac.Equal([]byte(metadata.Public.State), []byte(state)) ||
		!hmac.Equal(metadata.StateDigest[:], stateDigest) ||
		discriminator != providerProtocolSAML && !hmac.Equal(metadata.PKCECommitment[:], pkceCommitment) {
		clear(stored.Proof)
		return deny()
	}
	if err := ctx.Err(); err != nil {
		clear(stored.Proof)
		return providerLoginCallbackLookup{}, err
	}
	found.Binding = stored
	found.BindingWireDigest = sha256.Sum256(wire)
	return found, nil
}
