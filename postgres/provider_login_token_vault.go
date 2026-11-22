package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
)

// This finite native static-OIDC profile retains access/refresh custody only.
// The ID token has already supplied validated assertion evidence; retaining its
// raw bytes would add a second recoverable protocol-evidence owner.
const providerLoginTokenHeader = "sso-tokens-v1\x00"
const providerLoginTokenMaximumBytes = 16 << 10 // identity/oauth.OIDCConfig token bound.
const providerLoginTokenMaximumFrame = len(providerLoginTokenHeader) + 8 + 2*providerLoginTokenMaximumBytes

// Only the native owner's encrypted generation output may serialize this
// internal value. Neither claims, hooks, audit nor a public result receives it.
// The callback and generation select one immutable deposit, not refresh rights.
type providerLoginPreparedTokens struct {
	Input              providerLoginPayloadInput
	Callback           identity.CommandBinding
	CallbackGeneration uint64
	BindingDigest      [32]byte
	BindingWireDigest  [32]byte
	StateKey           uint32
	StateDigest        [32]byte
	Account            identity.Account
	SocialLinkVersion  uint64
	RequestedScopes    []string
	GrantedScopes      []string
	ScopeReported      bool
	ReceivedAt         time.Time
	AccessExpiresAt    time.Time
	Version            uint64
	Ciphertext         []byte
}

func (providerLoginPreparedTokens) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.providerLoginPreparedTokens(redacted)"))
}

func providerLoginTokenCallback(input providerLoginPayloadInput, callback identity.CommandID) identity.CommandBinding {
	b := input.Command
	op := providerOIDCCallbackOperation()
	b.CommandID, b.CorrelationID = callback, string(callback)
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	return b
}

func providerLoginTokenScopes(scopes []string) bool {
	if len(scopes) < 1 || len(scopes) > 32 {
		return false
	}
	for i, scope := range scopes {
		if !providerLoginVisible(scope, 128) || strings.ContainsAny(scope, " \"\\") || slices.Contains(scopes[:i], scope) {
			return false
		}
	}
	return true
}

func providerLoginTokenTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Unix() > 0 && value.Year() <= 9999
}

func (s *ProviderLoginService) validateProviderLoginTokenMetadata(p providerLoginPreparedTokens) error {
	if s == nil || p.Input.validate() != nil ||
		p.Input.Command.TenantID != s.config.TenantID || p.Version != 1 || p.CallbackGeneration == 0 ||
		p.BindingDigest == ([32]byte{}) || p.BindingWireDigest == ([32]byte{}) || p.StateKey == 0 || p.StateDigest == ([32]byte{}) ||
		p.Callback.CommandID == p.Input.Command.CommandID ||
		p.Callback != providerLoginTokenCallback(p.Input, p.Callback.CommandID) ||
		p.Callback.ValidateFor(providerOIDCCallbackOperation()) != nil ||
		p.Account.Validate(p.Input.Command.TenantID, p.Account.UserID) != nil ||
		p.Account.Issuer != p.Input.Issuer || p.SocialLinkVersion == 0 {
		return identity.ForbiddenError{}
	}
	profile, ok := s.profiles[providerLoginProfileKey{organization: organization.ID(p.Input.OrganizationID), provider: sso.ProviderID(p.Input.ProviderID)}]
	if !ok || string(profile.OrganizationID) != p.Input.OrganizationID || string(profile.ProviderID) != p.Input.ProviderID ||
		profile.ClientID != p.Input.ClientID || profile.ProtocolRedirectURI != p.Input.RedirectURI ||
		profile.ProviderVersion != p.Input.ProviderVersion || profile.CredentialGeneration != p.Input.CredentialGeneration ||
		profile.MappingVersion != p.Input.MappingVersion || !providerLoginTokenScopes(profile.Scopes) ||
		!slices.Contains(profile.Scopes, "openid") || !slices.Equal(p.RequestedScopes, profile.Scopes) ||
		!providerLoginTokenScopes(p.RequestedScopes) || !providerLoginTokenScopes(p.GrantedScopes) ||
		!p.ScopeReported && !slices.Equal(p.GrantedScopes, p.RequestedScopes) {
		return identity.ForbiddenError{}
	}
	for _, scope := range p.GrantedScopes {
		if !slices.Contains(p.RequestedScopes, scope) {
			return identity.ForbiddenError{}
		}
	}
	if !providerLoginTokenTime(p.ReceivedAt) || !providerLoginTokenTime(p.AccessExpiresAt) ||
		p.ReceivedAt.Before(p.Input.IssuedAt) || !p.ReceivedAt.Before(p.Input.ExpiresAt) ||
		!p.AccessExpiresAt.After(p.ReceivedAt) || p.AccessExpiresAt.Sub(p.ReceivedAt) > 365*24*time.Hour ||
		p.AccessExpiresAt.Nanosecond() != p.ReceivedAt.Nanosecond() {
		return identity.ForbiddenError{}
	}
	return nil
}

func providerLoginTokenAAD(p providerLoginPreparedTokens) (envelope.Context, error) {
	metadata := p
	metadata.Ciphertext = nil
	plain, err := json.Marshal(metadata)
	defer clear(plain)
	if err != nil {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	digest := sha256.Sum256(plain)
	return envelope.NewContext(map[string]string{
		"owner": "sso", "profile": "native-static-oidc-token-v1", "purpose": "enterprise-provider-tokens",
		"tenant": string(p.Input.Command.TenantID), "organization": p.Input.OrganizationID,
		"provider": p.Input.ProviderID, "subject": p.Account.Subject, "version": strconv.FormatUint(p.Version, 10),
		"callback": string(p.Callback.CommandID), "callback_generation": strconv.FormatUint(p.CallbackGeneration, 10),
		"metadata": base64.RawURLEncoding.EncodeToString(digest[:]),
	})
}

func providerLoginTokenFailure(ctx context.Context) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return identity.ForbiddenError{}
}

// prepareProviderLoginTokens consumes every shared TokenSet alias, including
// on rejection. The command already freezes the resolved existing account;
// this helper performs no lookup, network, authorization or transaction work.
func (s *ProviderLoginService) prepareProviderLoginTokens(ctx context.Context, found providerLoginCallbackLookup, command identity.Command, generation uint64, tokens oauth.TokenSet) (out providerLoginPreparedTokens, err error) {
	defer tokens.Destroy()
	defer func() {
		if recover() != nil {
			out = providerLoginPreparedTokens{}
			err = providerLoginTokenFailure(ctx)
		}
	}()
	if ctx == nil || s == nil || s.payload.Envelope == nil || s.payload.KeyReference == "" || found.CompletedAt != nil || found.Row != found.Binding.Metadata.Input.rowIdentity() ||
		found.ObservedAt.IsZero() || found.ObservedAt.Before(found.Row.IssuedAt) || !found.ObservedAt.Before(found.Row.ExpiresAt) {
		return out, identity.ForbiddenError{}
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	account, err := kernel.SSOOIDCSigninAccount(command)
	feature, ok := command.Feature()
	metadata := found.Binding.Metadata
	if err != nil || !ok || feature.Operation != providerOIDCCallbackOperation() || metadata.Schema != 1 ||
		feature.Binding != providerLoginTokenCallback(metadata.Input, metadata.CallbackCommand) {
		return out, identity.ForbiddenError{}
	}
	bound, err := providerLoginPayloadEncode(metadata)
	defer clear(bound)
	if err != nil {
		return out, identity.ForbiddenError{}
	}
	p := providerLoginPreparedTokens{
		Input: metadata.Input, Callback: feature.Binding, CallbackGeneration: generation,
		BindingDigest: sha256.Sum256(bound), BindingWireDigest: found.BindingWireDigest, StateKey: metadata.StateKey, StateDigest: metadata.StateDigest,
		Account: account.Account, SocialLinkVersion: account.SocialLinkVersion,
		RequestedScopes: tokens.RequestedScopes(), GrantedScopes: tokens.GrantedScopes(), ScopeReported: tokens.ScopeReported(),
		ReceivedAt: tokens.ReceivedAt().UTC(), AccessExpiresAt: tokens.ExpiresAt().UTC(), Version: 1,
	}
	if err := s.validateProviderLoginTokenMetadata(p); err != nil {
		return out, err
	}
	aad, err := providerLoginTokenAAD(p)
	if err != nil {
		return out, identity.ForbiddenError{}
	}
	err = tokens.Use(ctx, func(ctx context.Context, borrowed oauth.TokenBytes) error {
		if len(borrowed.AccessToken) < 1 || len(borrowed.AccessToken) > providerLoginTokenMaximumBytes ||
			len(borrowed.RefreshToken) > providerLoginTokenMaximumBytes || len(borrowed.IDToken) < 1 || len(borrowed.IDToken) > providerLoginTokenMaximumBytes {
			return identity.ForbiddenError{}
		}
		// Exact capacity prevents append from abandoning a bearer-bearing array.
		frame := make([]byte, 0, len(providerLoginTokenHeader)+8+len(borrowed.AccessToken)+len(borrowed.RefreshToken))
		defer func() { clear(frame) }()
		frame = append(frame, providerLoginTokenHeader...)
		for _, value := range [][]byte{borrowed.AccessToken, borrowed.RefreshToken} {
			frame = binary.BigEndian.AppendUint32(frame, uint32(len(value)))
			frame = append(frame, value...)
		}
		p.Ciphertext, err = s.payload.seal(ctx, aad, frame, 65536)
		return err
	})
	if err != nil || ctx.Err() != nil {
		return out, providerLoginTokenFailure(ctx)
	}
	return p, nil
}

// Authentication restores only a bounded private frame and immediately clears
// it. No public reveal path, hook or assertion receives recoverable token bytes.
func (s *ProviderLoginService) validateProviderLoginTokens(ctx context.Context, p providerLoginPreparedTokens) (err error) {
	defer func() {
		if recover() != nil {
			err = providerLoginTokenFailure(ctx)
		}
	}()
	if ctx == nil || s == nil || s.payload.Envelope == nil || s.payload.KeyReference == "" {
		return identity.ForbiddenError{}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.validateProviderLoginTokenMetadata(p); err != nil {
		return err
	}
	if len(p.Ciphertext) < 1 || len(p.Ciphertext) > 65536 {
		return identity.ForbiddenError{}
	}
	aad, err := providerLoginTokenAAD(p)
	if err != nil {
		return identity.ForbiddenError{}
	}
	plain, err := s.payload.open(ctx, aad, p.Ciphertext, 65536, providerLoginTokenMaximumFrame)
	defer clear(plain)
	if err != nil || len(plain) < len(providerLoginTokenHeader)+8 || string(plain[:len(providerLoginTokenHeader)]) != providerLoginTokenHeader {
		return providerLoginTokenFailure(ctx)
	}
	remaining := plain[len(providerLoginTokenHeader):]
	for i := range 2 {
		if len(remaining) < 4 {
			return identity.ForbiddenError{}
		}
		n := binary.BigEndian.Uint32(remaining)
		remaining = remaining[4:]
		if n > providerLoginTokenMaximumBytes || uint64(n) > uint64(len(remaining)) || i == 0 && n == 0 {
			return identity.ForbiddenError{}
		}
		remaining = remaining[int(n):]
	}
	if len(remaining) != 0 {
		return identity.ForbiddenError{}
	}
	return ctx.Err()
}

// FeaturePreparationOutput retains the original output generation across a
// journal takeover; the later reservation does not renew sealed provenance.
func providerLoginTokenGenerationMatches(prepared, original, current uint64) bool {
	return original > 0 && original <= current && prepared == original
}

func providerLoginTokenOutputMatches(prepared, original, current uint64, authenticated, retained [32]byte) bool {
	return authenticated != ([32]byte{}) && authenticated == retained && providerLoginTokenGenerationMatches(prepared, original, current)
}

// The original callback owns Work, capability consumption and completion. This
// deposit must precede marking its login terminal, and stays provisional until
// all session, browser, audit and state effects commit in that same Work.
// The owner must authenticate the complete prepared output, including token
// ciphertext, before entering Work and pass that exact output's digest. Envelope
// providers can perform network I/O, so no Encrypt/Decrypt runs under SQL locks.
func (s *ProviderLoginService) persistProviderLoginTokens(ctx context.Context, work kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, p providerLoginPreparedTokens, outputDigest [32]byte) error {
	if err := work.RequireFeatureCommand(ctx, owner, command); err != nil {
		return err
	}
	binding, _, generation, err := work.FeatureCommandIdentity(owner)
	if err != nil || binding != p.Callback {
		return identity.ForbiddenError{}
	}
	preparationOwner, ok := owner.(kernel.FeaturePreparationContributor)
	if !ok {
		return identity.ForbiddenError{}
	}
	retained, originalGeneration, err := work.FeaturePreparationOutput(preparationOwner)
	outputMatches := providerLoginTokenOutputMatches(p.CallbackGeneration, originalGeneration, generation, outputDigest, sha256.Sum256(retained))
	clear(retained)
	if err != nil || !outputMatches {
		return identity.ForbiddenError{}
	}
	consumed, err := work.SSOOIDCSigninConsumption(owner)
	if err != nil || consumed.Command != binding || consumed.Generation != generation {
		return identity.ForbiddenError{}
	}
	account, err := kernel.SSOOIDCSigninAccount(command)
	if err != nil || account.Account != p.Account || account.SocialLinkVersion != p.SocialLinkVersion {
		return identity.ForbiddenError{}
	}
	if _, err := work.RequireSSOOIDCSigninProviderAccount(ctx, owner, command); err != nil {
		return err
	}
	if err := s.validateProviderLoginTokenMetadata(p); err != nil {
		return err
	}
	if len(p.Ciphertext) < 1 || len(p.Ciphertext) > 65536 {
		return identity.ForbiddenError{}
	}
	rows, err := work.Query(ctx, providerLoginTokenOriginalSQL, string(p.Input.Command.TenantID), int64(p.StateKey), p.StateDigest[:])
	if err != nil {
		return err
	}
	var row providerLoginRowIdentity
	var tenant, start, version, credentials, mapping, callback string
	var wire []byte
	defer func() { clear(wire) }()
	valid := rows.Next() && rows.Scan(&tenant, &row.OrganizationID, &row.ProviderID, &version, &credentials, &mapping, &start, &callback, &row.IssuedAt, &row.ExpiresAt, &wire) == nil
	extra := rows.Next()
	readErr := rows.Err()
	rows.Close()
	if readErr != nil {
		return readErr
	}
	if !valid || extra || tenant != string(p.Input.Command.TenantID) || start != string(p.Input.Command.CommandID) {
		return identity.ForbiddenError{}
	}
	row.TenantID, row.StartCommandID = identity.TenantID(tenant), identity.CommandID(start)
	row.IssuedAt, row.ExpiresAt = row.IssuedAt.UTC(), row.ExpiresAt.UTC()
	row.ProviderVersion, row.CredentialGeneration, row.MappingVersion = p.Input.ProviderVersion, p.Input.CredentialGeneration, p.Input.MappingVersion
	if row != p.Input.rowIdentity() || callback != string(binding.CommandID) ||
		version != strconv.FormatUint(row.ProviderVersion, 10) || credentials != strconv.FormatUint(row.CredentialGeneration, 10) || mapping != strconv.FormatUint(row.MappingVersion, 10) {
		return identity.ForbiddenError{}
	}
	if len(wire) < 1 || len(wire) > 65536 || sha256.Sum256(wire) != p.BindingWireDigest {
		return identity.ForbiddenError{}
	}
	origin, err := base64.RawURLEncoding.Strict().DecodeString(string(binding.CommandID))
	defer clear(origin)
	if err != nil || len(origin) != 16 {
		return identity.ForbiddenError{}
	}
	n, err := work.Exec(ctx, providerLoginTokenInsertSQL,
		string(binding.TenantID), p.Input.OrganizationID, p.Input.ProviderID, string(p.Input.Command.CommandID), string(binding.CommandID), p.CallbackGeneration,
		string(p.Account.UserID), string(p.Account.ID), p.Account.Provider, p.Account.Issuer, p.Account.Subject,
		p.Account.Version, p.SocialLinkVersion, p.Input.ProviderVersion, p.Input.CredentialGeneration, p.Input.MappingVersion,
		strings.Join(p.RequestedScopes, " "), strings.Join(p.GrantedScopes, " "), p.ScopeReported,
		p.ReceivedAt.Unix(), p.ReceivedAt.Nanosecond(), p.AccessExpiresAt.Unix(), p.AccessExpiresAt.Nanosecond(), p.Ciphertext, origin)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return ctx.Err()
}

const providerLoginTokenOriginalSQL = `SELECT tenant_id,organization_id,provider_id,provider_version::text,credential_generation::text,mapping_version::text,start_command_id,callback_command_id,issued_at,expires_at,binding_envelope
 FROM sso_providers.login_transactions
 WHERE tenant_id=$1 AND state_key_version=$2 AND state_digest=$3 AND protocol='oidc' AND completed_at IS NULL
 FOR SHARE`

const providerLoginTokenInsertSQL = `INSERT INTO sso_providers.provider_login_token_sets(
 tenant_id,organization_id,provider_id,start_command_id,callback_command_id,callback_generation,
 user_id,account_id,account_provider,issuer,subject,account_version,social_link_version,
 provider_version,credential_generation,mapping_version,token_version,requested_scopes,granted_scopes,scope_reported,
 received_at_seconds,received_at_nanoseconds,access_expires_at_seconds,access_expires_at_nanoseconds,token_ciphertext,origin_operation,origin_command_id)
 VALUES($1,$2,$3,$4,$5,$6::numeric,$7,$8,$9,$10,$11,$12::numeric,$13::numeric,$14::numeric,$15::numeric,$16::numeric,1,
 string_to_array($17,' '),string_to_array($18,' '),$19,$20,$21,$22,$23,$24,'identity.sso.oidc-callback',$25)
 ON CONFLICT DO NOTHING`
