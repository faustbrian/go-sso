package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

// This projection is the v2 on-disk AAD encoding, not an evolving domain type.
// Callback preparation and lookup-proof facts are erased at terminalization.
type providerLoginStoredTokenBinding struct {
	Organization, Provider                                string
	Start, Callback                                       identity.CommandID
	CallbackGeneration                                    uint64
	Account                                               providerLoginStoredTokenAccount
	SocialLinkVersion, Version                            uint64
	ProviderVersion, CredentialGeneration, MappingVersion uint64
	RequestedScopes, GrantedScopes                        []string
	ScopeReported                                         bool
	ReceivedAt, AccessExpiresAt                           time.Time
}

type providerLoginStoredTokenAccount struct {
	ID       identity.AccountID
	TenantID identity.TenantID
	UserID   identity.UserID
	Provider string
	Issuer   string
	Subject  string
	Version  uint64
}

func (providerLoginStoredTokenBinding) Format(w fmt.State, _ rune) {
	_, _ = fmt.Fprint(w, "postgres.providerLoginStoredTokenBinding(redacted)")
}

func (p providerLoginPreparedTokens) storedTokenBinding() providerLoginStoredTokenBinding {
	return providerLoginStoredTokenBinding{
		Organization: p.Input.OrganizationID, Provider: p.Input.ProviderID, Start: p.Input.Command.CommandID,
		Callback: p.Callback.CommandID, CallbackGeneration: p.CallbackGeneration, Account: providerLoginStoredTokenAccount(p.Account),
		SocialLinkVersion: p.SocialLinkVersion, Version: p.Version, ProviderVersion: p.Input.ProviderVersion,
		CredentialGeneration: p.Input.CredentialGeneration, MappingVersion: p.Input.MappingVersion,
		RequestedScopes: p.RequestedScopes, GrantedScopes: p.GrantedScopes, ScopeReported: p.ScopeReported,
		ReceivedAt: p.ReceivedAt, AccessExpiresAt: p.AccessExpiresAt,
	}
}

func (b providerLoginStoredTokenBinding) aad() (envelope.Context, error) {
	_, startErr := identity.ParseCommandID(string(b.Start))
	_, callbackErr := identity.ParseCommandID(string(b.Callback))
	account := identity.Account(b.Account)
	if startErr != nil || callbackErr != nil || b.Start == b.Callback || !providerID(b.Organization) || !providerID(b.Provider) ||
		account.Validate(account.TenantID, account.UserID) != nil || b.CallbackGeneration == 0 || b.SocialLinkVersion == 0 ||
		b.Version == 0 || b.ProviderVersion == 0 || b.CredentialGeneration == 0 || b.MappingVersion == 0 ||
		!providerLoginTokenScopes(b.RequestedScopes) || !providerLoginTokenScopes(b.GrantedScopes) ||
		!b.ScopeReported && !slices.Equal(b.RequestedScopes, b.GrantedScopes) ||
		!providerLoginTokenTime(b.ReceivedAt) || !providerLoginTokenTime(b.AccessExpiresAt) || !b.AccessExpiresAt.After(b.ReceivedAt) ||
		b.AccessExpiresAt.Sub(b.ReceivedAt) > 365*24*time.Hour || b.AccessExpiresAt.Nanosecond() != b.ReceivedAt.Nanosecond() {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	for _, scope := range b.GrantedScopes {
		if !slices.Contains(b.RequestedScopes, scope) {
			return envelope.Context{}, identity.ForbiddenError{}
		}
	}
	wire, err := json.Marshal(b)
	defer clear(wire)
	if err != nil {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	digest := sha256.Sum256(wire)
	return envelope.NewContext(map[string]string{
		"owner": "sso", "profile": "native-static-oauth2-token-v2", "purpose": "enterprise-provider-tokens",
		"tenant": string(b.Account.TenantID), "organization": b.Organization, "provider": b.Provider,
		"subject": b.Account.Subject, "version": strconv.FormatUint(b.Version, 10), "callback": string(b.Callback),
		"callback_generation": strconv.FormatUint(b.CallbackGeneration, 10), "metadata": base64.RawURLEncoding.EncodeToString(digest[:]),
	})
}

// Only the already-authorized vault operation may borrow restored tokens.
// This helper authenticates custody and clears both borrowed aliases on return;
// it neither grants authority nor admits a legacy v1 deposit for remote use.
func (s *ProviderLoginService) borrowStoredOAuth2Tokens(ctx context.Context, binding providerLoginStoredTokenBinding, ciphertext []byte, use func(context.Context, []byte, []byte) error) (err error) {
	defer func() {
		if recover() != nil {
			err = providerLoginTokenFailure(ctx)
		}
	}()
	if ctx == nil || s == nil || s.payload.Envelope == nil || use == nil || len(ciphertext) == 0 || len(ciphertext) > 65536 {
		return identity.ForbiddenError{}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	aad, err := binding.aad()
	if err != nil {
		return err
	}
	plain, err := s.payload.open(ctx, aad, ciphertext, 65536, providerLoginTokenMaximumFrame)
	defer clear(plain)
	if err != nil {
		return providerLoginTokenFailure(ctx)
	}
	access, refresh, err := providerLoginTokenFrame(plain, providerLoginStoredTokenVersion, nil)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return use(ctx, access, refresh)
}

func providerLoginTokenFrame(plain []byte, version uint8, matchOrigin func([]byte) bool) ([]byte, []byte, error) {
	header := providerLoginTokenHeader
	if version == providerLoginStoredTokenVersion {
		header = providerLoginStoredTokenHeader
	} else if version != 0 {
		return nil, nil, identity.ForbiddenError{}
	}
	if !bytes.HasPrefix(plain, []byte(header)) {
		return nil, nil, identity.ForbiddenError{}
	}
	remaining := plain[len(header):]
	if version != 0 {
		var empty [sha256.Size]byte
		if len(remaining) < sha256.Size || bytes.Equal(remaining[:sha256.Size], empty[:]) || matchOrigin != nil && !matchOrigin(remaining[:sha256.Size]) {
			return nil, nil, identity.ForbiddenError{}
		}
		remaining = remaining[sha256.Size:]
	}
	var tokens [2][]byte
	for i := range tokens {
		if len(remaining) < 4 {
			return nil, nil, identity.ForbiddenError{}
		}
		n := binary.BigEndian.Uint32(remaining)
		remaining = remaining[4:]
		if n > providerLoginTokenMaximumBytes || uint64(n) > uint64(len(remaining)) || i == 0 && n == 0 {
			return nil, nil, identity.ForbiddenError{}
		}
		tokens[i] = remaining[:n:n]
		remaining = remaining[n:]
	}
	if len(remaining) != 0 {
		return nil, nil, identity.ForbiddenError{}
	}
	return tokens[0], tokens[1], nil
}
