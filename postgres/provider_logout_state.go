package postgres

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"time"

	identity "github.com/faustbrian/go-identity"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso/oidc"
)

const providerLogoutBindingWireLimit = 65536
const providerLogoutBindingPlainLimit = 16 << 10
const providerLogoutMaximumLifetime = 10 * time.Minute

// Only immutable columns from the exact tenant/key/digest lookup select AAD.
// The callback need not supply an issuer, user, or other authority selector.
type providerLogoutRow struct {
	TenantID        identity.TenantID
	StartCommandID  identity.CommandID
	StateKeyVersion uint32
	StateDigest     [sha256.Size]byte
	IssuedAt        time.Time
	ExpiresAt       time.Time
}

type providerLogoutBinding struct {
	UserID              identity.UserID
	OrganizationID      string
	ProviderID          string
	SessionID           string
	CredentialID        string
	SessionVersion      uint64
	ProviderVersion     uint64
	CredentialVersion   uint64
	CompletionCommandID identity.CommandID
	Protocol            oidc.RPLogoutProfileConfig
	FinalRedirect       string
}

func providerLogoutStateDigest(tenant identity.TenantID, key [32]byte, state oidc.RPLogoutState) [sha256.Size]byte {
	var digest [sha256.Size]byte
	encoded := state.Encode()
	if !providerID(string(tenant)) || key == ([32]byte{}) || encoded == "" {
		return digest
	}
	// The same deployment may retain its login lookup keys during rotation;
	// a separate keyed domain makes a login state unusable as logout custody.
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte("golib.sso.oidc.rp-logout.state.v1\x00"))
	_, _ = mac.Write([]byte(tenant))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(encoded))
	mac.Sum(digest[:0])
	return digest
}

func providerLogoutTime(after time.Time) bool {
	return after.Unix() > 0 && after.Year() <= 9999 && after.Nanosecond()%1000 == 0
}

func (r providerLogoutRow) aad() (envelope.Context, error) {
	_, err := identity.ParseCommandID(string(r.StartCommandID))
	if err != nil || !providerID(string(r.TenantID)) || r.StateKeyVersion == 0 || r.StateDigest == ([32]byte{}) ||
		!providerLogoutTime(r.IssuedAt) || !providerLogoutTime(r.ExpiresAt) || !r.ExpiresAt.After(r.IssuedAt) || r.ExpiresAt.After(r.IssuedAt.Add(providerLogoutMaximumLifetime)) {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	r.IssuedAt, r.ExpiresAt = r.IssuedAt.UTC(), r.ExpiresAt.UTC()
	frame, err := json.Marshal(r)
	if err != nil {
		return envelope.Context{}, identity.UnavailableError{}
	}
	defer clear(frame)
	digest := sha256.Sum256(frame)
	return envelope.NewContext(map[string]string{"profile": "sso-oidc-rp-logout-binding-v1", "row": base64.RawURLEncoding.EncodeToString(digest[:])})
}

func providerLogoutCallbackPath(id string) string {
	// RPLogoutProfile rejects an escaped or ambiguous path. Reject provider
	// identifiers that cannot appear unchanged as exactly one path segment.
	if !providerID(id) || url.PathEscape(id) != id || id == "." || id == ".." {
		return ""
	}
	return "/sso/oidc/" + id + "/logout/callback"
}

func (b providerLogoutBinding) valid(r providerLogoutRow) bool {
	_, err := identity.ParseCommandID(string(b.CompletionCommandID))
	if err != nil || b.CompletionCommandID == r.StartCommandID || !providerID(string(b.UserID)) || !providerID(b.OrganizationID) ||
		!providerID(b.SessionID) || !providerID(b.CredentialID) || b.SessionVersion == 0 || b.SessionVersion == ^uint64(0) ||
		b.ProviderVersion == 0 || b.CredentialVersion == 0 || !validProviderLoginCallback(b.FinalRedirect) {
		return false
	}
	if _, err := oidc.NewRPLogoutProfile(b.Protocol); err != nil {
		return false
	}
	callback, err := url.Parse(b.Protocol.CallbackURI)
	path := providerLogoutCallbackPath(b.ProviderID)
	return err == nil && path != "" && callback.Path == path
}

func sealProviderLogoutBinding(ctx context.Context, codec providerLoginPayloadConfig, row providerLogoutRow, binding providerLogoutBinding) ([]byte, error) {
	if err := providerLoginPayloadContext(ctx); err != nil {
		return nil, err
	}
	aad, err := row.aad()
	if err != nil || codec.Envelope == nil || !binding.valid(row) {
		return nil, identity.ForbiddenError{}
	}
	frame, err := json.Marshal(binding)
	defer clear(frame)
	if err != nil || len(frame) > providerLogoutBindingPlainLimit {
		return nil, identity.UnavailableError{}
	}
	return codec.seal(ctx, aad, frame, providerLogoutBindingWireLimit)
}

func openProviderLogoutBinding(ctx context.Context, codec providerLoginPayloadConfig, row providerLogoutRow, wire []byte) (providerLogoutBinding, error) {
	if err := providerLoginPayloadContext(ctx); err != nil {
		return providerLogoutBinding{}, err
	}
	aad, err := row.aad()
	if err != nil || codec.Envelope == nil {
		return providerLogoutBinding{}, identity.ForbiddenError{}
	}
	frame, err := codec.open(ctx, aad, wire, providerLogoutBindingWireLimit, providerLogoutBindingPlainLimit)
	if err != nil {
		return providerLogoutBinding{}, err
	}
	defer clear(frame)
	var binding providerLogoutBinding
	if json.Unmarshal(frame, &binding) != nil || !binding.valid(row) {
		return providerLogoutBinding{}, identity.ForbiddenError{}
	}
	canonical, err := json.Marshal(binding)
	defer clear(canonical)
	if err != nil || !bytes.Equal(frame, canonical) {
		return providerLogoutBinding{}, identity.ForbiddenError{}
	}
	return binding, nil
}
