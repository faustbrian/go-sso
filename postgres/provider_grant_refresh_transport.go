package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"slices"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
)

// ProviderGrantRefreshOutcome describes one provider attempt, not whether the
// caller observed the local settlement. A successor exists only on success.
type ProviderGrantRefreshOutcome string

const (
	ProviderGrantRefreshRotated  ProviderGrantRefreshOutcome = "rotated"
	ProviderGrantRefreshRetained ProviderGrantRefreshOutcome = "retained"
	ProviderGrantRefreshRejected ProviderGrantRefreshOutcome = "rejected"
	ProviderGrantRefreshRefused  ProviderGrantRefreshOutcome = "refused"
	ProviderGrantRefreshUnknown  ProviderGrantRefreshOutcome = "unknown"
	ProviderGrantRefreshNotSent  ProviderGrantRefreshOutcome = "not_sent"
)

type providerGrantRefreshPreparation struct {
	Outcome   ProviderGrantRefreshOutcome
	Successor *providerGrantRefreshSuccessor
}

type providerGrantRefreshSuccessor struct {
	ReceivedAt, AccessExpiresAt time.Time
	GrantedScopes               []string
	ScopeReported               bool
	Ciphertext                  []byte
}

func (providerGrantRefreshPreparation) Format(w fmt.State, _ rune) {
	_, _ = fmt.Fprint(w, "providerGrantRefreshPreparation(redacted)")
}

func (p providerGrantRefreshPreparation) clear() {
	if p.Successor != nil {
		clear(p.Successor.Ciphertext)
	}
}

func (p providerGrantRefreshPreparation) validFor(original providerLoginStoredTokenBinding) bool {
	switch p.Outcome {
	case ProviderGrantRefreshRotated, ProviderGrantRefreshRetained:
		if p.Successor == nil || len(p.Successor.Ciphertext) == 0 || len(p.Successor.Ciphertext) > 65536 {
			return false
		}
		binding, err := p.Successor.binding(original)
		if err != nil {
			return false
		}
		_, err = binding.aad()
		return err == nil
	case ProviderGrantRefreshRejected, ProviderGrantRefreshRefused, ProviderGrantRefreshUnknown, ProviderGrantRefreshNotSent:
		return p.Successor == nil
	default:
		return false
	}
}

func (s providerGrantRefreshSuccessor) binding(original providerLoginStoredTokenBinding) (providerLoginStoredTokenBinding, error) {
	if original.Version == math.MaxUint64 || s.ReceivedAt.Before(original.ReceivedAt) {
		return providerLoginStoredTokenBinding{}, identity.ForbiddenError{}
	}
	for _, scope := range s.GrantedScopes {
		if !slices.Contains(original.GrantedScopes, scope) {
			return providerLoginStoredTokenBinding{}, identity.ForbiddenError{}
		}
	}
	next := original
	next.Version++
	next.ReceivedAt, next.AccessExpiresAt = s.ReceivedAt, s.AccessExpiresAt
	next.GrantedScopes, next.ScopeReported = s.GrantedScopes, s.ScopeReported
	return next, nil
}

func (s *ProviderLoginService) prepareProviderGrantRefresh(ctx context.Context, binding providerLoginStoredTokenBinding, ciphertext []byte,
	attempt identity.CommandID, generation uint64, transport StaticOAuth2CompletionProfile,
) (out providerGrantRefreshPreparation, err error) {
	if binding.Version == math.MaxUint64 {
		return out, identity.ForbiddenError{}
	}
	digest := sha256.Sum256(ciphertext)
	err = s.withInstalledOAuth2GrantProvider(ctx, binding, transport, "", func(ctx context.Context, provider *oauth.SharedOAuth2UserInfoProvider) error {
		refresh, err := oauth.NewSharedOAuth2RefreshProvider(provider)
		if err != nil {
			return err
		}
		return s.borrowStoredOAuth2Tokens(ctx, binding, ciphertext, func(ctx context.Context, _, priorRefresh []byte) error {
			custody, err := oauth.NewRefreshToken(priorRefresh, provider.Profile(), binding.GrantedScopes)
			if err != nil {
				return identity.ForbiddenError{}
			}
			defer custody.Destroy()
			claim := providerGrantFenceClaim{Tenant: binding.Account.TenantID, Callback: binding.Callback, TokenVersion: binding.Version,
				CiphertextDigest: digest, Attempt: attempt, Operation: providerGrantRefreshOperation, Generation: generation}
			if err := claimProviderGrantFence(ctx, s.router.pool.Raw(), claim); err != nil {
				return err
			}
			// The refresh credential can still carry the original broader grant.
			// Request today's persisted scope explicitly, even on a retained token.
			result, err := refresh.RefreshWithExplicitScope(ctx, custody)
			defer result.Tokens.Destroy()
			if err != nil {
				out.Outcome = classifyProviderGrantRefreshFailure(err)
				return nil
			}
			out, err = s.sealProviderGrantRefreshSuccessor(ctx, binding, digest, priorRefresh, result)
			return err
		})
	})
	if err != nil {
		if out.Successor != nil {
			clear(out.Successor.Ciphertext)
		}
		return providerGrantRefreshPreparation{}, err
	}
	return out, nil
}

func classifyProviderGrantRefreshFailure(err error) ProviderGrantRefreshOutcome {
	var remote *oauth.Error
	if errors.As(err, &remote) {
		switch remote.Kind() {
		case oauth.RefreshGrantRejected:
			return ProviderGrantRefreshRejected
		case oauth.Refused:
			return ProviderGrantRefreshRefused
		case oauth.InvalidInput, oauth.Unavailable:
			return ProviderGrantRefreshNotSent
		}
	}
	return ProviderGrantRefreshUnknown
}

func (s *ProviderLoginService) sealProviderGrantRefreshSuccessor(ctx context.Context, original providerLoginStoredTokenBinding,
	predecessorDigest [32]byte, priorRefresh []byte, reply oauth.RefreshResult,
) (providerGrantRefreshPreparation, error) {
	if !slices.Equal(reply.Tokens.RequestedScopes(), original.GrantedScopes) || predecessorDigest == ([32]byte{}) {
		return providerGrantRefreshPreparation{}, identity.ForbiddenError{}
	}
	granted := reply.Tokens.GrantedScopes()
	// The stored flag also describes known inherited scope from an earlier
	// response; omission must not widen that scope back to configured scopes.
	successor := providerGrantRefreshSuccessor{ReceivedAt: reply.Tokens.ReceivedAt().UTC(), AccessExpiresAt: reply.Tokens.ExpiresAt().UTC(),
		GrantedScopes: granted, ScopeReported: reply.Tokens.ScopeReported() || !slices.Equal(granted, original.RequestedScopes)}
	binding, err := successor.binding(original)
	if err != nil {
		return providerGrantRefreshPreparation{}, err
	}
	aad, err := binding.aad()
	if err != nil {
		return providerGrantRefreshPreparation{}, err
	}
	var outcome ProviderGrantRefreshOutcome
	err = reply.Tokens.Use(ctx, func(ctx context.Context, borrowed oauth.TokenBytes) error {
		refresh := borrowed.RefreshToken
		switch reply.Rotation {
		case oauth.RotatedRefreshToken:
			outcome = ProviderGrantRefreshRotated
		case oauth.RetainOriginalRefreshToken:
			if len(refresh) != 0 {
				return identity.ForbiddenError{}
			}
			outcome, refresh = ProviderGrantRefreshRetained, priorRefresh
		default:
			return identity.ForbiddenError{}
		}
		if len(borrowed.AccessToken) == 0 || len(borrowed.AccessToken) > providerLoginTokenMaximumBytes ||
			len(refresh) == 0 || len(refresh) > providerLoginTokenMaximumBytes || len(borrowed.IDToken) != 0 {
			return identity.ForbiddenError{}
		}
		frame := make([]byte, 0, len(providerLoginStoredTokenHeader)+sha256.Size+8+len(borrowed.AccessToken)+len(refresh))
		defer func() { clear(frame) }()
		frame = append(frame, providerLoginStoredTokenHeader...)
		frame = append(frame, predecessorDigest[:]...)
		for _, token := range [][]byte{borrowed.AccessToken, refresh} {
			frame = binary.BigEndian.AppendUint32(frame, uint32(len(token)))
			frame = append(frame, token...)
		}
		successor.Ciphertext, err = s.payload.seal(ctx, aad, frame, 65536)
		return err
	})
	if err != nil {
		clear(successor.Ciphertext)
		return providerGrantRefreshPreparation{}, err
	}
	return providerGrantRefreshPreparation{Outcome: outcome, Successor: &successor}, nil
}
