package saml

import (
	"context"
	"crypto"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/faustbrian/go-sso"
)

// SPProtocolAdapterConfig binds one admitted SP-initiated login command. Source
// all fields from the same original, authenticated owner state. The request,
// capability cutoff, activated credential generation and mapped profiles must
// be retained from that state, never reconstructed from a callback.
//
// Clock and Signer are borrowed, concurrency-safe collaborators. Signer may be
// nil for completion-only use; otherwise it must provide bounded synchronous
// signing and remain installed for CredentialGeneration. No key bytes are
// copied or owned here. Browser correlation, optional RelayState validation,
// provider admission and replay reservation remain the coordinator's work.
type SPProtocolAdapterConfig struct {
	Transaction          sso.LoginTransaction
	CredentialGeneration uint64
	Request              AuthnRequest
	CapabilityExpiresAt  time.Time
	Clock                interface{ Now() time.Time }
	RedirectProfile      AuthnRedirectProfile
	ResponseProfile      POSTResponseProfile
	Signer               crypto.Signer
}

// SPProtocolAdapter implements sso.ProtocolAdapter for one original login.
// Its configuration is immutable and concurrent calls have no shared mutable
// state. It does not create, refresh or consume capabilities, reserve replay
// IDs, or grant local identity/session authority. Zero and nil adapters deny.
// It borrows the configured signer but retains no copied secret material.
type SPProtocolAdapter struct {
	config   SPProtocolAdapterConfig
	deadline time.Time
}

var _ sso.ProtocolAdapter = (*SPProtocolAdapter)(nil)

// NewSPProtocolAdapter validates the exact original transaction and profile
// scope. It performs no IO or signing. The retained deadline is the earlier
// original transaction/capability cutoff and is never renewed by an operation.
func NewSPProtocolAdapter(config SPProtocolAdapterConfig) (*SPProtocolAdapter, error) {
	if config.Clock == nil || !config.Request.valid() || !validSAMLTime(config.CapabilityExpiresAt) {
		return nil, ErrInvalidInput
	}
	now := config.Clock.Now()
	generation, err := config.Transaction.ValidateAt(now)
	if err != nil || generation != config.CredentialGeneration || config.Transaction.Protocol != "saml" ||
		!validSAMLTime(config.Request.IssuedAt) || now.Before(config.Request.IssuedAt) || !now.Before(config.CapabilityExpiresAt) {
		return nil, ErrInvalidInput
	}
	redirect, response, transaction := config.RedirectProfile, config.ResponseProfile, config.Transaction
	if redirect.endpoint.Host == "" || len(response.signing) == 0 || response.mapping == nil ||
		transaction.Callback.String() != redirect.config.AssertionConsumerURL || transaction.Callback.String() != response.acs ||
		redirect.config.SPEntityID != response.sp {
		return nil, ErrInvalidInput
	}
	mapping := response.mapping
	if string(mapping.provenance.ProviderID) != transaction.ProviderID || mapping.organizationID != transaction.OrganizationID ||
		mapping.provenance.ProviderProfileVersion != transaction.ProviderVersion || mapping.mappingVersion != transaction.MappingVersion {
		return nil, ErrInvalidInput
	}
	deadline := config.CapabilityExpiresAt
	if transaction.ExpiresAt.Before(deadline) {
		deadline = transaction.ExpiresAt
	}
	return &SPProtocolAdapter{config: config, deadline: deadline}, nil
}

// Start signs the retained AuthnRequest using only the configured Redirect
// endpoint. The unchanged command must still belong to the original scope.
// Cancellation and both original cutoffs are checked before disclosure; the
// synchronous signer must itself return within its caller-owned latency bound.
func (a *SPProtocolAdapter) Start(ctx context.Context, command sso.ProtocolStartCommand) (sso.ProtocolStartResult, error) {
	work, cancel, err := a.begin(ctx, command.Transaction)
	if err != nil {
		return sso.ProtocolStartResult{}, err
	}
	defer cancel()
	if generation, err := command.ValidateAt(a.config.Clock.Now()); err != nil || generation != a.config.CredentialGeneration {
		return sso.ProtocolStartResult{}, ErrInvalidInput
	}
	redirect, err := a.config.RedirectProfile.Redirect(work, a.config.Request, a.config.Signer)
	if err != nil {
		return sso.ProtocolStartResult{}, err
	}
	destination, err := redirect.URL()
	if err != nil {
		return sso.ProtocolStartResult{}, err
	}
	if err := a.validAt(work, a.config.Clock.Now()); err != nil {
		return sso.ProtocolStartResult{}, err
	}
	result := sso.ProtocolStartResult{Redirect: destination, ExpiresAt: a.deadline}
	if err := result.ValidateFor(a.config.Transaction, a.config.Clock.Now(), a.config.CapabilityExpiresAt); err != nil {
		return sso.ProtocolStartResult{}, ErrInvalidInput
	}
	return result, nil
}

// Complete returns the mapped signed assertion from CompleteVerified's same
// validation core. It never reserves replay IDs or applies account policy.
// Payload ownership and cancellation requirements are those of CompleteVerified.
func (a *SPProtocolAdapter) Complete(ctx context.Context, callback sso.ProtocolCallback) (sso.ProtocolAssertion, error) {
	verified, err := a.CompleteVerified(ctx, callback)
	if err != nil {
		return sso.ProtocolAssertion{}, err
	}
	return verified.ProtocolAssertion()
}

// CompleteVerified consumes only the already extracted Base64 SAMLResponse,
// not an HTTP form or HTML. It returns replay IDs, signed NameID and mapped
// observations from one parse, without replay reservation or login authority.
// The coordinator must first admit the exact route/browser/RelayState and
// reserve the transaction; it must atomically reserve the returned replay pair
// before applying policy or issuing authority.
//
// Payload transfers to this call and is closed exactly once on every return,
// including invalid scope and cancellation. Reads are synchronous; the caller
// must supply a buffered reader or one whose blocking Read is bounded and
// observes cancellation/deadlines itself. No detached reader goroutine or
// concurrent Close is started. At most min(MaximumBytes, protocol limit + 1)
// bytes are read; hitting that bound is denied because EOF was not established.
func (a *SPProtocolAdapter) CompleteVerified(ctx context.Context, callback sso.ProtocolCallback) (VerifiedPOSTResponse, error) {
	if callback.Payload == nil {
		return VerifiedPOSTResponse{}, ErrInvalidInput
	}
	defer callback.Payload.Close()
	work, cancel, err := a.begin(ctx, callback.Transaction)
	if err != nil {
		return VerifiedPOSTResponse{}, err
	}
	defer cancel()
	maximum := min(callback.MaximumBytes, uint64(maximumPOSTBase64Bytes+1))
	if maximum == 0 {
		return VerifiedPOSTResponse{}, ErrInvalidInput
	}
	raw, readErr := io.ReadAll(io.LimitReader(spProtocolPayloadReader{ctx: work, reader: callback.Payload}, int64(maximum)))
	defer clear(raw)
	now := a.config.Clock.Now()
	if err := a.validAt(work, now); err != nil {
		return VerifiedPOSTResponse{}, err
	}
	if readErr != nil || uint64(len(raw)) == maximum {
		return VerifiedPOSTResponse{}, ErrInvalidInput
	}
	verified, err := a.config.ResponseProfile.Validate(work, POSTResponseInput{
		SAMLResponse: string(raw), RequestID: a.config.Request.ID, IssuedAt: a.config.Request.IssuedAt,
		ExpiresAt: a.deadline, Now: now,
	})
	if err != nil {
		return VerifiedPOSTResponse{}, err
	}
	// Parsing/signature verification can cross an exclusive local or remote
	// cutoff. Neither elapsed work nor a retry renews the original window.
	now = a.config.Clock.Now()
	if err := a.validAt(work, now); err != nil {
		return VerifiedPOSTResponse{}, err
	}
	evidence, err := verified.Evidence()
	if err != nil || !now.Before(evidence.ValidUntil) {
		return VerifiedPOSTResponse{}, ErrInvalidInput
	}
	return verified, nil
}

func (a *SPProtocolAdapter) begin(ctx context.Context, transaction sso.LoginTransaction) (context.Context, context.CancelFunc, error) {
	if ctx == nil || a == nil || a.config.Clock == nil || transaction != a.config.Transaction {
		return nil, nil, ErrInvalidInput
	}
	now := a.config.Clock.Now()
	if err := a.validAt(ctx, now); err != nil {
		return nil, nil, err
	}
	work, cancel := context.WithTimeout(ctx, a.deadline.Sub(now))
	return work, cancel, nil
}

func (a *SPProtocolAdapter) validAt(ctx context.Context, now time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	generation, err := a.config.Transaction.ValidateAt(now)
	if err != nil || generation != a.config.CredentialGeneration || now.Before(a.config.Request.IssuedAt) || !now.Before(a.deadline) {
		return ErrInvalidInput
	}
	return nil
}

type spProtocolPayloadReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r spProtocolPayloadReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

func (SPProtocolAdapterConfig) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "saml.SPProtocolAdapterConfig(redacted)")
}
func (SPProtocolAdapterConfig) LogValue() slog.Value {
	return slog.StringValue("saml.SPProtocolAdapterConfig(redacted)")
}
func (SPProtocolAdapterConfig) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (SPProtocolAdapterConfig) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

func (SPProtocolAdapter) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "saml.SPProtocolAdapter(redacted)")
}
func (SPProtocolAdapter) LogValue() slog.Value {
	return slog.StringValue("saml.SPProtocolAdapter(redacted)")
}
func (SPProtocolAdapter) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (SPProtocolAdapter) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
