package postgres

import (
	"context"
	"crypto/hmac"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-sso"
)

func providerOIDCCallbackOperation() identity.FeatureOperation {
	return identity.FeatureOperation{
		Owner: "sso/oidc", OperationID: providerOIDCCallback, SchemaID: "sso-enterprise-oidc-callback-v1", SchemaVersion: 1,
		RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow,
	}
}

// Freeze the original browser and exact code without persisting either the
// raw code or a user selection. The callback ID was allocated by the original
// sign-in start. A different code has the same ID but a different keyed intent,
// so it cannot replace an existing reservation. receivedRedirect comes from
// the trusted transport route, never from callback parameters or headers.
func (s *ProviderLoginService) prepareProviderLoginCallbackCommand(ctx context.Context, found providerLoginCallbackLookup, receivedRedirect string, browser ProviderLoginBrowser, input identity.OAuthCallbackInput) (identity.Command, error) {
	if s == nil || ctx == nil || found.CompletedAt != nil || receivedRedirect == "" || receivedRedirect != found.Binding.Metadata.Input.RedirectURI {
		return identity.Command{}, sso.ErrForbidden
	}
	ctx, cancel := context.WithTimeout(ctx, s.config.Coordinator.MaximumDuration)
	defer cancel()
	if _, err := s.authenticateProviderLoginCallbackBrowser(ctx, found, browser); err != nil {
		return identity.Command{}, err
	}
	fields, err := s.providerLoginCallbackIntent(ctx, found, receivedRedirect, browser, input)
	if err != nil {
		return identity.Command{}, err
	}
	metadata := found.Binding.Metadata
	op := providerOIDCCallbackOperation()
	binding := metadata.Input.Command
	binding.CommandID, binding.CorrelationID = metadata.CallbackCommand, string(metadata.CallbackCommand)
	binding.RecordID = string(found.Row.StartCommandID)
	binding.OperationID, binding.SchemaID, binding.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	command, err := identity.NewFeaturePreAuthCommand(identity.FeatureCommandSpec{Operation: op, Binding: binding, Fields: fields}, browser.FlowCookie)
	if err != nil {
		return identity.Command{}, providerError(ctx, err)
	}
	return command, nil
}

// The two profiles bind the identical retained state and provider code rules.
// The complete authenticated metadata includes the original actor and mode.
func (s *ProviderLoginService) providerLoginCallbackIntent(ctx context.Context, found providerLoginCallbackLookup, receivedRedirect string, browser ProviderLoginBrowser, input identity.OAuthCallbackInput) ([]identity.FeatureField, error) {
	metadata := found.Binding.Metadata
	key, retained := s.payload.StateKeys[metadata.StateKey]
	if !retained || key == ([32]byte{}) || metadata.CallbackCommand == found.Row.StartCommandID {
		return nil, sso.ErrForbidden
	}
	frame, err := providerLoginPayloadEncode(metadata)
	if err != nil {
		return nil, sso.ErrUnavailable
	}
	defer clear(frame)
	var intent [32]byte
	err = input.Use(ctx, func(_ context.Context, code, state []byte) error {
		const maximumCodeBytes = 4096 // Bound the selected static OIDC protocol profile.
		if len(code) == 0 || len(code) > maximumCodeBytes || !hmac.Equal(state, []byte(metadata.Public.State)) {
			return sso.ErrForbidden
		}
		intent = providerLoginPayloadMAC(key, metadata.StateKey, "identity.sso.oidc.callback-input.v1", frame,
			[]byte(receivedRedirect), []byte(browser.Origin), []byte(browser.Network.String()), []byte(browser.Device), code, state)
		return nil
	})
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil || intent == ([32]byte{}) {
		return nil, sso.ErrForbidden
	}
	return []identity.FeatureField{{
		Name: "sso.oidc.callback-input", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: intent[:]},
	}}, nil
}
