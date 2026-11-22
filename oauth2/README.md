# Enterprise OAuth 2.0 sign-in

`github.com/faustbrian/go-sso/oauth2` is an experimental
[`sso.ProtocolAdapter`](../README.md) for an installed OAuth 2.0 provider
without OIDC. It supports the code flow with query response, S256 and the
exact RFC 9207 issuer on a shared callback. A separate configured HTTPS
identity endpoint provides the stable subject; an access token is not proof
of identity.

## Compose with an SSO coordinator

1. Build `Config` from the coordinator's original transaction, enabled
   provider, installed credential generation, state, S256 challenge and
   capability expiry. `Start` needs no `CallbackCustody` or client secret.
2. Authenticate and reserve the original callback before constructing
   callback custody. Supply the earliest original authority cutoff, a
   synchronous borrower for the exact client secret and decrypted verifier,
   and a synchronous token handoff. Invoke `Complete` with the same
   transaction projection and the buffered, bounded raw query. The adapter
   closes the query on every path; a query that exhausts its byte budget is
   rejected rather than truncated.
3. Use `AcceptTokens` to stage encrypted tokens under the coordinator's
   original command. The adapter destroys its copy when the call ends.
   Apply account, membership, mapping and session policy in the coordinator.
   Honor the evidence's original expiry. If the exchange is ambiguous or
   `ErrExchangeUnsettled` is returned, reconcile the original command; do
   not resend the code.

This module does not register HTTP routes, change native SSO selection, store
replay state, implement a vault, or refresh or revoke provider tokens. Only
the selected static HTTPS profile has executable coverage; other provider
profiles are not implied.

Run the local TLS consumer checks with `GOWORK=off go test -race .`.
