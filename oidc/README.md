# Enterprise OpenID Connect relying party

This optional adapter supports static OIDC metadata with an exact shared HTTPS
callback, authorization code, query response, nonce, and S256. It uses the
Golib signed ID-token validator with a trusted configured signing-key set.

1. After committing the original login transaction, construct the adapter with
   its provider profile, generation, original state, nonce, challenge, and
   cutoff. Call `Start` to render the provider redirect; no key or credential
   is needed for this step.
2. Authenticate the browser and callback route, then acquire the original
   one-use reservation. Construct the completion adapter with that transaction
   and a short-lived `CallbackCustody` tied to the reservation. Call `Complete`
   with the bounded buffered query; it owns closing the payload.
   If the transport has already parsed the query under the exact selected
   profile, call `CompleteParsed` instead. The transport owns destroying
   that custody after the synchronous call. Both paths share one attempt.
3. Use the signed subject and selected claim evidence to apply current
   organization and session policy. The token hook borrows the exchanged
   material for encrypted staging and returns before the adapter destroys it.
   If the operation is unsettled, reconcile the original command. Do not send
   its code again, including by constructing a second adapter.

Claim selection uses `sub` as the stable subject and optional exact scalar
names for email, verification, and display name. Email has verification
authority only when the selected signed Boolean is true and the email is
nonempty. Null, absent, false, and empty are not interchangeable. Signed
`auth_time`, when present, is distinct from `iat` or observation time.
Trusted native policies can request additional scalar observations via
`AdditionalClaims`. These are available through the original validated
identity in the token hook and do not widen the mapped assertion.

This module does not own HTTP routes, durable reservation or token storage,
provider discovery, UserInfo, local account or session policy, or provider
token refresh/revocation. Native PostgreSQL and Reference can opt in to this
sign-in adapter. It does not perform provider logout itself.

## RP-initiated logout wire support

`NewRPLogoutProfile` selects an explicit HTTPS provider logout endpoint,
client ID and registered RP callback. This profile follows the
[RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)
client-ID path without an ID-token hint. Select it only for a provider that
recognizes the registered callback for that client. The provider may require
the user to confirm logout, and a correlated browser return is not independent
proof that a provider session no longer exists.

The native owner generates and durably binds one-use state to the original
provider, session, version, registered callback, and final application
return target. Only after acknowledged local revocation and state persistence
may it disclose `RPLogoutProfile.Redirect`. On return,
`ParseRPLogoutCallback` discards provider error text and
`RPLogoutCallback.OutcomeFor` compares exact state and trusted route.
These helpers do not revoke or renew any session, persist or consume state,
or expose HTTP routes.
