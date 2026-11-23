# Changelog

## Unreleased

- Add the static RP-initiated logout wire profile for a configured client ID
  and preregistered callback. Render the original one-use state and classify
  its bounded return without storing state or revoking sessions.

- Borrow an already parsed OIDC query under the exact selected profile and
  preserve original verified identity and configured policy-only claims for
  the coordinator, without changing mapped attributes or exchange custody.

- Add standalone static enterprise OIDC code sign-in with original SSO
  transaction binding, verified signed identity and timestamps, and
  coordinator-owned token handoff.
- Add typed RP-initiated logout result variants. These values do not perform
  local or provider logout.
