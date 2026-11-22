# Changelog

## Unreleased

- Add the standalone enterprise OAuth 2.0 sign-in adapter. Render the original
  code/S256 redirect without credentials, require the exact issuer and state,
  use the configured identity endpoint, and return bounded claims and a
  synchronous token handoff to the reserving SSO coordinator.
