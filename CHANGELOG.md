# Changelog

## Unreleased

- Add storage-neutral enterprise OAuth registration intent and identity proof
  policy. Add bounded OIDC/OAuth assertion observations and opaque enterprise
  token correlation without exposing provider tokens. These values do not
  enable OAuth registration, callback exchange or vault access by themselves.

- Add storage-neutral `SigninStartRequest`, `SigninStartResult` and opaque
  immutable `LoginIntent` values. Shape validation preserves exact HTTPS
  callbacks, the original command/key and a resolved session remember policy;
  callback allowlists and current authority remain native responsibilities.
  Formatting and structured logs redact these values, and implicit JSON/text
  serialization fails closed. No callable login or protocol flow is added.

- Add separate storage-neutral provider-disable request/result values and an
  immutable, provider/version-bound drain-or-revoke selector. Shape validation
  rejects inconsistent bindings, exhausted versions and malformed bounded
  reasons; implicit request/disposition disclosure fails closed. These values
  add no callable disable operation or transaction-cleanup evidence.

- Add a typed opt-in SSO discovery service that accepts exact DNS or plain
  email input and projects only the safe provider choice. The trusted owner
  receives only the DNS domain and must establish abuse and route authority.

- Add bounded native domain-route input, deterministic provider selection, and
  redacted snapshots tied to the original organization proof and expiry.

- Add a separate storage-neutral `ProviderEnableRequest` and result, exact
  organization-owned domain-proof checkpoint and immutable enablement-only
  credential checkpoint. Shape validation binds owners, versions and original
  UTC-microsecond credential lifetimes of at most 20 seconds without granting
  current authority; implicit request/checkpoint disclosure fails closed.

- Add a separate storage-neutral disabled-OIDC credential-rotation request and
  result, explicit no-overlap policy and redacting encrypted-reference value.
  References authenticate exact context-bound envelope custody without exposing
  plaintext; native credential writes require their own current trusted
  ingress and fresh credentials-policy admission.

- Add the closed non-secret static-OIDC `ProviderUpdateRequest` and result
  contracts, preserving provider identity and subject-mapping compatibility
  without credentials, enablement, discovery requests or routing semantics.

- Add explicit opt-in HTTPS well-known domain challenges and method-bound
  observations through the existing organization-owned proof transition.
  Existing DNS constructors and request/config literal shapes remain unchanged;
  original retries and unknown recovery never repeat external observation.

- Require 1 through 128 canonical distinct pending domains for provider
  registration; domainless registration is unsupported.
- Add immutable explicit static-OIDC metadata and flat attribute-mapping values,
  with credential-free disabled-provider registration and safe read request and
  result contracts. Registration never verifies domains or enables sign-in.
- Add an experimental DNS-only domain challenge workflow bound to current
  organization authority, existing capabilities and explicit SSO policy.
- Keep domain proof commits and current reads in the organization owner;
  recover original ambiguous attempts without repeating DNS or inferring
  rollback from an absent/denied command lookup.
