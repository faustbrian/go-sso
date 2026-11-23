# Changelog

## Unreleased

- Sign an outbound SP LogoutRequest with the fixed HTTP-Redirect profile.
  Preserve the authenticated NameID and require its correlated SessionIndex.
  Both login verifiers can return the exact signed logout subject context
  without changing the existing login evidence contract.

- Add opt-in SP metadata export for an installed IdP-initiated SAML
  destination. The extra exact HTTP-POST ACS is non-default; ordinary SP
  metadata continues to advertise only its existing default ACS.

- Add a distinct signed IdP-initiated POST verifier that requires an exact
  derived destination, no request correlation fields, and a short signed
  issue-time window. It returns detached evidence and does not enable login.

- Fetch approved IdP metadata over bounded, direct HTTPS before importing the
  exact digest-pinned document. No automatic redirect, trust update or activation.

- Import bounded offline IdP metadata only when its exact entity and raw
  SHA-256 digest match separate approval. Return detached explicit Redirect
  registration inputs, with exclusive entity/role expiry checks and no trust
  discovery, metadata fetching, provider activation or certificate-time claim.

- Project the exact public signing certificate and original exclusive expiry
  from a validated active SP signing credential bundle. The returned DER is
  detached from secret storage; no private key or provider authority is exposed.

- Sign an original AuthnRequest directly with a validated SP signing credential
  bundle without exporting its parsed private key. Return the certificate's
  original exclusive expiry for transaction fencing; the caller retains
  ownership of clearing the plaintext bundle.

- Add a bounded versioned plaintext codec for a validated two-prime RSA SP signing key
  and matching active certificate. Callers must seal and clear the returned
  bytes; validation returns the certificate's original exclusive expiry and
  does not establish trust chains, provider authority or activation.

- Add stateless validation of selected IdP entity, Redirect endpoint and pinned
  signing certificates for protocol-neutral provider registration composition.
  It shares the response certificate policy without granting provider authority
  or checking wall-clock certificate validity.

- Validate a signed SP-initiated HTTP-POST Response and its exact signed
  Assertion against pinned IdP certificates and the original request. Return
  a selected NameID and the replay ID pair without issuing a session.

- Add signed SP-initiated AuthnRequest rendering and SP metadata export for a
  configured HTTP-POST assertion consumer endpoint. This does not enable
  receiving SAML responses or issuing identity sessions.
