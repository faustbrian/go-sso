# Changelog

## Unreleased

- Add opt-in signed SAML assertion mapping for SP and IdP-initiated login.
  Return the exact NameID, issuer and selected scalar observations, preserving
  absent, nil and empty values without granting email, membership or role trust.

- Preserve an installed URN IdP identifier in signed LogoutRequests. The
  browser redirect destination still requires the same approved HTTPS URL.

- Add the comparable local-session revocation projection with distinct
  committed, not-committed and unknown outcomes. Validation preserves the exact
  bounded session identity and does not establish authority or persistence.

- Sign outbound HTTP-POST LogoutResponse messages for the approved IdP
  response destination. Preserve the original request correlation and selected
  Success or PartialLogout status without exposing signing material.

- Verify signed inbound HTTP-POST LogoutRequest and LogoutResponse as
  different message types. A response exposes its signed correlation and
  status, never a subject or session selector.

- Discover the distinct approved IdP logout destinations and optionally
  advertise the SP's canonical POST-only Single Logout endpoint.

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
