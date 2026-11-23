# Changelog

## Unreleased

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
