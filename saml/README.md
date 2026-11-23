# Enterprise SAML service-provider wire operations

`github.com/faustbrian/go-sso/saml` is an experimental optional Go 1.27 module.
It can export SP metadata and produce a signed HTTP-Redirect `AuthnRequest`.
It does not yet accept an inbound SAML response or complete sign-in.

- `ExportSPMetadata` publishes one default HTTP-POST assertion consumer URL and
  one to five approved public RSA signing certificates in DER format. It does
  not advertise unsolicited sign-in or single logout. Serve it only for the
  explicitly configured provider and route.
- `NewAuthnRedirectProfile` binds the exact approved SP entity ID, ACS and IdP
  Redirect endpoint. Reuse those same entity and ACS values in metadata.
- `AuthnRedirectProfile.Redirect` takes the original request ID and issue time
  from the admitted SSO transaction and borrows the selected signer. If the
  owner issued a RelayState capability, pass its opaque handle unchanged;
  otherwise leave it empty. The wire layer creates no replay protection.

After the caller has authenticated the active provider, committed the
transaction, and selected a signer matching the registered SP certificate:

```go
result, err := profile.Redirect(ctx, saml.AuthnRequest{
    ID:         originalRequestID,
    IssuedAt:   originalIssueTime,
    RelayState: originalRelayHandle,
}, installedSigner)
if err != nil {
    return err
}
location, err := result.URL()
if err != nil {
    return err
}
// Disclose location to the admitted browser only. Do not log it.
```

The signed input follows [OASIS SAML Bindings §3.4.4.1](https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf)
and uses [RFC 6931 §2.3.10](https://www.rfc-editor.org/rfc/rfc6931.html#section-2.3.10)
fixed RSA-PSS-SHA256 parameters. The signer is borrowed synchronously and must
have bounded latency. Provider authority, the browser callback, replay,
account linking, and session issuance belong to other owners.
