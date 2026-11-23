# Enterprise SAML service-provider wire operations

`github.com/faustbrian/go-sso/saml` is an experimental optional Go 1.27 module.
It can export SP metadata, produce a signed HTTP-Redirect `AuthnRequest`, and
validate the signed HTTP-POST `SAMLResponse` for an original SP request. It
does not install HTTP routes, consume replay state, or complete sign-in.

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

## Validate the response

Construct `NewPOSTResponseProfile` with the exact SP entity and canonical ACS
also used at start, plus the selected IdP entity ID and active signing
certificates. Pass the original reserved request ID, original issue/expiry
times, trusted current time, and the single form `SAMLResponse` value to
`Validate`. The form, browser correlation, and optional RelayState are still
the caller's responsibility. An unconfigured certificate embedded in XML does
not grant trust.

The selected profile requires signatures on the Response and one Assertion,
RSA-PSS-SHA256 or ECDSA P-256, SHA-256 digests, and exclusive canonicalization
without comments. It accepts a single confirmed bearer subject in persistent
or email-address NameID format. It does not infer verified email or map roles
from incidental attributes. Solicited HTTPS POST, an exact audience and ACS,
and the original request and validity cutoffs are required. Unsolicited
responses, encrypted assertions and single logout are not supported here.

`Evidence` explicitly returns the selected subject, exact Response/Assertion
ID pair, and earliest verified cutoff. The native coordinator must reserve
both IDs and consume the original browser correlation before issuing a
session. An unsuccessful validation never returns evidence. Neither a good
signature nor the returned IDs are an authentication grant on their own.

XML parsing and exclusive canonicalization use `github.com/knroy/go-xml/v2`
at v2.3.1, the exact reviewed source below. The signed nodes are retained in
that tree and not serialized and parsed again.

- [Canonicalization source v2.3.1](https://github.com/knroy/go-xml/tree/97fbb7fcad33cc8dc92f03c3ede289222a51de61)
- [OASIS SAML Core](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf)
- [W3C XML Signature 1.1](https://www.w3.org/TR/xmldsig-core1/)
