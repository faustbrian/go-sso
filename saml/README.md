# Enterprise SAML service-provider wire operations

`github.com/faustbrian/go-sso/saml` is an experimental optional Go 1.27 module.
It can import approved IdP metadata, export SP metadata, produce a signed
HTTP-Redirect `AuthnRequest`, and validate the signed HTTP-POST `SAMLResponse`
for an original SP request. It does not install HTTP routes, consume replay
state, or complete sign-in.

## Import an approved IdP document

`ImportIDPMetadata(ctx, document, expectedEntityID, approvedSHA256, now)`
returns the explicit entity ID, Redirect endpoint and DER signing certificates
for native SAML registration. Obtain the exact entity and SHA-256 digest
through independent configuration approval. Hashing an untrusted download
and passing that hash to the importer does not authenticate the document.
The importer makes no network requests or provider state changes. Unlisted
roles, endpoints and encryption keys cannot stand in for the selected profile.

Use `FetchIDPMetadata(ctx, sourceURL, expectedEntityID, approvedSHA256)` for an
exact approved HTTPS source URL. Fetch only during provider setup, not during
sign-in. It uses verified TLS and direct public-address connections, follows
no redirects, and checks the raw document against the approved digest before
returning the same registration fields. A changed document requires fresh
approval. Neither API activates or refreshes a provider.

## Publish SP metadata and start sign-in

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

Both login verifiers expose `LogoutSubject()` separately from `Evidence()`.
It preserves the signed NameID value, format, optional qualifiers and optional
session index. Bind it to the issued session in the native owner; it does not
authorize a session read or revocation.

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
responses, encrypted assertions and single logout are not accepted by this
SP-initiated profile.

`Evidence` explicitly returns the selected subject, exact Response/Assertion
ID pair, and earliest verified cutoff. The native coordinator must reserve
both IDs and consume the original browser correlation before issuing a
session. An unsuccessful validation never returns evidence. Neither a good
signature nor the returned IDs are an authentication grant on their own.

Use `profile.WithAssertionMapping(provider, mapping)` to explicitly select
the same installed, enabled provider and mapping version as the signing
profile. After `Validate`, call `result.ProtocolAssertion()` for the detached
`sso.ProtocolAssertion`. Both SP- and IdP-initiated profiles support this opt-in;
the IdP profile also requires the provider ID to match its configured ACS.
Without the opt-in, `Evidence()` and `LogoutSubject()` work as before and
`ProtocolAssertion()` returns `ErrInvalidInput`.

The signed NameID is the stable subject and the `name_id` observation. The
configured email, email-verification and display names are exact, distinct
`Attribute` names, never aliases from `FriendlyName`. Selected attributes carry
the configured provider and mapping versions with the exact authenticated IdP
issuer. Missing, explicitly nil and empty string are distinct. This scalar
profile rejects duplicates, arrays, selected complex values and encrypted
attributes that could conceal a selected name. An `xsi:type`, where supplied,
must agree with the locally selected string or boolean decoder. A signed value
does not by itself verify email or confer authority; the SSO owner applies
current policy and owns replay and session effects. See [SAML Core §§2.3.3,
2.7.3](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf).

For an explicitly selected IdP-initiated protocol integration, construct
`NewIDPInitiatedPOSTResponseProfile` with the approved issuer, audience,
external HTTPS origin, canonical provider ID, signing pins and maximum
message age. It derives the separate `/saml2/{provider_id}/idp-init`
destination. Both `InResponseTo` attributes must be absent, as profiled from
[OASIS SAML Profiles §4.1.5](https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf#page=20).
Call `Validate` with the encoded response and a trusted current time. The
earliest signed issue time caps evidence freshness independently of clock
skew. This returns protocol evidence only. Do not advertise the endpoint or
issue a session without explicit enablement, current provider/domain
authority, independent browser confirmation and native replay settlement.

XML parsing and exclusive canonicalization use `github.com/knroy/go-xml/v2`
at v2.3.1, the exact reviewed source below. The signed nodes are retained in
that tree and not serialized and parsed again.

- [Canonicalization source v2.3.1](https://github.com/knroy/go-xml/tree/97fbb7fcad33cc8dc92f03c3ede289222a51de61)
- [OASIS SAML Core](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf)
- [W3C XML Signature 1.1](https://www.w3.org/TR/xmldsig-core1/)

## Compose Single Logout wire messages

`ImportIDPMetadataWithSingleLogout` selects the approved IdP Redirect
request destination and POST response destination separately. When the
native configuration actually installs the SP's inbound POST route, use
`ExportSPMetadataWithEndpoints` with `SingleLogout: true` to advertise it.

Use `NewLogoutRedirectProfile` to sign a request after the native owner
selects the original session's strongly matching NameID and session index.
`NewLogoutPOSTProfile` verifies inbound messages at the exact SP destination.
Only its request result contains a logout target. Its response result contains
an authenticated request ID and status; resolve the local session exclusively
from the outstanding request. Neither wire operation revokes a local session,
reserves replay state or proves that the IdP revoked its session.
