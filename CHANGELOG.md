# Changelog

## Unreleased

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
