# Changelog

## Unreleased

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
