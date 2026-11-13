# Changelog

## Unreleased

- Add an experimental DNS-only domain challenge workflow bound to current
  organization authority, existing capabilities and explicit SSO policy.
- Keep domain proof commits and current reads in the organization owner;
  recover original ambiguous attempts without repeating DNS or inferring
  rollback from an absent/denied command lookup.

