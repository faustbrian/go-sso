# Changelog

## Unreleased

- Add encrypted immutable DNS challenge persistence and original safe recovery
  binding custody, composed with the existing native organization evidence
  facade as sole commit/current-proof authority.
- Add the opt-in new-table migration; apply it before enabling DNS callers.
  Code rollback retains original encrypted challenge/recovery data.
