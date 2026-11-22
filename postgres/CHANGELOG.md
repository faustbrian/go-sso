# Changelog

## Unreleased

- Require update-only owner evidence binding the exact policy context, native
  actor authorization epoch and earliest absolute decision expiry; retain the
  original capped deadline through preparation and final commit.
- Reject complete oversized metadata successors before keyed custody, including
  retained domains and JSON escaping. Keep legacy registration bounds unchanged
  and bound update preparation encode/decode consistently for near-limit inputs.

- Add organization-bound disabled static-OIDC metadata/mapping updates through
  the existing native coordinator, current session/organization authority,
  protected counters, encrypted preparation, required audit and lifecycle outbox.
- Add the forward-only `ProviderUpdateMigrationSource`. Install it before new
  provider service code; legacy v1 columns remain unchanged while scoped reads
  project the nullable successor. Original registration retries retain v1 receipts.

- Add opt-in HTTPS method custody on the original encrypted challenge row through
  a separate additive migration and `NewHTTPSStore`. Apply the extension before
  enabling the constructor; historical DNS rows and old DNS-only construction
  remain compatible, while old readers cannot reinterpret HTTPS ciphertext.

- Enforce the provider-registration domain count of 1 through 128 before
  original request preparation and in persisted pending-domain constraints.
- Add native current-organization administration of disabled, metadata-only
  static OIDC providers, scoped bounded get/list, exact-original keyed retries
  and ambiguous-commit recovery through the existing identity coordinator.
- Add the independent forward-only `ProviderMigrationSource`; apply before
  enabling provider callers. It stores envelope-encrypted configuration in a
  separate namespace, enforces owner/issuer uniqueness and retains data on code
  rollback. Existing DNS migrations and stored challenges are unchanged.
- Add encrypted immutable DNS challenge persistence and original safe recovery
  binding custody, composed with the existing native organization evidence
  facade as sole commit/current-proof authority.
- Add the opt-in new-table migration; apply it before enabling DNS callers.
  Code rollback retains original encrypted challenge/recovery data.
