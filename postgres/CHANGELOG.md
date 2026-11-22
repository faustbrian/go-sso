# Changelog

## Unreleased

- Add opt-in static OIDC custom-role synchronization for existing linked
  members. Verified boolean claims replace only that provider's grants in the
  session transaction; unrelated grants, previous start ordering, and replay
  boundaries are preserved. An additive migration tracks provider eligibility.

- Add `SigninProtocolProfile` for exact organization/provider selection of
  detached, secret-free validated protocol metadata and effective parser limits.
  This read-only construction snapshot grants no callback or session authority.

- Add read-only callback quota attribution through `SigninCallbackRateSource`.
  Authenticate the original tenant, pending state and browser cookie before
  returning the original provider, flow, callback command and stored lifetime.
  No provider exchange, reservation or credential access is performed.

- Add opt-in native static OIDC callback sign-in for existing linked active
  members. Exchange the original code and S256 verifier once. Bind the issued
  cookie, browser use, encrypted provider-token deposit, audit and session
  lifecycle in one transaction. Definitive refusal erases original verifier
  custody; ambiguous exchange cannot retry or disclose credentials.

- Add opt-in native static OIDC provider disablement. The exact authorized
  mutation stops new sign-in starts and records the selected drain or revoke
  mode and original bounded count with required audit and lifecycle outbox.
  The organization proof and stored credential remain intact. Retries recover
  the original result; a separate confirmed-failure retry can start one fresh
  attempt. Callback enforcement and cleanup are not included.

- Add opt-in native static OIDC sign-in start. An original browser flow binds
  the selected provider and the persisted code/S256 redirect; state issuance,
  required audit and lifecycle effects commit together. The same request
  recovers the original redirect without another grant or a renewed lifetime.
  No callback processing or session issuance is included.

- Add the forward-only `LoginTransactionMigrationSource` for static OIDC
  transaction custody and versioned provider disposition. Install it after
  provider enablement schema and before activating later native writers.
  Existing provider data and operations are unchanged.

- Add native `ProviderDiscovery.ForTenantBrowser` to reject an empty or foreign
  trusted transport tenant before creating discovery authority. Existing direct
  single-tenant `ForBrowser` callers remain compatible.

- Compose opt-in anonymous static OIDC discovery from native verified-domain
  routing, counted risk and canonical audit. Publish only explicitly advertised
  provider choices; this does not authorize enterprise sign-in.

- Add opt-in native static OIDC provider routing with current organization
  proof, exact provider and credential rechecks, and deterministic selection.

- Add opt-in native static OIDC provider enablement with exact organization
  proof, authenticated credential generation, fresh policy and versioned
  atomic audit/outbox. Original-key recovery retains the redacted result.
- Add forward-only `ProviderEnableMigrationSource`; install before enabling
  provider administration. Routing, enforcement and protocol login are unchanged.

- Add separately composed disabled-OIDC client-secret initialization/replacement
  with exact configured-envelope ingress, fresh credentials-only authorization,
  shared provider-version fencing and explicit no overlap. Original commands
  retain native key/preparation/recovery ownership; audit/outbox and credential
  replacement commit atomically without enabling the provider or changing policy.
- Add forward-only `ProviderCredentialsMigrationSource` with bounded new-table
  custody and effect evidence; install before the credentials-only opt-in.
  Legacy provider projection and existing registration/update readers coexist.

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
