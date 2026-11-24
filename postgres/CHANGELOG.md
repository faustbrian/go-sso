# Changelog

## Unreleased

- Select direct Group Apply independently of human administration. The
  configured SCIM service account, generation and original Work fences
  retain authority; the existing `WithGroupEdges` path remains supported.

- Select native directory administration with a primary browser cookie and
  exact session-bound CSRF for writes. Keyless versioned cancellation can
  recover its original outcome without changing the existing keyed API.

- Reconcile bounded mapped Group-member batches in their original order.
  Recover issued child commands before continuing, and settle the cursor
  once from complete terminal receipts. Cancellation stops subsequent grant
  writes and preserves the predecessor when only a prefix executed.

- Cancel an exact directory generation with fresh administrator authority.
  Do not change committed grants or its cursor; if a child is held, settle
  only the original child before closing the generation. Recover cancellation
  by its original idempotency key without producing another audit or event.

- Opt in to one exact SCIM Group/User edge through native SSO. Apply and
  withdraw the matching team source grant in original identity Work;
  retain the predecessor until the original child receipt is known.
  An original retry reconciles a lost acknowledgment without duplicating
  audit, event, grant or successor.

- Start an opt-in directory generation against an enabled provider and
  exact mapping. A fresh authorized caller retains one replayable creation
  outcome; scoped status reads expose only the safe current projection.
  Install the additive directory-generation migration before use. No
  membership changes, cursor advancement or HTTP routes are enabled.

- Replace a disabled SAML provider's IdP signing certificates through the
  dedicated credential rotation operation. Preserve the installed SP signer,
  IdP identity, endpoints, domains and mapping. Original retries recover the
  same outcome without applying rotation again.

- Opt into provider-owned role replacement on SAML SP linked sign-in with
  `WithRoleSync`. Signed booleans grant or withdraw only the selected
  provider's roles; the exact role update, replay reservation and new session
  commit together. Missing or ill-typed claims fail closed and local roles
  are not changed.

- Preserve selected native IdP logout targets when user authorization is
  denied or interrupted. Require reconciliation rather than claiming an
  unobserved outcome, and return no signed response or RelayState.

- Opt into SP-generated SAML logout RelayState with `WithRelayState`.
  Acknowledged local logout survives remote failure. The signed request and
  one-use grant commit together; only the original handle and signed response
  can settle it. An exact replay does not reveal the continuation again.

- Echo optional opaque RelayState only with a fresh, signed IdP-initiated
  logout response. A changed value cannot reopen the original request and
  no-state requests retain their existing replay identity.

- Add SAML logout constructors with an explicit request-key namespace
  independent of canonical sign-in. Existing constructors retain their
  replay namespace and configuration shapes.

- Handle opt-in signed SAML IdP LogoutRequests against the installed provider
  and complete retained subject selection. Recheck targets and provider in the
  same native command as session revocation. Return a signed POST response only
  after known commit; exact retries recover the local result without changing
  sessions or signing again.

- Settle signed SAML LogoutResponses against the one original request and
  installed provider. Preserve previously committed local revocation on
  provider failure, expiry and unavailable settlement. Exact replay can
  recover the status without redisclosing the application continuation.
  Install the additive response migration before enabling this native path.

- Add an opt-in signed SAML provider redirect after exact local revocation.
  Reserve one encrypted request before disclosure and reuse its exact wire
  on authorized retries. No provider route or storage failure erases a
  committed local revocation. Install the request migration before opting in.

- Add opt-in native local SAML logout using the original cookie, CSRF and
  linked provider. A disabled provider does not prevent local revocation.
  The exact keyed retry recovers the original outcome without revoking
  again. Install the SAML session-revocation journal migration before enabling
  this workflow. No provider operation or HTTP route is installed.

- Optionally retain encrypted SAML logout correlation with the original issued
  session on either sign-in path. A failed correlation write rolls back
  issuance. Install the subject migration before selecting this custody.

- Let selected SAML sign-in verifiers return the exact signed logout subject
  alongside login evidence. Preserve it in existing encrypted preparation for
  both sign-in paths; existing callers and payloads are unchanged.

- Expose authenticated read-only quota correlation for an original pending
  SAML IdP confirmation. Return only its provider, ID and retained lifetime.

- Confirm explicitly selected unsolicited SAML for a linked member from the
  original same-origin browser pair. Consume pending custody, the one-use
  grant and both replay IDs with the session in one transaction. Receipt
  recovery is authorized and never reissues credentials. No HTTP route is
  installed by the PostgreSQL adapter.

- Prepare an explicitly selected unsolicited SAML arrival by committing the
  existing linked user's encrypted pending record and single confirmation
  grant together. Return the independent browser pair only after a fresh
  commit; receipt recovery never reveals it. This does not create a session
  or enable an HTTP route.

- Resolve eligible linked users from verified unsolicited SAML evidence on
  the existing native account, organization, factor, and policy readers.
  Preserve bounded original evidence without a prior SP start. Add the
  separate, exact-purpose IdP replay reservation and recovery statements.
  These paths alone do not write a session or expose a route.

- Add optional PostgreSQL storage for pending unsolicited SAML confirmation.
  Preserve the original expiry, erase pending custody only on exact completion,
  and extend the existing replay table without splitting replay uniqueness.
  No browser route, confirmation writer or session issuer is enabled.

- Admit detached IdP-initiated SAML evidence for explicitly allowed current
  providers, without an SP start or RelayState. Recheck current native
  provider and domain authority after the borrowed wire verification.

- Expose the exact installed SAML SP entity, ACS and public signing certificate
  for the selected current route, without exporting credential custody.

- Attribute SP-initiated SAML POST callbacks to their authenticated original
  provider, frontchannel flow, callback command and initial lifetime for
  transport quotas. Read-only attribution does not process the response,
  reserve grants or change custody; native completion repeats protected checks.

- Complete the opt-in SP-initiated SAML callback for an existing linked member.
  Bind the trusted response verifier to the installed provider and original
  browser, and reserve the replay pair in the same native Work as the session.
  Only a fresh acknowledged commit discloses session and CSRF custody.

- Start an explicitly configured SP-initiated SAML sign-in using its original
  ACS browser flow and installed signer. Retain the exact signed redirect
  through restarts and optional key retries without PKCE or renewed expiry.
  This does not install an HTTP route or complete the ACS/session flow.

- Expand shared login transaction custody for SAML without PKCE, preserving
  populated OIDC and OAuth 2.0 rows and their original verifier rules.

- Opt into explicit SAML provider routing with current verified domain proof
  and an installed signer whose certificate bounds the original route lifetime.

- Enable an explicitly selected SAML provider only with current domain proof,
  trusted origin, and the original installed signer lifetime. Add exact SAML
  disable, including durable disposition and keyed recovery. No browser route
  is installed by these administrative operations.

- Select SAML SP signing credential installation and disabled-provider
  replacement through the existing encrypted rotation transaction. Require
  the current trusted origin and a local signer validator; retain the
  certificate's exclusive expiry in the write admission. No provider is
  enabled by installing a credential.

- Register explicitly configured, disabled SAML providers through the
  current organization authority and keyed native coordinator. Retain pinned
  IdP configuration encrypted and return only safe metadata. Mixed readers
  preserve the protocol; registration alone cannot activate login.

- Add optional forward-only provider protocol expansion for SAML and a
  distinct stable namespace for existing SAML account links. Neither change
  enables registration or a sign-in route.

- Add optional forward-only SAML replay storage after the provider and
  identity command migrations. Reserve the authenticated Response and
  Assertion IDs atomically and retain the exact pair for recovery. This
  prerequisite enables neither a SAML callback nor local session issuance.

- Add opt-in native grant refresh for linked enterprise OAuth2 members. Use
  one provider attempt per generation, commit the encrypted successor and
  receipt together, and recover the original result without resending.

- Add optional forward-only schema for enterprise OAuth2 refresh generations
  and safe outcome history. Applying it alone does not enable refresh.

- Add opt-in native revocation for restorable enterprise OAuth2 grants. Check
  current session, factor and organization authority, fence the provider call,
  and recover the committed provider disposition with the original key. Erase
  the encrypted grant only on acknowledged settlement. No HTTP route is added.

- Add the optional enterprise grant-attempt fence. Competing revocation and
  refresh commands cannot both claim the same grant generation. The private
  revocation transport distinguishes acknowledgement, refusal and ambiguity
  without resending; no public lifecycle operation is enabled yet.

- Allow an opt-in OAuth2 vault format that retains restorable encrypted grant
  custody after callback preparation is erased. Keep OIDC and legacy OAuth2
  writes unchanged by default; no provider-token lifecycle API is enabled.

- Add native RP-initiated enterprise OIDC logout backed by one-use PostgreSQL
  state and the original session's revocation. The callback settles provider
  success, refusal or timeout without reactivating the local cookie. No HTTP
  routes are installed by this module.

- Allow selected OIDC sign-in and explicit-link completion to use the original
  parsed callback with a protocol adapter inside the native acknowledged
  reservation. Keep token-vault and account/session effects native.

- Allow configured static OIDC login profiles to use an optional protocol
  adapter for committed start redirects without changing native state,
  callback ownership, or existing unselected profiles.

- Select one standalone adapter for original OAuth2 redirect rendering and
  reserved callback completion. Start discloses only the committed state and
  S256 challenge against the exact current provider, with no callback custody.

- Allow a trusted standalone OAuth2 adapter to complete the already reserved
  native callback. The original coordinator retains credential custody, linked
  recipient checks, encrypted token staging and atomic session issuance.

- Before provider exchange, bind the shared adapter transaction to the original
  enterprise OAuth2 command, exact redirect, credential generation, expiry and
  resolved remember policy. Substituted custody fails before provider I/O.

- Attribute native OAuth2 browser callbacks to their authenticated original
  provider, flow, callback command and immutable lifetime for transport quotas.
  Attribution leaves custody untouched, including definitive issuer refusals;
  native callback completion still performs every protected check.

- Complete native enterprise OAuth2 sign-in for already linked members.
  Reserve the original OAuth state before exchange, confirm identity through
  the installed TLS endpoint, and commit the session, encrypted token vault,
  and custody erasure together. Definitive refusals erase executable custody;
  ambiguous outcomes keep original custody without resubmitting the code.

- Support OAuth2-only deposits in the existing enterprise token vault. Bind
  access/refresh tokens to exact scopes, callback generation and linked
  account, use a separate encryption profile, and require no ID token.
  The vault alone does not enable OAuth callback completion.

- Allow the existing enterprise token vault schema to accept native OAuth
  callback origins without rewriting grants or relaxing command and account
  provenance. Keep OAuth callback state and verifier custody separate from OIDC.

- Add opt-in native enterprise OAuth sign-in start for an exact installed
  provider and browser flow. Commit separate encrypted PKCE custody and one
  OAuth state grant before returning the original code/S256 redirect.

- Resolve one exact activated OAuth 2.0 route from the explicit protocol
  registry. Authenticate its protocol-bound domain proof and installed
  encrypted credential without falling back to OIDC.
- Provide additive login-transaction protocol expansion and separate
  validation migrations. Existing encrypted OIDC custody and indexes remain
  unchanged; no OAuth login writer is activated by the schema.

- Enable and disable explicitly selected static OAuth 2.0 providers using
  exact encrypted credential and current domain proof. Both operations
  preserve historical retry semantics, with separate protocol bindings.
- Let existing OIDC routers opt into the mixed provider registry. OAuth
  rows cannot enter OIDC routing or change its explicit/default selection.

- Install and replace protocol-bound OAuth 2.0 client secrets for disabled
  providers through the existing credential command. Exact retries retain one
  encrypted generation, audit and outbox effect. OIDC enablement and credential
  use cannot substitute OAuth custody; OAuth routing remains inactive.

- Add a selected native registration path for disabled static OAuth2
  providers. The provider registry retains existing OIDC metadata, encrypts
  the OAuth configuration with its own protocol binding, and recovers exact
  retries through the existing coordinator. Registration does not enable
  OAuth routing or sign-in.

- Add native `SharedCallbackRateSource` attribution for a shared enterprise
  sign-in/member-link callback. Authenticated stored mode selects only its
  original flow or fresh local password cookie, with no cross-mode fallback,
  callback reservation, provider exchange, writes or renewed lifetime. The
  existing anonymous-only rate source retains its behavior.

- Add opt-in static enterprise OIDC linking for an existing active member
  using the original fresh password cookie and same-origin consent. Commit
  the new provider credential, encrypted token deposit and lifecycle once;
  leave session issuance to later ordinary sign-in.

- Add opt-in first-login provisioning for enabled enterprise OIDC profiles.
  An exact verified-domain mailbox and never-linked subject create an ordinary
  member and session in the original callback transaction. Existing-account
  auto-linking is not supported.

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
