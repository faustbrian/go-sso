# Native SSO PostgreSQL adapter

Experimental optional adapter for DNS/opt-in HTTPS domain proof and disabled static-OIDC
provider metadata registration.
`Store` persists only immutable challenge binding, envelope-encrypted capability
and original safe organization recovery scope. It has no proof/result table,
transaction coordinator or alternative ownership truth. The separate provider
service persists disabled metadata; a separate opt-in credential service stores
only configured-envelope client-secret custody. Separate opt-ins enable or
disable a static OIDC provider. Trusted routing, anonymous discovery, static
OIDC sign-in start and completion are separate opt-ins. Completion supports
existing linked members only; it does not provision accounts or create links.

### Static OIDC login custody schema

`LoginTransactionMigrationSource` is an additive schema prerequisite. Install
it after `ProviderEnableMigrationSource`, before configuring a login or
disable writer that requires it. It creates two empty tables and indexes
without rewriting provider, credential, or command rows. Foreign-key lock
acquisition on existing tables is bounded to five seconds. There is no
backfill or destructive down migration. Rolling back the code leaves the new
custody and disposition records intact; existing provider reads and writes
do not depend on these tables.

Login rows separate keyed lookup and replay commitments from encrypted
binding and verifier custody. The verifier column must be absent once a row is
terminal. The second table retains the selected drain or revoke disposition
and its original bounded active count for one exact provider version. Applying
this migration does not enable sign-in, execute disablement, or start cleanup.

### Native static OIDC sign-in start

Before constructing `NewProviderLoginService`, install the existing native
provider and login custody migrations, the session pre-auth and issuer
migrations, the risk counter and audit/outbox histories, and
`identity/postgres.SSOOIDCPreparationErasureMigrationSource` after the prior
OAuth provider refresh erasure. The last migration is required to finalize a
successful start and erase the temporary coordinator copy. It does not erase
the separate native login transaction or its callback verifier.

Configure one tenant, its trusted service actor and browser origin, exact
allowed HTTPS return URLs, and the installed provider/mapping/credential
versions with client ID, provider callback URL and `openid` scopes. The risk
evaluator must count and durably audit `identity.sso.signin-start`; supply
retained flow, preparation, state, replay and PKCE keys for their original
lifetimes. The provider holds current credentials, but start does not retrieve
or use a client secret to contact the provider.

First issue an original pre-auth flow through the existing session owner for
`identity.sso.oidc-callback`, the exact successful return URL and resolved
remember policy. Pass that flow and its opaque browser cookie to `SigninStart`
with a network address and device identity from the trusted transport. Keep
the full request and idempotency key for retries. The request command ID is
correlation input; the coordinator chooses the durable command ID returned as
`TransactionID`. An acknowledged, still-admitted retry returns the original
code/S256 authorization redirect and never renews state or the pre-auth flow.
An unknown commit or stale current authority returns no redirect. Start
installs no HTTP route, exchanges no code and creates no user or session.

### Native static OIDC callback for an existing linked member

Before opting in, install the native callback account, capability, MFA,
session and audit/outbox schemas. Apply `ProviderLoginTokenVaultMigrationSource`
after `LoginTransactionMigrationSource` and the identity account schema on the
same primary. Append the identity PostgreSQL
`SSOOIDCCallbackPreparationErasureMigrationSource` after the enterprise start
erasure migration. The callback and session adapters share the same primary.

Construct `NewProviderLoginCompletionService` from the selected start service.
Supply the same provider's pinned HTTPS metadata, client authentication,
permitted algorithms and signing keys, and the consumer's session audience,
authorization namespace, cookie policy, and CSRF key. Existing accounts must
have an active `sso`-owned provider credential in the namespace given by
`SSOOIDCAccountProviderNamespace`, a current membership, and known factor
authority. This profile cannot satisfy a required second factor.

Call `SigninCallback` with the exact configured provider callback URL, the
original browser flow cookie/context, and the parsed authorization-code query.
For transport-owned callback quotas, first call `SigninCallbackRateSource`
with the trusted tenant and the same request. It authenticates the original
pending state and cookie, deriving the flow when a provider GET has no flow
selector. Its callback command and immutable stored lifetime provide quota
correlation only; it neither reserves the callback nor opens provider secrets.
Pass its `FlowID` with the same original cookie to `SigninCallback`, which
repeats every protected gate after quota admission.
Only an acknowledged first commit discloses the session cookie, CSRF token and
configured return URL. Configure the session PostgreSQL service's explicit
enterprise OIDC cookie profile for authenticated session reads and strict
logout. Provider tokens are never returned; the encrypted vault is the only
durable owner after a successful callback. A definitive refusal or a verified
response without an eligible link or member closes original verifier custody.
An uncertain provider response remains unresolved and must not be exchanged
again. None of these failures creates a session.

This API installs no public HTTP route and does not implement JIT provisioning,
new account linking, or non-OIDC federation.

For transport-owned callback parsing, `SigninProtocolProfile` selects the exact
configured organization/provider pair and returns detached, secret-free public
metadata with the effective protocol parser limits. Native IDs remain
case-sensitive; the returned protocol ID is the existing scoped lowercase
alias, not the stored provider ID. This construction-time snapshot performs no
I/O and supplies no freshness or admission authority. `SigninCallback` retains
all current provider, browser, linked-member and session checks.

### Static OIDC provider enablement

Install `ProviderEnableMigrationSource` after the metadata and credential
migrations and before selecting enablement. It keeps existing disabled rows
unchanged: a bounded metadata-only `ALTER TABLE` replaces the disabled-only
constraint and adds nullable fields, with no rewrite or historical scan. The
new receipt table retains only the original mapping version alongside existing
command effect custody. Both DDL steps have a five-second lock timeout; retry
failed installation through the migration runner. There is no destructive
down migration. Older writers continue to fail closed for enabled providers;
older readers report disabled rather than establishing positive authority.

Bind `ProviderService` to an organization, then call
`WithProviderEnableAuthorization(owner)` with a policy owner for this exact
enablement use. Obtain an organization-issued proof for the provider's single
configured domain and call `ObserveProviderCredentialCheckpoint` for the
expected provider version. Pass both checkpoints and an explicit idempotency
key to `ProviderEnable`. It supports fresh password bearer sessions with
current `org:sso-write` permission and the exact privileged risk action. It
does not install HTTP or cookie handling, enable enforcement, contact an IdP,
or permit authentication through the provider.

The adapter authenticates the current configured credential, then fences the
original session, organization authority version, proof expiry, provider
version and exact credential generation in native Work. It stores an
encrypted reference to the organization-owned proof, not a second source of
domain authority. Change, required audit, and lifecycle outbox commit together.
Keep the exact original key and request for recovery; a committed historical
result is neither refreshed proof nor permission to start login. Get/List
expose the persisted `Enabled` flag as administrative configuration only.

### Native static OIDC provider disablement

Install `LoginTransactionMigrationSource` and identity PostgreSQL request-key
preparation before enabling this operation. Bind `ProviderService` to the
organization and select `WithProviderDisableAuthorization(owner)` with the
disable-specific policy callback. The native path requires a fresh password
bearer session, current `org:sso-write` authority, and the exact privileged risk
counter policy for `identity.sso.provider.disable`. It adds no HTTP or cookie
handling.

Use `sso.NewActiveTransactionDisposition` to select `ActiveTransactionDrain`
or `ActiveTransactionRevoke` for the exact enabled provider version. Pass that
selection and a nonblank reason to `ProviderDisable`. The operation advances the
provider version, clears activation evidence, and stops new sign-in starts.
The organization's domain proof and the installed client credential are not
changed. The original count includes only nonterminal, unexpired transactions
at that provider version and is capped at one million. The explicit mode and
count commit with provider state, required audit and lifecycle outbox. Recording
a mode is not execution of a callback or proof of cleanup.

Keep the same request-key configuration and retry the exact request after an
unknown outcome. No client idempotency key is accepted. A matching authorized
retry returns the original receipt, not a new count; changing the reason or
mode for the original request conflicts. Keep the reason out of logs. It binds
the request intent but is not emitted in the audit or outbox.

If the original returns confirmed `NotCommitted`, correct the failure and call
`RetryProviderDisable` with the same request and the failed result's command ID.
The adapter checks the original intent and rollback on the primary before
admitting one fresh attempt. Repeating that failed ID recovers only its single
successor attempt. Never use a pending, unknown, or committed result as a retry
anchor; use the original method and request to reconcile an unknown outcome.

### Verified-domain provider routing

`NewProviderRouter` opts trusted native composition into routing. Pass a
`DomainRouteRequest` for the service's tenant and exact domain, optionally with
an explicit provider. The router resolves the current organization-owned proof
on the same primary as the provider data, checks the encrypted proof reference
and authenticates the selected credential generation without returning it.

Configure per-tenant, organization and domain defaults only when the selected
provider must win. Missing explicit or configured defaults do not fall back.
Without a preferred provider, automatic selection needs a single matching route
inside the complete bounded provider window. Scope overflow or ambiguity
denies; explicit and default selections still use an exact primary-key read.
No extra route table, backfill, or copy of organization authority is needed.

The returned native binding is bounded by the original route read and proof
expiry. Reusing it cannot renew those deadlines or bypass a future login
transaction's current provider and organization admission. This adapter does
not install a public discovery or login endpoint.

### Anonymous discovery for advertised static OIDC providers

Build an audited evaluator with `risk.NewSSODiscoveryPolicy`, the same policy
in the durable counter coordinator, and the existing required audit owner.
Install the selected counter storage migration before serving requests.
Construct `NewProviderDiscovery` with the native router, evaluator, and a
startup allowlist of exact tenant/organization/domain/provider choices.
From trusted transport, call `ForTenantBrowser` with the resolved tenant, peer
IP and verified browser-device ID, then call `Service.Discover` with the
untrusted email or domain. An empty or foreign tenant returns `sso.ErrForbidden`
without creating a service or starting I/O; it never falls back to the configured
tenant. Direct single-tenant callers may continue to use `ForBrowser`. Never use
a query field or unchecked cookie as browser-device proof.

The adapter counts and audits before lookup and rechecks the original decision
before disclosure. A verified, enabled, ready provider is visible only if the
exact selected route is advertised. Unproved, ambiguous, revoked or otherwise
unadvertised choices return the same no-match response. Neither that response
nor a match reveals whether an account exists, and neither grants login.
This adapter does not install an HTTP endpoint or browser-device issuance.

### Disabled provider metadata updates

Apply the unchanged `ProviderMigrationSource`, then the independently versioned
`ProviderUpdateMigrationSource`, before starting update-aware provider service
code (including its Get/List projection). The extension adds a constant-default
numeric metadata version and nullable successor envelope/mapping columns. It
does not backfill or rewrite historical provider rows. The single bounded
`ALTER TABLE` uses a five-second lock timeout and an unvalidated check that
enforces every subsequent write without scanning the populated table. It needs
a brief exclusive metadata lock; retry the migration through the migration
runner if that bounded acquisition fails. There is no data-changing backfill
or destructive rollback. Reverting code retains successor state.

The original version/configuration/mapping columns remain a consistent disabled
v1 projection for old readers and old registration writers. New registrations
still produce v1 receipts. An original registration retry still returns its v1
receipt after an update; ordinary scoped Get/List observe the current successor.
An old binary does not observe successors and must not administer update-aware
state. This is read/write schema compatibility, not a downgrade of successors.

The canonical native risk owner must explicitly select
`identity.sso.provider.update` as privileged before callers enable updates;
an unselected pinned catalog fails closed, never borrowing registration's
operation or bypassing counters. All existing session, organization, risk,
request-key, preparation, audit and outbox owners remain required.

Select `service.WithProviderUpdateAuthorization(owner)`, then bind the native
service using `service.ForOrganization(organizationID)` before calling
`ProviderUpdate(ctx, request)`. The update-only policy owner must return an Allow
decision for the exact detached context, native actor authorization epoch and
an absolute `ValidUntil`: the earliest activation/condition boundary that could
change that decision. Invalidating changes before this deadline must advance
the existing native actor authorization epoch. A generic authorization service
returning only a decision/revision is insufficient; there is no inferred TTL.
Missing, denied, expired or mismatched evidence fails closed.

The owner evaluates once outside Work at the original primary database admission
time. Its deadline caps that admission's existing minimum validity horizon.
Preparation/final commit use authoritative database time and the existing
unchanged actor/organization authority checks; they never call arbitrary policy
code while locks are held or renew the original deadline. Successful response
and original-key recovery disclosure may separately reauthorize current access.
An expired mutation cannot become committed by that later disclosure check.
Registration and ordinary Get/List retain their existing authorization contract.

Trusted composition or transport supplies
that separate organization selector because the catalog request contains none.
The selector is not an ownership assertion: current authenticated tenant/actor,
native organization owner/admin authority and `org:sso-write` are checked on
every call and rechecked in coordinator Work. An unbound service rejects updates;
the adapter never globally resolves the provider ID or accepts caller-vouched
ownership. Every provider read and compare-and-set uses tenant, organization
and provider together.

The selected profile replaces explicit static-OIDC endpoints and a complete
flat attribute mapping only while disabled. Issuer, stable subject claim and
pending domains remain unchanged; provider and mapping versions advance without
wraparound. Configuration is envelope-encrypted with exact tenant, organization,
provider, protocol, purpose and successor version. The same native transaction
commits the successor, command effect, required audit and lifecycle outbox event.
Original-key retries recover the original receipt without another update;
changed input conflicts, and unknown completion exposes no provider result.
Credential, enablement, discovery-network and routing profiles remain excluded.

The complete successor JSON, including retained pending domains and JSON escaping,
is limited to 48KiB before any keyed custody is retained. The same bound controls
stored-configuration decoding. Update preparation allows 96KiB JSON to hold the
base64-encoded encrypted configuration (itself capped at 64KiB) and scalar frame;
the matching encrypted outer-wire limit is 96KiB plus 4096 bytes of envelope
overhead. Original registration's 64KiB preparation profile stays unchanged.

### Disabled OIDC client-secret initialization and replacement

Install `ProviderCredentialsMigrationSource` at a later unique version after
the provider/update migrations and **before opting into credential service code**.
It creates only current-ciphertext and atomic-effect tables. Existing providers
are not rewritten, backfilled or enrolled; new primary/check constraints apply
before traffic. A five-second lock timeout bounds foreign-key acquisition on the
existing provider table. Code rollback retains encrypted custody and evidence;
there is no destructive down migration. Original registration readers/writers
continue to use unchanged legacy v1 columns on the expanded schema.

Bind `ProviderService.ForOrganization`, then construct the separate
`NewProviderCredentialsService(base, ProviderCredentialsConfig{...})`. Supply a
credentials-only `ProviderCredentialsAuthorization`, the deployment-configured
`IngressKeyID` and explicit `MaximumReferenceLifetime`. The configured native
envelope service and clock come from the existing base service, never the
request or reference factory. The actual canonical risk owner must select
`identity.sso.provider.credentials-rotate` as privileged; unsupported pins deny.
Generic metadata authorization cannot substitute for fresh `org:sso-credentials`.

Trusted ingress encrypts one client secret under the exact root-owned
`CredentialReferenceContext.EncryptionContext()`. The public reference factory
authenticates bounded ciphertext but conveys no native trust. The credential
service reauthenticates with its own configured service/key and requires exact
tenant, organization, provider, OIDC protocol, client-secret purpose, operation
audience, current provider version, next credential generation and original
lifetime. Expired/future ingress, a different factory key or a renewed original
request cannot authorize a write. No raw secret is accepted or returned by this
service; temporary decrypt output is cleared by the root reference factory.

The separate policy owner observes the exact primary-time action/resource,
policy revision, current actor authorization epoch and earliest absolute decision
deadline. Original native session freshness, policy/organization authority and
ingress expiry cap the admitted deadline. Work rechecks these same facts after
waits and immediately before commit, without policy callbacks under locks or
renewing authentication. A failed postcommit disclosure check preserves the
known native completion but returns no active credential result.

`ProviderCredentialsRotate` accepts only the explicit no-overlap policy. Both
initialization and replacement lock the exact provider, advance its shared
optimistic version, re-envelope identical non-secret metadata under that version,
and replace only the current encrypted client-secret generation. Mapping, issuer,
pending domains, legacy v1 projection, disabled state and routing are unchanged.
Competing metadata updates at the same provider version cannot both commit.
The same native transaction commits credential custody, effect evidence, required
audit and `sso.provider_credentials_rotated.v1` outbox; any failure rolls them back.

There is no external idempotency key. The existing native key/preparation owner
correlates the original command within authenticated tenant/actor/operation scope
and binds its complete immutable intent. Changed input conflicts. Original
retries recover only the exact native historical receipt, including after later
generations; they never decrypt/reveal a current secret or repeat effects.
`Active` describes the originally configured credential successor, not current
provider enablement or present-day credential authority. Unknown exposes no
active result and requires original reconciliation; missing preparation cannot
become a fresh mutation. Native preparation retains only re-enveloped non-secret
metadata, not predecessor client-secret ciphertext. No active-use overlap,
drain, SAML keys/certificates, provider calls, login, HTTP or app is selected.

The executable boundary is in
[provider_credentials_integration_test.go](provider_credentials_integration_test.go)
and its credentials-policy and query-scale companions.

## Setup and ownership

Apply the existing identity/kernel/session/risk/authorization/audit/outbox and
organization migrations, including organization's domain claim/evidence
extensions. Apply `DomainChallengeMigrationSource` at a unique migration version
**before enabling the SSO DNS profile**. It creates a new `sso` schema and table;
it never alters, locks or backfills existing organization/identity tables.
New-table primary/unique/check constraints are installed before traffic exists.
There is no destructive down migration: disabling/reverting code retains
challenge and safe recovery custody. Retention/deletion automation is not selected.

Construct `NewStore` with a borrowed primary `go-postgres.Pool`, positive bounded
duration, existing `secret-envelope/v2.Service` and retained encryption key
reference. Capability ciphertext uses authenticated tenant, org, claim/version,
domain, actor, command, purpose, digest and UTC original time context. Keep
decrypting keys available while supported recovery remains possible. The store
starts no goroutines and never closes the caller's pool or key provider.

Create the real DNS engine and root `sso.NewDomainObserver` with this Store.
Install that observer with `organizationpg.NewDomainEvidenceSource` on the
existing native organization contributor, then compose the existing native
organization service. `NewDomainEvidenceFactory` wraps that service's private
authentication-bound `DomainEvidence` facade. It never accepts/retains a Work,
transaction, coordinator, replacement observer or result journal.

The complete reproducible graph is in
[domain_integration_test.go](domain_integration_test.go) and its native fixture.
It uses actual public organization/kernel/session/risk/audit/outbox adapters and
an independent task-owned authoritative DNS wire server, not fake domain stores.

### Additive HTTPS method custody

The original `DomainChallengeMigrationSource` SQL is immutable.
`DomainChallengeMethodMigrationSource` is a separate forward-only extension
adding `method smallint NOT NULL DEFAULT 1` to the **same** challenge row.
Its constraint allows only historical DNS (1) or HTTPS (2). The constant default
is a metadata-only PostgreSQL expansion, not a row rewrite/backfill; the new
check is NOT VALID to avoid scanning historical rows and applies to new writes.
The migration has a one-second lock timeout and fails rather than waiting behind
long-held locks. Apply/replay this schema extension first, then explicitly enable
`NewHTTPSStore` in a later composition rollout. No serving code requires the
column unless that constructor is selected. No production rollout is performed
by this library or its tests.

`NewStore` remains DNS-only and works before or after the extension. Its inserts
receive the database DNS default. `NewHTTPSStore` reads both methods, including
unchanged historical DNS ciphertext. Method is authenticated in capability
caveats and envelope AAD; old DNS readers fail closed on HTTPS ciphertext, and
tampering with the SQL method cannot reinterpret a challenge. The existing
tenant/org/claim primary key and global command uniqueness preserve exactly one
original challenge/recovery binding across both methods. A method-changing
retry conflicts, never creates another original or overwrites recovery custody.

Use `sso.NewHTTPSDomainObserver` with `domainverification.NewHTTPSEngine` and the
same native organization evidence source/factory, then `sso.NewHTTPSService`.
Schema/code rollback retains the additive column, ciphertext and original
recovery data; do not drop them or rotate away decrypting keys during rollback.
The populated/mixed-reader tests and 100k-row typed native-query plans in
[domain_method_integration_test.go](domain_method_integration_test.go) cover
the extension without changing provider storage or organization proof ownership.

## Disabled static OIDC provider administration

`NewProviderService(pool, config, authentication, canonicalClientIP)` composes
the existing native session, organization, directory, authorization, risk,
coordinator, audit and transactional-outbox owners. Authentication is an actual
ordinary password-bearer human session, not a caller-provided administrator
boolean. Current active owner/administrator membership and revision-matched
`org:sso-write` or `org:sso-read` policy are required on each call. Cookie,
selected-organization-session and other authentication profiles are not selected.
No fresh action proof is synthesized or accepted by this profile.

Install the real selected owners' migrations first, including the kernel's
`PreparationMigrationSource`, `AdmissionPreparationMigrationSource`,
`CounterPreparationMigrationSource`, `RequestKeyMigrationSource` and
`RequestKeyPreparationMigrationSource`, native protected counters, organization
credential authority, audit and outbox. Apply `ProviderMigrationSource` at an
unused later version before enabling this API. It creates only the new
`sso_providers` namespace and has no backfill or destructive down migration;
old code and DNS challenge storage are unaffected, and code rollback retains
encrypted configuration and original recovery bindings. Provider-only
installation does not require the DNS challenge migration or change its order.

The complete native composition and calls are in
[provider_integration_test.go](provider_integration_test.go). Call
`ProviderRegisterOidc` with the root-owned request. It accepts only complete
explicit static metadata with an exact matching issuer, 1 through 128 distinct
canonical pending domains and a positive flat mapping version. It fetches no
metadata or keys, stores no provider credentials, and never enables a provider,
creates a domain proof, routes a login or applies mapped claims. Configuration
is envelope-encrypted with tenant, organization, provider, protocol, purpose and
version context. Retain decrypting keys while original operations are supported.

Provider IDs are allocated once by the native owner. Issuer identity is exact
byte identity, uniquely indexed by tenant and organization; endpoints and issuer
URLs are not normalized. A conflicting owner/issuer registration cannot take
over the existing provider. Provider mutations, required audit and outbox commit
atomically in the existing kernel Work. Original session, credential, directory,
user-policy and organization authority are locked and checked again after waits
and immediately before commit, without renewing the original admission window.

Retain the exact command, key and request across retries. The existing encrypted
request-key mapping restores only the original binding. A matching retry recovers
that command and stable provider ID, not another registration or counter charge;
changed keyed input conflicts. An acknowledged mapping with no command journal
remains `Unknown`, never permission to execute afresh. Unknown returns no provider
metadata. Current organization disclosure authority is required for recovery.

`ProviderGet` and `ProviderList` expose detached nonsecret metadata only; they
never open the encrypted configuration. Lists use the scoped primary index,
opaque ID cursor and limits of 1 through 100. Current authority is checked before
querying and again before disclosure; a cursor grants no authority. Requested
domains remain pending, `Enabled` is false and `VerifiedDomains` is empty.

## Domain recovery

The exact original safe organization `CommandBinding` is compare-and-set before
Apply. Neither a saved binding nor an observation grants proof. Only the native
organization/coordinator determines committed, not-committed or unknown outcomes.
An uncertain acknowledgement of that save retains Unknown and the original
scope; SSO does not call Apply after the save reports an error.
After process loss construct a fresh root invocation with current authentication,
reload the exact original request, then recover. Do not reconstruct/execute a new
prepared command or repeat the external DNS lookup.

A lost successful COMMIT response recovers the identical historical proof from
the native coordinator. A saved-but-never-applied preparation instead retains
the original Unknown: generic native recovery deliberately does not disclose
whether a denied/absent command exists. Absence is not rollback proof and cannot
authorize automatic observation or execution. An explicit current-authorized
withdrawal followed by a new immutable claim is the supported operator option
when abandoning the old attempt. Current proof reads always consult the real
organization primary owner and reject expired/withdrawn/revoked proof, even when
historical committed recovery remains available.

## Checks

Run inside this module with the pinned Go toolchain and task-owned Go caches:

```sh
go test -tags=integration ./...
go test -race -tags=integration ./...
go vet -tags=integration ./...
```

`GOLIB_ORGANIZATION_TEST_POSTGRES_DSN` **must identify an isolated task-owned
cluster**, not an existing/shared database. Tests create/drop their own databases
and native audit roles. The query-scale test populates 100,001 synthetic
challenge rows, captures actual pgx SQL/binding types and plans and measures
bounded local operation cost. Its synthetic ciphertext is never treated as
authority; local timings are not production promises. This profile's behavioral
proof is distinct from complete SSO unit/release qualification.
