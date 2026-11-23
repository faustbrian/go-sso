# Native SSO PostgreSQL adapter

Experimental optional adapter for DNS/opt-in HTTPS domain proof and disabled static-OIDC
provider metadata registration.
`Store` persists only immutable challenge binding, envelope-encrypted capability
and original safe organization recovery scope. It has no proof/result table,
transaction coordinator or alternative ownership truth. The separate provider
service persists disabled metadata; a separate opt-in credential service stores
only configured-envelope client-secret custody. Separate opt-ins enable or
disable a static OIDC provider. Trusted routing, anonymous discovery, static
OIDC sign-in start and completion are separate opt-ins. Completion defaults
to existing linked members. First-login provisioning requires a further
selection; it never links an existing local account by email.

### Optional SAML replay schema

Before enabling SAML provider writes, apply both versions of
`ProviderSAMLProtocolMigrationSource` after the existing provider protocol
history. The first version expands the check atomically without scanning
existing rows; the second validates in a separate transaction. Both bound
lock acquisition. These migrations leave OIDC/OAuth2 rows unchanged and
do not enable any writer. Keep the expansion on rollback. Upgrade registry
readers, mutators and routers to understand protocol discriminators before
writing any SAML provider; legacy OIDC-only readers assume OIDC metadata.

After migration, select `ProviderService.WithSAMLRegistration` with the
deployment's exact external HTTPS origin and the SAML module's
`ValidateRegistration` function. Call `ProviderRegisterSaml` with an
explicit `sso.SAMLConfiguration` and the original command and idempotency
key. This native bearer operation checks current `org:sso-write` authority,
validates the pinned IdP certificate material through the local port without
fetching URLs or depending on a wire module, and
persists one disabled SAML provider with pending domain verification. It
returns safe metadata; it does not install an SP key, activate a route,
publish SP metadata, or grant sign-in. Keep the original origin and request
inputs for keyed retries. The aggregate encoded configuration has the native
registry's 48 KiB storage limit in addition to wire-profile limits. Ordinary
OAuth2 writes remain separately selected.

Install `SAMLReplayMigrationSource` after the native identity command and
SSO provider migrations. Choose the next unused version in that migration
history. Installation creates an empty table, bounds the foreign-key lock
wait to five seconds, and requires no backfill. Keep the table on code
rollback so a previously recorded ID cannot be reused.

The schema records the exact authenticated Response and consumed Assertion
as a pair under the installed tenant, organization, provider, and issuer.
An ID is unique within that scope regardless of its role. Applying the
migration does not enable a SAML callback, issue sessions, or delete records.

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

### Native static OAuth 2.0 sign-in start

Install the start prerequisites above and both versions of
`LoginTransactionProtocolMigrationSource`. Pass a router selected with
`WithProtocolRegistry` and exact `StaticOAuth2LoginProfile` values to
`NewProviderLoginServiceWithOAuth2`; no OIDC profiles are required. The trusted
configuration selects the current provider, organization, domain, credential
and mapping versions, HTTPS protocol redirect, client ID and scopes excluding
`openid`.

Issue the original pre-auth flow for `identity.sso.oauth-callback` and its exact
successful return URL. Call `SigninStartOAuth2` with the exact provider and
domain, original browser evidence, request and idempotency key. The method
returns a code/S256 redirect without OIDC nonce only after durable state,
separate encrypted PKCE verifier and one OAuth callback grant commit. An
admitted retry returns the original redirect without renewing its expiry.
This entry point installs no HTTP route, exchanges no code and creates no user
or session. OIDC start and callback do not accept OAuth custody.

Before enabling a native OAuth callback writer, install both versions of
`ProviderLoginTokenVaultProtocolMigrationSource` after the original token
vault history. The first version atomically replaces only the origin check
under a five-second lock wait, with no row rewrite. The second validates the
expanded check without that exclusive lock. Existing encrypted grants,
command/account foreign keys and indexes stay intact. Leave the expansion
installed on code rollback; applying it alone enables no callback or API.

### Native static OAuth 2.0 callback for an existing linked member

Install the selected OAuth start and token-vault histories above. Append the
kernel's OAuth callback preparation erasure migration after its OIDC erasure
history, and apply the session adapter's OAuth issuance expansion and
validation after its OIDC issuance history. Install the retained MFA, CSRF,
audit, and lifecycle owners before selecting the callback.

Select `NewProviderOAuth2LoginCompletionService` with trusted static profiles
and cookie issuer keys. Each profile selects the exact installed provider
version, client, HTTPS endpoints, trusted identity subject field and encoding,
and original scope set. The logical OAuth profile ID is the value from
`SSOOAuth2AccountProviderNamespace` with dots replaced by hyphens. Arm the
same exact `sso-oauth2` authority profile when composing native cookie reads
and strict local logout through the session adapter.

Pass the untouched query, trusted local redirect URI and original browser to
`SigninCallbackOAuth2`. The original state selects the profile; the provider's
`iss` proves exact agreement, never a new selection. After acknowledged
reservation the adapter sends the code and PKCE verifier once, then reads the
configured authenticated identity endpoint. It accepts no ID token or
unverified access token as identity. This profile looks up an already linked
member under the OAuth2-specific account namespace. It does not create a
user, link, member, or role. This native service does not expose an HTTP route.
An invalid issuer terminalizes only a uniquely selected state whose original
browser and trusted local redirect authenticate; foreign or unidentified
browser custody cannot cancel another callback.

The original transaction writes the session, encrypted token deposit,
successful audit and lifecycle event and erases the executable preparation.
Only an acknowledged new commit returns the cookie credential and CSRF token.
Definitive refusal terminalizes original custody; an ambiguous exchange retains
the original lease and cannot resubmit the code. No provider token is returned.

To make new OAuth2 grants restorable from the committed encrypted vault after
callback cleanup, set `ProviderLoginConfig.RestorableOAuth2Vault`. Upgrade
every worker that may resume a callback before enabling it; old binaries
cannot read the new preparation format. Turning the setting off affects only
new deposits. It does not change OIDC or convert earlier OAuth2 deposits,
which cannot be opened independently after callback cleanup. This setting
does not expose tokens or enable upstream refresh or revocation.

### Native enterprise OAuth 2.0 grant revocation

Install `ProviderGrantFenceMigrationSource` after both OAuth2 vault protocol
migrations and the identity command history. Then install
`ProviderGrantRevocationReceiptMigrationSource` on the same primary. Both
add empty tables without changing existing grants. Leave both installed on
code rollback. Installing them enables no provider call or HTTP route.

Register the provider's revocation endpoint in its installed configuration
and select the same HTTPS URL in `NewProviderGrantRevocationService`. Use the
native OAuth2 completion service for that provider and configure the uncached
session reader for the same audience. `Revoke` takes an exact restorable grant
version, an idempotency key, and the current linked member's cookie, trusted
origin and session-bound CSRF token. Legacy OAuth2 and OIDC vault entries are
not eligible.

Provider acknowledgement and local commit are separate. An acknowledged result
removes the exact encrypted grant only when the local transaction commits.
Refused or unknown provider outcomes retain the encrypted grant, but the fence
prevents another attempt against that version. Retry the original authorized
request with the same key to recover its local result, not to send again.
An unknown commit does not establish either local erasure or provider refusal.
Retain the existing versioned login state keys for pending revocation
preparations. Revocation derives separate local outcome keys so opening the
redacted disposition does not call the vault's key provider during settlement.

### Native enterprise OAuth 2.0 grant refresh

Install `ProviderGrantRefreshMigrationSource` after the vault protocol history
and `ProviderGrantFenceMigrationSource`. Install the identity PostgreSQL
`SSOEnterpriseGrantRefreshPreparationErasureMigrationSource` after the OAuth2
callback erasure history on the same primary. Apply the schema before enabling
the refresh writer. Neither migration contacts a provider or adds a route.

Use `NewProviderGrantRefreshService` with the native OAuth2 completion owner,
the same audience, and an explicit set of installed provider IDs. Its token
endpoint and client credential come from the installed generation. Pass
`sso.NewRefreshEnterpriseToken` the exact restorable grant version and a retry
key, then submit it to `Refresh` with the linked member's current cookie,
trusted origin, and session-bound CSRF token. Legacy OAuth2 and OIDC deposits
are not eligible. Refresh does not issue, replace, or revoke a session.

A successful refresh replaces the original encrypted grant with exactly the
next version and returns that grant reference, never the token bytes. If the
provider omits a replacement refresh token, the successor retains the original
refresh credential. Each refresh explicitly requests the current stored scope;
it cannot widen to the provider credential's original scope. Rejection, refusal, an
unknown provider result, or a known no-send after the fence does not write a
successor. Such a fenced predecessor is retained encrypted for reconciliation
but cannot be used by a second refresh or revocation attempt.

Only the final transaction writes the successor and outcome together and clears
the temporary encrypted preparation. A successful PostgreSQL commit can still
lose its reply. Retry with the exact original key to recover its committed
result without contacting the provider, even if a later operation has already
advanced or revoked the successor. A successor reference from history does not
establish that the successor is still current.

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

For a shared sign-in/member-link callback route, use `SharedCallbackRateSource`
with that same trusted request and the local member-session cookie. Its single
authenticated pending lookup selects the stored mode, not whichever cookies
are present. Anonymous mode authenticates the original flow cookie and returns
its `FlowID`; member-link mode requires the exact original fresh password
cookie and returns `MemberLink=true` with an empty `FlowID`. Neither missing
nor invalid custody falls back to the other mode. Both return the original
callback command and immutable lifetime without reservation, writes or provider
I/O; `SigninCallback` or `LinkCallback` must still repeat protected admission.
The existing `SigninCallbackRateSource` remains anonymous-only.

Only an acknowledged first commit discloses the session cookie, CSRF token and
configured return URL. Configure the session PostgreSQL service's explicit
enterprise OIDC cookie profile for authenticated session reads and strict
logout. Provider tokens are never returned; the encrypted vault is the only
durable owner after a successful callback. A definitive refusal or a verified
response without an eligible link or member closes original verifier custody.
An uncertain provider response remains unresolved and must not be exchanged
again. None of these failures creates a session.

This API installs no public HTTP route. Explicit linking of an existing local
account is an opt-in workflow, separate from anonymous sign-in and non-OIDC
federation.

For transport-owned callback parsing, `SigninProtocolProfile` selects the exact
configured organization/provider pair and returns detached, secret-free public
metadata with the effective protocol parser limits. Native IDs remain
case-sensitive; the returned protocol ID is the existing scoped lowercase
alias, not the stored provider ID. This construction-time snapshot performs no
I/O and supplies no freshness or admission authority. `SigninCallback` retains
all current provider, browser, linked-member and session checks.

#### Optional explicit account linking

Construct `NewProviderLoginServiceWithLink` with the real native password
session service, local credential admission profile and its retained cookie
and CSRF keys. Install the identity account and retired-subject index history
even if JIT is disabled. The callback uses the same installed static profile,
capability, token-vault and audit/lifecycle histories as native sign-in.

Call `LinkStart` only for an authenticated same-origin POST with the original
fresh local password cookie and its CSRF proof, using the browser-session
intent. This profile requires active membership of the provider's organization
and known-empty factors. Return only the provider redirect from the committed
start. Handle the provider query with `LinkCallback` and the same original
cookie; the trusted transport supplies the configured return URI and browser
context. The anonymous callback cannot complete this member transaction.

The verified OIDC subject identifies a new credential, never a target user.
No role, user, membership or session is created. The link advances the
member's credential epoch; do not assume the original password cookie remains
usable. A subsequent normal enterprise sign-in can resolve the new account to
the same member, subject to the usual current provider and user policy.

#### Optional repeat-login role synchronization

Install the organization PostgreSQL `ProviderRoleGrantMigrationSource` and
`ProviderRoleSourceProjectionMigrationSource` before this module's
`ProviderRoleSourceMigrationSource`. The latter attaches to the existing
provider lifecycle after its enablement history. It does not seed existing
provider rows. Select a provider for role sync only after its enabled generation
has been projected by its native lifecycle; unselected providers are unchanged.

Use `NewProviderLoginCompletionServiceWithRoleSync` with explicit
`StaticOIDCRoleMapping` rules scoped to the installed provider, organization and
mapping version. Project each named claim from the signed ID token. An explicit
`true` grants its mapped custom role and `false` withdraws it. Missing, null or
nonboolean values deny the selected sign-in. The newer original start must
replace older grants atomically with session issuance. This neither changes
application-assigned or team roles nor admits an unlinked identity. For
permission evaluation use the organization PostgreSQL
`NewRepositoryWithProviderRoleGrants` reader.
Role changes invalidate earlier organization-bound sessions; the newly issued
session binds the successor organization revision. Disabling a provider with
retained grants invalidates the old revision when the disable commits. Under
contention the native disable remains subject to its ordinary outcome recovery
and confirmed-failure retry rules.

#### Optional first-login provisioning

Use `NewProviderLoginCompletionServiceWithJIT` with a `StaticOIDCJITPolicy`
for each eligible exact organization/provider/mapping version. Select both
installed mailbox and verification claims in `StaticOIDCCompletionProfile`;
the installed subject mapping must be `sub`. The signed ID token must carry
the mailbox as a string and its verification as boolean `true`. Use the
tenant's existing email parser and identifier-retirement keys. The canonical
mailbox domain must equal the originally routed and still verified domain.

Install the identity account, credential, identifier normalization and
retirement histories, `SSOOIDCSubjectAvailabilityMigrationSource`, the MFA
`SSOOIDCJITFactorMigrationSource`, and the organization membership and
credential-authority histories. Set the JIT membership limits to the
organization's existing admission limits. JIT creates a new ordinary member,
never an owner, administrator or existing user. Existing or retired mailbox
ownership and previously occupied provider subjects refuse the attempt. A
disabled provider cannot provision even while earlier linked sign-ins drain.

The original callback commit owns all new identity, membership, authorization,
factor, token-vault, session, audit and outbox effects. Replay cannot issue a
second credential; an unknown outcome returns no session. Optional `RoleSync`
applies on subsequent linked sign-ins, not on first-login admission.

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

### Disabled OIDC and OAuth 2.0 client-secret initialization and replacement

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
tenant, organization, provider, protocol, client-secret purpose, operation
audience, current provider version, next credential generation and original
lifetime. Expired/future ingress, a different factory key or a renewed original
request cannot authorize a write. No raw secret is accepted or returned by this
service; temporary decrypt output is cleared by the root reference factory.

For OAuth 2.0, use the protocol-aware base from `WithOAuthRegistration` after
the provider protocol migrations, and set `CredentialReferenceContext.Protocol`
to `oauth2` before sealing. The stored configuration independently authenticates
the same protocol; an OIDC envelope for the same provider cannot substitute.
Installing an OAuth secret leaves the provider disabled and does not opt it into
OIDC enablement or routing.

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

## Disabled static OAuth2 provider registration

After the provider and provider-metadata migrations, apply both steps of
`ProviderProtocolMigrationSource` before selecting
`ProviderService.WithOAuthRegistration`. The expansion uses a constant OIDC
default for historical rows and legacy inserts. The later step validates the
closed protocol constraint under a weaker lock. Neither step rewrites the
encrypted provider settings or creates a route.

Select protocol-aware administration on every registry consumer sharing that
primary before the first OAuth registration. Legacy OIDC-only readers assume
that no OAuth rows exist. On rollback, keep the schema and use protocol-aware
reads if any OAuth provider has already been registered.

`ProviderRegisterOauth` accepts only the validated root-owned static intent.
It resolves the same current organization administration, protected risk, audit
and outbox owners as OIDC, with a separate action and encrypted protocol binding.
Exact retries recover the original disabled result. Pending domains do not
become verified, and registration does not install credentials, enable the
provider, make a provider request or issue a session.

### OAuth provider activation and safe OIDC coexistence

Before enabling any OAuth provider, apply the protocol, credential, enablement
and login-transaction histories and select `WithProtocolRegistry` on every
OIDC `ProviderRouter` sharing that database. This immutable copy uses the
registry discriminator to ignore OAuth candidates before reading an OIDC
proof. It still counts all rows against the automatic selection limit and
will not fall back from an explicit or configured OAuth selection. The
original router remains supported for a registry without OAuth activations.

Use the protocol-aware organization-bound `ProviderService` with both explicit
enable and disable authorization owners. After installing the exact OAuth
client secret, obtain `ObserveOAuth2ProviderCredentialCheckpoint` and pass it
with the current verified organization domain proof to `ProviderEnable`. The
checkpoint selects the protocol and does not extend the original observation.
Only a provider with a single configured verified domain can be enabled. Keep
the original inputs and key to recover an ambiguous result. A later disabled
provider does not erase or rewrite the historical result of that request.

Use `ProviderDisableOAuth2` with the exact enabled version and a disposition
selector. A lost acknowledgement is reconciled through the original request;
use `RetryProviderDisableOAuth2` only for a confirmed not-committed command.
The older OIDC methods cannot consume OAuth credentials, proofs or recovery
anchors. These are native administrative operations; activation alone does
not register an OAuth start/callback, reach the provider or issue a session.

`RouteOAuth2` is available only on the protocol registry copy. Pass the exact
tenant, verified domain and provider ID. The bounded native read authenticates
the current proof and installed credential under the OAuth protocol; it does
not fall back to OIDC or select an automatic/default OAuth provider. A route
is not a login transaction, and copying it does not renew the proof or expiry.

Install both `LoginTransactionProtocolMigrationSource` versions after the
existing login-transaction and provider-registry migrations, before any OAuth
start writer. The expansion atomically replaces the OIDC-only check with a
closed OIDC/OAuth check without scanning the populated table under its short
exclusive lock. The second version validates the new check under a weaker lock.
Neither rewrites ciphertext, PKCE custody or indexes. Leave the expanded schema
in place during code rollback; an OIDC-only constraint cannot be restored while
OAuth rows exist.

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
