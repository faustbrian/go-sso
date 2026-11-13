# Enterprise SSO threat model

[Documentation map](../index.md) · [Repository README](../../README.md)
[Next: Goal: planned go-sso boundary](../goal.md)

Version: 2. Scope: selected experimental DNS proof profile and retained broader
`github.com/faustbrian/go-sso` planning boundary.

## Status and assets

The selected runtime issues bounded capability-bound DNS challenges and consumes
organization-owned proof transitions. Assets include encrypted challenge
capabilities, original safe recovery scope, organization isolation, freshness and
current session/management authority. No provider, routing, protocol login, JIT,
HTTPS or HTTP capability is exposed. The broader requirements below remain
future scope, not current protocol or whole-platform security claims.

## Selected DNS boundaries

| Boundary | Current policy and attributable regression |
| --- | --- |
| Current caller to issued challenge | Actual primary organization claim/session admission plus SSO action policy; tenant/org/claim/version, actor, purpose, method, command ID and original expiry bind the existing signed capability. |
| Current invocation to DNS observation | Private invocation-scoped exact-request/current-network binding; existing fail-closed rate admission for tenant/org/domain/network and fixed process concurrency before bounded external work. No global request selector. |
| DNS wire to non-authoritative observation | Exact TXT owner/value, canonical IDNA/PSL scope, bounded UDP/records/bytes, zero CNAME depth, classified denial/unavailability, no retries, cache or DNSSEC claim. Domain/DNS fuzz targets and an independent authoritative DNS wire server exercise this boundary. |
| Observation to organization proof | Only the configured trusted organization source and existing native facade may prepare/apply evidence. Actual kernel/org/session/risk/audit/outbox owners retain current authority, commit, rollback, unique ownership and current-proof reads. |
| Ciphertext to challenge custody | Existing secret-envelope AEAD binds exact scope and UTC times. No capability plaintext, DNS answers, private network addresses or raw dependency diagnostics enter persistence/log output. |
| Ambiguous attempt to recovery | Original safe binding saved before Apply; lost commit recovers the identical native result without DNS. Saved-but-unapplied absence/denial remains unresolved, never inferred rollback or automatic reexecution. Historical proof does not replace current primary proof. |

Native tests cover wrong-tenant, mismatch, expired/withdrawn challenge, current
network throttle, pre-Apply cancellation and actual lost COMMIT response. Local
profile evidence is not complete unit/release qualification or live external
DNS validation. Callers own keys, configured resolver, bounded policy/rate owners
and runtime resource lifetime; they do not supply substitute domain stores or
proof/transaction authorities.

## Proposed trust boundaries

| Boundary | Attacker-controlled input and required future proof |
| --- | --- |
| Domain routing and discovery | Domain strings, tenant identifiers and remote metadata must be canonical, bounded, tenant-bound and fail closed. Discovery, redirects, DNS, proxies and network access require explicit caller policy and SSRF tests. |
| Protocol adapter to core assertion | OAuth/OIDC/SAML adapters remain separate owners. Core must not trust an unverified assertion; issuer, audience, organization, transaction and freshness binding require independent acceptance/rejection tests. |
| Provider and login lifecycle | Untrusted callbacks, state and retries must not bypass enforcement or replay completed transactions. Prove bounded state lifetime, single-use admission, cancellation and concurrent transition ownership. |
| Mapping, JIT and membership | External attributes are not authority to grant privileged roles. Prove explicit policy, tenant isolation, duplicate handling and atomic or recoverable provisioning without cross-organization membership changes. |
| Tokens and directory synchronization | Caller-owned custody and persistence must preserve least privilege, explicit secret handling, bounded pages and retries, cancellation, poison-entry handling and idempotent reconciliation. No implicit background worker is permitted. |
| Enforcement and break-glass recovery | Every privileged bypass needs explicit authorization and safe audit attribution. Test revoked access, malformed policy, recovery concurrency and failure paths without logging token or identity payloads. |
| Automation and disclosure | Pin external tools/actions; protect private reports, credentials and release authority. Required CI and manual review must distinguish planning metadata from executable evidence. |

## Ownership and future acceptance

The application owns provider configuration, runtime resources, secret custody,
persistence and deployment. The future core owns only its explicit policy and
lifecycle contracts. Protocol verification remains with the chosen adapter;
composition must prove that an unverified adapter result cannot become a core
authorization decision. Mutable inputs must be copied and external operations
must have finite caller-visible size, depth, count, concurrency, retry and time
budgets before retaining or processing hostile data.

Implementation must add observable fail-closed, isolation, redaction, replay,
concurrency, cancellation and exhaustion regressions at the owned boundaries.
Parser fuzzing, race checks, actual protocol fixtures and direct consumer tests
apply only to the risks introduced. Maintained standard or x/crypto primitives
are required; custom cryptography and timing-sensitive credential comparison
are not acceptable shortcuts. Scanner success does not establish these
behavioral contracts or replace independent design review.

## Current risk disposition

| Risk | Owner, rationale, mitigation and review condition |
| --- | --- |
| Selected DNS profile mistaken for complete SSO | Repository maintainer; the README and security policy name the exact experimental runtime and excluded variants. Whole-unit/release qualification remains separate. Review on any capability, source, catalog or release change. |
| Application or protocol adapter mistakes after future composition | Future application and adapter owners; those components are intentionally outside this root boundary. Require explicit integration authority and executable binding/failure tests before implementation or support claims. Not an acceptance of an exploitable runtime defect. |

No broader protocol or platform security acceptance is implied. Each additional
profile must revisit this model and establish its own executable evidence and
release verdict; this document does not satisfy that future completion gate.
