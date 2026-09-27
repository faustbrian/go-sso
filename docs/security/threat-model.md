# Enterprise SSO threat model

Version: 1. Scope: the planned root `github.com/faustbrian/go-sso` boundary.

## Status and assets

No runtime implementation exists. The following requirements must be proved
when executable code is introduced; none is an assertion of current protocol
support or security behavior. Present assets are planning integrity, maintainer
authority, immutable automation inputs, and private security reports. Future
assets include organization membership, verified domains, login transactions,
enterprise tokens, directory state, and break-glass access.

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
| Proposed design mistaken for a usable SSO implementation | Repository maintainer; planning documents can be mistaken for guarantees. README and security policy state no runtime/release, metadata marks non-releasable. Review on any source, catalog or release change. |
| Application or protocol adapter mistakes after future composition | Future application and adapter owners; those components are intentionally outside this root boundary. Require explicit integration authority and executable binding/failure tests before implementation or support claims. Not an acceptance of an exploitable runtime defect. |

No known runtime finding is accepted or declared fixed in this planning-only
repository. A future implementation must revisit this model and produce its
own release verdict; this document cannot satisfy that future completion gate.
