# go-sso

Experimental, storage-neutral enterprise SSO workflows for Go 1.27.

Selected profiles are **DNS domain proof** and explicitly opted-in **HTTPS
well-known domain proof**: an existing authorized organization claim receives
an SSO-issued capability-bound challenge, the selected adapter observes its
exact public commitment, and the organization owner alone
commits and reads authoritative proof. A separate native profile registers
**disabled, metadata-only static OIDC providers** and reads safe organization
metadata. A separate opt-in native credential profile initializes or replaces
an encrypted client secret while preserving disabled state. These profiles are
not a release-qualified SSO platform. The separate opt-in enablement profile
changes disabled static-OIDC provider state only after current native domain,
credential and organization checks. Trusted native verified-domain routing
is opt-in. Active-use credential overlap, public discovery, login, JIT,
protocol adapters and HTTP routes are not implemented or advertised.

## Disabled static OIDC provider values

`NewOIDCStaticMetadata` validates explicit HTTPS issuer, authorization, token
and JWKS locations without fetching them. `NewAttributeMapping` freezes a
positive mapping version and explicit flat claim names; it interprets no claims
and grants no roles or permissions. Zero values are invalid. Their explicit
`Spec` projections are detached configuration, not protocol or domain proof;
implicit formatting is redacted and serialization fails closed.

The storage-neutral `ProviderRegisterOidcRequest` accepts these values, an exact
issuer, canonical distinct pending domains, a command ID and an idempotency key.
It accepts no provider credential, enabled flag or freshly manufactured proof.
The native [PostgreSQL composition](postgres/README.md) authenticates current
organization administration and owns persistence through the existing identity
coordinator. `ProviderGetRequest` and bounded `ProviderListRequest` select safe
metadata only. Registered providers remain disabled with empty `VerifiedDomains`;
requested domains do not become ownership evidence or routes.

`ProviderUpdateRequest` carries the catalog command, provider ID, expected
version, closed `TypedProviderConfiguration`, complete mapping and original
idempotency key. `NewStaticOIDCProviderConfiguration` selects only explicit
metadata: there is no credential, enablement, discovery-fetch or routing input.
The selected update preserves issuer, subject claim and pending domains; mapping
versions advance by exactly one. The native service binds the organization
separately before invocation and checks current organization authority, rather
than resolving ownership globally from the provider ID. See the PostgreSQL
schema and protected-counter prerequisites before enabling this profile.

### Credential-reference boundary

The storage-neutral `ProviderCredentialsRotateRequest` is a separate contract
with an original command, provider ID, optimistic version, an authenticated
`EncryptedCredentialReference` and an explicit `NewNoCredentialOverlapPolicy()`.
It has no external idempotency key and is not a generic metadata update.

Trusted ingress encrypts the client secret with the configured envelope owner
and the exact `CredentialReferenceContext.EncryptionContext()`: tenant,
organization, provider, OIDC protocol, client-secret purpose, credential
generation, current provider version, operation audience, configured key identity
and the original UTC-microsecond lifetime. `NewEncryptedCredentialReference`
authenticates bounded envelope bytes and immediately clears temporary plaintext;
it accepts and returns no raw secret. The reference is immutable and redacted.

Construction does not establish native trust or current authorization. A native
consumer must authenticate it again with its own configured envelope service,
immutable key/lifetime profile and clock, and compare current owner, provider
version and generation. Caller-selected keys or a renewed lifetime cannot
authorize a write. Native composition uses the separately configured
`postgres.NewProviderCredentialsService` and a current fresh
`org:sso-credentials` policy owner. Install its additive migration before opting
in. Initial/replacement commands advance the shared provider version without
changing metadata or mapping; only one current encrypted generation is retained.
Original command retries return their exact historical result, never credential
bytes or a renewed lifetime. Active-use overlap, drain, SAML keys/certificates
and provider-network calls remain unsupported.

### Enablement-checkpoint boundary

`ProviderEnableRequest` is distinct from registration, metadata updates and
credential rotation. It carries the provider ID, exact expected version, an
organization-owned `DomainProofCheckpoint`, an immutable `CredentialCheckpoint`
and the original idempotency key. It has no caller-selected command ID.

`NewCredentialCheckpoint` snapshots a `CredentialCheckpointBinding` for the
exact tenant, organization, static-OIDC provider, provider version and active
client-secret generation. Its original observation and expiry must be UTC
microseconds with a positive lifetime of at most 20 seconds. `Bindings()`
explicitly returns a detached non-authoritative copy; neither construction nor
`ProviderEnableRequest.Validate()` checks current readiness or renews a lifetime.
The checkpoint type is specific to enablement and cannot select another
credential purpose or operation. Checkpoints and requests redact diagnostics
and reject implicit JSON/text serialization.

The native enablement transition must read the exact current organization proof
and active encrypted credential, reject expiry, revocation, owner/version or
generation changes, and obtain fresh `org:sso-write` authorization before a
write. Domain checkpoints never replace `organization.DomainProofReader`.
Enabling provider state alone establishes no route, enforcement or login flow.

### Verified domain route contract

Public discovery is a separate opt-in `Service.Discover` workflow. It accepts
an exact DNS domain or plain ASCII email address, discards the email local
part before calling the trusted discovery owner, and returns only a safe
provider ID, protocol, and optional confirmation requirement for a match.
A no-match contains no provider or organization data. Validated domain
discovery does not authorize login or prove that an account exists. Use the
native adapter, not an unguarded router, to back an anonymous surface.

`NewDomainRouteRequest` takes an exact tenant, a DNS name, and optionally a
provider ID. It uses the organization owner's ASCII domain grammar and never
infers a tenant or organization from an email. `SelectDomainRoute` chooses an
eligible explicit provider, configured default, or the unique remaining
candidate; it denies missing choices and reports ambiguity rather than picking
by insertion or row order.

`DomainRoute.Bindings()` gives trusted native code the provider, credential
generation, policy version, organization proof and original deadline. The
snapshot is not a login grant and is never implicitly serialized. Any later
login transaction must recheck its current provider and organization authority.

## Composition

The root package defines immutable `DomainProofRequest`,
`DomainProofObservation`, `DomainProofMethod` and exactly
`DomainProofEngine.Observe(context.Context, DomainProofRequest)`. It imports
neither the DNS implementation nor database/transaction types.

- [domain-verification](domain-verification/README.md) implements bounded DNS
  and verified-TLS HTTPS profiles.
- [postgres](postgres/README.md) supplies encrypted challenge persistence and
  the existing native organization evidence facade. It stores no proof truth or
  command outcomes.
- `github.com/faustbrian/go-organization` owns domain claims, unique ownership,
  versioning, expiry, withdrawal/revocation and current proof reads.

Configure the existing native organization/kernel/session/risk/audit/outbox
owners first. Construct the challenge store and DNS engine, then construct
`NewDomainObserver` and install it as the deployment-selected
`organization/postgres.DomainEvidenceSource`. This ensures external observation
runs only inside organization's existing current claim/session/policy admission.
The native `NewDomainEvidenceFactory` wraps that same organization service.

Create an invocation-scoped `NewService` with current authentication and the
canonical client IP from a trusted transport. The caller supplies configuration,
capability keys/resolver, the existing authorization service and a fail-closed
rate-limit service/policy, not missing domain stores or transaction glue.

```go
issued, err := service.ChallengeDomain(ctx, sso.DomainChallengeRequest{
    OrganizationID: organizationID,
    ClaimID:        existingClaimID,
    CommandID:      originalCommandID,
    CorrelationID:  "domain-proof",
})
if err != nil {
    return err
}
owner, value := issued.DNSTXT()
// Publish exactly this owner/value through your DNS administrator.
_ = owner
_ = value

result, err := service.VerifyDomain(ctx, issued.Request())
if err != nil {
    // Retain the original request and outcome. Unknown must be recovered.
    return err
}
current, err := service.GetDomainProof(ctx, organization.DomainProofKey(result.Proof))
_ = current
return err
```

The complete executable native composition is in
[postgres/domain_integration_test.go](postgres/domain_integration_test.go).
Its independent authoritative DNS server controls only external TXT publication;
actual public native owners retain all organization, authorization, session,
risk, transaction, audit and proof authority.

### Explicit HTTPS composition

Install `postgres.DomainChallengeMethodMigrationSource` after the original
challenge migration and before enabling HTTPS callers. Keep `NewStore`,
`NewDomainObserver`, `NewService` and the original request/config literals for
unchanged DNS behavior, including against the original schema.

For HTTPS, use `postgres.NewHTTPSStore`, `domainverification.NewHTTPSFetcher`,
`domainverification.NewHTTPSEngine`, `NewHTTPSDomainObserver` and
`NewHTTPSService` at the same existing composition points. `ChallengeDomain`
then selects HTTPS; publish the URL/body from `issued.HTTPSWellKnown()` with
exact `Content-Type: text/plain`, no parameters or trailing newline. The URL is
`https://<canonical-claim-domain>/.well-known/golib-sso` on port 443 and the body
is `golib-sso=<issued lowercase SHA-256 digest>`. `DNSTXT` returns empty strings
for HTTPS issuance, and vice versa. Verification, recovery and current-proof
reads use the same methods above and the organization owner remains authoritative.

Method changes cannot replace an original challenge or renew it. Use a new
organization-owned immutable claim after an authorized withdrawal; no automatic
renewal, takeover, DNS fallback or HTTPS-to-DNS downgrade is implemented.

## Custody and recovery

Generate a command ID using `identity.NewCommandID` and preserve it. There is one
immutable challenge per exact tenant/organization/claim; issuance retries never
renew its expiry. The capability is envelope-encrypted at rest. DNS contains
only its SHA-256 commitment. The commitment and a method label confer no
organization authority by themselves. Current owner/admin authentication and
explicit SSO action policy are required again at verification and recovery.

The observer receives a private invocation-scoped binding with the exact issued
request and **current invoking network**, not the original challenge's network.
It applies the existing rate limiter to tenant, organization, domain and network
before DNS. The engine additionally bounds process concurrency and network work.
No global request selector, background worker, cached allow or replacement
ownership authority exists.

Before Apply, SSO saves only the original safe organization recovery binding.
A lost commit response exposes Unknown and no proof. `RecoverDomain`, and a
verification retry with saved recovery scope, query only that original native
command and never perform DNS or reexecute.

A process/cancellation window after saving the binding but before Apply is
also Unknown, not a proved rollback. The native generic coordinator deliberately
makes absent and denied recovery indistinguishable. Such recovery may remain
undisclosed; retain the original Unknown and binding. Do not infer
NotCommitted, automatically retry observation or invent a new command outcome.
An operator who explicitly abandons the attempt may use the existing
current-authorized organization withdrawal operation, then reserve a **new**
immutable claim and issue a new challenge. This is not automatic renewal,
transfer or takeover.

For process recovery, rebuild the invocation service with fresh current
authentication, use `LoadDomainRequest` with the exact original key, then call
`RecoverDomain`. A historical committed result remains historical after expiry
or withdrawal. Only `GetDomainProof` consults current primary proof authority;
neither a retained challenge nor recovered proof snapshot authorizes routing.

## Verification and limits

Focused module tests, native integration, race/cancellation, bounded domain/DNS
fuzzing and representative indexed query tests cover this selected profile.
The query test records actual pgx SQL/binding types and plans on 100,001
synthetic challenge rows; its local warmed timings are not production claims.
Full unit coverage/mutation, release supply-chain and clean published-consumer
qualification remain separate obligations. No full `sso`,
`sso/domain-verification`, `sso/postgres` or M25 completion is claimed.

Every Go run needs task-owned `GOCACHE`, `GOMODCACHE` and `GOTMPDIR`. Run tests
inside the selected module; native tests require the explicitly task-owned
`GOLIB_ORGANIZATION_TEST_POSTGRES_DSN` fixture and integration tag. Never point
the fixture at an existing/shared database cluster.

See [SECURITY.md](SECURITY.md), [the repository goal](docs/goal.md) and
[CHANGELOG.md](CHANGELOG.md). Existing planning goals retain the broader scope.
