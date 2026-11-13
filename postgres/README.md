# Native SSO challenge custody

Experimental optional adapter for the selected DNS domain-proof journey.
`Store` persists only immutable challenge binding, envelope-encrypted capability
and original safe organization recovery scope. It has no proof/result table,
transaction coordinator or alternative ownership truth. Provider/login/JIT
persistence and every optional wire-protocol module remain unselected.

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

## Recovery

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
