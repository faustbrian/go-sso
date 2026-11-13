# DNS domain verification

Experimental optional implementation of `sso.DomainProofEngine`. The root SSO
package does not import this module. Only DNS TXT is selected; HTTPS, aliases,
DNSSEC validation, quorum, retries and local result caching are unsupported.

Construct an immutable `Profile` with an explicit clock, total duration
(1ms..30s), observation TTL (1s..24h) and process concurrency bound (1..1024).
Construct a `DNSResolver` with a trusted numeric resolver endpoint, timeout,
UDP wire budget (512..4096 bytes) and total record budget (1..64), then call
`NewEngine`. Startup configuration is not request-controlled.

The exact record owner is `_golib-sso.<canonical-domain>.`; the entire TXT RR
value, after joining its DNS character-string segments, must be
`golib-sso=<64 lowercase hex SHA-256 capability commitment>`. The engine obtains
this commitment only from the immutable SSO-issued request. It neither issues
nor exposes capability authority and cannot commit ownership or route SSO.

Domains use pinned `x/net/idna.Lookup` and Public Suffix List data. The selected
profile requires a registrable canonical ASCII name and rejects IPs, public
suffixes, unknown single-label suffixes, wildcard ambiguity, trailing root dots,
invalid labels and overlong exact TXT owners. Organization's existing ASCII
claim identity is preserved; the engine does not silently rename a stored claim.

DNS uses bounded UDP. CNAME depth is zero: aliases fail closed, with no target
following. NXDOMAIN, NODATA and mismatch are distinct bounded denials. SERVFAIL,
timeout, TC/truncation and malformed/unexpected data remain unavailable evidence,
never success or automatic ownership loss. An AD bit is not a DNSSEC assertion.
There is no fallback to another resolver, TCP or a weaker method.

Successful expiry is the earliest of original DNS remaining TTL measured from
read start, configured observation TTL and original challenge expiry. Network
latency cannot renew freshness. No prior success is cached. Current proof use
still requires the organization owner's primary read, including its expiry,
withdrawal, revocation and exact version checks.

The engine immediately rejects excess process concurrency, honors bounded
contexts, closes each socket and owns no background worker. SSO's trusted
observer applies configured existing per-tenant/org/domain/current-network rate
admission before invoking it. Errors and observations exclude DNS bodies,
challenge values, complete domains and resolver addresses from diagnostics.

The independent task-owned DNS server in the tests exercises actual wire TXT
retrieval and TTL. Deterministic response cases and bounded fuzz targets cover
domain normalization and DNS response parsing. This is local interoperability,
not a claim of live external verification or complete unit/release qualification.

Dependency: `github.com/miekg/dns v1.1.73`, BSD-3-Clause, immutable upstream
source `d854399da1ee385b432e8b07f79e53bbfc1ab1b0`. Its bounded UDP reader and
non-preallocating RR parser are used rather than a home-grown DNS protocol.
