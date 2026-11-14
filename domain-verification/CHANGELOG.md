# Changelog

## Unreleased

- Add an explicitly selected verified-TLS HTTPS well-known engine with exact
  host/path/body binding, vetted public destination pinning, no proxies or
  redirects, bounded network resources and active cancellation. DNS stays the
  existing constructor's default; neither engine grants domain ownership.

- Add the experimental bounded DNS TXT implementation of the root SSO proof
  engine with exact challenge binding, IDNA/public-suffix validation, classified
  DNS failures and TTL-bounded non-authoritative observations.
- Keep HTTPS, aliases, retries, caching and DNSSEC claims unselected.
