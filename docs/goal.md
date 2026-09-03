# Goal: planned go-sso boundary

Status: planned

The coordination plan identifies `github.com/faustbrian/go-sso` as the future
storage-neutral owner of enterprise SSO provider lifecycle, verified-domain
routing, discovery, mapping and JIT provisioning, organization membership,
enforcement, break-glass recovery, enterprise token custody, and directory
synchronization.

The source planning record is `.ai/identity-platform/goals/sso.md` in the Golib
coordination tree, with SHA-256
`d5455f0f9d2b2d934451a859b235f532b76d68d202223e3832b3480f3403153e`.
That record contains proposed contracts; it is not implementation evidence.

## Current planning acceptance

- Keep this repository visibly planned and absent from installable consumer
  catalogs.
- Record the frozen Service Edge family, enterprise SSO capabilities,
  ownership, and delivery lifecycle in schema-v2 engineering metadata.
- Validate the metadata locally and in hosted CI with immutable,
  checksum-verified `go-library-tools` v1.4.0 tooling.
- Do not claim a public package identifier, installation path, runtime API,
  protocol support, compatibility promise, or released behavior.

## Deferred implementation

Source packages, nested modules, dependencies, protocol and persistence
adapters, API contracts, behavior, hardening evidence, interoperability,
compatibility commitments, tags, and releases remain outside this planning-only
goal. They require separately authorized work and their own executable
acceptance evidence.
