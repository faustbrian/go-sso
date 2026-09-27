# Security policy

## Current support boundary

This repository is planning-only. It contains no implemented SSO package,
runtime API, supported protocol, or published release. Its module declaration
is a tooling identity, not an installable security product. No version is
currently supported for production use, and no module release is eligible.

The [threat model](docs/security/threat-model.md) records design requirements
for future work, not verified protections or a completed security assessment.
Future implementation requires its own behavioral security evidence and review
before any support or release claim.

## Private reporting

Use [GitHub private vulnerability reporting](https://github.com/faustbrian/go-sso/security/advisories/new)
for security-sensitive defects in this repository, its automation, or its
proposed contracts. Do not open a public issue containing exploit details,
credentials, private identities, tenant data, or reporter information.

Include the affected commit or planning document, the relevant trust boundary,
a minimal sanitized reproduction where possible, and the expected impact.
The repository maintainer owns acknowledgement, severity assessment,
remediation coordination, and disclosure. No response-time or runtime support
guarantee is made by this planning policy.

Confirmed issues are triaged by impact and reproducibility. Coordinate public
disclosure through the private report; identify affected source and versions
accurately rather than assigning a release to an unimplemented package.
Future runtime vulnerabilities require regression evidence, upgrade guidance,
and a coordinated security release before claiming remediation. Documentation
or automation defects may be fixed without a module release.

## Release verdict

Non-releasable. There is no runtime attack surface to exercise here yet;
runtime scans, protocol tests, and public consumer installation are not proof
that the planning design has been implemented. Repository automation and
documentation remain subject to review and required CI.
