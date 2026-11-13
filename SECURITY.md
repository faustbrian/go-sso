# Security policy

## Current support boundary

The experimental runtime profile is DNS domain challenge/proof orchestration,
with optional bounded DNS retrieval and encrypted native challenge custody.
Organization remains the sole domain proof/ownership authority. Provider
registration, routing, HTTPS verification, protocol login, JIT and HTTP routes
are not implemented or advertised. No stable supported production release or
complete SSO-platform security qualification is claimed.

The [threat model](docs/security/threat-model.md) records design requirements
for the selected profile and future work, not a completed security assessment.
Behavioral evidence and independent review remain required before support or
release claims; scanner success does not establish those properties.

## Private reporting

Use [GitHub private vulnerability reporting](https://github.com/faustbrian/go-sso/security/advisories/new)
for security-sensitive defects in this repository, its automation, or its
proposed contracts. Do not open a public issue containing exploit details,
credentials, private identities, tenant data, or reporter information.

Include the affected commit or planning document, the relevant trust boundary,
a minimal sanitized reproduction where possible, and the expected impact.
The repository maintainer owns acknowledgement, severity assessment,
remediation coordination, and disclosure. No response-time or runtime support
guarantee is made by this policy.

Confirmed issues are triaged by impact and reproducibility. Coordinate public
disclosure through the private report; identify affected source and versions
accurately rather than assigning a release to an unimplemented package.
Future runtime vulnerabilities require regression evidence, upgrade guidance,
and a coordinated security release before claiming remediation. Documentation
or automation defects may be fixed without a module release.

## Release verdict

Experimental and not fully release-qualified. Selected DNS behavioral evidence
does not establish every SSO unit, protocol, supply-chain or release obligation.
Repository automation, runtime source and documentation remain subject to review
and applicable required checks.
