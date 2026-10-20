# Changelog

All notable changes to `@loquitur/verify` are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project targets semantic versioning once the public API stabilizes.

## [0.1.0] - 2026-10-20

First release of `@loquitur/verify`, the TypeScript offline verifier for Loquitur evidence
bundles, as a preview. README.md states its status and its limits.

### Added
- `verifyBundle`: offline verification of a directory bundle, its manifest and declared file
  hashes, P1 and its canonical-input hash, and the envelope and its links, with every JSON
  member held to its closed contract.
- The named checks `structure`, `integrity`, `link` and `authorization`: the registry link,
  the issuer signature and trust-registry authorization at the operator's evaluation time, and
  the trust registry's authentication against a trust root supplied out of band.
- Keys compared as secp256k1 points, whatever their labels: a trust entry or a pinned root
  whose point another one carries, in any SEC1 encoding, is `TRUST_REGISTRY_AMBIGUOUS_KEY` or
  `AMBIGUOUS_ROOT_KEY`, so a revoked key listed again under another id authorizes nothing.
- Version gates on every versioned object: a well-formed later version is reported as
  `UNSUPPORTED_VERSION`, exit 4.
- Signing Envelope v2 verification. No earlier signing payload is defined.
- The report of loquitur-protocol `docs/specification/report-contract.md`, with the outcome
  table, the checks requested and established, and the review reasons.
