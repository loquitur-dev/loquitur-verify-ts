# Security policy

This policy covers `loquitur-verify-ts`, the repository of `@loquitur/verify`, the TypeScript
offline verifier for Loquitur evidence bundles. The package is a preview, maintained by one
person.

No independent cryptographic review of this protocol or its reference verifiers has been done yet.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | Fixes land on the default branch only |

There is no earlier release, so there is nothing to backport to. A fix ships in the next 0.1.x
release.

Releases are built by `.github/workflows/release.yml`, which attaches `SHA256SUMS`, a CycloneDX
SBOM and GitHub artifact attestations to the files it builds;
[`docs/maintainers/releasing.md`](docs/maintainers/releasing.md) says how to check them.

## Reporting a vulnerability

**Use GitHub's private vulnerability reporting on this repository**: open the *Security* tab and
choose *Report a vulnerability*. The report is visible only to the maintainer, it carries no
address that can be scraped or spoofed, and it opens a draft security advisory with a fixed
identifier both sides can cite later. It is the primary channel and needs nothing set up on your
side.

If private reporting is unavailable to you, write to **security@loquitur.dev**. Keep the
details of the vulnerability out of the first message if you prefer: the maintainer replies and
agrees a private channel for them. Do not describe a vulnerability in a public issue.

Do not include real issuer evidence, private bundles, private keys, credentials, tokens,
personal data or confidential third-party material in a public issue, a pull request, a
discussion or an unencrypted report. A bundle built from test material reproduces a finding as
well.

## What to expect

- Acknowledgement within 5 working days.
- An assessment, including whether the report is in scope, within 10 working days.
- Coordinated disclosure: the maintainer agrees a publication date with you first, and
  credits you unless you ask not to be credited.
- The maintainer aims to publish a fix and an advisory within 90 days of the day the report is
  received, and may agree a different date with you.

## Advisories and identifiers

A confirmed vulnerability is published as a GitHub security advisory on this repository, with
the affected and fixed versions. Its `GHSA-` identifier is the reference. For a vulnerability in
a released version, the maintainer requests a CVE identifier through GitHub, and the advisory
carries it once assigned. A vulnerability in the specification itself is published on
`loquitur-protocol`, and this repository's advisory points to it.

## Scope

In scope, for this repository:

- a verdict, status or exit code that differs from what the specification requires for the
  same input, above all a `PASS` that the specification does not allow;
- canonicalization, strict JSON loading, hashing, signature verification, registry link,
  trust-registry authorization and trust-root authentication;
- the directory reader: containment, links, reparse points and member names;
- content of a bundle or a host document that makes the verifier throw, hang or exhaust memory;
- a network access, or any path outside the allow-list of
  `scripts/check-verdict-path-isolation.mjs`, reachable from the verdict path;
- the package contents, the publication guard and the build;
- documentation that would lead an integrator to an unsafe use or to a trust assumption the
  verifier does not support.

Out of scope here:

- the specification's rules, which `loquitur-protocol` owns, and the Python verifier, which
  `loquitur-verify-py` owns: report those on the repository that owns them;
- what the README lists under "What it does not verify" and "Scope and limits", such as anchor
  finality, registry inclusion, archive intake or an issuer's real-world identity: stating that
  one of them is absent is a correct reading of the documentation, not a finding;
- legal ownership, valuation correctness, regulatory compliance and the operation of a
  registry, which this package does not claim to establish.
