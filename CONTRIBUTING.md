# Contributing to loquitur-verify-ts

This repository holds `@loquitur/verify`, the TypeScript offline verifier for Loquitur evidence
bundles, a preview maintained by one person.

## Contributions during the preview

External contributions start with an issue. A pull request is welcome under the Developer
Certificate of Origin when it is tied to an issue the maintainer has accepted. A normative
change to the protocol goes through the LCP change-proposal register of `loquitur-protocol`,
`docs/change-proposals.md`.

Report a vulnerability privately, as [`SECURITY.md`](SECURITY.md) says, never in an issue or a
pull request.

## What a contribution states

Keep a contribution small, reviewable and inside this repository's surface: the verifier, its
tests and its documentation. State:

1. what changes in the verifier's behavior, its exported surface or the package contents;
2. whether a public claim changes;
3. what public or private boundary risk you considered;
4. which checks you ran;
5. what remains unverified.

## What does not belong here

- private evidence bundles;
- real issuer material, or third-party material whose license does not permit redistribution
  or that `NOTICE` does not credit;
- credentials, tokens, headers, cookies, API keys or private URLs;
- claims of production readiness, compliance, audit, legal truth, chain finality or valuation
  correctness;
- code or documents that another repository owns, or the internals of an unpublished one;
- network access or AI anywhere on the verdict path.

## Checks

[`docs/maintainers/testing.md`](docs/maintainers/testing.md) gives the commands CI runs and how
to run the tests that read sibling repositories. The static checks are TypeScript's strict mode
with `noUnusedLocals` and `noUnusedParameters`, over the sources and the tests; no linter runs.

## Maintainer documents

- [`docs/maintainers/testing.md`](docs/maintainers/testing.md): the build, the checks and the
  whole suite.
- [`docs/maintainers/releasing.md`](docs/maintainers/releasing.md): the tag rules, the release
  workflow and how a release's files are checked.
- [`docs/maintainers/REPOSITORY_LAYOUT.md`](docs/maintainers/REPOSITORY_LAYOUT.md): what each
  path holds and what the npm package carries.
- [`docs/maintainers/TEST_OWNERSHIP.md`](docs/maintainers/TEST_OWNERSHIP.md): which tests this
  repository owns.
- [`docs/maintainers/DOCS_OWNERSHIP.md`](docs/maintainers/DOCS_OWNERSHIP.md): what its
  documentation covers.
- [`docs/maintainers/public-private-boundary.md`](docs/maintainers/public-private-boundary.md):
  what the package is and is not.

## Developer Certificate of Origin

Contributions are made under the Developer Certificate of Origin 1.1
(https://developercertificate.org/). Every commit, the maintainer's own included, carries a
sign-off line whose name and address match the commit's author, and CI checks every commit of
a push or pull request for it. `git commit -s` adds the line:

```
Signed-off-by: Your Name <your.email@example.com>
```

The sign-off certifies that the contributor wrote the change or otherwise has the right to
submit it under the project's licenses. There is no separate contributor agreement.

## License

The repository is licensed under either of the Apache License, Version 2.0
([`LICENSE-APACHE`](LICENSE-APACHE)) or the MIT license ([`LICENSE-MIT`](LICENSE-MIT)), at your
option (`MIT OR Apache-2.0`). The third-party test data `NOTICE` credits keeps its own license.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
this repository by you, as defined in the Apache-2.0 license, is dual licensed as above, without
any additional terms or conditions. The Developer Certificate of Origin sign-off above is
required as well.
