# Repository layout

This repository holds `@loquitur/verify`, the TypeScript offline verifier for Loquitur evidence
bundles. It is a package repository: it holds no server and no specification text.

| Path | Purpose | In the npm package |
| --- | --- | --- |
| `src/` | The verifier, exported from the package root and from `@loquitur/verify/browser` | Built to `dist/src` |
| `src/generated/loquitur-protocol.ts` | Protocol types generated from the `loquitur-schemas` declaration artifact, bound by `SCHEMA_TYPES_LOCK.json` | Built to `dist/src` |
| `src/receipt-contract.generated.ts` and `scripts/generate-receipt-contract.mjs` | The verification receipt's closed contract, generated from `loquitur-protocol/docs/specification/schemas/verification_receipt.schema.json` and enforced by `src/receipt-contract.ts`; `node scripts/generate-receipt-contract.mjs --check` compares it with the sibling schema. Never edited by hand | The generated file, built to `dist/src` |
| `test/` and `test-vectors/` | The suite, and `test-vectors/`, the local fixtures of this repository: some files are identical to the files of the pinned conformance corpus, some differ and some exist only here; the corpus, not this directory, is the reference | No |
| `examples/verify-test-vectors.mjs` | The runnable example of `README.md`: verifies `test-vectors/` through the package's public entry point | No |
| `scripts/publish-guard.mjs` | The npm publication guard, which fails closed. It stays active until a release approves npm publication | No |
| `scripts/conformance-adapter.mjs` | Read-only adapter that answers one JSON request on standard input with `verifyBundle` or the protocol parsers, from `src/` compiled into the directory `LOQUITUR_CONFORMANCE_BUILD` names. It owns no protocol expectation. The cross-repository gate that calls it is in `loquitur-conformance`, which is not published; a reader verifies the same corpus with `test/corpus-roots.test.ts` | No |
| `scripts/differential-adapter.mjs` | Line-by-line adapter, compiled the same way, for the differential harness of `loquitur-conformance`, which is not published: the strict loader on bytes, RFC 8785 bytes, the two signing messages, the evaluation time and member names. `test/differential-adapter.test.ts` builds and runs it | No |
| `scripts/check-verdict-path-isolation.mjs` | Holds every source under `src/` to an allow-list of imports, so that the verdict path reaches no network and no AI | No |
| `tools/check_public_boundary.py` | Boundary scan of every tracked file for disclosure needles and private-perimeter names; the same file as in `loquitur-schemas` and `loquitur-verify-py` | No |
| `tools/check_packed_tarball.py` | The same search over every file of the packed npm tarball, which the release workflow runs before it sums the files | No |
| `tools/readme_includes.py` | The rules a README include block keeps, which `test/readme-include-markers.test.ts` runs over `README.md`; the same file as `tests/readme_includes.py` in `loquitur-schemas` and `loquitur-verify-py` | No |
| `.github/workflows/ci.yml` | The checks every push to `main` and every pull request runs | No |
| `.github/workflows/release.yml` | The release workflow: on a `vX.Y.Z` tag, the npm tarball, its SBOM and `SHA256SUMS`, attested and attached to a draft GitHub release; [`releasing.md`](releasing.md) describes it | No |
| `docs/maintainers/` | These maintainer documents | No |
| `CONFORMANCE_CONSUMER.json` | The conformance corpus this repository is measured against, pinned by digest | No |
| `SCHEMA_TYPES_LOCK.json` | The digest that binds the generated types to the `loquitur-schemas` declaration artifact | No |
| `package.json` | npm package metadata; `private: true` until a release approves npm publication | Yes |

`README.md`, `LICENSE-APACHE`, `LICENSE-MIT` and `NOTICE` are in the npm package beside `dist/src`.
Nothing else is. That is what the `files` list of `package.json` says (`dist/src`, `README.md`,
the two licenses and `NOTICE`; npm adds `package.json` itself), and what `npm run pack:dry-run`
lists: a file the repository holds and the list does not name, such as `SECURITY.md`,
`CONTRIBUTING.md`, `SCHEMA_TYPES_LOCK.json` or `test-vectors/`, is not in the tarball, so the
README links to those files by their address on GitHub.

## Boundary

The package is a preview. It is not described as production-grade, stable or audited. It ships
no HTTP client.

## Local checks

The commands are in [`testing.md`](testing.md).
