# `@loquitur/verify`: TypeScript offline verifier

`@loquitur/verify` checks Loquitur evidence on your own machine. Given a bundle, the directory of
evidence files an issuer hands over, it checks that the bundle is internally consistent: its
files match the manifest and the digests agree. Given the public registry entry that commits to
the bundle, it checks that the two agree, and given a trust registry, that the key which signed
the entry was authorized at the time you name. A bundle that is only internally consistent does
not show that nothing changed after issuance, since whoever alters the input can recompute every
digest; what shows it is a match with a signed public commitment from an authorized key, which
the link and authorization checks establish. It needs no server, no network and no trust in the
issuer's systems. It is a TypeScript library for Node.js. `loquitur-verify`, in Python,
implements the same specification: the two are implementations written separately against the
specification, by the same maintainer, and their reports are compared on the same vectors.

This package is the verifier and nothing else: it ships **no HTTP client** and makes no network
calls. Obtaining a registry entry, a trust registry or a trust-root document is the host
application's concern.

## Status

<!-- lq-include: status -->
- **0.1.0 preview (Alpha).** The API is not a stable contract and may change in a later 0.x
  release. The package is not production-grade.
- Not yet published to a package index: build it from a clone of `loquitur-verify-ts`
  ([Installation](https://github.com/loquitur-dev/loquitur-verify-ts/blob/main/README.md#installation)).
- No independent cryptographic review of this protocol or its reference verifiers has been
  done yet.
- What it does not check, and its limits:
  [What it does not verify](https://github.com/loquitur-dev/loquitur-verify-ts/blob/main/README.md#what-it-does-not-verify) and
  [Scope and limits](https://github.com/loquitur-dev/loquitur-verify-ts/blob/main/README.md#scope-and-limits).
<!-- lq-include-end: status -->

## Start here

- **You rely on a verdict, or review the risk of relying on one.** A `PASS` asserts what the
  specification's [`threat-model.md`](https://github.com/loquitur-dev/loquitur-protocol/blob/main/docs/specification/threat-model.md)
  section 2 states and nothing more; its sections 8 to 10 list the assumptions, residual risks
  and tasks that stay with a relying party. Then read
  [What it does not verify](#what-it-does-not-verify) and [Scope and limits](#scope-and-limits)
  below.
- **You integrate the verifier.** [Installation](#installation) builds and installs it from a
  clone, [Try it](#try-it) runs it over the shared vectors, and [Quick start](#quick-start)
  shows the call and the report.
- **You review its security.** The threat model above;
  [`SECURITY.md`](https://github.com/loquitur-dev/loquitur-verify-ts/blob/main/SECURITY.md) for how to report a vulnerability;
  [`cryptographic-capabilities.md`](https://github.com/loquitur-dev/loquitur-protocol/blob/main/docs/specification/cryptographic-capabilities.md)
  for the algorithms; and
  [`conformance-testing.md`](https://github.com/loquitur-dev/loquitur-protocol/blob/main/docs/specification/conformance-testing.md)
  for how an implementation is held to the specification.

## What it verifies

<!-- lq-include: what-it-verifies -->
The checks are the named checks of loquitur-protocol
[`docs/specification/verification-checks.md`](https://github.com/loquitur-dev/loquitur-protocol/blob/main/docs/specification/verification-checks.md),
each established only when every check before it is:

| Check | What it establishes | Requested by |
|---|---|---|
| `structure` | every JSON member loaded strictly (I-JSON under RFC 8785) and held to its closed contract, the version identifiers read first, `verification_receipt.json` included whenever present; the manifest carries its `nonce` and the schema version `loquitur.bundle.v1` | `verifyBundle(path)` |
| `integrity` | `manifest.json` canonical SHA-256 and the declared file digests, written as `sha256:` and the hexadecimal digest, and no undeclared file; `p1.json` digest and the canonical-input digest rebuilt; the envelope digest and its links | `verifyBundle(path)` |
| `link` | the bundle against its `registry_entry`: manifest digest, receipt digest, exact field agreement, the receipt naming this bundle and this P1; the verdict the entry commits to bounds the result: FAIL fails, WARN and REVIEW review | `verifyBundle(path, { registryEntry })` |
| `authorization` | at the operator's evaluation time: the issuer key authorized by a `trust_registry` (the registry's contract and coherence, exact issuer and key identifiers, key status, the registry's and the key's validity windows, asset-type and workflow scope), the issuer secp256k1 ECDSA-SHA256 signature (low-S enforced), and the trust registry's own signature against a trust-root document supplied out of band (`trust-root.md`) | `verifyBundle(path, { registryEntry, trustRegistry, trustRoots, evaluationTime })` |

The two checks the specification reserves, `transparency` and `anchoring`, are never requested
and never reported in this version.

The report carries the normative surface of loquitur-protocol
[`docs/specification/report-contract.md`](https://github.com/loquitur-dev/loquitur-protocol/blob/main/docs/specification/report-contract.md):
`status`, `verdict` and `exit_code` from its outcome table, `outcome.reason` derived by its
section 5.2, `errors` with their codes in the order of section 5.3, `checks_requested` and
`checks_established` (the named checks, in their order), `review_reasons` (section 3.3, in their
order), `evaluation_time` (the operator's time as supplied, or `null`), and, when the trust
registry was evaluated, `trust_registry` with the authorization, signature and root signature
statuses of section 5.4 (`null` otherwise). Beside them it carries the informative members:
`checks_evaluated`, `notes`, the `checks` map with the same eleven keys as `loquitur-verify`,
and `vocabularies`, the registered vocabulary document held for each kind. A report has, in this
order, `status`, `verdict`, `exit_code`, `outcome`, `errors`, `checks_requested`,
`checks_established`, `checks_evaluated`, `review_reasons`, `evaluation_time`, `notes`,
`trust_registry`, `checks` and `vocabularies`. A conformance comparison reads the normative
members and not the informative ones.

| `status` | `verdict` | `exit_code` | meaning |
|---|---|---|---|
| `OFFLINE_OK` | `PASS` | 0 | every requested check was established |
| `OFFLINE_FAIL` | `FAIL` | 1 | a check did not hold, or content was refused |
| `OFFLINE_REVIEW` | `REVIEW` | 2 | nothing failed, and a requested check is not established; `review_reasons` says why |
| `UNSUPPORTED_VERSION` | `null` | 4 | an object of a known type carries a well-formed version this verifier does not support; the single error `unsupported_version` names the object and the version |
| `HOST_FAILURE` | `null` | 5 | the host failed an operation on the input; the failure is the host's, can be repeated, and says nothing about the evidence |

Only `PASS` is verified. This verifier reads directory bundles and no archive, so the codes of
section 5.3 whose condition is about a ZIP archive alone (`invalid_zip`, `archive_unsafe_member`,
`archive_safety_limit` and `archive_load_failed`) never occur here. `bundle_root_invalid` is not
one of them: its condition also names a directory input whose listing has no entry named exactly
`manifest.json`, and that is what this verifier reports for such a directory, whether or not the
host ignores letter case. A regular file given to `verifyBundle` is refused as
`unsupported_input`, a directory the host fails to list as `filesystem_error`, and a fault of the
library is an exception rather than an `internal_error` report. A reader that fails to reach,
inspect or read a member for any reason other than finding nothing there throws
`BundleReadError`, which the run reports as that layer's `*_read_failed` error; the Node reader
does so for a directory on the member's path that the host fails to list. The layer is then
refused, and its presence flags record what the verifier saw: a member in the reader's listing,
or one a reader without a listing threw `BundleReadError` for, is present; a member whose entry
the Node reader failed to reach or inspect was not seen. A run whose only errors are the host's
is `HOST_FAILURE`; beside a content failure it is `OFFLINE_FAIL`. The input path is read as it
is written (`report-contract.md` section 5.3): the empty path and a path longer than the host
allows find nothing (`input_not_found`, `HOST_FAILURE`), and on Windows a device that Node's stat
cannot describe, and every path in the named-pipe namespace, is `unsupported_input`.
<!-- lq-include-end: what-it-verifies -->

## What it does not verify

<!-- lq-include: does-not-verify -->
This verifier does **not** verify anchor finality or registry inclusion, does **not** verify
valuation correctness or regulatory compliance, and does **not** verify an issuer's real-world
identity. It verifies the trust registry's root signature only against roots the caller
supplies, and it establishes nothing about who holds a root key: obtaining the trust-root
document through a channel the issuer does not control is the operator's task
(`trust-root.md` section 7). A `PASS` is a statement about evidence integrity and issuer
authorization on local material. It is a precondition for relying on the underlying verdict,
not a verdict on the underlying valuation.
<!-- lq-include-end: does-not-verify -->

The verdict path contains no AI: no machine-learning model or other learned component takes
part in any outcome (enforced by the allow-list in `scripts/check-verdict-path-isolation.mjs`).

## Requirements

- Node.js 22 or later (`engines` in `package.json`). CI runs the suite on Node 22 and 24, on
  Linux; the suite also passes on Windows locally. macOS is not tested. JSON is decoded by the
  package's own tokenizer, never by the host's `JSON.parse`, so a value the verifier hashes
  depends on the document's text alone.
- An ES module consumer: the package is ESM only (`"type": "module"`), with no CommonJS build
  and no `require` condition in its `exports` map, so `import` is the supported way to load it,
  and it ships its own type declarations. The `types` condition comes first in each entry of
  the map, as TypeScript resolves them in order.
- A library only: version 0.1 has no command line and the package declares no `bin`. The
  command-line contract of `report-contract.md` (exit code 64 for a usage error) belongs to the
  command of the Python package, `loquitur-verify`; this library raises its own faults and has no
  usage error.
- Runtime dependencies: `@noble/curves`, `@noble/hashes` and `canonicalize`, each held to the
  patch line CI tests (`~` in `package.json`). `npm ci` in a clone installs exactly the versions
  `package-lock.json` records; a tarball carries no lockfile, so installing one resolves each
  dependency within its patch line.

## Installation

<!-- lq-include: installation -->
Build a tarball from a clone of `loquitur-verify-ts` and install it in your project. The commands
are the same in PowerShell and in a POSIX shell:

```bash
cd loquitur-verify-ts
npm ci
npm pack        # builds dist/ and writes loquitur-verify-0.1.0.tgz
cd ../your-project
npm install ../loquitur-verify-ts/loquitur-verify-0.1.0.tgz
```
<!-- lq-include-end: installation -->

## Try it

<!-- lq-include: try-it -->
`examples/verify-test-vectors.mjs` verifies the bundles in `test-vectors/` through the package's
public entry point and compares each report with the outcome `test-vectors/verify.json` records
for it. From a clone:

```bash
npm ci
npm run build
node examples/verify-test-vectors.mjs
```

It prints one line per case and exits 0 when every report matches, 1 otherwise:

```text
valid                 PASS   exit 0  local_integrity_checks_passed
tampered              FAIL   exit 1  p1_integrity_failed
link                  PASS   exit 0  local_integrity_and_registry_link_checks_passed
authorization_valid   REVIEW exit 2  trust_registry_root_not_pinned AUTHORIZED_ACTIVE_KEY VALID_SIGNATURE NO_PINNED_TRUST_ROOT
authorization_revoked FAIL   exit 1  trust_registry_verification_failed ISSUER_KEY_REVOKED null ROOT_SIGNATURE_NOT_EVALUATED
all 5 reports match test-vectors/verify.json
```

The example passes the evaluation time `test-vectors/verify.json` records for the two
authorization cases, `2026-05-20T00:00:00Z`. `authorization_valid` is REVIEW because no
trust-root document is supplied: the trust registry is authorized at that time and the signature
holds, but nothing authenticates the registry itself. The case names and outcomes are those
`test-vectors/verify.json` records. `test-vectors/` holds local fixtures, not the corpus: the
pinned conformance corpus is the reference (see Conformance below).
<!-- lq-include-end: try-it -->

## Quick start

<!-- lq-include: quickstart -->
```ts
import { verifyBundle } from "@loquitur/verify";

// registryEntry, trustRegistry and trustRoots are documents the host has read,
// for instance with readDocumentPath, which the package exports.
const report = verifyBundle("./my_bundle", {
  registryEntry, // optional: requests the link check
  trustRegistry, // optional: requests the authorization check; FAIL without registryEntry
  trustRoots,    // optional: without it, an authorization that holds is REVIEW
  // The operator's time; without it, authorization is not established (REVIEW).
  evaluationTime: "2026-05-20T00:00:00Z",
});

console.log(report.status, report.verdict, report.exit_code);
console.log(report.checks_requested, report.checks_established, report.review_reasons);
console.log(report.outcome.reason, report.errors.map((e) => e.code)); // the reason surface
console.log(report.trust_registry); // the three authorization statuses, or null
console.log(report.checks); // per-check results, same keys as loquitur-verify
```

The documents are values, not paths: the host reads them and passes what it found. That is the
parsed document, or one of four markers this package exports: `DOCUMENT_PATH_NAMES_NOTHING` when
nothing is found at the path, `DOCUMENT_PATH_NAMES_NO_REGULAR_FILE` when what is found is a
directory or anything else that is not a regular file, `DOCUMENT_READ_FAILED` when reading the
file failed, and `DOCUMENT_NOT_STRICT_JSON` when the bytes are not strict JSON.
`report-contract.md` section 5.3 gives the first three conditions errors of their own for a
registry entry, different from a document that is not strict JSON, so a host that passed a
document for them would report what `loquitur-verify`, which reads the path itself, does not. A
file the host failed to read is a host failure for the trust registry and the trust roots too:
`trust_registry_read_failed` and `trust_root_read_failed`, `HOST_FAILURE`, exit 5.
<!-- lq-include-end: quickstart -->

`readDocumentPath(path)` reads a document path as `loquitur-verify` reads the path it is given,
and returns what to pass:

```ts
import { readDocumentPath, verifyBundle } from "@loquitur/verify";

const report = verifyBundle("./my_bundle", {
  registryEntry: readDocumentPath("./registry_entry.json"),
});
```

It takes three steps, and a host that reads document paths itself takes the same:

1. Inspect the path as it is written, following links (`report-contract.md` section 5.3). Node
   reads a path in the file namespace, so on Windows no name loses a trailing dot or space
   and `NUL` in a directory is an entry of that name, except in two forms it leaves to the
   Win32 layer: a path whose root is `\\.\`, and a share whose server's name begins with `.`
   or `?`. On Windows, when `path.win32.toNamespacedPath(path)` begins with `\\.\`, hand
   `statSync` and `readFileSync` that string with `\\?\` in place of the `\\.\`; when it
   begins with `\\` not followed by `?\`, with `\\?\UNC\` in place of the `\\`; otherwise
   hand them the path as it is, since Node reads a string already in the file namespace a
   second time, and `\\?\C:\` names the volume there. `ENOENT`, `ENOTDIR`, `ELOOP` or
   `ENAMETOOLONG` from `statSync` means nothing is found there, and so does the empty path
   and a path holding a NUL, which `statSync` refuses with `ERR_INVALID_ARG_VALUE`:
   `DOCUMENT_PATH_NAMES_NOTHING`, and a run given it for the registry entry or the trust
   registry is refused as a whole, `input_not_found`. An entry that is not a regular file is
   `DOCUMENT_PATH_NAMES_NO_REGULAR_FILE`. On Windows `statSync` reports a named pipe as a
   regular file whose device number is 0, and fails with `EISDIR` or `EINVAL` on a device
   it cannot describe, such as the console or a volume opened as a device: each is an entry
   that is not a regular file. On Windows Node reports `ENOENT` also when the host fails to
   follow a link to an entry that is there, such as a symbolic link to `\\.\nul`
   (`ERROR_INVALID_REPARSE_DATA`): when the deepest entry on the path that `lstatSync` finds is
   a link that `statSync` cannot follow, and the entry its target (`readlinkSync`, with `\??\`
   read as `\\?\`) names is found, that is `DOCUMENT_READ_FAILED`, looked for through at
   most 63 links. Any other error is `DOCUMENT_READ_FAILED`.
2. `readFileSync` of the same string as bytes, without an encoding. An error is
   `DOCUMENT_READ_FAILED`.
3. Decode the bytes with `new TextDecoder("utf-8", { fatal: true, ignoreBOM: true })`
   and parse the text with `parseJsonStrict`. When either throws, pass
   `DOCUMENT_NOT_STRICT_JSON`.

`readFileSync(path, "utf8")` replaces invalid UTF-8 with U+FFFD instead of refusing it, so a
file that is not UTF-8 reaches the verifier as another document, one that may be strict JSON. A
`TextDecoder` without `ignoreBOM: true` removes a leading byte-order mark, which makes a file
the strict reader refuses into one it accepts.

The library receives the registry entry, the trust registry and the trust-root document as
parsed values, so it cannot see what a lenient parser has already discarded: a duplicate member
name (`JSON.parse` keeps the last), a byte-order mark or invalid UTF-8, and a number with more
precision than a double holds. `canonicalization-and-hashing.md` section 6 refuses each of these
in every document the caller supplies. Parse every document you pass to `verifyBundle`,
`verifyBundleFiles`, `evaluateTrustRegistry`, `parseRegistryEntry`, `parseTrustRegistry`,
`parseTrustRoots` or `authenticateTrustRegistry` with this package's strict parser:
`readDocumentPath`, which reads the bytes and parses them strictly, or, where there is no file
system, as in the `@loquitur/verify/browser` entry, step 3 above: a fatal `TextDecoder` with
`ignoreBOM: true`, then `parseJsonStrict`, exported from both entry points. Never pass the result
of `JSON.parse`: the run then reports on a document the specification refuses, and can differ from
`loquitur-verify`, which reads the bytes itself.

Lower-level primitives are exported for host applications that need them:

```ts
import {
  canonicalJsonBytes, canonicalHash,          // RFC 8785 (JCS) + SHA-256
  verifyRegistryEntrySignature,               // secp256k1, low-S enforced
} from "@loquitur/verify";
```

`verifyRegistryEntrySignature(entry, publicKeyHex, { expectedKeyId, keyType })` checks one
signature against one key. It does not decide whether that key may sign for the entry's issuer.
The entry's `signature` object is not signed, so anyone can rewrite `signature.key_id`. Resolve
the key from the trust entry the trust registry holds for the entry's (`issuer_id`,
`issuer_key_id`), never from `signature.key_id`, and pass that trust entry's `public_key_hex`,
`issuer_key_id` and `key_type`. Both options are required: a call without a key type is
`UNSUPPORTED_SIGNATURE_ALGORITHM` and a call without a key id is `SIGNATURE_KEY_MISMATCH`, never
`VALID_SIGNATURE`. `evaluateTrustRegistry` and `verifyBundle` find the trust entry, apply its
status, windows and scope, and then make this call. Keys are compared as secp256k1 points, not
as labels: a trust entry whose point another trust entry of the registry also carries, in any
SEC1 encoding and whatever the statuses, issuers and key types, is
`TRUST_REGISTRY_AMBIGUOUS_KEY`, as two trust entries under one (`issuer_id`, `issuer_key_id`)
are, so a revoked key listed again under another id does not authorize.

## Public API and stability

The package has two entries: `@loquitur/verify` for Node.js, and `@loquitur/verify/browser`, the
I/O-free entry, which leaves out `verifyBundle`, `readDocumentPath` and
`LOQUITUR_VERIFY_STATUS`. In a 0.x release every exported name, value or type, is provisional:
a name can be renamed, moved or removed in a later 0.x release, and the changelog says so when
one is. What does not move with a name is the meaning of the report members that
`report-contract.md` defines. The closed sets the report draws on, its `status` values, its
check names and its review reasons (typed on `VerifyReport` as unions), can grow in a minor
version, as the specification adds a status, a check or a reason, so a caller handles a value it
does not know rather than assuming the list is closed; `verdict` is `PASS`, `REVIEW`, `FAIL`
or `null`. `SIGNATURE_ALGORITHM` names the algorithm of the current registry-entry signing
payload, `secp256k1_ecdsa_sha256` in signing envelope v2, and not the algorithm of the protocol
in general: a later payload can name another.

The closed sets themselves are exported, in both entries, so a caller does not copy them:
`CHECK_NAMES`, `REVIEW_REASONS` and `AUTHORIZATION_STATUSES` (the values of
`trust_registry.authorization_status`), the report statuses `STATUS_OFFLINE_OK`,
`STATUS_OFFLINE_REVIEW`, `STATUS_OFFLINE_FAIL`, `STATUS_UNSUPPORTED_VERSION` and
`STATUS_HOST_FAILURE`, and the exit codes `EXIT_OFFLINE_OK`, `EXIT_OFFLINE_FAIL`,
`EXIT_OFFLINE_REVIEW`, `EXIT_INTERNAL_ERROR`, `EXIT_UNSUPPORTED_VERSION` and `EXIT_HOST_FAILURE`.
The types `AuthorizationStatus`, `CheckName`, `ReviewReason`, `ReportStatus` and `ReportVerdict`
name the unions the report members carry. Each has a counterpart in `loquitur-verify-py`, listed
in `scripts/public-api-parity.json`.

## Schema-derived TypeScript contract

The five canonical object interfaces and the `VerificationStatus` and `RegistryVerdict` unions
in `src/generated/loquitur-protocol.ts` are generated from the exact `loquitur-schemas`
declaration artifact. `SCHEMA_TYPES_LOCK.json` binds both copies by SHA-256, and
`npm run types:schema:check` fails when either differs from the lock. The other generated
modules, `src/reason-code-severity.generated.ts`, `src/receipt-contract.generated.ts` and
`src/registered-vocabularies.generated.ts`, are written by the scripts named `generate-*` in
`scripts/` from the protocol's files and are compared with a fresh generation by the suite.

`verification_receipt.status` and `verification_summary.status` are closed to
`pass | warning | review | fail`. They are not free strings.

`summaryViolatedRules(summary)` checks a verification summary against the seven rules of
loquitur-protocol `verdict-grounds.md` and returns the rules it violates, `VG-1` to `VG-7`, in
rule order; a violation of `VG-1` or `VG-2` is returned alone, since either stops the check. An
empty list means the summary's verdict follows from the grounds it cites, not that the grounds
are true.

Registry and trust-registry inputs cross an explicit untrusted boundary. Use
`parseRegistryEntry` and `parseTrustRegistry`; successful results return branded validated
types. Verification APIs accept `unknown` inputs and fail closed when parsing fails.
`verifyBundle` and `verifyBundleFiles` also hold a registry entry's `signature.signature` to its
schema pattern, exactly 128 lowercase hex characters: any other form fails the entry
(`registry_link` false, no trust conclusion), as in `loquitur-verify`. They hold every instant
of both documents, and the bundle receipt's `verified_at`, to be a calendar instant of the form
`YYYY-MM-DDTHH:MM:SSZ`: no February 30, no February 29 of a common year, no second 60.
Otherwise a registry entry fails the link and authorization checks, a trust registry gives
`trust_registry` false, and a receipt fails the run whatever is requested. A registry entry
whose verdict is not the verdict its reason codes derive, or whose `issuer_key_id` or
`policy_id` is made only of whitespace, fails the link and authorization checks, and a trust
registry whose revocation fields or validity windows contradict each other gives
`trust_registry` false. An algorithm or key type the documents name and this verifier's
allowlist does not hold (`secp256k1_ecdsa_sha256` with `secp256k1` in this version) satisfies
the documents' contracts and is answered at the signature step:
`UNSUPPORTED_SIGNATURE_ALGORITHM`. `parseRegistryEntry` and `parseTrustRegistry` themselves
check none of these rules, nor the signature pattern.

## Agreement with the Python verifier

This package and `loquitur-verify` are two implementations written separately against the
specification, by the same maintainer. Their agreement shows that the specification can be
implemented as written; it is not independent evidence that the specification is right.

- **Canonicalization**: RFC 8785 (JCS) through the `canonicalize` package, with the same
  acceptance guard as `loquitur-verify`: non-finite numbers and integers outside the
  JavaScript safe range are refused, never coerced.
- **Hashing**: SHA-256. Every digest inside a JSON document is written `sha256:` and 64
  lowercase hexadecimal characters and compared as the whole string; the sidecar files carry
  the 64 characters alone.
- **Signatures**: secp256k1 ECDSA-SHA256 with mandatory low-S, over the signing envelope v2 of
  loquitur-protocol `docs/specification/signing-envelope-v2.md`: a fixed Loquitur prefix, then
  the RFC 8785 bytes of an envelope whose payload, `registry_entry_signing_payload_v2`, is the
  registry entry without `signature`, `anchor` and `anchored_at`, so anchoring never changes
  signed bytes. This version
  defines no earlier signing payload: a signature object without `payload_id` and
  `payload_version` breaks the entry's contract, and no option verifies it. A well-formed later
  payload is an unsupported version (`UNSUPPORTED_VERSION`, exit 4), and unknown payload
  metadata never falls back.
- **Shared vectors**: the suite runs the cross-language vectors in `test-vectors/`: canonical
  bytes, signature results, and full verify reports that `loquitur-verify` produced from the
  same fixtures.

## Scope and limits

<!-- lq-include: scope-and-limits -->
- Bundle input is a **directory**. ZIP loading is the host application's responsibility, which
  keeps this library free of archive dependencies.
- Node-oriented I/O (`node:fs`) is confined to `verifyBundle` and `readDocumentPath`. The I/O-free
  entry, `@loquitur/verify/browser` (`src/index.browser.ts`), exposes `verifyBundleFiles` over a
  reader, such as `bundleReaderFromMap`. `npm run build:browser` also bundles that entry into one
  script, `dist/loquitur-verifier.browser.js`, which defines the global `LoquiturVerifier`; that
  script is not part of the package.
- No bundle member, registry entry or trust registry makes `verifyBundle` or
  `verifyBundleFiles` throw: JSON that is not valid UTF-8, repeats a member name, nests deeper
  than 64 levels, or carries a non-finite number, an integer beyond 2^53-1 or a lone surrogate
  is a failed check, whether or not the value is hashed. The operator's own inputs are the
  exception: a trust-root document or vocabulary document that is not strict JSON is refused
  with `TrustRootError` or `VocabularyError` before any evidence is read, as the `trustRoots`
  and `vocabularies` items say.
- Containment is checked on every path component immediately before each read and links are
  refused, but a directory that another process modifies during verification can still change
  between the check and the read; verify bundles from a location no other process writes to. A
  hard link is indistinguishable from a regular file and is verified as one.
- Both verifiers refuse every reparse point in a directory bundle, whatever its tag: the Node
  reader reads it from the type the host's listing gives each entry. Placeholders of a
  synchronized folder are reparse points; do not verify bundles from one.
- Alternate data streams attached to a member are not bundle members and are neither
  inventoried nor verified.
- A file in the bundle that `manifest.json` does not declare (other than the manifest, its
  sidecar, `envelope_env1.json`, its sidecar and the receipt), and whose name is a portable
  member name, makes the result REVIEW (`bundle_extra_files`). A member under `attestations/`,
  or named `document_index.json` or `claims_openings.json`, is a name this bundle version
  reserves: REVIEW (`bundle_reserved_member`), declared or not. `verifyBundleFiles` learns what
  the bundle holds from the reader's `listMembers()`; the filesystem reader and
  `bundleReaderFromMap` implement it, and a host's own reader that does not (or returns null)
  cannot show that nothing is undeclared, so its result is capped at REVIEW.
- Every member's path from the root must be a portable member name (`bundle-objects.md`
  section 2): each segment holds only `A`-`Z`, `a`-`z`, `0`-`9`, `.`, `_` and `-`, is not `.`
  or `..`, does not end with `.` or begin with `-`, and is not a Windows device name such as
  `CON` or `nul.txt`, and the whole name is at most 255 bytes. A name outside the rule (a file
  named `a b.json`, a lone surrogate, bytes that are not UTF-8), or two names of one directory
  that conflict under ASCII case folding, whether the filesystem reader lists it or a host's
  reader does, cannot be declared by any manifest: it is never opened, and the run fails with
  `bundle_member_name_invalid`. A link in the same bundle is not reported beside it, because an
  inventory that fails takes the place of `unsafe_bundle_member`. Every other error is still
  reported: a refused name beside a `manifest.json` that is not JSON gives
  `bundle_member_name_invalid` and `manifest_verification_failed`. A host that fails to list a
  directory of the bundle is `bundle_inventory_failed`, a host failure.
- `bundleReaderFromMap` takes each member as a string or a `Uint8Array`. A host that passes
  already-decoded strings to `bundleReaderFromMap` has already replaced invalid UTF-8; pass
  `Uint8Array` values to get the same refusal as the Node reader. Build the map with
  `JSON.parse` or `Object.defineProperty`; assigning `files[name] = value` cannot create a
  member named `__proto__`.
- `trustRoots` takes the trust-root document of `trust-root.md` section 3
  (`{"object_type": "trust_root_document", "schema_version": "v1", "roots": [...]}`, each root
  with its `key_type`), never roots read from the registry it authenticates. The whole document
  is validated when it is read, every root of it whether or not the registry names it, before
  any evidence is read: a document that breaks section 3 anywhere throws `TrustRootError` and
  returns no report, from `verifyBundle`, `verifyBundleFiles` and `evaluateTrustRegistry` alike,
  and whatever the other inputs. A document of a well-formed later version is not malformed:
  the run is `UNSUPPORTED_VERSION`, and `evaluateTrustRegistry`, which returns no run, throws
  `TrustRootError`. With well-formed roots, an authorization run that holds at
  the operator's evaluation time is PASS when the registry authenticates
  (`ROOT_SIGNATURE_VALID`) and FAIL otherwise; without roots it is REVIEW
  (`NO_PINNED_TRUST_ROOT`). A root window that does not hold the evaluation time is REVIEW
  (`trust_root_outside_validity_window`). A matched root whose secp256k1 point another pinned
  root also carries, in any SEC1 encoding and whatever its status or key type, is
  `AMBIGUOUS_ROOT_KEY`, as two roots under one `key_id` are. A document given without a trust
  registry is validated and then unused. `parseTrustRoots`, `authenticateTrustRegistry` and
  `trustRegistrySigningMessageBytes` are exported for hosts that read or sign registries.
- `evaluationTime` is the operator's evaluation time of `trust-registry-authorization.md`
  section 2, a calendar instant of the form `YYYY-MM-DDTHH:MM:SSZ`: the registry's and the key's
  windows and root authentication are judged at it, and at nothing else. The entry's own
  `effective_at`, `issued_at` and `anchored_at` are never read as a time. An empty value or any
  other form throws `EvaluationTimeError` before any evidence is read. Without it, the trust
  registry is still evaluated with the rows that do not read the time, a revoked or suspended
  key still fails, and a run that would otherwise hold is REVIEW
  (`evaluation_time_not_provided`). A registry or key window that does not hold the time is
  REVIEW (`trust_registry_not_current`, `issuer_key_outside_validity_window`), not FAIL. The
  report states the time in `evaluation_time`.
- `vocabularies` takes, by kind (`asset_type`, `workflow`, `anchoring_method`), a registered
  vocabulary document of `verification-vocabularies.md` section 6 that the operator supplies; a
  kind not given is judged against the version built into this package
  (`REGISTERED_VOCABULARIES`, the protocol's files as they are), and two documents of one kind
  are never merged. A document that is not a strict JSON object, breaks section 6 or registers
  another kind throws `VocabularyError` before any evidence is read. A receipt's `asset_type`,
  or an entry's `asset_type` or `workflow`, that is an identifier the vocabulary held does not
  register makes the run REVIEW (`vocabulary_value_unknown`), and withholds no check; an unknown
  `anchor.method` changes nothing. The report records each document held in `vocabularies`: its
  version, digest and source. This package takes a supplied document already parsed, not as the
  file's bytes, so the digest it records for one is the SHA-256 of the document's RFC 8785
  canonical bytes. `loquitur-verify` records the SHA-256 of the file it reads, so for a file that
  is not in canonical form the two verifiers record different digests in this informative member.
- Verdict narrative rendering (explanations for several audiences) lives in the Python
  `loquitur-verify[narrative]` extra and is not replicated here.
<!-- lq-include-end: scope-and-limits -->

## Conformance

Normative vectors and expected outcomes belong to the protocol's governance role,
`loquitur-protocol-governance` (loquitur-protocol `GOVERNANCE.md`), and reach this repository
through the corpus `loquitur-conformance-bdbadee7f6144d08`, which `CONFORMANCE_CONSUMER.json`
pins by digest. This repository reads that corpus and never changes it. Its own fixtures,
`test-vectors/`, are local implementation tests: some files are identical to the corpus's, some
differ, some exist only here, and none redefines what the protocol expects. The corpus is
pinned by `CONFORMANCE_CONSUMER.json`, and the generated types by `SCHEMA_TYPES_LOCK.json`;
`test-vectors/` is neither: the copies of corpus files it holds are kept in step with the
pinned corpus by the maintainer's own checks; the corpus source is not published.

## Links

- Specification:
  [loquitur-protocol `docs/README.md`](https://github.com/loquitur-dev/loquitur-protocol/blob/main/docs/README.md),
  the table of contents of its parts.
- Security policy: [`SECURITY.md`](https://github.com/loquitur-dev/loquitur-verify-ts/blob/main/SECURITY.md), which says how to report a vulnerability.
- Contributing: [`CONTRIBUTING.md`](https://github.com/loquitur-dev/loquitur-verify-ts/blob/main/CONTRIBUTING.md), which links the maintainer documents,
  among them how to build and test the package.
- License: see [License](#license).

## License

Licensed under either of

- Apache License, Version 2.0 ([`LICENSE-APACHE`](LICENSE-APACHE)), or
- MIT license ([`LICENSE-MIT`](LICENSE-MIT)),

at your option. The SPDX license expression is `MIT OR Apache-2.0`. Copyright 2026 Andrea Venè;
[`NOTICE`](NOTICE) credits the third-party test data, which keeps its own license.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
this repository by you, as defined in the Apache-2.0 license, is dual licensed as above, without
any additional terms or conditions. Every contribution carries a Developer Certificate of Origin
sign-off, as [`CONTRIBUTING.md`](https://github.com/loquitur-dev/loquitur-verify-ts/blob/main/CONTRIBUTING.md) describes.
