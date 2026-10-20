# Releasing

A release of `@loquitur/verify` is a version tag and a GitHub release for it that carries three
files, built by [`.github/workflows/release.yml`](../../.github/workflows/release.yml) from the
tag:

| File | What it is |
| --- | --- |
| `loquitur-verify-X.Y.Z.tgz` | The npm package, as `npm pack` writes it after `npm ci` |
| `loquitur-verify-X.Y.Z.cdx.json` | A CycloneDX SBOM of the package, written by `npm sbom` |
| `SHA256SUMS` | The SHA-256 of the two files above, in the format `sha256sum -c` reads |

Each of the three carries a GitHub artifact attestation of where it was built, and the tarball
also carries an attestation of its SBOM. The package is not published to npm or to any other
package index; see [Publishing to npm later](#publishing-to-npm-later).

## Tag rules

- A release tag is `vX.Y.Z`, three numbers and nothing else, and `X.Y.Z` is the `version` of
  `package.json` and `package-lock.json` at the tagged commit.
- It is annotated and signed with the maintainer's key: `git tag -s vX.Y.Z -m "vX.Y.Z"`.
- It points at a commit on the default branch, whose `CHANGELOG.md` has a section headed
  `## [X.Y.Z]`, or `## [X.Y.Z] - YYYY-MM-DD` with an ASCII hyphen, with text in it.
- It is never moved and never deleted. A release that turns out wrong is followed by a new
  version, never by a tag reused.

The workflow checks the first three rules. It reads the tag from GitHub's API, not from its own
clone: only the API reports whether GitHub verified the tag's signature. It requires the tag to
be an annotated tag object, to point at the commit the run builds, and to be marked verified by
GitHub, which means its signature checks against a signing key registered on the GitHub account
that made it. Whether that key is the maintainer's is what `git tag -v` checks, below. The last rule
is held by the repository's settings, below. A tag is released by pushing it: a run started by
hand on a tag is refused before anything else runs, because it would skip the tag check and
still attest its files as built from the tag.

## What the workflow does

The workflow runs when a tag matching `vX.Y.Z` is pushed, and when it is started by hand
(`workflow_dispatch`). Every action it uses is pinned by full commit SHA. The workflow grants no
permission at the top; each job declares the ones it needs.
The workflows run on a pinned runner image (`ubuntu-24.04`), not on the moving `ubuntu-latest`
label, so that the CI does not change when GitHub moves the label; the pin is moved deliberately,
with a run on the new image.

1. `verify` (read only) refuses a run started by hand on a tag, and checks the tag rules above,
   the version in `package.json` and `package-lock.json`, and the `CHANGELOG.md` section.
2. `checks` (read only), once `verify` passes, runs [`ci.yml`](../../.github/workflows/ci.yml)
   on the tagged commit: every check a commit to the default branch runs. Its `siblings` job
   checks out the sibling repositories at their default branch's head, not at a matching tag, so
   the run depends on their state at that moment. A red `siblings` job on a tag is fixed in the
   sibling and the run is started again; the tag is never moved.
3. `build` (read only) installs the lockfile's tree with `npm ci --ignore-scripts`, builds the
   tarball with `npm pack`, whose `prepack` runs the publication guard and a clean build,
   searches every file of the tarball for the needles of `tools/public_boundary.json` with
   `tools/check_packed_tarball.py`, writes the SBOM with
   `npm sbom --sbom-format cyclonedx --omit dev`, names its root component `@loquitur/verify`
   (npm names it after the folder it runs in), writes `SHA256SUMS` over the two, and keeps the
   three files as a workflow artifact.
4. `attest` downloads that artifact, checks that it holds exactly the three files and that they
   match `SHA256SUMS`, and attests them with `actions/attest`: a provenance attestation for each
   of the three files and an SBOM attestation for the tarball. It is the one job that may write
   attestations (`id-token: write`, `attestations: write`), and it checks out nothing and installs
   nothing, so neither the package's build nor any dependency's code runs where that token is.
5. `release`, on a tag push only, checks the files against `SHA256SUMS` and creates the GitHub
   release for the tag as a draft, with `gh release create --draft --verify-tag`, which refuses
   to create a tag that does not exist. It is the one job that may write to the repository
   (`contents: write`).

A run started by hand is a dry run, on a branch: it verifies, builds and attests the files of the
commit it is started on, keeps them as a workflow artifact, and creates no release. GitHub stores
artifact attestations for a public repository on every plan, and for a private one only on the
plans that offer them, so a dry run in a private repository skips the two attestation steps and
says so in a notice. A tag push never skips them.

The draft is published by the maintainer, by hand, in the GitHub interface, after reading it.

## The maintainer's settings

These are settings of the repository and of the maintainer's account. The workflow does not
change them and cannot check them.

- **Immutable releases**, in the repository settings: once the draft is published, its files and
  its tag cannot be changed or removed.
- **A tag ruleset** on `v*`: only the maintainer creates such a tag, and no one updates or
  deletes one.
- **Two-factor authentication with a security key or a passkey** (FIDO2/WebAuthn) on the
  maintainer's GitHub account.
- **No long-lived tokens**: no personal access token or registry token is stored as a secret of
  the repository, and the workflow uses only the token GitHub issues for each run.

## Verifying a release

Download the three files of the release into one directory, for example with
`gh release download vX.Y.Z --repo loquitur-dev/loquitur-verify-ts`. Then:

```bash
sha256sum -c SHA256SUMS
```

checks that the files are the ones `SHA256SUMS` names. `SHA256SUMS` sits beside the files it
names, so this shows that nothing was damaged in transit, not where the files came from. The
attestations show that:

```bash
gh attestation verify loquitur-verify-X.Y.Z.tgz --repo loquitur-dev/loquitur-verify-ts \
  --signer-workflow loquitur-dev/loquitur-verify-ts/.github/workflows/release.yml \
  --source-ref refs/tags/vX.Y.Z --deny-self-hosted-runners
gh attestation verify loquitur-verify-X.Y.Z.cdx.json --repo loquitur-dev/loquitur-verify-ts \
  --signer-workflow loquitur-dev/loquitur-verify-ts/.github/workflows/release.yml \
  --source-ref refs/tags/vX.Y.Z --deny-self-hosted-runners
gh attestation verify SHA256SUMS --repo loquitur-dev/loquitur-verify-ts \
  --signer-workflow loquitur-dev/loquitur-verify-ts/.github/workflows/release.yml \
  --source-ref refs/tags/vX.Y.Z --deny-self-hosted-runners
gh attestation verify loquitur-verify-X.Y.Z.tgz --repo loquitur-dev/loquitur-verify-ts \
  --signer-workflow loquitur-dev/loquitur-verify-ts/.github/workflows/release.yml \
  --source-ref refs/tags/vX.Y.Z --deny-self-hosted-runners \
  --predicate-type https://cyclonedx.org/bom
```

The first three check each file's provenance: that it was built by this repository's release
workflow, from the tag, on a GitHub-hosted runner. Without `--signer-workflow` and
`--source-ref`, `gh` would accept an attestation from any workflow and any ref of the
repository, a dry run on a branch included; without `--deny-self-hosted-runners`, it would accept
one made on a self-hosted runner. The
last checks that the same workflow, run from the tag, attested an SBOM for the tarball; with
`--format json` it prints that SBOM, to compare with the published file. In a clone of the
repository,

```bash
git tag -v vX.Y.Z
```

checks the tag's signature against the maintainer's public key, which must be in your keyring
(or, for an SSH signature, in your `gpg.ssh.allowedSignersFile`).

## What a release does not claim

- **No reproducible build.** No one has shown that building the tag again gives the same bytes,
  and this document does not claim it. The SBOM in particular carries a time stamp and a random
  serial number, so two runs never write the same SBOM.
- **An attestation is about origin, not correctness.** It shows which repository, workflow and
  commit built a file on a GitHub-hosted runner. It says nothing about whether the code is right,
  safe or reviewed.
- **The SBOM lists, it does not judge.** It names the package and the runtime dependency tree
  that `package-lock.json` resolves. It is not a vulnerability report, and it leaves out the build
  tools, which the tarball does not carry.
- **The Node.js version floats.** The build runs on the newest Node.js 22 at the time of the run
  (`actions/setup-node` with `check-latest`), and the npm that ships with it; the run's log
  records which.

## Publishing to npm later

The package is not published to npm, and the workflow has no step that could publish it:
`package.json` keeps `"private": true`, and `scripts/publish-guard.mjs` refuses `npm publish`
unless `LOQUITUR_VERIFY_NPM_PUBLISH_APPROVED=1` is set, which no job of the release does: the
`build` job packs the tarball through the guard without it. Publication to a package index
is a decision for the maintainer, and it is not part of a release until that decision is made.

If it is made, the publication would be added without a stored token:

1. On npmjs.com, configure the package for trusted publishing from this repository and
   `release.yml`, so that npm accepts a publication only from a run of that workflow, with a
   short-lived credential exchanged for the run's OIDC token.
2. Add a `publish` job to `release.yml` that needs `release`, runs in a GitHub environment whose
   protection rule requires the maintainer's approval, has `id-token: write` and nothing else, and
   publishes the attested tarball itself, `npm publish loquitur-verify-X.Y.Z.tgz`, with the npm
   that trusted publishing requires. A trusted publication carries npm provenance, which links
   the package on npm to this workflow run.
3. In the same change, remove `"private": true` and change the publication guard to match. The
   tarball that `publish` sends is the one `build` packed, and the guard runs on that
   `npm pack` too: today, without the approval variable, it refuses any `package.json` that is
   not private, so removing the flag alone would stop the build. The guard's rule changes so that
   `npm pack` is allowed without the flag while `npm publish` still needs the approval variable,
   which is set in the `publish` job. `REPOSITORY_LAYOUT.md`, the guard's tests and this document
   change with it.

It is not enabled now because the package is a preview that is not published to a package index,
and a publication job that exists can be triggered; a draft release that the maintainer publishes
by hand cannot publish anything to npm.
