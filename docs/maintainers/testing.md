# Testing

Run these checks from the `loquitur-verify-ts` repository root. The commands are the same in
PowerShell and in a POSIX shell.

```bash
npm ci
npm run publish:guard
npm run typecheck
npm run typecheck:test
node scripts/check-verdict-path-isolation.mjs
npm test
npm run types:schema:check
python tools/check_public_boundary.py
npm run pack:dry-run
node examples/verify-test-vectors.mjs
```

`npm run check` runs five of them in one command: `typecheck`, `typecheck:test`,
`check:isolation` (the verdict-path isolation script above), `types:schema:check` and `npm test`.

These are the steps of `.github/workflows/ci.yml`. `npm run pack:dry-run` builds `dist/`,
which `examples/verify-test-vectors.mjs` imports. `tools/check_public_boundary.py` needs a
Python 3 interpreter and only its standard library. The packaging job of `ci.yml` also writes
the tarball with `npm pack`, installs it into an empty project, and runs a copy of the example
there, so the import resolves to the installed package and not to this checkout.

## Building

`npm run typecheck` checks the sources under strict TypeScript, and `npm run build` emits
`dist/`: ES modules and their `.d.ts` declarations. `npm run pack:dry-run` lists what the
package would carry without writing a tarball. How a release builds, attests and attaches the
tarball is in [`releasing.md`](releasing.md).

## The schema-derived types

`npm run types:schema:check` verifies the committed copy of `src/generated/loquitur-protocol.ts`
against `SCHEMA_TYPES_LOCK.json`. `npm run types:schema:check:workspace` also compares it byte
for byte with the declaration artifact of a `loquitur-schemas` checkout beside this one;
`test/schema-types-workspace.test.ts` runs that form, and skips where the sibling is absent.

## The whole suite

Some tests read sibling repositories. In a clone on its own they skip, and each skipped test
says which sibling is absent. To run them, check these repositories out beside this one, under
these directory names:

- `loquitur-protocol`: the specification tables that the `spec-*.test.ts` files hold this
  verifier to, and the verification receipt's schema;
- `loquitur-schemas` and `loquitur-verify-py`: the validators and fixtures that the
  cross-language tests compare this verifier with.

Install the two Python packages into a Python 3.11 or later, and name that interpreter in
`LOQUITUR_PYTHON` when it is not the first `python` on the path:

```bash
python -m pip install ../loquitur-schemas ../loquitur-verify-py
```

Then run the suite with `LOQUITUR_REQUIRE_SIBLINGS` set, which turns every skip for a missing
sibling into a failure that names it:

```bash
LOQUITUR_REQUIRE_SIBLINGS=1 npm test              # POSIX shell
$env:LOQUITUR_REQUIRE_SIBLINGS = "1"; npm test    # PowerShell
```

`LOQUITUR_CORPUS_ROOTS` names corpus roots, separated by `;` on Windows and `:` elsewhere. A
corpus root is the directory that holds `vectors/`: once the conformance archive that
`loquitur-protocol` pins in `CONFORMANCE_LOCK.json` is extracted, the archive's top-level
directory, or any directory laid out as one. `test/corpus-roots.test.ts` verifies every run
that each root declares and compares the reports with the declared outcomes. Without the
variable that test skips.

The repository stays runnable on its own: every dependency on a sibling is named here and in
the skip message of the test that needs it, never reached implicitly through a path outside the
repository.

See [`TEST_OWNERSHIP.md`](TEST_OWNERSHIP.md) for what this repository's tests own.
