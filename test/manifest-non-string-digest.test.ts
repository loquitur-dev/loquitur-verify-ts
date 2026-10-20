// A manifest.files entry whose digest is not a string (bundle-objects.md section 2 types every
// declared digest as 64 lowercase hexadecimal characters) fails the file check: the run fails
// and checks.manifest_files is false. The name is still declared, so the member is not an
// undeclared file. loquitur-verify-py holds the same rows in
// tests/test_manifest_non_string_digest.py.
import { test } from "node:test";
import assert from "node:assert/strict";
import { Bundle, ENTRIES, FAIL, PASS, outcome } from "./bundle-kit.ts";

const NON_STRING_DIGESTS: Record<string, unknown> = {
  number: 7,
  boolean: true,
  null: null,
  list: ["a".repeat(64)],
  object: { sha256: "a".repeat(64) },
};

for (const [entryName, verify] of ENTRIES) {
  test(`${entryName}: a declared digest that is not a string fails manifest_files`, () => {
    const got: Record<string, unknown> = { sealed: outcome(verify(Bundle.linkValid().seal()), ["manifest_files"]) };
    const want: Record<string, unknown> = { sealed: { ...PASS, manifest_files: true } };
    for (const [kind, digest] of Object.entries(NON_STRING_DIGESTS)) {
      const bundle = Bundle.linkValid().seal();
      const name = Object.keys(bundle.json("manifest.json").files).sort()[0]!;
      bundle.edit("manifest.json", (manifest) => {
        manifest.files[name] = digest;
      });
      bundle.seal({ files: false });
      const report = verify(bundle);
      got[kind] = { ...outcome(report, ["manifest_files"]), extra: report.notes.includes("bundle_extra_files") };
      want[kind] = { ...FAIL, manifest_files: false, extra: false };
    }
    assert.deepEqual(got, want);
  });
}
