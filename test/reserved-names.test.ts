// The names a loquitur.bundle.v1 bundle reserves (bundle-objects.md section 1): every member under
// attestations/, document_index.json and claims_openings.json. A member at a reserved name is not
// evidence this version defines: the review reason bundle_reserved_member, whether or not the
// manifest declares it, and never bundle_extra_files. A declared one is still hashed by the
// manifest file check, so a digest that does not match still fails the run.
import { test } from "node:test";
import assert from "node:assert/strict";
import { Bundle, ENTRIES, sha256Hex } from "./bundle-kit.ts";

const RESERVED = ["attestations/statement.json", "attestations/nested/deeper.json", "document_index.json", "claims_openings.json"];

function withMember(name: string, declared: boolean, digest?: (bytes: Uint8Array) => string): Bundle {
  const bundle = Bundle.linkValid();
  bundle.setBytes(name, '{"reserved":true}');
  if (declared) bundle.edit("manifest.json", (m) => { m.files[name] = ""; });
  bundle.seal();
  if (digest !== undefined) {
    bundle.edit("manifest.json", (m) => { m.files[name] = digest(bundle.bytes(name)); });
    bundle.seal({ files: false });
  }
  return bundle;
}

for (const [entryName, verify] of ENTRIES) {
  test(`${entryName}: a member at a reserved name is bundle_reserved_member, declared or not`, () => {
    const got: Record<string, unknown> = {};
    const expected: Record<string, unknown> = {};
    for (const name of RESERVED) {
      for (const declared of [false, true]) {
        const report = verify(withMember(name, declared));
        got[`${name} ${declared ? "declared" : "undeclared"}`] = [report.status, report.review_reasons, report.errors, report.checks.manifest_files];
        expected[`${name} ${declared ? "declared" : "undeclared"}`] = ["OFFLINE_REVIEW", ["bundle_reserved_member"], [], true];
      }
    }
    assert.deepEqual(got, expected);
  });

  test(`${entryName}: a reserved name beside an undeclared one gives both reasons, in order; a near name is an ordinary member`, () => {
    const both = withMember("document_index.json", false).setBytes("extra.txt", "x");
    assert.deepEqual(verify(both).review_reasons, ["bundle_reserved_member", "bundle_extra_files"]);
    for (const near of ["attestations.json", "Document_Index.json", "sub/claims_openings.json", "attestation/x.json"]) {
      assert.deepEqual(verify(withMember(near, false)).review_reasons, ["bundle_extra_files"], near);
    }
  });

  test(`${entryName}: a declared reserved member is still hashed by the manifest file check`, () => {
    const wrong = withMember("claims_openings.json", true, () => `sha256:${sha256Hex("other bytes")}`);
    const report = verify(wrong);
    assert.deepEqual([report.status, report.checks.manifest_files], ["OFFLINE_FAIL", false]);
  });
}
