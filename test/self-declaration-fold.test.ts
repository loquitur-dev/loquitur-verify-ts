// Whether a manifest `files` key names the manifest or its sidecar is decided by ASCII letter case
// alone (bundle-objects.md section 2): A to Z read as a to z, nothing else folded. A full Unicode
// lower-casing would also fold U+0130 and U+212A KELVIN SIGN, which the specification does not.
import { test } from "node:test";
import assert from "node:assert/strict";
import { Bundle, ENTRIES, FAIL, outcome } from "./bundle-kit.ts";
import { foldMemberName, isSelfDeclaration, memberNameValid } from "../src/verify-core.ts";

const DOTTED_CAPITAL_I = "\u0130";
const KELVIN = "\u212a";

test("MANIFEST.JSON and Manifest.Sha256 are self-declarations; MAN\u0130FEST.JSON is not", () => {
  assert.deepEqual(
    {
      "manifest.json": isSelfDeclaration("manifest.json"),
      "MANIFEST.JSON": isSelfDeclaration("MANIFEST.JSON"),
      "Manifest.Sha256": isSelfDeclaration("Manifest.Sha256"),
      [`MAN${DOTTED_CAPITAL_I}FEST.JSON`]: isSelfDeclaration(`MAN${DOTTED_CAPITAL_I}FEST.JSON`),
      "./manifest.json": isSelfDeclaration("./manifest.json"),
      "sub/manifest.json": isSelfDeclaration("sub/manifest.json"),
    },
    {
      "manifest.json": true,
      "MANIFEST.JSON": true,
      "Manifest.Sha256": true,
      [`MAN${DOTTED_CAPITAL_I}FEST.JSON`]: false,
      "./manifest.json": false,
      "sub/manifest.json": false,
    },
  );
  // An ordinary declaration, which the portable member-name rule then refuses.
  assert.equal(memberNameValid(`MAN${DOTTED_CAPITAL_I}FEST.JSON`), false);
});

test("the fold reads only A to Z: U+212A and U+0130 are left as they are", () => {
  assert.equal(foldMemberName(KELVIN), KELVIN);
  assert.equal(KELVIN.toLowerCase(), "k", "String.prototype.toLowerCase folds KELVIN SIGN, the member-name fold does not");
  assert.equal(foldMemberName(DOTTED_CAPITAL_I), DOTTED_CAPITAL_I);
  assert.notEqual(DOTTED_CAPITAL_I.toLowerCase(), DOTTED_CAPITAL_I);
  assert.equal(foldMemberName("Manifest.Sha256"), "manifest.sha256");
  assert.equal(foldMemberName("\u00c9T\u00c9.JSON"), "\u00c9t\u00c9.json");
});

test("a manifest declaring MAN\u0130FEST.JSON fails on the member name, in every entry", () => {
  const name = `MAN${DOTTED_CAPITAL_I}FEST.JSON`;
  const got: Record<string, unknown> = {};
  const want: Record<string, unknown> = {};
  for (const [entryName, verify] of ENTRIES) {
    const b = Bundle.linkValid();
    b.setBytes(name, "{}");
    b.edit("manifest.json", (m) => { m.files[name] = ""; });
    want[entryName] = { ...FAIL, manifest_files: false };
    got[entryName] = outcome(verify(b.seal()), ["manifest_files"]);
  }
  assert.deepEqual(got, want);
});
