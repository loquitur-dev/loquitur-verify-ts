// Input strictness rule 9 (canonicalization-and-hashing.md, RFC 7493 section 2.1): no string or
// member name holds a noncharacter. The exported canonicalizer refuses one as the Python
// verifier's canonical_json_bytes does, so the two answer every value alike.
import { test } from "node:test";
import assert from "node:assert/strict";
import { CanonicalizationError, canonicalJsonBytes } from "../src/canonical.ts";

const NONCHARACTERS = ["\uFDD0", "\uFDEF", "\uFFFE", "\uFFFF", "\uD83F\uDFFE", "\uDBFF\uDFFF"];

for (const nc of NONCHARACTERS) {
  const label = [...nc].map((c) => c.codePointAt(0)!.toString(16).toUpperCase()).join(",");
  test(`a value holding U+${label} is refused`, () => {
    assert.throws(() => canonicalJsonBytes({ a: `x${nc}y` }), CanonicalizationError);
    assert.throws(() => canonicalJsonBytes([nc]), CanonicalizationError);
  });
  test(`a member name holding U+${label} is refused`, () => {
    assert.throws(() => canonicalJsonBytes({ [nc]: 1 }), CanonicalizationError);
    assert.throws(() => canonicalJsonBytes({ outer: { [`k${nc}`]: [1] } }), CanonicalizationError);
  });
}

test("the neighbors of the noncharacters are canonicalized", () => {
  for (const ok of ["\uFDCF", "\uFDF0", "\uFFFD", "\uD83F\uDFFD", "\uE000"]) {
    assert.ok(canonicalJsonBytes({ [ok]: ok }).length > 0);
  }
});
