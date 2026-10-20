// The P1 projection reads the canonical input's own members only.
//
// canonicalization-and-hashing.md §2: a key listed in `ik` but absent from the canonical input maps
// to JSON null. Presence tested with `k in canonicalInput` would also find what Object.prototype
// carries: an absent "constructor" would project a function and the canonicalizer would throw out
// of the verifier, and an absent "__proto__" would project the prototype.
import { test } from "node:test";
import assert from "node:assert/strict";
import { Bundle, ENTRIES, PASS, defineMember, jcsText, outcome } from "./bundle-kit.ts";

const INHERITED_NAMES = ["constructor", "toString", "hasOwnProperty", "valueOf", "__proto__"];

for (const [entryName, verify] of ENTRIES) {
  for (const name of INHERITED_NAMES) {
    test(`${entryName}: ik naming ${name} projects null when it is absent and its own value when present`, () => {
      const absent = Bundle.linkValid();
      absent.edit("p1.json", (p) => {
        p.ik = [...p.ik, name];
        p.ih = absent.inputHashFor(p);
      });
      let report;
      assert.doesNotThrow(() => {
        report = verify(absent.seal());
      });
      assert.deepEqual(outcome(report!, ["p1_input_hash"]), { ...PASS, p1_input_hash: true });

      const present = Bundle.linkValid();
      const input = present.json("canonical_input.json");
      defineMember(input, name, "own value");
      present.setBytes("canonical_input.json", jcsText(input));
      present.edit("p1.json", (p) => {
        p.ik = [...p.ik, name];
        p.ih = present.inputHashFor(p);
      });
      assert.deepEqual(outcome(verify(present.seal()), ["p1_input_hash"]), { ...PASS, p1_input_hash: true });
    });
  }
}
