// A canonical_input.json that exists but is not a JSON object is a rejected input, not a missing
// one (bundle-objects.md: presence flags are facts; only a file that is not there leaves the input
// hash unevaluated). A primitive fails the run rather than throwing out of the verifier, and
// `null` is not absent, so it does not yield REVIEW.
import { test } from "node:test";
import assert from "node:assert/strict";
import { Bundle, ENTRIES, FAIL, REVIEW, outcome } from "./bundle-kit.ts";

const REJECTED = { ...FAIL, canonical_input_present: true, p1_input_hash: false };

function withInput(text: string, dropIk = false): Bundle {
  const b = Bundle.linkValid();
  b.setBytes("canonical_input.json", text);
  if (dropIk) b.edit("p1.json", (p) => { delete p.ik; });
  return b.seal();
}

function expectAll(build: () => Bundle, checks: string[], expected: Record<string, unknown>) {
  const got: Record<string, unknown> = {};
  for (const [entryName, verify] of ENTRIES) {
    try {
      got[entryName] = outcome(verify(build()), checks);
    } catch (err) {
      got[entryName] = `threw ${(err as Error).name}: ${(err as Error).message}`;
    }
  }
  assert.deepEqual(got, Object.fromEntries(ENTRIES.map(([name]) => [name, expected])));
}

test("canonical_input.json holding a JSON value that is not an object fails; an absent one does not", () => {
  for (const [text, dropIk] of [["null", false], ["1", false], ['"x"', false], ["true", false], ["[1,2]", false], ["1", true], ["[1,2]", true]] as const) {
    expectAll(() => withInput(text, dropIk), ["canonical_input_present", "p1_input_hash"], REJECTED);
  }
  // Absent and undeclared is still a question; absent but declared is still a failure.
  expectAll(() => {
    const b = Bundle.linkValid().delete("canonical_input.json");
    b.edit("manifest.json", (m) => { delete m.files["canonical_input.json"]; });
    return b.seal();
  }, ["canonical_input_present", "p1_input_hash"], { ...REVIEW, canonical_input_present: false, p1_input_hash: null });
  expectAll(() => Bundle.linkValid().seal().delete("canonical_input.json"),
    ["manifest_files", "canonical_input_present"], { ...FAIL, manifest_files: false, canonical_input_present: false });
});

test("canonical_input_present stays true when P1 is unreadable or malformed", () => {
  expectAll(() => withInput("null").setBytes("p1.json", "not JSON").seal({ p1: false, envelope: false }),
    ["canonical_input_present"], { ...FAIL, canonical_input_present: true });
  expectAll(() => {
    const b = withInput("null");
    b.edit("p1.json", (p) => { p.smuggled = true; });
    return b.seal();
  }, ["canonical_input_present"], { ...FAIL, canonical_input_present: true });
});
