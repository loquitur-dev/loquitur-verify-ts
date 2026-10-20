// Content bounded by the protocol must not stall the verifier: the conflict check over member
// names (bundle-objects.md section 2) and the member reads of a large directory are linear.
import { test } from "node:test";
import assert from "node:assert/strict";
import { conflictingNames } from "../src/verify-core.ts";
import { Bundle, verifyOnDisk } from "./bundle-kit.ts";

function nested(count: number, depth: number): string[] {
  const prefix = Array.from({ length: depth }, (_, i) => `d${i}`).join("/");
  return Array.from({ length: count }, (_, i) => `${prefix}/f${i}.json`);
}

test("conflictingNames is linear in the names: 40000 names 20 deep in seconds, not minutes", { timeout: 15000 }, () => {
  const names = nested(40000, 20);
  const started = Date.now();
  assert.equal(conflictingNames(names).size, 0);
  assert.ok(Date.now() - started < 5000, `took ${Date.now() - started} ms`);
});

test("conflictingNames still finds every conflict after the rewrite", () => {
  assert.deepEqual([...conflictingNames(["a.json", "A.JSON", "b.json"])].sort(), ["A.JSON", "a.json"]);
  assert.deepEqual([...conflictingNames(["a", "a/b"])].sort(), ["a", "a/b"]);
  assert.deepEqual([...conflictingNames(["X/one", "x/two", "y/three"])].sort(), ["X/one", "x/two"]);
  assert.deepEqual([...conflictingNames(["x/one", "x/two"])], []);
});

test("a directory bundle of 4000 undeclared members verifies in seconds", { timeout: 60000 }, () => {
  const bundle = Bundle.linkValid();
  for (let i = 0; i < 4000; i++) bundle.files.set(`extra${i}.txt`, new Uint8Array([0x61]));
  const started = Date.now();
  const report = verifyOnDisk(bundle);
  assert.equal(report.status, "OFFLINE_REVIEW");
  assert.ok(Date.now() - started < 20000, `took ${Date.now() - started} ms`);
});
