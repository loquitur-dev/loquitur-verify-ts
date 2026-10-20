// An envelope link holds only to a manifest or P1 that verified (bundle-objects.md section 4):
// parsed, satisfied its contract and matched its sidecar. Compared with whatever digest the
// verifier recomputes, an envelope would link "successfully" to a manifest that fails its
// contract or to a P1 its own sidecar disowns.
import { test } from "node:test";
import assert from "node:assert/strict";
import { Bundle, ENTRIES, FAIL, PASS, outcome } from "./bundle-kit.ts";

function expectAll(rows: Array<[string, () => Bundle, Record<string, unknown>]>) {
  const got: Record<string, unknown> = {};
  const want: Record<string, unknown> = {};
  for (const [label, build, expected] of rows) {
    const checks = Object.keys(expected).filter((k) => !["status", "verdict", "exit_code"].includes(k));
    for (const [entryName, verify] of ENTRIES) {
      want[`${entryName}: ${label}`] = expected;
      got[`${entryName}: ${label}`] = outcome(verify(build()), checks);
    }
  }
  assert.deepEqual(got, want);
}

test("envelope_links is false over a manifest that failed its contract or its sidecar", () => {
  expectAll([
    ["manifest bundle_id false, sealed everywhere", () => {
      const b = Bundle.linkValid();
      b.edit("manifest.json", (m) => { m.bundle_id = false; });
      return b.seal();
    }, { ...FAIL, manifest_sha256: true, envelope_links: false }],
    ["manifest.sha256 disagreeing, envelope linked to the manifest as it is", () => {
      const b = Bundle.linkValid().seal();
      return b.setBytes("manifest.sha256", "0".repeat(64));
    }, { ...FAIL, manifest_sha256: false, envelope_links: false }],
    ["the fixture", () => Bundle.linkValid().seal(), { ...PASS, envelope_links: true }],
  ]);
});

test("envelope_links is false over a P1 that failed its sidecar or is absent, and holds over a tampered input", () => {
  expectAll([
    ["p1.sha256 disagreeing, envelope linked to the P1 as it is", () => {
      const b = Bundle.linkValid().seal();
      b.setBytes("p1.sha256", "0".repeat(64));
      return b.seal({ p1: false });
    }, { ...FAIL, p1_sha256: false, envelope_links: false }],
    ["p1.json absent but declared", () => Bundle.linkValid().seal().delete("p1.json"), { ...FAIL, p1_sha256: false, envelope_links: false }],
    ["canonical input tampered after sealing", () => {
      const b = Bundle.linkValid().seal();
      b.edit("canonical_input.json", (c) => { c.external_mark = 1; });
      return b.seal();
    }, { ...FAIL, p1_input_hash: false, envelope_links: true }],
  ]);
});
