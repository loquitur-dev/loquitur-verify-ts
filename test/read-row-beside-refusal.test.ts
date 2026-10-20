// A layer's read row and its verification row are each judged on their own. Each layer reads the
// members it finds whatever else refuses it, and a host failure on one is the layer's
// `*_read_failed` row (bundle-objects.md section 6). report-contract.md section 5.3 judges every
// row on its own: a layer refused for what one member holds still reports the host failing to read
// another, and a host failure on one member does not hide a refusal of what another holds.
//
// The envelope layer reads the envelope and its sidecar whenever either is present, also when it
// lacks the other, and one without the other is envelope_incomplete; envelope.json is an ordinary
// member and never read as an envelope (bundle-objects.md section 4). envelope_links is false when
// the manifest layer is refused and the bundle carries both the envelope and its sidecar, and null
// when it lacks either. Every case carries a content row beside its read row, so the run is
// OFFLINE_FAIL, not HOST_FAILURE (report-contract.md section 3.1).
//
// The failures are injected into node:fs, which the Node reader imports, so they hold on every
// host.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { basename, dirname, join } from "node:path";
import { Bundle, tempDir } from "./bundle-kit.ts";
import { BundleReadError, verifyBundle, type VerifyReport } from "../src/verify.ts";
import { verifyBundleFiles, type BundleReader } from "../src/verify-core.ts";

/** Run `fn` while the host refuses to open the member `name` of a bundle directory named "bundle"; returns the refusals too. */
function withOpenRefused<T>(name: string, fn: () => T): { out: T; refused: number } {
  const module = fs as unknown as Record<"openSync", (...args: unknown[]) => unknown>;
  const original = module.openSync;
  let refused = 0;
  module.openSync = function (this: unknown, path: unknown, ...rest: unknown[]) {
    const p = String(path);
    if (basename(p) === name && basename(dirname(p)) === "bundle") {
      refused += 1;
      const err = new Error(`EBUSY: resource busy or locked, open '${p}'`) as NodeJS.ErrnoException;
      err.code = "EBUSY";
      err.syscall = "open";
      err.path = p;
      throw err;
    }
    return original.call(this, path, ...rest);
  };
  syncBuiltinESMExports();
  try {
    return { out: fn(), refused };
  } finally {
    module.openSync = original;
    syncBuiltinESMExports();
  }
}

function onDisk<T>(bundle: Bundle, fn: (root: string) => T): T {
  const dir = tempDir("read-row-beside-refusal");
  try {
    return fn(bundle.writeTo(join(dir, "bundle")));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

const codes = (report: VerifyReport): string[] => report.errors.map((e) => e.code);

function notStrict(bundle: Bundle, name: string): Bundle {
  return bundle.setBytes(name, '{"s": ');
}
function p1BreakingItsContract(): Bundle {
  const bundle = Bundle.linkValid();
  bundle.edit("p1.json", (p1) => { p1.unexpected = 1; });
  return bundle.seal();
}
function bothEnvelopeNames(): Bundle {
  const bundle = Bundle.linkValid().seal();
  return bundle.setBytes("envelope.json", bundle.bytes("envelope_env1.json"));
}

// name -> [bundle, the member the host fails to read, the errors, the outcome.reason]
const CASES: Array<[string, () => Bundle, string, string[], string]> = [
  ["manifest not strict JSON, its sidecar unread", () => notStrict(Bundle.linkValid().seal(), "manifest.json"), "manifest.sha256",
    ["manifest_verification_failed", "manifest_read_failed"], "manifest_verification_failed"],
  ["manifest unread, no sidecar", () => Bundle.linkValid().seal().delete("manifest.sha256"), "manifest.json",
    ["manifest_verification_failed", "manifest_read_failed"], "manifest_verification_failed"],
  ["P1 breaking its contract, the canonical input unread", p1BreakingItsContract, "canonical_input.json",
    ["manifest_read_failed", "p1_verification_failed", "p1_read_failed"], "manifest_read_failed"],
  ["P1 breaking its contract, its sidecar unread", p1BreakingItsContract, "p1.sha256",
    ["manifest_read_failed", "p1_verification_failed", "p1_read_failed"], "manifest_read_failed"],
  ["P1 unread, the canonical input not strict JSON", () => notStrict(Bundle.linkValid(), "canonical_input.json").seal(), "p1.json",
    ["manifest_read_failed", "p1_verification_failed", "p1_read_failed"], "manifest_read_failed"],
  ["envelope not strict JSON, its sidecar unread", () => notStrict(Bundle.linkValid().seal(), "envelope_env1.json"), "envelope.sha256",
    ["envelope_verification_failed", "envelope_read_failed"], "envelope_verification_failed"],
  ["envelope without its sidecar, unread", () => Bundle.linkValid().seal().delete("envelope.sha256"), "envelope_env1.json",
    ["envelope_incomplete", "envelope_read_failed"], "envelope_incomplete"],
  ["sidecar without its envelope, unread", () => Bundle.linkValid().seal().delete("envelope_env1.json"), "envelope.sha256",
    ["envelope_incomplete", "envelope_read_failed"], "envelope_incomplete"],
];

for (const [name, make, unread, errors, reason] of CASES) {
  test(`the read row and the verification row are each reported: ${name}`, () => {
    onDisk(make(), (root) => {
      const { out: report, refused } = withOpenRefused(unread, () => verifyBundle(root));
      assert.ok(refused > 0, `the host was never asked to open ${unread}`);
      assert.deepEqual(codes(report), errors);
      assert.equal(report.outcome.reason, reason);
      assert.equal(report.status, "OFFLINE_FAIL");
    });
  });
}

test("each case is refused for its content alone when every member is read", () => {
  // Non-vacuity of the cases above: with every member readable, the run carries the verification
  // row and no read row, so the read row above comes from the host failure alone.
  for (const [name, make, , errors] of CASES) {
    onDisk(make(), (root) => {
      const got = codes(verifyBundle(root));
      assert.deepEqual(got.filter((c) => c.endsWith("_read_failed")), [], name);
      const content = (c: string) => !c.endsWith("_read_failed");
      assert.deepEqual(got.filter(content), errors.filter(content), name);
    });
  }
});

/** A reader with no listing over `bundle`, which fails to read `failing` with a BundleReadError. */
function unlistedReader(bundle: Bundle, failing: string): BundleReader {
  const read = (name: string): Uint8Array | null => {
    if (name === failing) throw new BundleReadError(`the host cannot read ${name}`);
    return bundle.has(name) ? bundle.bytes(name) : null;
  };
  return { readBytes: read, readText: (name) => { const b = read(name); return b === null ? null : new TextDecoder().decode(b); } };
}

test("a reader without a listing judges both rows on their own as well", () => {
  for (const [name, make, unread, errors, reason] of CASES) {
    const report = verifyBundleFiles(unlistedReader(make(), unread));
    assert.deepEqual(codes(report), errors, name);
    assert.equal(report.outcome.reason, reason, name);
  }
});

test("envelope.json beside envelope_env1.json is never read", () => {
  onDisk(bothEnvelopeNames(), (root) => {
    const { out: report, refused } = withOpenRefused("envelope.json", () => verifyBundle(root));
    assert.equal(refused, 0);
    assert.deepEqual([codes(report), report.status, report.review_reasons], [[], "OFFLINE_REVIEW", ["bundle_extra_files"]]);
  });
});

test("a member the host fails to read keeps the flags of what was found", () => {
  const cases: Array<[Bundle, string, boolean]> = [
    [Bundle.linkValid().seal().delete("envelope.sha256"), "envelope_env1.json", true],
    [Bundle.linkValid().seal().delete("envelope_env1.json"), "envelope.sha256", false],
  ];
  for (const [bundle, unread, present] of cases) {
    onDisk(bundle, (root) => {
      const { out: report } = withOpenRefused(unread, () => verifyBundle(root));
      const c = report.checks;
      assert.deepEqual([c.envelope_present, c.envelope_sha256, c.envelope_links], [present, false, false], unread);
    });
  }
});

for (const [envelope, links] of [["both", false], ["envelope only", null], ["sidecar only", null], ["neither", null]] as const) {
  test(`envelope_links beside a refused manifest: ${envelope}`, () => {
    const bundle = Bundle.linkValid().seal();
    if (envelope === "sidecar only" || envelope === "neither") bundle.delete("envelope_env1.json");
    if (envelope === "envelope only" || envelope === "neither") bundle.delete("envelope.sha256");
    onDisk(bundle, (root) => {
      const { out: report } = withOpenRefused("manifest.sha256", () => verifyBundle(root));
      assert.equal(codes(report)[0], "manifest_read_failed");
      assert.equal(report.checks.envelope_links, links);
    });
  });
}
